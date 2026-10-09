//! What the composed discovery reads off its transport, and what it reports back: the one `advertise`
//! call that starts mDNS is also the one source of the reach a surface reports, so a bind that could
//! publish nothing never reads as a node another host can hear.
//!
//! And the reach half of the seam: the relay and the resolver a bind leans on come from the flags, else
//! the two home files `serve` wrote, else n0's. The rules pinned here are the ones an operator feels: a
//! round trip through a home, a flag that overrides the file for one run without rewriting it, a file
//! that names nothing usable refusing instead of falling back to n0, and `--local` refusing both flags.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bifrost::{Addr, Error, InProcess, NodeId};
use bifrost_mdns::MdnsError;
use bifrost_mem::{MemSession, MemTransport};

use super::{MdnsState, PeerHint, Reach, ReachArgs, RelayHome, Resolver, Transport};
use crate::credential::Credential;
use crate::home::Home;
use crate::reaching::BindRole;

/// A wildcard bind on a fixed port: the shape the rewrite destroys, since `local_addr` reports it as
/// loopback and a publisher cannot then tell it from a node that deliberately bound `127.0.0.1`.
const WILDCARD: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);

/// An address accessor read off the transport, with what it handed back.
#[derive(Debug, PartialEq, Eq)]
enum Read {
    /// The dialable hints, which rewrite an unspecified bind to loopback.
    LocalAddr(Vec<SocketAddr>),
    /// The sockets as bound, unspecified IP preserved.
    BoundSockets(Vec<SocketAddr>),
}

/// A transport over mem's sessions that records which address accessor was read and answers
/// [`bound_sockets`](bifrost::Transport::bound_sockets) with a wildcard bind of its own.
///
/// The two accessors are indistinguishable downstream (the advertisement goes to the network, not to a
/// value the test holds), so recording the read at the source is what proves which one the composition
/// root trusted.
struct Recording {
    inner: MemTransport,
    reads: Arc<Mutex<Vec<Read>>>,
}

impl bifrost::Transport for Recording {
    type Security = InProcess;
    type Session = MemSession;

    fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    fn local_addr(&self) -> Addr {
        let addr = self.inner.local_addr();
        self.record(Read::LocalAddr(addr.hints.clone()));
        addr
    }

    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.record(Read::BoundSockets(vec![WILDCARD]));
        vec![WILDCARD]
    }

    async fn connect(&self, addr: Addr) -> Result<Self::Session, Error> {
        self.inner.connect(addr).await
    }

    async fn accept(&self) -> Result<Self::Session, Error> {
        self.inner.accept().await
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}

impl Recording {
    /// Note one accessor read. A poisoned lock would only be a panic inside an accessor, which would have
    /// failed the test already.
    fn record(&self, read: Read) {
        self.reads.lock().unwrap().push(read);
    }
}

/// Composing the discovery for a serving bind hands mDNS the transport's bound sockets, and never asks
/// for the hints.
///
/// The advertisement itself may or may not reach the network here (a sandbox blocks multicast, which is
/// the honest degraded path), so the assertion is on what the composition root read, which holds either
/// way.
#[tokio::test]
async fn composing_discovery_advertises_the_bound_sockets() {
    let (transport, reads) = recording();

    let _composed = PeerHint::discovery(&transport, [], &BindRole::Serving);

    assert_eq!(
        *reads.lock().unwrap(),
        vec![Read::BoundSockets(vec![WILDCARD])],
        "the advertisement must take raw bind truth, not the loopback-rewritten hints"
    );
}

/// A bind with no local addresses to advertise (the in-process transport's shape) cannot be published,
/// so the composed discovery never reports a node another host can hear: it either browses without
/// announcing, or (where the service itself will not start) reads as blocked. A caller that reports
/// discovery reads this state rather than assuming it.
#[tokio::test]
async fn a_bind_without_advertisable_addresses_reports_mdns_unavailable() {
    let transport = MemTransport::bind();
    let composed = PeerHint::discovery(&transport, [], &BindRole::Serving);
    assert!(
        matches!(composed.mdns, MdnsState::BrowseOnly(_) | MdnsState::Blocked),
        "no addresses to advertise never reads as advertised, got {:?}",
        composed.mdns
    );
}

/// A dialing role, as every verb but `serve` declares it.
fn dialing() -> BindRole {
    BindRole::Dialing(Credential::Family { present: None })
}

/// A [`Recording`] transport and the log of what was read off it.
fn recording() -> (Recording, Arc<Mutex<Vec<Read>>>) {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let transport = Recording {
        inner: MemTransport::bind(),
        reads: Arc::clone(&reads),
    };
    (transport, reads)
}

/// A serving bind hands its bound sockets to the advertisement: a dialer finds it by its key.
#[test]
fn a_serving_bind_advertises_its_bind() {
    let (transport, _reads) = recording();

    assert_eq!(
        BindRole::Serving.advertised(&transport),
        vec![WILDCARD],
        "a serving node must still publish its bind"
    );
}

/// A dialing bind hands the advertisement no address, and reads none off the transport: there is
/// nothing to publish, so no record on the LAN names this node's key.
#[test]
fn a_dialing_bind_advertises_no_address() {
    let (transport, reads) = recording();

    assert_eq!(
        dialing().advertised(&transport),
        Vec::<SocketAddr>::new(),
        "a dialing node must publish no address"
    );
    assert_eq!(
        *reads.lock().unwrap(),
        Vec::new(),
        "a dialing node reads no address to publish"
    );
}

/// Composing discovery for a dialing bind still starts mDNS (it browses) but advertises nothing: the
/// composition root never reads the bind, and the state is browse-only for want of an address, or
/// blocked where multicast cannot start at all. It never reads as a node another host can hear.
#[tokio::test]
async fn composing_discovery_for_a_dialing_bind_advertises_nothing() {
    let (transport, reads) = recording();

    let composed = PeerHint::discovery(&transport, [], &dialing());

    assert_eq!(
        *reads.lock().unwrap(),
        Vec::new(),
        "a dialing bind must hand the advertisement nothing"
    );
    assert!(
        matches!(
            composed.mdns,
            MdnsState::BrowseOnly(MdnsError::NoAddrs) | MdnsState::Blocked
        ),
        "a dialing bind browses without advertising, got {:?}",
        composed.mdns
    );
}

/// A unique home under the temp dir, resolved as an explicit [`Home`] so its reach files derive from that
/// dir. The dir does not exist yet, so the first write exercises the `0700` create.
fn home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-reach-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    Home::resolve(Some(dir)).expect("resolve an explicit home")
}

/// The reach-family defaults: what clap hands a verb that named neither flag.
fn no_flags() -> ReachArgs {
    ReachArgs {
        transport: Transport::default(),
        local: false,
        peer: Vec::new(),
        relay: None,
        resolver: None,
    }
}

/// Keep `flags` in `home`'s `serve.toml`, as a `serve` does once its routes bind.
fn keep(home: &Home, flags: &ReachArgs) {
    crate::serve_toml::ServeToml::update(&crate::testkit::lock(), home, |file| {
        flags.keep_reach(file);
    })
    .expect("serve writes the reach fields");
}

/// `serve --relay --resolver` writes both into `serve.toml`, and a later verb under the SAME home reads
/// them back as the two URLs it was pointed at. This is the whole contract: name the two servers once, on
/// the node, and every verb after it reaches the same fleet with no flags repeated.
#[tokio::test]
async fn both_reach_files_round_trip_through_a_home() {
    let home = home("round-trip");
    let served = ReachArgs {
        relay: Some("https://relay.example".parse().expect("a valid relay url")),
        resolver: Some(
            "https://dns.example/pkarr"
                .parse()
                .expect("a valid resolver url"),
        ),
        ..no_flags()
    };
    keep(&home, &served);

    let read = no_flags()
        .reach(&home)
        .await
        .expect("a later verb reads them back");
    assert_eq!(
        read,
        Reach {
            relay: RelayHome::Custom("https://relay.example".parse().expect("a valid relay url")),
            resolver: Resolver::Custom(
                "https://dns.example/pkarr"
                    .parse()
                    .expect("a valid resolver url")
            ),
        },
        "what serve wrote is what the next verb binds over"
    );

    // Owner-only, like every other file in the store: which relay a node offers and which resolver it
    // publishes to is this node's configuration, not a co-tenant local user's to read or rewrite.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let path = home.serve_toml();
        let mode = std::fs::metadata(&path)
            .expect("stat serve.toml")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "{} is written owner-only",
            path.display()
        );
    }
}

/// A home with no reach files is n0's on both halves: the default every node has always had, reached
/// without touching the disk.
#[tokio::test]
async fn a_home_with_no_reach_files_is_n0s() {
    let read = no_flags()
        .reach(&home("absent"))
        .await
        .expect("an unwritten home resolves");
    assert_eq!(read, Reach::default());
}

/// A flag on a dial overrides the file for that run and leaves the file alone: a one-off dial through
/// another fleet's resolver must not silently re-point the home.
#[tokio::test]
async fn a_flag_overrides_the_file_for_one_run() {
    let home = home("override");
    let served = ReachArgs {
        resolver: Some(
            "https://dns.example/pkarr"
                .parse()
                .expect("a valid resolver url"),
        ),
        ..no_flags()
    };
    keep(&home, &served);

    let dialed = ReachArgs {
        resolver: Some(
            "https://other.example/pkarr"
                .parse()
                .expect("a valid resolver url"),
        ),
        ..no_flags()
    }
    .reach(&home)
    .await
    .expect("the dial resolves");
    assert_eq!(
        dialed.resolver,
        Resolver::Custom(
            "https://other.example/pkarr"
                .parse()
                .expect("a valid resolver url")
        ),
        "the flag wins for this run"
    );

    let after = no_flags()
        .reach(&home)
        .await
        .expect("the home still resolves");
    assert_eq!(
        after.resolver,
        Resolver::Custom(
            "https://dns.example/pkarr"
                .parse()
                .expect("a valid resolver url")
        ),
        "a dial's flag never rewrites the home"
    );
}

/// A relay or resolver in `serve.toml` that is not a usable one REFUSES, naming the file, in swoosh's own
/// line alone: no parser text after it, and no command, since which server to use is the person's call. It
/// never shrugs back to n0: the operator set it to keep this node off n0's servers, so a silent fallback
/// would put it back there without a word.
#[tokio::test]
async fn an_unusable_kept_relay_or_resolver_refuses_with_the_file_named() {
    let home = home("refuse");
    std::fs::create_dir_all(home.dir()).expect("create the home dir");

    for kept in ["", "not a url", "http://relay.example"] {
        std::fs::write(home.serve_toml(), format!("relay = \"{kept}\"\n"))
            .expect("write serve.toml");
        let error = no_flags()
            .reach(&home)
            .await
            .expect_err("a kept relay that is no relay is a refusal, not a shrug back to n0");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "the relay in {} is not a usable relay, and swoosh will not fall back to the default one",
                home.serve_toml().display()
            ),
        );
    }

    std::fs::write(
        home.serve_toml(),
        "relay = \"https://relay.example\"\nresolver = \"ftp://dns.example\"\n",
    )
    .expect("write serve.toml");
    let error = no_flags()
        .reach(&home)
        .await
        .expect_err("a kept resolver that is no resolver refuses too");
    assert_eq!(
        format!("{error:#}"),
        format!(
            "the resolver in {} is not a usable resolver, and swoosh will not fall back to the default one",
            home.serve_toml().display()
        ),
    );
}

/// A bind that reads neither reach flag refuses both BY NAME rather than parsing and ignoring them:
/// `--local` (no n0 at all) and each quirk spelling (direct-only, no record of its own). Every flag here is
/// hidden and read from the environment too, so the refusal names both spellings of the flag and of
/// `--local`: the person may only ever have set the variable.
#[test]
fn a_bind_that_uses_neither_reach_flag_refuses_both_by_name() {
    for (local, transport, spelling, relay_line, resolver_line) in [
        (
            true,
            Transport::default(),
            "--local",
            "--relay or SWOOSH_RELAY has no effect with --local or SWOOSH_LOCAL\n  swoosh uses no relay \
             when it runs on this network only.",
            "--resolver or SWOOSH_RESOLVER has no effect with --local or SWOOSH_LOCAL\n  swoosh publishes \
             no record when it runs on this network only.",
        ),
        (
            false,
            Transport::Quirk,
            "--transport quirk",
            "--relay or SWOOSH_RELAY has no effect over quirk\n  quirk uses no relay.",
            "--resolver or SWOOSH_RESOLVER has no effect over quirk\n  quirk publishes no record.",
        ),
        (
            false,
            Transport::QuirkNoise,
            "--transport quirk+noise",
            "--relay or SWOOSH_RELAY has no effect over quirk\n  quirk uses no relay.",
            "--resolver or SWOOSH_RESOLVER has no effect over quirk\n  quirk publishes no record.",
        ),
    ] {
        let bind = |relay, resolver| ReachArgs {
            transport,
            local,
            relay,
            resolver,
            ..no_flags()
        };
        assert!(
            bind(None, None).reject_unused_reach().is_ok(),
            "{spelling} that named neither flag has nothing to refuse"
        );

        let relay = bind(
            Some("https://relay.example".parse().expect("a valid relay url")),
            None,
        )
        .reject_unused_reach()
        .expect_err("--relay on a bind that never reads it is refused");
        assert_eq!(relay.to_string(), relay_line, "{spelling}");

        let resolver = bind(
            None,
            Some(
                "https://dns.example/pkarr"
                    .parse()
                    .expect("a valid resolver url"),
            ),
        )
        .reject_unused_reach()
        .expect_err("--resolver on a bind that never reads it is refused");
        assert_eq!(resolver.to_string(), resolver_line, "{spelling}");
    }

    // An iroh bind is the one that reads both, so it refuses neither.
    assert!(
        ReachArgs {
            relay: Some("https://relay.example".parse().expect("a valid relay url")),
            resolver: Some(
                "https://dns.example/pkarr"
                    .parse()
                    .expect("a valid resolver url")
            ),
            ..no_flags()
        }
        .reject_unused_reach()
        .is_ok(),
        "the iroh bind is the one that uses both flags"
    );
}

/// A `serve.toml` that cannot be read refuses, naming the file, rather than reaching through n0.
#[tokio::test]
async fn a_serve_toml_that_cannot_be_read_refuses_with_the_file_named() {
    let home = home("directory");
    std::fs::create_dir_all(home.serve_toml())
        .expect("create a directory where serve.toml belongs");
    let error = no_flags()
        .reach(&home)
        .await
        .expect_err("a directory is not a relay");
    assert_eq!(
        error.to_string(),
        format!("could not use {}", home.serve_toml().display())
    );
}

/// A form that reaches no machine refuses a reach flag typed on it, by name, and reads its defaults as
/// nothing typed. Only the command line counts: the variables are held through the real binary
/// (`tests/bare_verbs.rs`), since setting one here would race every other test in the process.
#[test]
fn a_typed_reach_flag_is_found_by_its_typed_name() {
    let model = <ReachArgs as clap::Args>::augment_args(clap::Command::new("x"));
    let typed = |argv: &[&str]| {
        let matches = model
            .clone()
            .try_get_matches_from(argv)
            .expect("the reach flags parse");
        ReachArgs::typed_bare(&matches).map(|flag| flag.to_string())
    };
    assert_eq!(typed(&["x"]), None, "the defaults are nothing typed");
    let hint = format!("{}=127.0.0.1:9000", NodeId::from_ed25519_secret(&[5u8; 32]));
    for (argv, flag) in [
        (vec!["x", "--transport", "quirk"], "--transport"),
        (vec!["x", "--local"], "--local"),
        (vec!["x", "--peer", hint.as_str()], "--peer"),
        (vec!["x", "--relay", "https://relay.example"], "--relay"),
        (
            vec!["x", "--resolver", "https://dns.example/pkarr"],
            "--resolver",
        ),
    ] {
        assert_eq!(
            typed(&argv).as_deref(),
            Some(format!("{flag} has no effect without a machine").as_str()),
            "{argv:?}"
        );
    }
}
