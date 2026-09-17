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
use bifrost_mem::{MemSession, MemTransport};

use super::{MdnsState, PeerHint, Reach, ReachArgs, RelayHome, Resolver, Transport};
use crate::home::Home;

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

/// Composing the discovery hands mDNS the transport's bound sockets, and never asks for the hints.
///
/// The advertisement itself may or may not reach the network here (a sandbox blocks multicast, which is
/// the honest degraded path), so the assertion is on what the composition root read, which holds either
/// way.
#[tokio::test]
async fn composing_discovery_advertises_the_bound_sockets() {
    let reads = Arc::new(Mutex::new(Vec::new()));
    let transport = Recording {
        inner: MemTransport::bind(),
        reads: Arc::clone(&reads),
    };

    let _composed = PeerHint::discovery(&transport, []);

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
    let composed = PeerHint::discovery(&transport, []);
    assert!(
        matches!(composed.mdns, MdnsState::BrowseOnly(_) | MdnsState::Blocked),
        "no addresses to advertise never reads as advertised, got {:?}",
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

/// `serve --relay --resolver` writes both files, and a later verb under the SAME home reads them back as
/// the two URLs it was pointed at. This is the whole contract of the home files: name the two servers once,
/// on the node, and every verb after it reaches the same fleet with no flags repeated.
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
    served
        .persist_reach(&home)
        .await
        .expect("serve writes both reach files");

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

        for path in [home.relay(), home.resolver()] {
            let mode = std::fs::metadata(&path)
                .expect("stat the reach file")
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
    ReachArgs {
        resolver: Some(
            "https://dns.example/pkarr"
                .parse()
                .expect("a valid resolver url"),
        ),
        ..no_flags()
    }
    .persist_reach(&home)
    .await
    .expect("serve writes the resolver file");

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

/// An empty or malformed reach file REFUSES, naming the file and both fixes. It never shrugs back to n0:
/// the operator wrote the file to keep this node off n0's servers, so a silent fallback would put it back
/// there without a word.
#[tokio::test]
async fn an_empty_or_malformed_reach_file_refuses_with_the_file_named() {
    let home = home("refuse");
    std::fs::create_dir_all(home.dir()).expect("create the home dir");

    for (contents, tail) in [
        ("   \n", "is empty"),
        ("http://relay.example\n", "usable relay"),
    ] {
        std::fs::write(home.relay(), contents).expect("write the relay file");
        let error = no_flags()
            .reach(&home)
            .await
            .expect_err("a file that names no relay is a refusal, not a shrug back to n0");
        let message = format!("{error:#}");
        assert!(
            message.contains(&home.relay().display().to_string()),
            "the message names the file: {message}"
        );
        assert!(message.contains(tail), "{message}");
        assert!(
            message.contains("delete it, or pass --relay <url>"),
            "the message names both fixes: {message}"
        );
    }

    std::fs::write(home.relay(), "https://relay.example\n").expect("write a usable relay");
    std::fs::write(home.resolver(), "ftp://dns.example\n").expect("write the resolver file");
    let error = no_flags()
        .reach(&home)
        .await
        .expect_err("a file that names no resolver refuses too");
    let message = format!("{error:#}");
    assert!(
        message.contains(&home.resolver().display().to_string())
            && message.contains("does not name a usable resolver")
            && message.contains("delete it, or pass --resolver <url>"),
        "{message}"
    );
    assert!(
        message.contains("only https is accepted"),
        "the parse fault rides the source chain, so the reader is told WHY: {message}"
    );
}

/// A bind that reads neither reach flag refuses both BY NAME rather than parsing and ignoring them:
/// `--local` (no n0 at all) and each quirk spelling (direct-only, no record of its own). The refusal
/// names the bind as the user spelled it, so the reader can find the flag to drop on their own line.
#[test]
fn a_bind_that_uses_neither_reach_flag_refuses_both_by_name() {
    for (local, transport, spelling, relay_subject, resolver_subject) in [
        (
            true,
            Transport::default(),
            "--local",
            "a local bind uses no relay",
            "a local bind publishes no record",
        ),
        (
            false,
            Transport::Quirk,
            "--transport quirk",
            "quirk uses no relay",
            "quirk publishes no record",
        ),
        (
            false,
            Transport::QuirkNoise,
            "--transport quirk+noise",
            "quirk uses no relay",
            "quirk publishes no record",
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
        assert_eq!(
            format!("{relay:#}"),
            format!("--relay has no effect under {spelling}: {relay_subject}; drop one of the two")
        );

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
        assert_eq!(
            format!("{resolver:#}"),
            format!(
                "--resolver has no effect under {spelling}: {resolver_subject}; drop one of the two"
            )
        );
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

/// A directory where a reach file belongs is the same mistake as a file holding nothing usable, and it
/// gets the same teaching line: the raw `Is a directory` names neither the file nor the way out.
#[tokio::test]
async fn a_reach_file_that_is_a_directory_refuses_with_the_file_named() {
    let home = home("directory");
    std::fs::create_dir_all(home.relay()).expect("create a directory where the relay file belongs");
    let error = no_flags()
        .reach(&home)
        .await
        .expect_err("a directory is not a relay");
    assert_eq!(
        format!("{error:#}"),
        format!(
            "the relay file {} is a directory; remove it, or pass --relay <url>",
            home.relay().display()
        )
    );
}
