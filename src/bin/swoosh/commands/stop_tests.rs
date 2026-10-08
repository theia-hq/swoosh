//! `stop`'s tests: the machine shapes it refuses before anything binds, read against a real device home;
//! the local stop over the control socket; and the remote stop over the in-process transport, its
//! teardown race included: a peer that admits the session then vanishes before answering the control
//! stream is never reported stopped, only unconfirmed, and a live peer behind the same failure stays loud.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use bifrost::{NoDiscovery, Node, NodeId, Session as _, Transport as _};
use bifrost_mem::MemTransport;
use clap::Parser as _;
use keystore::{KeyFile, Protection};
use swoosh::home::Home;
use swoosh::node_client::ControlClient;
use swoosh::peer::{OwnDevice, Peer};
use swoosh::roster::{Epoch, RevokedDevice, RosterDoc};
use swoosh::serve::{CONTROL_STOP_SERVICE, FirstRound, Resident, Stop, StopKind};
use swoosh::serve_toml::LiveServeToml;
use swoosh::testkit::{HostilePeer, STANDING_UNTIL, TestNode, TestRoot};
use tightbeam::enabled::EnabledServices as _;
use tightbeam::tunnel::{CancellationToken, Router, ServiceCatalog};

use super::{
    A_LINK_STOPS_NOTHING, Aim, StopCmd, StopDevice, Target, Usage, Yours, confirmed, stop_line,
};

/// The root this machine's devices belong to.
const ROOT: u8 = 0x61;
/// This machine, `me/desk`.
const DESK: u8 = 0x62;
/// Another of your devices, `me/nas`.
const NAS: u8 = 0x63;
/// Another of your devices, `me/pi`.
const PI: u8 = 0x64;
/// A device the list revokes, once `me/old`.
const OLD: u8 = 0x65;
/// Bob's laptop, a contact's machine.
const BOB: u8 = 0x66;

/// Serializes scratch names within this test process; the pid keeps two concurrent runs apart.
static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A unique 0700 scratch base under the temp dir.
fn scratch(tag: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sw4-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("0700 scratch");
    dir
}

/// A node home under `base`, created so `Home::resolve` sees a directory.
fn home_in(base: &Path) -> Home {
    let dir = base.join("home");
    std::fs::create_dir_all(&dir).expect("scratch home");
    Home::resolve(Some(dir)).expect("the scratch home resolves")
}

/// This machine as `me/desk`, one of `ROOT`'s devices: its key, the pin, and a list of your devices naming
/// desk, nas and pi and revoking old; and bob's laptop saved as a contact.
async fn device_home(tag: &str) -> (PathBuf, Home) {
    let base = scratch(tag);
    let dir = base.join("home");
    swoosh::config::create_store_dir(&dir).expect("the store dir");
    let home = Home::resolve(Some(dir)).expect("the scratch home resolves");
    let mut seed = TestNode::seeded(DESK).seed();
    swoosh::identity::make_machine_dir(&home).expect("the machine dir");
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .expect("this machine's key");
    let root = TestRoot::seeded(ROOT);
    swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).expect("the pin");
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
    let badge = root
        .device_badge(TestNode::seeded(DESK).node_id(), until)
        .expect("a badge");
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).expect("the badge");
    let members = [(DESK, "desk"), (NAS, "nas"), (PI, "pi")]
        .into_iter()
        .map(|(seed, label)| {
            root.member(
                TestNode::seeded(seed).verify_key(),
                label.parse().expect("a name"),
            )
            .expect("a member")
        })
        .collect();
    let revoked = vec![RevokedDevice {
        node: TestNode::seeded(OLD).verify_key(),
        label: "old".parse().expect("a name"),
    }];
    let update = root.sign_update(
        &RosterDoc::with_revocations(Epoch(1), members, Vec::new(), revoked).expect("a list"),
    );
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&home)
            .await
            .expect("home.lock"),
        &home,
        &update,
    )
    .await
    .expect("the list folds");
    std::fs::write(
        home.contacts(),
        format!("[bob]\nlaptop = \"{}\"\n", TestNode::seeded(BOB).node_id()),
    )
    .expect("bob saved");
    (base, home)
}

/// Parse `text` as `stop`'s machine and resolve it against `home`'s list of your devices.
async fn aim(home: &Home, text: &str) -> Result<Target, String> {
    let Ok(aim) = Aim::parse(text);
    let yours = Yours::read(home).await.expect("the list reads");
    aim.resolve(&yours).map_err(|Usage(line)| line)
}

/// A refusal: the line `stop <text>` refuses with, never a machine to dial.
async fn refused(home: &Home, text: &str) -> String {
    match aim(home, text).await {
        Err(line) => line,
        Ok(target) => {
            panic!("stop {text} resolved to {target:?}: a refused shape must dial nothing")
        }
    }
}

/// A bare word is never a machine: one of your device names typed without `me/` names the command that
/// would stop it, a contact says it is one, and any other word shows the shape. Nothing resolves, so nothing
/// dials. Fall through to the peer parser and `stop nas` dials nas, `stop bob` bob's first machine.
#[tokio::test]
async fn stop_a_bare_word_is_never_a_machine() {
    let (base, home) = device_home("word").await;
    assert_eq!(
        refused(&home, "nas").await,
        "swoosh stop takes one of your machines: swoosh stop me/nas"
    );
    assert_eq!(
        refused(&home, "bob").await,
        "you can stop only your own machines; bob is a contact"
    );
    assert_eq!(
        refused(&home, "ssh").await,
        "swoosh stop takes one of your machines, like me/desk"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// With no list of your devices, every refusal that would show yours says this machine knows none of them,
/// the bare word's included. Drop the detail from the bare word and it alone prints with nothing under it.
#[tokio::test]
async fn stop_with_no_list_says_this_machine_knows_none_of_your_devices() {
    let base = scratch("none");
    let home = home_in(&base);
    let none = "This machine knows none of your devices.";
    assert_eq!(
        refused(&home, "nas").await,
        format!("swoosh stop takes one of your machines\n  {none}")
    );
    assert_eq!(
        refused(&home, "me").await,
        format!("which machine?\n  {none}")
    );
    assert_eq!(
        refused(&home, "me/nsa").await,
        format!("you have no machine me/nsa\n  {none}")
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// Text that is no name, no key and no link is refused like a word that names nothing of yours, and is
/// kept as nothing, so the refusal cannot print it back. Let the parser fail and clap prints it whole.
#[tokio::test]
async fn stop_refuses_text_that_is_no_name_without_keeping_it() {
    let (base, home) = device_home("notaname").await;
    for typed in ["bob laptop", "a/b/c", "me/nas!", "nas!", "-nas"] {
        assert!(
            matches!(Aim::parse(typed), Ok(Aim::NotAName)),
            "{typed} is no name"
        );
        assert_eq!(
            refused(&home, typed).await,
            "swoosh stop takes one of your machines, like me/desk",
            "{typed}"
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// `me` alone names no one machine: it refuses and lists yours. Hand it on and it stops your first device.
#[tokio::test]
async fn stop_me_without_a_name_refuses_and_dials_nothing() {
    let (base, home) = device_home("me").await;
    assert_eq!(
        refused(&home, "me").await,
        "which machine?\n  Yours: me/desk, me/nas, me/pi."
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// Only a `me/<name>` the list holds reaches a dial: a contact's machine, a key (one of yours or not), a
/// link and a path all refuse, a link and a path at parse. A name the list does not hold lists yours, and a
/// revoked one says so. Resolve any of them and a dial goes out to a machine nobody named as theirs.
#[tokio::test]
async fn stop_accepts_only_own_device_names() {
    let (base, home) = device_home("shapes").await;
    assert_eq!(
        refused(&home, "bob/laptop").await,
        "you can stop only your own machines; bob is a contact"
    );
    assert_eq!(
        refused(&home, "carol/nas").await,
        "you can stop only your own machines; carol/nas is not one of them"
    );
    let nas = TestNode::seeded(NAS).node_id().to_string();
    assert_eq!(
        refused(&home, &nas).await,
        "name the machine: swoosh stop me/nas"
    );
    // The book also holds nas's key under a contact, whose name sorts before `me`: the key is still one of
    // yours. Look it up in the whole book and the first name found says it is not.
    std::fs::write(
        home.contacts(),
        format!(
            "[alice]\nx = \"{nas}\"\n\n[bob]\nlaptop = \"{}\"\n",
            TestNode::seeded(BOB).node_id()
        ),
    )
    .expect("nas saved under alice too");
    assert_eq!(
        refused(&home, &nas).await,
        "name the machine: swoosh stop me/nas"
    );
    let bob = TestNode::seeded(BOB).node_id().to_string();
    assert_eq!(
        refused(&home, &bob).await,
        "that key is not one of your machines"
    );
    let link = swoosh::link::Link::from(
        TestRoot::seeded(ROOT)
            .bound_slip(
                &CONTROL_STOP_SERVICE.parse().expect("a service"),
                TestNode::seeded(NAS).verify_key(),
                nauthy::Request::expires_in(Duration::from_secs(300)),
            )
            .expect("a slip"),
    )
    .to_string();
    let bare = link.trim_start_matches("swoosh:").to_owned();
    for text in [
        link.as_str(),
        bare.as_str(),
        "./nas.link",
        "/tmp/nas.link",
        "~/nas.link",
    ] {
        assert_eq!(refused(&home, text).await, A_LINK_STOPS_NOTHING, "{text}");
    }
    assert_eq!(
        refused(&home, "me/nsa").await,
        "you have no machine me/nsa\n  Yours: me/desk, me/nas, me/pi."
    );
    assert_eq!(refused(&home, "me/old").await, "me/old was revoked");

    // And the one shape that does resolve: a device of yours, by its key in the list.
    let Ok(Target::Device { device, node }) = aim(&home, "me/nas").await else {
        panic!("me/nas is one of your devices");
    };
    assert_eq!(device.to_string(), "me/nas");
    assert_eq!(node, TestNode::seeded(NAS).node_id());
    let _ = std::fs::remove_dir_all(&base);
}

/// This machine's own name stops it locally, the way bare `stop` does, and never dials it. Dial self and the
/// stop goes over the network to a node that may not admit its own key.
#[tokio::test]
async fn stop_own_name_stops_locally() {
    let (base, home) = device_home("own").await;
    assert!(
        matches!(aim(&home, "me/desk").await, Ok(Target::Here)),
        "your own name is this machine"
    );
    let _ = std::fs::remove_dir_all(&base);

    // The local stop prints the pid line, as bare `stop` does.
    let Running {
        leaf,
        client,
        cancel,
        ..
    } = resident("own-local");
    let line = super::stop_resolved(&client)
        .await
        .expect("the socket stop succeeds");
    assert!(cancel.is_cancelled());
    assert!(
        line.starts_with("Stopped swoosh serve here"),
        "the local stop's line: {line}"
    );
    let _ = std::fs::remove_dir_all(&leaf);
}

/// The stop line names the pid the client read from the resident's lock, and degrades to the pid-less
/// form rather than printing a blank when the lock record is absent.
#[test]
fn the_stop_line_names_the_pid_when_known() {
    assert_eq!(
        stop_line(Some(4242)),
        "Stopped swoosh serve here (pid 4242).",
        "the stop confirmation names the resident pid"
    );
    assert_eq!(
        stop_line(None),
        "Stopped swoosh serve here.",
        "no lock record leaves the parenthetical off"
    );
}

/// A bare `stop` with no addressable resident is the teaching error naming the fix, non-zero at the
/// root: the control client resolution fails `NoResident`, never a silent success.
#[tokio::test]
async fn bare_stop_without_resident_is_teaching() {
    let base = scratch("teach");
    let home = home_in(&base);

    let error = bare_stop()
        .run_local(&home)
        .await
        .expect_err("no resident must refuse, never a silent success");
    assert_eq!(
        format!("{error:#}"),
        "swoosh serve is not running on this machine",
        "the error says nothing is running, as a clause with no closing period"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Parse a bare `stop` through clap, so the test drives the real verb shape (no transport flags).
fn bare_stop() -> StopCmd {
    parsed(&["x"])
}

/// `argv` parsed as `stop`'s arguments.
fn parsed(argv: &[&str]) -> StopCmd {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        stop: StopCmd,
    }

    Wrap::try_parse_from(argv).expect("stop parses").stop
}

/// A bare `stop` reaches no peer, so the reach trio (`--transport`/`--local`/`--peer`) has nothing to
/// bind or find: each is refused by name, never silently ignored (I.3, B4).
#[tokio::test]
async fn bare_stop_rejects_the_reach_flags() {
    let base = scratch("reach");
    let home = home_in(&base);
    let hint = format!("{}=127.0.0.1:9000", NodeId::from_ed25519_secret(&[5u8; 32]));
    let cases: [(&[&str], &str); 3] = [
        (&["x", "--transport", "quirk"], "--transport"),
        (&["x", "--local"], "--local"),
        (&["x", "--peer", &hint], "--peer"),
    ];
    for (argv, flag) in cases {
        let error = parsed(argv)
            .run_local(&home)
            .await
            .expect_err("no peer, no effect: the flag must refuse, never be ignored");
        assert_eq!(
            format!("{error:#}"),
            format!("{flag} only applies when reaching a peer; drop it or name one")
        );
    }

    let _ = std::fs::remove_dir_all(&base);
}

/// An in-process resident serving a real temp socket under a scratch leaf.
struct Running {
    /// The scratch leaf holding the socket.
    leaf: PathBuf,
    /// A client resolved to the socket.
    client: ControlClient,
    /// The resident's teardown token.
    cancel: CancellationToken,
    /// The resident.
    resident: Arc<Resident>,
    /// Its serve task.
    serving: tokio::task::JoinHandle<eyre::Result<()>>,
}

/// Start a [`Running`] resident under a fresh scratch leaf.
fn resident(tag: &str) -> Running {
    let leaf = scratch(tag);
    let off = services_off(&leaf);
    resident_reading(leaf, off)
}

/// The services off under `leaf`, read live, as `serve` loads them for its gate and its resident.
fn services_off(leaf: &Path) -> LiveServeToml {
    LiveServeToml::load(&Home::resolve(Some(leaf.to_path_buf())).expect("a scratch home"))
        .expect("the services off load")
}

/// Start a [`Running`] resident under `leaf`, reading the services off from `off`.
fn resident_reading(leaf: PathBuf, off: LiveServeToml) -> Running {
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    let cancel = CancellationToken::new();
    let resident = Arc::new(Resident::new(
        NodeId::from_ed25519_secret(&[9u8; 32]),
        None,
        empty_catalog(),
        off,
        cancel.clone(),
        Arc::default(),
    ));
    let serving = tokio::spawn({
        let this = Arc::clone(&resident);
        async move { this.serve(listener).await }
    });
    let client = ControlClient::resolve_socket(socket).expect("the bound socket resolves");
    Running {
        leaf,
        client,
        cancel,
        resident,
        serving,
    }
}

/// An empty catalog: these tests exercise the stop path, not service content.
fn empty_catalog() -> ServiceCatalog {
    ServiceCatalog::decode(&0u32.to_be_bytes()).expect("an empty catalog decodes")
}

/// An in-process resident serving a real temp socket: the bare stop resolves the socket backend,
/// fires the resident's one teardown token, and records the socket stop as its own kind.
#[tokio::test]
async fn bare_stop_through_the_socket_cancels_the_resident() {
    let Running {
        leaf,
        client,
        cancel,
        resident,
        serving,
    } = resident("stop");
    super::stop_resolved(&client)
        .await
        .expect("the socket stop succeeds");

    assert!(
        cancel.is_cancelled(),
        "the stop cancelled the one teardown token"
    );
    assert_eq!(
        resident.stop_source().first(),
        Some(StopKind::Socket),
        "the socket stop is recorded as its own kind, never collapsed into the wire stop"
    );
    serving
        .await
        .expect("the serve task joins")
        .expect("serve ends Ok");

    let _ = std::fs::remove_dir_all(&leaf);
}

/// A bare `stop` on the machine stops its `serve` while the first sync round still holds `control.stop`
/// shut: the hold wraps the oracle the gate asks, as `serve` wires it, and the socket never passes the
/// gate. Hold the socket too and a machine that cannot reach its devices could not be stopped where it
/// runs until its first round gave up.
#[tokio::test]
async fn bare_stop_is_never_held() {
    let leaf = scratch("held");
    let off = services_off(&leaf);
    let (_first_round, held) = FirstRound::hold_stop(off.clone());
    let Running {
        leaf,
        client,
        cancel,
        resident,
        serving,
    } = resident_reading(leaf, off);
    let stop: nauthy::Service = CONTROL_STOP_SERVICE.parse().expect("a name");
    assert!(
        !held.is_enabled(&stop),
        "the first round has not ended, so a remote stop is refused"
    );

    super::stop_resolved(&client)
        .await
        .expect("the bare stop is answered before the first round ends");
    assert!(cancel.is_cancelled(), "and it stopped the node");
    assert_eq!(resident.stop_source().first(), Some(StopKind::Socket));
    serving
        .await
        .expect("the serve task joins")
        .expect("serve ends Ok");

    let _ = std::fs::remove_dir_all(&leaf);
}

/// `stop me/<name>` for `node`, resolved, as the root would hand it to the reach path.
fn stop_device(node: NodeId) -> StopDevice {
    let Ok(Aim::Device(device)) = Aim::parse("me/pi") else {
        panic!("me/pi is a device shape");
    };
    StopDevice {
        peer: Peer::Raw(node),
        device,
        node,
        reach: parsed(&["x"]).reach,
    }
}

/// `stop me/pi` stops pi over its member-only `control.stop`, with nothing else on pi: no ssh served and
/// no control socket. The stop lands (pi's run ends), and the line names pi by its name and short key.
/// Route the stop through ssh and pi stays up.
#[tokio::test]
async fn stop_me_name_reaches_control_stop_with_no_ssh_or_socket_on_the_peer() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (pi, run) = pi_serving_only_control_stop();
            let me = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = TestRoot::seeded(ROOT)
                .device_badge(
                    me.node_id(),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
                )
                .expect("a badge");
            let line = stop_device(pi)
                .run_stop(&me, Some(badge), None)
                .await
                .expect("one of your devices stops pi");
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("pi stopped, its run ended")
                .expect("the run task joins")
                .expect("a graceful stop");
            assert!(line.starts_with("Stopped me/pi ("), "{line}");
        })
        .await;
}

/// The remote success line names the machine and its key, then says when it serves again. Print today's
/// `stopped <key>.` and the name is gone.
#[tokio::test]
async fn stop_remote_line_names_name_and_key() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (pi, run) = pi_serving_only_control_stop();
            let me = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = TestRoot::seeded(ROOT)
                .device_badge(
                    me.node_id(),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
                )
                .expect("a badge");
            let line = stop_device(pi)
                .run_stop(&me, Some(badge), None)
                .await
                .expect("pi stops");
            let short: String = pi.to_string().chars().take(12).collect();
            assert_eq!(
                line,
                format!(
                    "Stopped me/pi ({short}\u{2026}).\nIt serves again when swoosh serve next runs on \
                     pi.\n"
                )
            );
            let _ = run.await;
        })
        .await;
}

/// pi, serving the member-only `control.stop` and the gated diagnostics behind a gate rooted at `ROOT`, and
/// no ssh and no control socket, on its own task: its key, and its run. A second route is there because a
/// node exposing exactly one service answers every name with it, which would let a dial to any service land
/// on `control.stop`.
fn pi_serving_only_control_stop() -> (NodeId, tokio::task::JoinHandle<eyre::Result<()>>) {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let pi = host.node_id();
    let cancel = CancellationToken::new();
    let denylist = std::env::temp_dir().join(format!("swoosh-stop-pi-{}", std::process::id()));
    let gate = tightbeam::tunnel::resolve_gate(
        Some(TestRoot::seeded(ROOT).node_id()),
        nauthy::Denylist::load(denylist).expect("an empty denylist"),
    )
    .expect("a gate");
    let exposer = swoosh::serve::diagnostics(Router::new(gate), &[])
        .expect("the diagnostics bind")
        .member_service(
            CONTROL_STOP_SERVICE.parse().expect("a service"),
            Stop::new(cancel.clone(), Arc::default()),
        )
        .expect("control.stop binds")
        .expose()
        .expect("the exposer builds");
    let run = tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });
    (pi, run)
}

/// The teardown-race fixture over the in-process transport: the peer admits the client's connect and its
/// first control stream, then drops both WITHOUT answering (the v0.8.0 failure). `vanish` additionally
/// unregisters the endpoint, so the client's probe finds the listener gone; without it the endpoint stays
/// live behind the failed stream open.
async fn answer_with_a_vanishing_peer(peer: &MemTransport, vanish: bool) {
    let session = peer.accept().await.expect("the client connects");
    let stream = session
        .accept_bi()
        .await
        .expect("the client opens the control stream");
    if vanish {
        // The listener goes away between the stream open and its answer: the deterministic form of the
        // observed race, where the node tears itself down right after the stop request lands.
        peer.close().await;
    }
    drop(stream);
    drop(session);
}

/// A peer gone behind a failed stream open is never reported stopped: the open never saw the admission, so
/// the node tearing itself down for this request and a path that dropped it look the same. The line says
/// the stop is unconfirmed and the verb fails. Report the race as a stop and a dropped path prints
/// `Stopped` while the machine keeps serving.
#[tokio::test(start_paused = true)]
async fn a_peer_gone_behind_a_failed_stream_open_is_unconfirmed() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();

    let (result, ()) = tokio::join!(
        stop_device(peer_id).run_stop(&dialer, None, None),
        answer_with_a_vanishing_peer(&peer, true),
    );
    let error = result.expect_err("nothing proves the stop");
    assert_eq!(
        format!("{error:#}"),
        "could not confirm that me/pi stopped; it may still be serving"
    );
}

/// Only the ack byte or a clean close proves an admitted stop. A wrong byte or a stream broken any other way
/// proves nothing, and the line says the device may still be serving. Take any read error as the node going
/// down and a reset path prints `Stopped`.
#[test]
fn only_the_ack_or_a_clean_close_confirms_the_stop() {
    let Ok(Aim::Device(pi)) = Aim::parse("me/pi") else {
        panic!("me/pi is a device shape");
    };
    let broken = |kind| Err(io::Error::from(kind));
    assert!(confirmed(Ok(swoosh::serve::STOP_ACK), &pi).is_ok());
    assert!(confirmed(broken(io::ErrorKind::UnexpectedEof), &pi).is_ok());
    let line = |answer| format!("{:#}", confirmed(answer, &pi).expect_err("not confirmed"));
    assert_eq!(
        line(Ok(b'x')),
        "me/pi sent an unknown reply to the stop; it may still be serving"
    );
    // `NotConnected` is what a lost QUIC connection reads as (iroh's): the node's teardown and a dropped
    // path look the same there, so neither proves the stop.
    for kind in [
        io::ErrorKind::NotConnected,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::Other,
    ] {
        assert_eq!(
            line(broken(kind)),
            "could not confirm that me/pi stopped; it may still be serving",
            "{kind:?}"
        );
    }
}

/// A LIVE peer behind the same failed stream open is never masked: the endpoint stays registered, so the
/// probe reaches it and the stop fails, naming the machine.
#[tokio::test(start_paused = true)]
async fn a_live_peer_behind_a_failed_stream_open_is_not_masked() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();

    let (result, ()) = tokio::join!(
        stop_device(peer_id).run_stop(&dialer, None, None),
        answer_with_a_vanishing_peer(&peer, false),
    );
    let error = result.expect_err("a live peer behind the failed stream must stay an error");
    assert_eq!(
        format!("{error:#}"),
        "could not stop me/pi\n  Nothing was stopped."
    );
    // The probe dialled the still-live peer after the failure: the fixture consumed the client's first
    // inbound session, so the one now pending is the probe's own connect. Its presence proves the verb
    // probed before deciding, and the live endpoint proves success would have masked a live node.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), peer.accept())
            .await
            .is_ok(),
        "the failed stream open was probed against the still-live peer"
    );
}

/// `stop` takes no link and no path: either is refused as the line is parsed, before the home is read or a
/// file opened, exit 2, and the refusal prints back neither the path nor the link's token. Let clap's own
/// value error carry it and the whole link is echoed onto the terminal.
#[test]
fn stop_refuses_a_link_or_a_path_without_echoing_it() {
    let link = swoosh::link::Link::from(
        TestRoot::seeded(ROOT)
            .bound_slip(
                &CONTROL_STOP_SERVICE.parse().expect("a service"),
                TestNode::seeded(NAS).verify_key(),
                nauthy::Request::expires_in(Duration::from_secs(300)),
            )
            .expect("a slip"),
    )
    .to_string();
    // A link with its key half damaged no longer parses as a key, so only the dot marks it a link.
    let damaged = format!("swoosh:x{}", link.trim_start_matches("swoosh:"));
    let bare_damaged = damaged.trim_start_matches("swoosh:").to_owned();
    for typed in [
        "./nas.link",
        link.as_str(),
        damaged.as_str(),
        bare_damaged.as_str(),
        "nas.local",
    ] {
        let error = crate::parse_from(["swoosh", "stop", typed])
            .map(|_| ())
            .expect_err("a link or a path refuses");
        assert_eq!(error.exit_code(), 2, "a refused machine is a usage error");
        let printed = error.to_string();
        assert!(
            printed.starts_with(&format!("error: {A_LINK_STOPS_NOTHING}\n")),
            "{printed}"
        );
        assert!(
            !printed.contains(typed),
            "what was typed is not echoed: {printed}"
        );
    }
}

/// A link typed as a second machine on a line clap refuses for another reason too is refused as a link,
/// never with clap's own error, which names the first argument it did not expect: the link. That holds
/// whatever the program file is called, since the refusal knows the line from clap's usage. A path given to
/// a flag is not a machine, so it leaves clap's error alone.
#[test]
fn stop_refuses_a_link_beside_an_unknown_flag_without_echoing_it() {
    let link = swoosh::link::Link::from(
        TestRoot::seeded(ROOT)
            .bound_slip(
                &CONTROL_STOP_SERVICE.parse().expect("a service"),
                TestNode::seeded(NAS).verify_key(),
                nauthy::Request::expires_in(Duration::from_secs(300)),
            )
            .expect("a slip"),
    )
    .to_string();
    let token = link
        .split_once('.')
        .map(|(_, token)| token)
        .expect("a token");
    // Whatever the program file is called: a release asset keeps its platform name, a symlink its own.
    for program in ["swoosh", "swoosh-aarch64-macos", "sw"] {
        let error = crate::parse_from([program, "stop", "me/nas", link.as_str(), "--bogus"])
            .map(|_| ())
            .expect_err("the line refuses");
        assert_eq!(error.exit_code(), 2);
        let printed = error.to_string();
        assert!(
            printed.starts_with(&format!("error: {A_LINK_STOPS_NOTHING}\n")),
            "{program}: {printed}"
        );
        assert!(
            !printed.contains(token),
            "{program}: the token is not echoed: {printed}"
        );
    }

    let other = crate::parse_from(["swoosh", "--home", "./x", "stop", "--bogus"])
        .map(|_| ())
        .expect_err("an unknown flag refuses");
    assert!(!other.to_string().contains(A_LINK_STOPS_NOTHING), "{other}");
}

/// A peer that closes the dial gives a reason, and that reason never reaches the line: the refusal is
/// swoosh's own sentence, and the peer's text goes only to the log, escaped. A carriage return, an ESC CSI
/// sequence and a bidi override there cannot erase the error and draw a `Stopped` line in its place.
#[tokio::test]
async fn a_hostile_connect_failure_prints_none_of_the_peers_text() {
    let node = Node::new(
        HostilePeer::Unreachable("closed by peer: no\r\u{1b}[2KStopped x.\u{202e}"),
        NoDiscovery,
    );

    let error = stop_device(HostilePeer::node_id())
        .run_stop(&node, None, None)
        .await
        .expect_err("a dial the peer closed is an error");
    assert_eq!(
        format!("{error:#}"),
        "could not reach me/pi: it is offline or not running swoosh serve\n  Nothing was stopped."
    );
}

/// `OwnDevice` reads `me/<name>` only; `me` alone and anyone else's machine are not one.
#[test]
fn an_own_device_is_me_and_a_name() {
    let of = |text: &str| OwnDevice::of(&text.parse().expect("an address"));
    assert_eq!(
        of("me/nas").map(|device| device.to_string()),
        Some("me/nas".to_owned())
    );
    assert!(of("me").is_none());
    assert!(of("bob/nas").is_none());
}
