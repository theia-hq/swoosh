//! `stop`'s tests: the machine shapes it refuses before anything binds, read against a real device home;
//! the local stop over the control socket; and the remote stop over the in-process transport, its
//! teardown race included: a peer that admits the session then vanishes before answering the control
//! stream is never reported stopped, only unconfirmed, and a live peer behind the same failure stays loud.

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bifrost::{Discovery, NoDiscovery, Node, NodeId, Session as _, Transport};
use bifrost_mem::MemTransport;
use clap::Parser as _;
use keystore::{KeyFile, Protection};
use swoosh::contacts::Contacts;
use swoosh::credential::Credential;
use swoosh::home::{Home, ProcessId};
use swoosh::node_client::ControlClient;
use swoosh::peer::{OwnDevice, Peer};
use swoosh::peers::{DialFailure, Hints, OpenError, Peers};
use swoosh::roster::{Epoch, RevokedDevice, RosterDoc};
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::serve::{CONTROL_STOP_SERVICE, FirstRound, Resident, Stop, StopKind};
use swoosh::serve_toml::LiveServeToml;
use swoosh::streams::{Ask, Opened, OwnBind, StreamSource, Unopened};
use swoosh::testkit::{HostilePeer, STANDING_UNTIL, TestNode, TestRoot, TestWrite};
use swoosh::transport::ReachArgs;
use tightbeam::enabled::EnabledServices as _;
use tightbeam::tunnel::{CancellationToken, Router, ServiceCatalog};
use tokio::io::DuplexStream;

use super::{
    A_LINK_STOPS_NOTHING, Aim, STOP_SETTLE, StopCmd, StopDevice, Target, Usage, Yours, confirmed,
    stop_line,
};
use crate::commands::route::Route;

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

/// A bare word that names a service on this machine's list keeps its refusal and gains the command that
/// turns that service off here: the person may have meant the service, not a machine.
#[tokio::test]
async fn stop_a_service_name_names_service_off() {
    let (base, home) = device_home("service-word").await;
    std::fs::write(home.serve_toml(), "services = [\"ssh=sshd:\"]\n").expect("ssh listed");
    assert_eq!(
        refused(&home, "ssh").await,
        "swoosh stop takes one of your machines, like me/desk\n  To turn ssh off here:\n    swoosh \
         service off ssh"
    );
    assert_eq!(
        refused(&home, "web").await,
        "swoosh stop takes one of your machines, like me/desk",
        "a word the list does not hold gains nothing"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// A built-in written by hand as its name alone (`ping`) is on the list as a bare `serve` reads it, so the
/// hint names it too. Read the raw entries and `ping`, which has no `=`, would count as not served.
#[tokio::test]
async fn stop_a_hand_written_built_in_names_service_off() {
    let (base, home) = device_home("service-built-in").await;
    std::fs::write(home.serve_toml(), "services = [\"ping\"]\n").expect("ping listed by hand");
    assert_eq!(
        refused(&home, "ping").await,
        "swoosh stop takes one of your machines, like me/desk\n  To turn ping off here:\n    swoosh \
         service off ping"
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

#[test]
fn the_stop_line_names_the_attributed_pid() {
    assert_eq!(
        stop_line(ProcessId::try_from(4242).unwrap()),
        "Stopped swoosh serve here (pid 4242)."
    );
}

#[tokio::test]
async fn local_stop_retains_connected_attribution_when_ack_or_eof_clears_the_record() {
    use swoosh::serve::control_codec::{Request, Response};

    for ack in [false, true] {
        let leaf = scratch("clear");
        let home = Home::resolve(Some(PathBuf::clone(&leaf))).unwrap();
        let path = leaf.join("control.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        // Resolve against A's stale record, then connect to B with its current record.
        std::fs::write(home.serve_lock(), b"2147483647\n").unwrap();
        let client = ControlClient::resolve_socket(&home, path).unwrap();
        std::fs::write(home.serve_lock(), format!("{}\n", std::process::id())).unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(Request::read(&mut stream).await.unwrap(), Request::Stop);
            std::fs::write(home.serve_lock(), b"").unwrap();
            if ack {
                Response::Ack.write(&mut stream).await.unwrap();
            }
        };
        let ((), line) = tokio::join!(server, super::stop_resolved(&client));
        assert_eq!(
            line.unwrap(),
            stop_line(ProcessId::try_from(std::process::id()).unwrap())
        );
        assert!(std::fs::read(home.serve_lock()).unwrap().is_empty());
        drop(listener);
        std::fs::remove_dir_all(leaf).unwrap();
    }
}

#[tokio::test]
async fn local_stop_truncated_frames_never_return_a_stopped_line() {
    use swoosh::serve::control_codec::{ControlError, Request};
    use tokio::io::AsyncWriteExt as _;

    let leaf = scratch("partial");
    let home = Home::resolve(Some(PathBuf::clone(&leaf))).unwrap();
    std::fs::write(home.serve_lock(), format!("{}\n", std::process::id())).unwrap();
    let path = leaf.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let client = ControlClient::resolve_socket(&home, path).unwrap();
    let mut cases = 0;
    for (name, frame) in [
        ("ack", b"SWC2\x03\0\0".as_slice()),
        ("refusal", b"SWC2\x04\0\x07\0\x05gated"),
        ("error", b"SWC2\x05\0\x07\0\x05gated"),
        ("ack-body", b"SWC2\x03\0\x01x"),
    ] {
        for end in 1..frame.len() {
            let server = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert_eq!(Request::read(&mut stream).await.unwrap(), Request::Stop);
                stream.write_all(&frame[..end]).await.unwrap();
            };
            let ((), result) = tokio::join!(server, super::stop_resolved(&client));
            let error = result.expect_err("a partial response cannot return a success line");
            assert!(
                matches!(error.downcast_ref::<ControlError>(), Some(ControlError::Io(source))
                    if source.kind() == io::ErrorKind::UnexpectedEof),
                "{name} prefix {end}: {error:#}"
            );
            assert!(!format!("{error:#}").contains("Stopped"));
            cases += 1;
        }
    }
    assert_eq!(cases, 39);
    drop(listener);
    std::fs::remove_dir_all(leaf).unwrap();
}

#[tokio::test]
async fn local_stop_missing_or_mismatched_record_never_writes_a_request_or_confirms() {
    use tokio::io::AsyncReadExt as _;

    let leaf = scratch("pid-miss");
    let home = Home::resolve(Some(PathBuf::clone(&leaf))).unwrap();
    let path = leaf.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let client = ControlClient::resolve_socket(&home, path).unwrap();
    for text in [None, Some("2147483647\n")] {
        if let Some(text) = text {
            std::fs::write(home.serve_lock(), text).unwrap();
        }
        let error = super::stop_resolved(&client).await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<swoosh::serve::control_codec::ControlError>(),
            Some(swoosh::serve::control_codec::ControlError::Unattributed { .. })
        ));
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    drop(listener);
    std::fs::remove_dir_all(leaf).unwrap();
}

#[tokio::test(start_paused = true)]
async fn local_stop_refusal_and_response_timeout_never_return_a_success_line() {
    use swoosh::serve::control_codec::{ControlError, Request, Response};

    for refuse in [false, true] {
        let leaf = scratch("stop-err");
        let home = Home::resolve(Some(PathBuf::clone(&leaf))).unwrap();
        std::fs::write(home.serve_lock(), format!("{}\n", std::process::id())).unwrap();
        let path = leaf.join("control.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let client = ControlClient::resolve_socket(&home, path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(Request::read(&mut stream).await.unwrap(), Request::Stop);
            if refuse {
                Response::Refused("gated".to_owned())
                    .write(&mut stream)
                    .await
                    .unwrap();
            } else {
                core::future::pending::<()>().await;
            }
        });
        let error = super::stop_resolved(&client).await.unwrap_err();
        assert!(matches!(
            (refuse, error.downcast_ref::<ControlError>()),
            (true, Some(ControlError::Refused(_)))
                | (
                    false,
                    Some(ControlError::Timeout {
                        phase: "response read"
                    })
                )
        ));
        server.abort();
        let _ = server.await;
        std::fs::remove_dir_all(leaf).unwrap();
    }
}

/// A bare `stop` with no addressable resident is the teaching error naming the fix, non-zero at the
/// root: the control client resolution fails `NoResident`, never a silent success.
#[tokio::test]
async fn bare_stop_without_resident_is_teaching() {
    let base = scratch("teach");
    let home = home_in(&base);

    let error = bare_stop()
        .run_local(&home, None)
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

/// A bare `stop` reaches no machine, so a reach flag typed on it is a usage error naming the flag, never
/// silently ignored. Read from clap's matches as the root reads them: only a typed flag counts.
#[tokio::test]
async fn bare_stop_refuses_a_typed_reach_flag() {
    use clap::{Args as _, FromArgMatches as _};

    let base = scratch("reach");
    let home = home_in(&base);
    let hint = format!("{}=127.0.0.1:9000", NodeId::from_ed25519_secret(&[5u8; 32]));
    let cases: [(&[&str], &str); 2] = [
        (&["x", "--local"], "--local"),
        (&["x", "--peer", &hint], "--peer"),
    ];
    for (argv, flag) in cases {
        let matches = StopCmd::augment_args(clap::Command::new("x"))
            .try_get_matches_from(argv)
            .expect("stop parses");
        let typed = ReachArgs::typed_bare(&matches);
        let error = StopCmd::from_arg_matches(&matches)
            .expect("stop parses")
            .run_local(&home, typed)
            .await
            .expect_err("no machine, no effect: the flag must refuse, never be ignored");
        let Some(Usage(line)) = error.downcast_ref::<Usage>() else {
            panic!("a typed reach flag is a usage error: {error:#}");
        };
        assert_eq!(line, &format!("{flag} has no effect without a machine"));
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
        async move { this.serve(listener, &swoosh::testkit::NoOpens).await }
    });
    let home = Home::resolve(Some(PathBuf::clone(&leaf))).expect("a scratch home");
    std::fs::write(home.serve_lock(), format!("{}\n", std::process::id())).unwrap();
    let client = ControlClient::resolve_socket(&home, socket).expect("the bound socket resolves");
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

/// A home whose standing is `root`'s badge for `node`, the key a test's dialer binds, so each open by its
/// own bind presents it; with no `root`, a home that presents nothing.
async fn standing_home(tag: &str, root: Option<u8>, node: NodeId) -> (PathBuf, Home) {
    let base = scratch(tag);
    let dir = base.join("home");
    swoosh::config::create_store_dir(&dir).expect("the store dir");
    let home = Home::resolve(Some(dir)).expect("the scratch home resolves");
    if let Some(root) = root {
        let root = TestRoot::seeded(root);
        swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id())
            .expect("the pin");
        let badge = root
            .device_badge(
                node,
                SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
            )
            .expect("a badge");
        swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).expect("the badge");
    }
    (base, home)
}

/// `stop me/pi` to `pi` by `me`'s own bind, presenting what `home` stores, as the own bind runs it: what it
/// printed on stderr, or its error as the composition root prints it.
async fn stop_by_own_bind<T: Transport, D: Discovery>(
    me: &Node<T, D>,
    home: &Home,
    pi: NodeId,
) -> Result<String, String>
where
    T::Session: 'static,
{
    let peers = Peers::new(me);
    let source = OwnBind::new(
        &peers,
        home,
        me.node_id(),
        &Credential::Family { present: None },
    );
    stop_from(source, pi, me.node_id()).await
}

/// `stop me/pi` to `pi` over `source`, worded by the own bind's route for the machine `this`: what it
/// printed on stderr, or its error as the composition root prints it.
async fn stop_from(
    source: impl StreamSource + Copy,
    pi: NodeId,
    this: NodeId,
) -> Result<String, String> {
    let device = stop_device(pi);
    let machine = device
        .peer
        .machine(&Contacts::default())
        .expect("a key is one machine");
    let bound = crate::probe_route_tests::bound();
    let route = Route::Own {
        peer: &device.peer,
        bound: &bound,
        this,
    };
    let mut err = Vec::new();
    let ended = device.stop(source, &route, &machine, &mut err).await;
    ended
        .map(|()| String::from_utf8(err).expect("utf-8"))
        .map_err(|report| format!("{report:#}"))
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
            let (base, home) = standing_home("reach", Some(ROOT), me.node_id()).await;
            let line = stop_by_own_bind(&me, &home, pi)
                .await
                .expect("one of your devices stops pi");
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("pi stopped, its run ended")
                .expect("the run task joins");
            assert!(line.starts_with("Stopped me/pi ("), "{line}");
            let _ = std::fs::remove_dir_all(base);
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
            let (base, home) = standing_home("line", Some(ROOT), me.node_id()).await;
            let line = stop_by_own_bind(&me, &home, pi).await.expect("pi stops");
            let short: String = pi.to_string().chars().take(12).collect();
            assert_eq!(
                line,
                format!(
                    "Stopped me/pi ({short}\u{2026}).\nIt serves again when swoosh serve next runs on \
                     pi.\n"
                )
            );
            let _ = run.await;
            let _ = std::fs::remove_dir_all(base);
        })
        .await;
}

/// A device that refuses the stop gets the rule, then what to try: a machine that has just started refuses
/// a stop from another device until its first sync with your devices ends, and the wire says only "not
/// admitted", so one line alone tells your own device it is not one of yours.
#[tokio::test]
async fn a_refused_stop_says_to_try_again_if_the_machine_has_just_started() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (pi, run) = pi_serving_only_control_stop();
            let me = Node::new(MemTransport::bind(), NoDiscovery);
            let (base, home) = standing_home("refused", Some(BOB), me.node_id()).await;
            let error = stop_by_own_bind(&me, &home, pi)
                .await
                .expect_err("pi refuses a badge of another root");
            assert_eq!(
                error,
                "me/pi refused: only your own devices can stop it\n  If it has just started, try again in \
                 a minute."
            );
            assert!(!run.is_finished(), "and pi keeps serving");
            run.abort();
            let _ = std::fs::remove_dir_all(base);
        })
        .await;
}

/// pi, serving the member-only `control.stop` and the gated diagnostics behind a gate rooted at `ROOT`, and
/// no ssh and no control socket, on its own task: its key, and its run. A second route is there because a
/// node exposing exactly one service answers every name with it, which would let a dial to any service land
/// on `control.stop`.
fn pi_serving_only_control_stop() -> (NodeId, tokio::task::JoinHandle<()>) {
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
/// first control stream, then drops both WITHOUT answering (the v0.8.0 failure), and unregisters the
/// endpoint, so the client's probe finds the listener gone.
async fn answer_with_a_vanishing_peer(peer: &MemTransport) {
    let session = peer.accept().await.expect("the client connects");
    let stream = session
        .accept_bi()
        .await
        .expect("the client opens the control stream");
    // The listener goes away between the stream open and its answer: the deterministic form of the
    // observed race, where the node tears itself down right after the stop request lands.
    peer.close().await;
    drop(stream);
    drop(session);
}

/// What a [`gate_by_service`] device does with a stream, by the service its request asks for.
#[derive(Clone, Copy)]
enum Gate {
    /// Read the request and drop the stream unanswered: a request that left, then a path that dropped.
    Drops,
    /// Admit it and hold the stream open.
    Admits,
    /// Refuse it: a live gate saying no.
    Refuses,
}

/// A device on `peer` that takes every connection and every stream on it, reads each stream's request,
/// and answers as `gate` says for its service: the services it heard, in order, and the connections it
/// took. Runs until the test's runtime ends.
fn gate_by_service(
    peer: MemTransport,
    gate: fn(&str) -> Gate,
) -> (Arc<Mutex<Vec<String>>>, Arc<AtomicU32>) {
    let heard = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicU32::new(0));
    let (heard_by, counted) = (Arc::clone(&heard), Arc::clone(&connections));
    tokio::spawn(async move {
        while let Ok(session) = peer.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let heard = Arc::clone(&heard_by);
            tokio::spawn(async move {
                let session = Arc::new(session);
                while let Ok((mut write, mut read)) = session.accept_bi().await {
                    let Ok(request) = tightbeam::protocol::Request::read(&mut read).await else {
                        continue;
                    };
                    heard
                        .lock()
                        .expect("the record")
                        .push(request.service.clone());
                    match gate(&request.service) {
                        Gate::Drops => drop((write, read)),
                        Gate::Refuses => {
                            let refusal = bifrost::Refusal::NotAdmitted;
                            let _ = tightbeam::protocol::Response::Refused(refusal)
                                .write(&mut write)
                                .await;
                        }
                        Gate::Admits => {
                            let _ = tightbeam::protocol::Response::Ok.write(&mut write).await;
                            tokio::spawn(async move {
                                let _held = (write, read);
                                core::future::pending::<()>().await;
                            });
                        }
                    }
                }
            });
        }
    });
    (heard, connections)
}

/// A peer gone behind a failed stream open is never reported stopped: the open never saw the admission, so
/// the node tearing itself down for this request and a path that dropped it look the same. The line says
/// the stop is unconfirmed and the verb fails. Report the race as a stop and a dropped path prints
/// `Stopped` while the machine keeps serving.
#[tokio::test(start_paused = true)]
async fn a_peer_gone_behind_a_failed_stream_open_is_unconfirmed() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let (base, home) = standing_home("gone", None, dialer.node_id()).await;
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();

    let (result, ()) = tokio::join!(
        stop_by_own_bind(&dialer, &home, peer_id),
        answer_with_a_vanishing_peer(&peer),
    );
    let error = result.expect_err("nothing proves the stop");
    assert_eq!(
        error,
        "could not confirm that me/pi stopped; it may still be serving"
    );
    let _ = std::fs::remove_dir_all(base);
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

/// A LIVE peer behind the same failed stream open is never masked: its gate still answers the probe's
/// `ping`, if only to refuse it, so the stop fails, naming the machine, and says nothing was stopped. A
/// connect alone is not live: a node mid-teardown can still accept one.
#[tokio::test(start_paused = true)]
async fn a_live_peer_behind_a_failed_stream_open_is_not_masked() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let (base, home) = standing_home("live", None, dialer.node_id()).await;
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();
    let (heard, _) = gate_by_service(peer, |service| match service {
        CONTROL_STOP_SERVICE => Gate::Drops,
        _ => Gate::Refuses,
    });

    let error = stop_by_own_bind(&dialer, &home, peer_id)
        .await
        .expect_err("a live peer behind the failed stream must stay an error");
    assert_eq!(error, "could not stop me/pi\n  Nothing was stopped.");
    // The probe asked the still-live gate after the failure, for `ping` and never a second stop.
    assert_eq!(
        *heard.lock().expect("the record"),
        [CONTROL_STOP_SERVICE, swoosh::reach::PING_SERVICE]
    );
    let _ = std::fs::remove_dir_all(base);
}

/// By own bind, with a held Main session to the device already open, the stop dials a connection of its
/// own. A device that reads the request and drops the stream gets exactly one request, and the line is
/// the probe's: the held session still answers, so nothing was stopped. Ride the held session and its
/// failed open is retried on a fresh dial, which sends the stop a second time.
#[tokio::test(start_paused = true)]
async fn a_stop_never_rides_a_held_session() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let (base, home) = standing_home("held", None, dialer.node_id()).await;
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();
    let (heard, connections) = gate_by_service(peer, |service| match service {
        CONTROL_STOP_SERVICE => Gate::Drops,
        _ => Gate::Admits,
    });
    let peers = Peers::new(&dialer);
    let source = OwnBind::new(
        &peers,
        &home,
        dialer.node_id(),
        &Credential::Family { present: None },
    );
    let held = source
        .open(&Ask {
            peer: peer_id,
            hints: Hints::NONE,
            service: swoosh::reach::PING_SERVICE.parse().expect("a service"),
            lane: OpenLane::Main,
            slip: None,
        })
        .await
        .map_err(|unopened| format!("{unopened:?}"))
        .expect("the held session's stream");
    assert_eq!(connections.load(Ordering::SeqCst), 1);

    let error = stop_from(source, peer_id, dialer.node_id())
        .await
        .expect_err("nothing proves the stop");
    assert_eq!(error, "could not stop me/pi\n  Nothing was stopped.");
    let stops = heard
        .lock()
        .expect("the record")
        .iter()
        .filter(|service| *service == CONTROL_STOP_SERVICE)
        .count();
    assert_eq!(stops, 1, "the stop's request went out once");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "the stop dialed a connection of its own"
    );
    drop(held);
    let _ = std::fs::remove_dir_all(base);
}

/// A source whose `control.stop` open meets what `stop` gives and whose every other open, the probe's,
/// meets what `probe` gives, noting each open's service.
#[derive(Clone, Copy)]
struct Meets<'a> {
    stop: fn() -> Unopened,
    probe: fn() -> Unopened,
    opened: &'a RefCell<Vec<String>>,
}

impl StreamSource for Meets<'_> {
    type Write = TestWrite<DuplexStream>;
    type Read = DuplexStream;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        let service = ask.service.as_str().to_owned();
        let meets = if service == CONTROL_STOP_SERVICE {
            self.stop
        } else {
            self.probe
        };
        self.opened.borrow_mut().push(service);
        Err(meets())
    }
}

/// One row of the stop's open table: what its open meets, and the line the run ends with.
type Row = (fn() -> Unopened, &'static str);

/// A probe the device's live gate refuses.
fn live() -> Unopened {
    Unopened::Refused(OpenRefusal::Peer(PeerRefusal::Unavailable(
        bifrost::RefusalDetail::bounded("off"),
    )))
}

/// `stop me/pi` by own bind over a source whose stop meets `stop` and whose probe meets `probe`: its
/// error, and the services it opened.
async fn met(stop: fn() -> Unopened, probe: fn() -> Unopened) -> (String, Vec<String>) {
    let opened = RefCell::new(Vec::new());
    let source = Meets {
        stop,
        probe,
        opened: &opened,
    };
    let pi = TestNode::seeded(PI).node_id();
    let error = stop_from(source, pi, TestNode::seeded(DESK).node_id())
        .await
        .expect_err("an open that gave no stream is the run's error");
    (error, opened.into_inner())
}

/// Each row of the stop's open table by own bind, the table the resident's path reads too: a dial that
/// never connected says nothing was stopped; a live gate's refusal is the refused line; an open that
/// failed after the dial probes, and a gate still answering stopped nothing while one gone over the
/// window is unconfirmed; and an outcome that says nothing of the device is the route's line, with no
/// probe. Say nothing was stopped where a request may have left, and a stop that landed reads as
/// failed.
#[tokio::test(start_paused = true)]
async fn one_open_table_for_stop() {
    let unreachable =
        "could not reach me/pi: it is offline or not running swoosh serve\n  Nothing was stopped.";
    let refused = "me/pi refused: only your own devices can stop it\n  If it has just started, try \
                   again in a minute.";
    let still_live = "could not stop me/pi\n  Nothing was stopped.";
    let gone = "could not confirm that me/pi stopped; it may still be serving";
    let stop_only = vec![CONTROL_STOP_SERVICE.to_owned()];
    let named: &[Row] = &[
        (
            || {
                Unopened::Own(OpenError::Unreachable(DialFailure::Failed(Arc::new(
                    bifrost::Error::Connect("refused".into()),
                ))))
            },
            unreachable,
        ),
        (
            || Unopened::Own(OpenError::Unreachable(DialFailure::TimedOut)),
            unreachable,
        ),
        (
            || {
                Unopened::Refused(OpenRefusal::Unreachable(bifrost::RefusalDetail::bounded(
                    "timed out",
                )))
            },
            unreachable,
        ),
        (
            || Unopened::Refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
            refused,
        ),
    ];
    for (at, (stop, line)) in named.iter().enumerate() {
        assert_eq!(
            met(*stop, live).await,
            ((*line).to_owned(), stop_only.clone()),
            "row {at}"
        );
    }
    // The request may have left: the probe asks the gate, and only a live one says nothing was stopped.
    let probed: &[fn() -> Unopened] = &[
        || Unopened::Own(OpenError::Timeout),
        || Unopened::Own(OpenError::Open(bifrost::Error::Stream("reset".into()))),
        || Unopened::Refused(OpenRefusal::Timeout),
        || Unopened::Refused(OpenRefusal::Broken(bifrost::RefusalDetail::bounded("cut"))),
        || {
            Unopened::Refused(OpenRefusal::PeerUnreadable(
                bifrost::RefusalDetail::bounded("garbled"),
            ))
        },
    ];
    for (at, stop) in probed.iter().enumerate() {
        let (error, opened) = met(*stop, live).await;
        assert_eq!(error, still_live, "row {at}");
        assert_eq!(
            opened,
            [CONTROL_STOP_SERVICE, swoosh::reach::PING_SERVICE],
            "row {at}"
        );
        let (error, opened) = met(*stop, || {
            Unopened::Own(OpenError::Unreachable(DialFailure::TimedOut))
        })
        .await;
        assert_eq!(error, gone, "row {at}");
        // One probe decides, and it is never a second stop.
        assert_eq!(
            opened,
            [CONTROL_STOP_SERVICE, swoosh::reach::PING_SERVICE],
            "row {at}"
        );
    }
    // No claim about the device: the route's own line, with no probe.
    let routed: &[fn() -> Unopened] = &[
        || Unopened::Own(OpenError::Busy),
        || Unopened::Refused(OpenRefusal::Busy),
        || Unopened::Refused(OpenRefusal::StandingEnded),
        || Unopened::Home(eyre::eyre!("the badge could not be read")),
    ];
    let device = stop_device(TestNode::seeded(PI).node_id());
    let machine = device
        .peer
        .machine(&Contacts::default())
        .expect("a key is one machine");
    let bound = crate::probe_route_tests::bound();
    let route = Route::Own {
        peer: &device.peer,
        bound: &bound,
        this: TestNode::seeded(DESK).node_id(),
    };
    for (at, stop) in routed.iter().enumerate() {
        let line = format!("{:#}", route.line(stop(), &machine).await);
        assert_eq!(
            met(*stop, live).await,
            (line, stop_only.clone()),
            "row {at}"
        );
    }
}

/// A source whose `control.stop` open fails `Timeout` after the request may have left, and whose gate
/// refuses the probe (live) until `closes` after `began`, then meets `after`; noting each open's service
/// and when, after `began`, it ran. With no `closes` the gate never closes.
#[derive(Clone, Copy)]
struct Settling<'a> {
    began: tokio::time::Instant,
    closes: Option<Duration>,
    after: fn() -> Unopened,
    opened: &'a RefCell<Vec<(String, Duration)>>,
}

impl StreamSource for Settling<'_> {
    type Write = TestWrite<DuplexStream>;
    type Read = DuplexStream;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        let service = ask.service.as_str().to_owned();
        let at = self.began.elapsed();
        let stop = service == CONTROL_STOP_SERVICE;
        self.opened.borrow_mut().push((service, at));
        Err(if stop {
            Unopened::Own(OpenError::Timeout)
        } else if self.closes.is_some_and(|closes| at >= closes) {
            (self.after)()
        } else {
            live()
        })
    }
}

/// `stop me/pi` by own bind over a [`Settling`] gate that closes at `closes` and then meets `after`: its
/// error, each open with when it ran, and how long the run took, on the paused clock.
async fn settled(
    closes: Option<Duration>,
    after: fn() -> Unopened,
) -> (String, Vec<(String, Duration)>, Duration) {
    let opened = RefCell::new(Vec::new());
    let began = tokio::time::Instant::now();
    let source = Settling {
        began,
        closes,
        after,
        opened: &opened,
    };
    let error = stop_from(
        source,
        TestNode::seeded(PI).node_id(),
        TestNode::seeded(DESK).node_id(),
    )
    .await
    .expect_err("an open that gave no stream is the run's error");
    (error, opened.into_inner(), began.elapsed())
}

/// A stop whose open timed out after it landed: the node keeps its gate up through its ack grace, then
/// closes it. The probe waits out the settle, so it meets the closed gate and the stop is unconfirmed.
/// Probe at once and the gate still up inside the grace prints "Nothing was stopped" for a node that then
/// stops.
#[tokio::test(start_paused = true)]
async fn stop_ambiguous_open_landed_gate_up_is_unconfirmed() {
    let (error, opened, _) = settled(Some(swoosh::serve::ACK_GRACE), || {
        Unopened::Own(OpenError::Unreachable(DialFailure::TimedOut))
    })
    .await;
    assert_eq!(
        error,
        "could not confirm that me/pi stopped; it may still be serving"
    );
    assert_eq!(
        opened,
        [
            (CONTROL_STOP_SERVICE.to_owned(), Duration::ZERO),
            (swoosh::reach::PING_SERVICE.to_owned(), STOP_SETTLE),
        ],
        "one probe, none before the settle"
    );
}

/// A gate still answering after the settle proves no stop landed: nothing was stopped, on one probe.
/// Read the gate's refusal as gone and a live device that ignored the stop reads as maybe stopped.
#[tokio::test(start_paused = true)]
async fn stop_gate_live_past_the_settle_stopped_nothing() {
    let (error, opened, _) = settled(None, live).await;
    assert_eq!(error, "could not stop me/pi\n  Nothing was stopped.");
    assert_eq!(
        opened,
        [
            (CONTROL_STOP_SERVICE.to_owned(), Duration::ZERO),
            (swoosh::reach::PING_SERVICE.to_owned(), STOP_SETTLE),
        ]
    );
}

/// A probe that meets `serve` gone or of another version says nothing of the device and every later open
/// would repeat it: the route's line, at once, with no window spent after the settle. Read it as the
/// device gone and the stop is unconfirmed after the whole window.
#[tokio::test(start_paused = true)]
async fn stop_probe_meeting_serve_gone_ends_at_once() {
    let device = stop_device(TestNode::seeded(PI).node_id());
    let machine = device
        .peer
        .machine(&Contacts::default())
        .expect("a key is one machine");
    let bound = crate::probe_route_tests::bound();
    let route = Route::Own {
        peer: &device.peer,
        bound: &bound,
        this: TestNode::seeded(DESK).node_id(),
    };
    let ended: &[fn() -> Unopened] = &[|| Unopened::ServeGone, || Unopened::Skew];
    for (at, after) in ended.iter().enumerate() {
        let line = format!("{:#}", route.line(after(), &machine).await);
        let (error, opened, took) = settled(Some(Duration::ZERO), *after).await;
        assert_eq!(error, line, "row {at}");
        assert_eq!(opened.len(), 2, "row {at}: one probe: {opened:?}");
        assert_eq!(took, STOP_SETTLE, "row {at}: ends at once after the settle");
    }
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

    let (base, home) = standing_home("hostile", None, node.node_id()).await;
    let error = stop_by_own_bind(&node, &home, HostilePeer::node_id())
        .await
        .expect_err("a dial the peer closed is an error");
    assert_eq!(
        error,
        "could not reach me/pi: it is offline or not running swoosh serve\n  Nothing was stopped."
    );
    let _ = std::fs::remove_dir_all(base);
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
