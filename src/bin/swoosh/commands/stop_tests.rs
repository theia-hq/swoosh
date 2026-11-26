//! `stop`'s tests: the machine shapes it refuses before anything binds, read against a real device home;
//! the local stop over the control socket; and the remote stop over `control.serve`: only `Done` is a stop,
//! an open that fails stopped nothing, and once the request may have left every other ending is
//! unconfirmed.

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
use swoosh::serve::control::{Answer, Request};
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::serve::{CONTROL_SERVE_SERVICE, Resident, StopKind, StopSource, control};
use swoosh::serve_toml::LiveServeToml;
use swoosh::streams::{Ask, Opened, OwnBind, StreamSource, Unopened};
use swoosh::testkit::{HostilePeer, STANDING_UNTIL, TestNode, TestRoot, TestWrite, control_frame};
use swoosh::transport::ReachArgs;
use tightbeam::tunnel::{CancellationToken, Router, ServiceCatalog};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

use super::{
    A_LINK_STOPS_NOTHING, ANSWER_DEADLINE, Aim, StopCmd, StopDevice, Target, Usage, Yours,
    confirmed, stop_line,
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
                &CONTROL_SERVE_SERVICE.parse().expect("a service"),
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
        ("ack", control_frame(b"\x03\0\0").as_slice()),
        ("refusal", &control_frame(b"\x04\0\x07\0\x05gated")),
        ("error", &control_frame(b"\x05\0\x07\0\x05gated")),
        ("ack-body", &control_frame(b"\x03\0\x01x")),
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
    resident_stopping(leaf, off, CancellationToken::new(), Arc::default())
}

/// Start a [`Running`] resident under `leaf`, reading the services off from `off`, stopping through
/// `cancel` and noting the stop in `source`: the node's one teardown token and record, as `serve` shares
/// them between the socket and `control.serve`.
fn resident_stopping(
    leaf: PathBuf,
    off: LiveServeToml,
    cancel: CancellationToken,
    source: Arc<StopSource>,
) -> Running {
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    let resident = Arc::new(Resident::new(
        NodeId::from_ed25519_secret(&[9u8; 32]),
        swoosh::testkit::loopback_source(),
        empty_catalog(),
        off,
        cancel.clone(),
        source,
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

/// A bare `stop` stops the machine while its first sync round still holds a remote stop: the node and
/// its socket share one teardown token, as `serve` wires them, and at the same moment one of your
/// devices asking over `control.serve` is answered `NotYet`. Hold the socket stop too and a machine that
/// cannot reach its devices could not be stopped where it runs until its first round gave up.
#[tokio::test]
async fn bare_stop_is_never_held() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let cancel = CancellationToken::new();
            let source = Arc::new(StopSource::new());
            let (gate, cut, home) =
                swoosh::testkit::admitting(TestRoot::seeded(ROOT).node_id(), host_id).await;
            let (router, _catalog, _first_round) = control::bind_serve(
                swoosh::serve::diagnostics(Router::new(gate), &[]).expect("the diagnostics bind"),
                cancel.clone(),
                Arc::clone(&source),
                &cut,
            )
            .expect("control.serve binds");
            let exposer = router.expose().expect("the exposer builds");
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });
            let leaf = scratch("held");
            let off = services_off(&leaf);
            let Running {
                leaf,
                client,
                resident,
                serving,
                ..
            } = resident_stopping(leaf, off, cancel.clone(), Arc::clone(&source));

            // The round holds a remote stop: your device is told `NotYet`.
            let me = Node::new(MemTransport::bind(), NoDiscovery);
            let (base, standing) = standing_home("held-remote", Some(ROOT), me.node_id()).await;
            let error = stop_by_own_bind(&me, &standing, host_id)
                .await
                .expect_err("the first round holds a remote stop");
            assert_eq!(error, NOT_YET);
            assert!(!cancel.is_cancelled(), "and stops nothing");

            super::stop_resolved(&client)
                .await
                .expect("the bare stop is answered while the round holds a remote stop");
            assert!(cancel.is_cancelled(), "and it stopped the node");
            assert_eq!(resident.stop_source().first(), Some(StopKind::Socket));
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("the node's run ends on the socket stop")
                .expect("the run task joins");
            serving
                .await
                .expect("the serve task joins")
                .expect("serve ends Ok");
            for dir in [leaf, base, home.dir().to_path_buf()] {
                let _ = std::fs::remove_dir_all(dir);
            }
        })
        .await;
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

/// `stop me/pi` stops pi over its member-only `control.serve`, with nothing else on pi: no ssh served and
/// no control socket. The stop lands (pi's run ends), and the line names pi by its name and short key.
/// Route the stop through ssh and pi stays up.
#[tokio::test]
async fn stop_me_name_reaches_control_serve_with_no_ssh_or_socket_on_the_peer() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (pi, run) = pi_serving(Round::Over).await;
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
            let (pi, run) = pi_serving(Round::Over).await;
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

/// A device that refuses the stop gets the rule alone: a machine that has just started answers `NotYet`,
/// so a refusal is never that case. Add a "try again" detail and a machine of another root is told to wait
/// for a stop it will never take.
#[tokio::test]
async fn a_refused_stop_has_no_just_started_detail() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (pi, run) = pi_serving(Round::Over).await;
            let me = Node::new(MemTransport::bind(), NoDiscovery);
            let (base, home) = standing_home("refused", Some(BOB), me.node_id()).await;
            let error = stop_by_own_bind(&me, &home, pi)
                .await
                .expect_err("pi refuses a badge of another root");
            assert_eq!(error, "me/pi refused: only your own devices can stop it");
            assert!(!run.is_finished(), "and pi keeps serving");
            run.abort();
            let _ = std::fs::remove_dir_all(base);
        })
        .await;
}

/// A stop to a machine still in its first sync round is answered `NotYet`: the two lines that say so, an
/// error (exit 1), and the machine still serving. Read `NotYet` as a stop or as an unknown reply and the
/// person is told the wrong thing about a machine that will take the stop in a minute.
#[tokio::test]
async fn stop_in_the_first_round_prints_not_yet() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (pi, run) = pi_serving(Round::Running).await;
            let me = Node::new(MemTransport::bind(), NoDiscovery);
            let (base, home) = standing_home("not-yet", Some(ROOT), me.node_id()).await;
            let error = stop_by_own_bind(&me, &home, pi)
                .await
                .expect_err("a machine in its first round is not stopped");
            assert_eq!(error, NOT_YET);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!run.is_finished(), "and pi keeps serving");
            run.abort();
            let _ = std::fs::remove_dir_all(base);
        })
        .await;
}

/// The lines a `NotYet` ends `stop me/pi` with.
const NOT_YET: &str = "me/pi has just started; it cannot be stopped from here yet\n  pi is still syncing \
                       with your devices. Try again in a minute.";

/// Whether pi's first sync round has ended, so it takes a remote stop.
enum Round {
    /// Ended: a stop is answered `Done`.
    Over,
    /// Still running, and never ends: a stop is answered `NotYet`.
    Running,
}

/// pi, serving `control.serve` (bound through the same `bind_serve` `serve` calls) and the gated
/// diagnostics behind a gate rooted at `ROOT`, with its first round as `round` says, and no ssh and no
/// control socket, on its own task: its key, and its run. A second route is there because a node exposing
/// exactly one service answers every name with it.
async fn pi_serving(round: Round) -> (NodeId, tokio::task::JoinHandle<()>) {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let pi = host.node_id();
    let cancel = CancellationToken::new();
    let (gate, cut, _home) = swoosh::testkit::admitting(TestRoot::seeded(ROOT).node_id(), pi).await;
    let (router, _catalog, first_round) = control::bind_serve(
        swoosh::serve::diagnostics(Router::new(gate), &[]).expect("the diagnostics bind"),
        cancel.clone(),
        Arc::new(StopSource::new()),
        &cut,
    )
    .expect("control.serve binds");
    // A round dropped before it finished holds a stop for good, as a run whose round never ends does.
    match round {
        Round::Over => first_round.finished(),
        Round::Running => drop(first_round),
    }
    let exposer = router.expose().expect("the exposer builds");
    let run = tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });
    (pi, run)
}

/// What a [`gate_by_service`] device does with a stream, by the service its request asks for.
#[derive(Clone, Copy)]
enum Gate {
    /// Read the request and drop the stream unanswered: an open that breaks after the dial.
    Drops,
    /// Admit it and hold the stream open.
    Admits,
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

/// A stop whose open broke after the dial stopped nothing, and says so at once: the request rides only an
/// opened stream, so it never left. Asked once and only once; no `ping`, no wait. Probe the device after a
/// failed open and a live device costs seconds to say the same.
#[tokio::test(start_paused = true)]
async fn a_failed_stop_open_stopped_nothing() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let (base, home) = standing_home("dropped", None, dialer.node_id()).await;
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();
    let (heard, _) = gate_by_service(peer, |service| match service {
        CONTROL_SERVE_SERVICE => Gate::Drops,
        _ => Gate::Admits,
    });

    let error = stop_by_own_bind(&dialer, &home, peer_id)
        .await
        .expect_err("a broken open is never a stop");
    assert_eq!(error, NOTHING_STOPPED);
    assert_eq!(
        *heard.lock().expect("the record"),
        [CONTROL_SERVE_SERVICE],
        "one open, never a probe"
    );
    let _ = std::fs::remove_dir_all(base);

    // Each open that fails after the dial, on a source that answers at once: the line, with no time spent.
    let failed: &[fn() -> Unopened] = &[
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
    for (at, stop) in failed.iter().enumerate() {
        let started = tokio::time::Instant::now();
        let (error, opened) = met(*stop).await;
        assert_eq!(error, NOTHING_STOPPED, "row {at}");
        assert_eq!(opened, [CONTROL_SERVE_SERVICE], "row {at}");
        assert_eq!(started.elapsed(), Duration::ZERO, "row {at}: at once");
    }
}

/// The lines an open that failed after the dial ends `stop me/pi` with.
const NOTHING_STOPPED: &str = "could not stop me/pi\n  Nothing was stopped.";

/// By own bind, with a held Main session to the device already open, the stop dials a connection of its
/// own. A device that reads the open and drops the stream gets exactly one, and nothing was stopped. Ride
/// the held session and its failed open is retried on a fresh dial, which asks a second time.
#[tokio::test(start_paused = true)]
async fn a_stop_never_rides_a_held_session() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let (base, home) = standing_home("held", None, dialer.node_id()).await;
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();
    let (heard, connections) = gate_by_service(peer, |service| match service {
        CONTROL_SERVE_SERVICE => Gate::Drops,
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
    assert_eq!(error, NOTHING_STOPPED);
    let stops = heard
        .lock()
        .expect("the record")
        .iter()
        .filter(|service| *service == CONTROL_SERVE_SERVICE)
        .count();
    assert_eq!(stops, 1, "the stop's stream was asked for once");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "the stop dialed a connection of its own"
    );
    drop(held);
    let _ = std::fs::remove_dir_all(base);
}

/// A source whose every open meets what `stop` gives, noting each open's service.
#[derive(Clone, Copy)]
struct Meets<'a> {
    stop: fn() -> Unopened,
    opened: &'a RefCell<Vec<String>>,
}

impl StreamSource for Meets<'_> {
    type Write = TestWrite<DuplexStream>;
    type Read = DuplexStream;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        self.opened
            .borrow_mut()
            .push(ask.service.as_str().to_owned());
        Err((self.stop)())
    }
}

/// One row of the stop's open table: what its open meets, and the line the run ends with.
type Row = (fn() -> Unopened, &'static str);

/// `stop me/pi` by own bind over a source whose open meets `stop`: its error, and the services it opened.
async fn met(stop: fn() -> Unopened) -> (String, Vec<String>) {
    let opened = RefCell::new(Vec::new());
    let source = Meets {
        stop,
        opened: &opened,
    };
    let pi = TestNode::seeded(PI).node_id();
    let error = stop_from(source, pi, TestNode::seeded(DESK).node_id())
        .await
        .expect_err("an open that gave no stream is the run's error");
    (error, opened.into_inner())
}

/// Each row of the stop's open table by own bind, the table the resident's path reads too: an unreached
/// device and a refusing one keep their own lines, every other failed open says nothing was stopped, and
/// an outcome that says nothing of the device is the route's line. One open each, never a second.
#[tokio::test(start_paused = true)]
async fn one_open_table_for_stop() {
    let unreachable =
        "could not reach me/pi: it is offline or not running swoosh serve\n  Nothing was stopped.";
    let serve_only = vec![CONTROL_SERVE_SERVICE.to_owned()];
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
            "me/pi refused: only your own devices can stop it",
        ),
        (|| Unopened::Own(OpenError::Timeout), NOTHING_STOPPED),
        (
            || Unopened::Refused(OpenRefusal::Broken(bifrost::RefusalDetail::bounded("cut"))),
            NOTHING_STOPPED,
        ),
    ];
    for (at, (stop, line)) in named.iter().enumerate() {
        assert_eq!(
            met(*stop).await,
            ((*line).to_owned(), serve_only.clone()),
            "row {at}"
        );
    }
    // No claim about the device: the route's own line.
    let routed: &[fn() -> Unopened] = &[
        || Unopened::Own(OpenError::Busy),
        || Unopened::Refused(OpenRefusal::Busy),
        || Unopened::Refused(OpenRefusal::StandingEnded),
        || Unopened::Home(eyre::eyre!("the badge could not be read")),
        || Unopened::ServeGone,
        || Unopened::Skew,
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
        assert_eq!(met(*stop).await, (line, serve_only.clone()), "row {at}");
    }
}

/// How a [`Device`] double answers the stop on its opened stream.
#[derive(Clone, Copy)]
enum Answers {
    /// This byte, then the end of its side.
    Byte(u8),
    /// The end of its side, with no answer: what no conforming node sends.
    EndsClean,
    /// Nothing, holding its side open: a stalled `serve` or a device that will not say.
    Silent,
}

/// What a [`Device`] saw on the stop's stream, in order.
#[derive(Debug, PartialEq, Eq)]
enum Saw {
    /// The request's byte.
    Request(u8),
    /// The stop's side ended before any answer was sent.
    EndedBeforeAnswer,
    /// Its answer was sent.
    Answered,
    /// The stop's side ended.
    Ended,
}

/// Where the stop's own write half stalls, as a transport waiting on a peer that grants nothing would.
#[derive(Clone, Copy)]
enum Stalls {
    /// Nowhere: every write and the close go through.
    Never,
    /// On the request's write.
    Write,
    /// On the close.
    Close,
    /// Nowhere: the half is aborted as it opens, so the request's write fails.
    Aborted,
}

/// The stop's write half over a [`Device`]: the pipe to it, stalling as `stalls` says.
struct Pipe {
    inner: TestWrite<DuplexStream>,
    stalls: Stalls,
}

impl tokio::io::AsyncWrite for Pipe {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.stalls {
            Stalls::Write => core::task::Poll::Pending,
            Stalls::Never | Stalls::Close | Stalls::Aborted => {
                core::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<()>> {
        core::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.stalls {
            Stalls::Close => core::task::Poll::Pending,
            Stalls::Never | Stalls::Write | Stalls::Aborted => {
                core::pin::Pin::new(&mut this.inner).poll_shutdown(cx)
            }
        }
    }
}

impl bifrost::WriteEnd for Pipe {
    fn abort(&mut self) {
        self.inner.abort();
    }

    fn delivered(self) -> impl Future<Output = io::Result<()>> + Send + 'static {
        self.inner.delivered()
    }
}

/// A source whose open gives a stream to a device that answers as `answers` says, noting what it saw in
/// `saw`, over a write half that stalls as `stalls` says.
#[derive(Clone, Copy)]
struct Device<'a> {
    answers: Answers,
    stalls: Stalls,
    saw: &'a Arc<Mutex<Vec<Saw>>>,
}

impl StreamSource for Device<'_> {
    type Write = Pipe;
    type Read = DuplexStream;

    async fn open(&self, _ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        let (up, mut from_stop) = tokio::io::duplex(64);
        let (mut to_stop, down) = tokio::io::duplex(64);
        let (answers, saw) = (self.answers, Arc::clone(self.saw));
        tokio::spawn(async move {
            let note = |seen| saw.lock().expect("the record").push(seen);
            let mut request = [0u8; 1];
            if from_stop.read_exact(&mut request).await.is_err() {
                return;
            }
            note(Saw::Request(request[0]));
            let mut rest = Vec::new();
            match answers {
                Answers::Byte(byte) => {
                    // A stop that ends its side before it reads the answer lets the node's teardown drop
                    // the answer in flight: watch for that end before answering.
                    let mut more = [0u8; 1];
                    let early =
                        tokio::time::timeout(Duration::from_millis(50), from_stop.read(&mut more))
                            .await;
                    if matches!(early, Ok(Ok(0))) {
                        note(Saw::EndedBeforeAnswer);
                    }
                    let _ = to_stop.write_all(&[byte]).await;
                    note(Saw::Answered);
                    let _ = to_stop.shutdown().await;
                }
                Answers::EndsClean => {
                    let _ = to_stop.shutdown().await;
                }
                Answers::Silent => {}
            }
            let _ = from_stop.read_to_end(&mut rest).await;
            note(Saw::Ended);
            // Held, so a silent device never ends its side: only the stop's own bound ends the wait.
            let _held = to_stop;
            core::future::pending::<()>().await;
        });
        Ok(Opened {
            info: bifrost::ConnInfo::default(),
            write: {
                let mut inner = TestWrite::from(up);
                if matches!(self.stalls, Stalls::Aborted) {
                    bifrost::WriteEnd::abort(&mut inner);
                }
                Pipe {
                    inner,
                    stalls: self.stalls,
                }
            },
            read: down,
        })
    }
}

/// `stop me/pi` over a [`Device`] that answers as `answers` says: its line or error, what the device
/// saw, and how long the run took on the paused clock.
async fn answered(answers: Answers) -> (Result<String, String>, Vec<Saw>, Duration) {
    stalled(answers, Stalls::Never).await
}

/// [`answered`], over a write half that stalls as `stalls` says.
async fn stalled(answers: Answers, stalls: Stalls) -> (Result<String, String>, Vec<Saw>, Duration) {
    let saw = Arc::new(Mutex::new(Vec::new()));
    let started = tokio::time::Instant::now();
    let ended = tokio::time::timeout(
        ANSWER_DEADLINE * 2,
        stop_from(
            Device {
                answers,
                stalls,
                saw: &saw,
            },
            TestNode::seeded(PI).node_id(),
            TestNode::seeded(DESK).node_id(),
        ),
    )
    .await
    .expect("the stop ends within its own bound");
    let took = started.elapsed();
    // The device notes the stop's end on its own task: give it the turn to.
    tokio::task::yield_now().await;
    let seen = core::mem::take(&mut *saw.lock().expect("the record"));
    (ended, seen, took)
}

/// The stop writes its one request, reads the answer with its side still open, and only then ends its
/// side: the node stops once it sees that end, so its teardown cannot drop `Done` in flight. End the side
/// first and a stop that worked can read as unconfirmed.
#[tokio::test(start_paused = true)]
async fn stop_reads_the_answer_before_it_closes() {
    let (ended, seen, _) = answered(Answers::Byte(Answer::Done.encode())).await;
    assert!(ended.is_ok_and(|line| line.starts_with("Stopped me/pi (")));
    assert_eq!(
        seen,
        [
            Saw::Request(Request::Stop.encode()),
            Saw::Answered,
            Saw::Ended
        ]
    );
}

/// A stream that ends cleanly with no answer is not a stop: no conforming node ends it before its answer,
/// so only a broken or hostile one does, and the line says the stop is unconfirmed. Read that end as the
/// node going down and a double or a broken node prints `Stopped` for a machine still serving.
#[tokio::test(start_paused = true)]
async fn a_clean_end_with_no_answer_is_not_stopped() {
    let (ended, seen, _) = answered(Answers::EndsClean).await;
    assert_eq!(
        ended,
        Err("could not confirm that me/pi stopped; it may still be serving".to_owned())
    );
    assert_eq!(seen[0], Saw::Request(Request::Stop.encode()));
}

/// A device that takes the request and never answers holds `stop` for the answer bound and no longer,
/// then the stop is unconfirmed: the request may have landed. Wait on with no bound and a stalled `serve`
/// or a device that keeps the stream open holds a CI teardown forever.
#[tokio::test(start_paused = true)]
async fn a_silent_device_is_unconfirmed_at_the_answer_bound() {
    let (ended, seen, took) = answered(Answers::Silent).await;
    assert_eq!(
        ended,
        Err("could not confirm that me/pi stopped; it may still be serving".to_owned())
    );
    assert_eq!(took, ANSWER_DEADLINE);
    assert_eq!(seen, [Saw::Request(Request::Stop.encode()), Saw::Ended]);
}

/// A close that never completes holds `stop` to the same bound and no longer, and the stop it read `Done`
/// for is still reported: the answer is in hand. Await the close with no bound and a transport whose close
/// waits on a peer granting nothing holds a CI teardown forever.
#[tokio::test(start_paused = true)]
async fn a_stalled_close_ends_at_the_answer_bound() {
    let (ended, _, took) = stalled(Answers::Byte(Answer::Done.encode()), Stalls::Close).await;
    assert!(ended.is_ok_and(|line| line.starts_with("Stopped me/pi (")));
    assert_eq!(took, ANSWER_DEADLINE);
}

/// A request whose write never completes, or fails, may still have left: the stop ends at the bound, or at
/// once, unconfirmed. Read a failed write as nothing stopped and a byte that left before the break is a
/// stop reported as none.
#[tokio::test(start_paused = true)]
async fn a_stalled_or_failed_request_write_is_unconfirmed() {
    let unconfirmed = "could not confirm that me/pi stopped; it may still be serving";
    let (ended, seen, took) = stalled(Answers::Silent, Stalls::Write).await;
    assert_eq!(ended, Err(unconfirmed.to_owned()));
    assert_eq!(took, ANSWER_DEADLINE);
    assert!(seen.is_empty(), "the request never arrived: {seen:?}");

    // A failed write, over a source whose write half is aborted as it opens.
    let (ended, seen, _) = stalled(Answers::Silent, Stalls::Aborted).await;
    assert_eq!(ended, Err(unconfirmed.to_owned()));
    assert!(seen.is_empty(), "the request never arrived: {seen:?}");
}

/// Each answer byte, over the double: `NotYet` is the first-round lines, and `BadRequest` or a byte no
/// node sends is an unknown reply. Neither is a stop.
#[tokio::test(start_paused = true)]
async fn every_answer_but_done_is_no_stop() {
    let unknown = "me/pi sent an unknown reply to the stop; it may still be serving";
    for (byte, line) in [
        (Answer::NotYet.encode(), NOT_YET),
        (Answer::BadRequest.encode(), unknown),
        (Request::Stop.encode(), unknown),
        (0xff, unknown),
    ] {
        let (ended, _, _) = answered(Answers::Byte(byte)).await;
        assert_eq!(ended, Err(line.to_owned()), "{byte}");
    }
}

/// Only `Done` proves the stop. `NotYet` is a machine that took none yet; another byte, a clean end with no
/// answer, a stream broken any other way, or no answer in time proves nothing, and the line says the device
/// may still be serving.
#[test]
fn only_done_confirms_the_stop() {
    let Ok(Aim::Device(pi)) = Aim::parse("me/pi") else {
        panic!("me/pi is a device shape");
    };
    let broken = |kind| Err(io::Error::from(kind));
    assert!(confirmed(Ok(Answer::Done.encode()), &pi).is_ok());
    let line = |answer| format!("{:#}", confirmed(answer, &pi).expect_err("not confirmed"));
    assert_eq!(line(Ok(Answer::NotYet.encode())), NOT_YET);
    assert_eq!(
        line(Ok(b'x')),
        "me/pi sent an unknown reply to the stop; it may still be serving"
    );
    // `NotConnected` is what a lost QUIC connection reads as (iroh's): the node's teardown and a dropped
    // path look the same there, so neither proves the stop.
    for kind in [
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::TimedOut,
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

/// `stop` takes no link and no path: either is refused as the line is parsed, before the home is read or a
/// file opened, exit 2, and the refusal prints back neither the path nor the link's token. Let clap's own
/// value error carry it and the whole link is echoed onto the terminal.
#[test]
fn stop_refuses_a_link_or_a_path_without_echoing_it() {
    let link = swoosh::link::Link::from(
        TestRoot::seeded(ROOT)
            .bound_slip(
                &CONTROL_SERVE_SERVICE.parse().expect("a service"),
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
                &CONTROL_SERVE_SERVICE.parse().expect("a service"),
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
