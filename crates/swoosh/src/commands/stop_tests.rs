//! S4 tests: bare `stop` resolves the local control client, stops the resident over the socket,
//! and teaches when no resident is addressable under the home. The remote half's teardown race is proven
//! over the in-process transport: a peer that admits the session then vanishes before answering the
//! control stream is reported as a completed stop, while a live peer behind the same failure stays loud.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bifrost::{NoDiscovery, Node, NodeId, Session as _, Transport as _};
use bifrost_mem::MemTransport;
use clap::Parser as _;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};

use super::{StopCmd, stop_line};
use crate::commands::serve::{Resident, StopKind};
use crate::contacts::Contacts;
use crate::home::Home;
use crate::node_client::ControlClient;

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

/// An empty catalog: these tests exercise the stop path, not service content.
fn empty_catalog() -> ServiceCatalog {
    ServiceCatalog::decode(&0u32.to_be_bytes()).expect("an empty catalog decodes")
}

/// Parse a bare `stop` through clap, so the test drives the real verb shape (no transport flags).
fn bare_stop() -> StopCmd {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        stop: StopCmd,
    }

    Wrap::try_parse_from(["x"]).expect("bare stop parses").stop
}

/// The stop line names the pid the client read from the resident's lock, and degrades to the pid-less
/// form rather than printing a blank when the lock record is absent.
#[test]
fn the_stop_line_names_the_pid_when_known() {
    assert_eq!(
        stop_line(Some(4242)),
        "stopped your node (pid 4242).",
        "the stop confirmation names the resident pid"
    );
    assert_eq!(
        stop_line(None),
        "stopped your node.",
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
    let message = format!("{error:#}");
    assert!(
        message.contains("no resident node under this home"),
        "the error leads with the missing thing: {message}"
    );
    assert!(
        message.contains("start one with `swoosh serve --resident`"),
        "the error names the fix: {message}"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// A bare `stop` reaches no peer, so `--present` has nothing to select: it is refused with the exact
/// teaching line, never silently dropped (I.3, MAJOR-1).
#[tokio::test]
async fn bare_stop_rejects_present() {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        stop: StopCmd,
    }

    let base = scratch("present");
    let home = home_in(&base);
    let link = crate::identity::Secret::ephemeral()
        .member_badge()
        .expect("mint a stand-in slip");
    let stop = Wrap::try_parse_from(["x", "--present", &link])
        .expect("bare stop --present parses")
        .stop;

    let error = stop
        .run_local(&home)
        .await
        .expect_err("--present without --at must refuse, never be ignored");
    assert_eq!(
        format!("{error:#}"),
        "--present only applies when reaching a peer; drop it or name one"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// An in-process resident serving a real temp socket: the bare stop resolves the socket backend,
/// fires the resident's one teardown token, and records the socket stop as its own kind.
#[tokio::test]
async fn bare_stop_through_the_socket_cancels_the_resident() {
    let leaf = scratch("stop");
    let socket = leaf.join("control.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("bind the control socket");
    std::fs::write(leaf.join("control.lock"), "4242\n").expect("record the resident pid");

    let cancel = CancellationToken::new();
    let resident = Arc::new(Resident::new(
        NodeId::from_ed25519_secret(&[9u8; 32]),
        None,
        empty_catalog(),
        leaf.join("disabled"),
        cancel.clone(),
    ));
    let serving = tokio::spawn({
        let this = Arc::clone(&resident);
        async move { this.serve(listener).await }
    });

    let client = ControlClient::resolve_socket(socket).expect("the bound socket resolves");
    assert_eq!(
        client.pid(),
        Some(4242),
        "the client holds the pid the stop line prints"
    );
    StopCmd::stop_resolved(&client)
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

/// A `stop --at <raw node id>` command, as the root would hand the verb (no transport flags).
fn stop_at(peer: NodeId) -> StopCmd {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        stop: StopCmd,
    }

    Wrap::try_parse_from(["x", "--at", &peer.to_string()])
        .expect("stop --at parses")
        .stop
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

/// The teardown race is a SUCCESS: the peer admits the session, then vanishes before answering the control
/// stream, so the client's stream open fails ("stream") while the stop itself landed. The bounded probe
/// sees the listener gone and reports the completed stop instead of `could not stop ...: stream`.
#[tokio::test(start_paused = true)]
async fn a_teardown_race_reports_the_stop_as_completed() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();
    let contacts = Contacts::default();

    let (result, ()) = tokio::join!(
        StopCmd::run_stop(stop_at(peer_id), &dialer, &contacts, None, None),
        answer_with_a_vanishing_peer(&peer, true),
    );
    assert!(
        result.is_ok(),
        "a peer gone behind the failed stream open is a completed stop: {result:?}"
    );
}

/// A LIVE peer behind the same failed stream open is never masked: the endpoint stays registered, so the
/// probe reaches it and the original stream error stands.
#[tokio::test(start_paused = true)]
async fn a_live_peer_behind_a_failed_stream_open_is_not_masked() {
    let dialer = Node::new(MemTransport::bind(), NoDiscovery);
    let peer = MemTransport::bind();
    let peer_id = peer.node_id();
    let contacts = Contacts::default();

    let (result, ()) = tokio::join!(
        StopCmd::run_stop(stop_at(peer_id), &dialer, &contacts, None, None),
        answer_with_a_vanishing_peer(&peer, false),
    );
    let error = result.expect_err("a live peer behind the failed stream must stay an error");
    assert!(
        format!("{error:#}").contains("could not stop"),
        "the live-peer failure keeps its loud message: {error:#}"
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
