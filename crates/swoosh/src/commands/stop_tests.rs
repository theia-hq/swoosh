//! S4 tests: bare `stop` resolves the local control client, stops the resident over the socket,
//! and teaches when no resident is addressable under the home.

use core::sync::atomic::{AtomicU32, Ordering};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bifrost::NodeId;
use clap::Parser as _;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};

use super::{StopCmd, stop_line};
use crate::commands::serve::{Resident, StopKind};
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
