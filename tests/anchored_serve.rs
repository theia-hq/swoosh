// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `serve`'s gate end to end: the compiled binary serves a scratch home over `quirk+noise` on loopback,
//! and a dialer in this process reaches it with the credential each case is about.
//!
//! What is proven is what the composition root builds, not a gate assembled here: a machine with no pin
//! admits no member, even one its own key signed; a link `grant issue` signed is admitted through the
//! ledger and cut within a sweep once revoked; a link session outlives ten sweeps and the pin's removal;
//! a fleet link's session outlives ten sweeps; and a pin written while `serve` runs is trusted at the next
//! admission with no restart.
//!
//! A session is kept on an `echo:` route: each check writes a line and reads it back, so a session the
//! cut ended reads as an end of stream.

use core::net::SocketAddr;
use core::time::Duration;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use bifrost::{Node, NodeId};
use bifrost_noise::Noise;
use bifrost_quirk::Endpoint;
use nauthy::{Link, Request};
use swoosh::credential::Credential;
use swoosh::reaching::BindRole;
use swoosh::testkit::TestRoot;
use swoosh::transport::PeerHint;
use tightbeam::tunnel::{Connector, ServiceSession};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The role the dialer binds under: it browses the LAN and advertises nothing.
const DIALING: BindRole = BindRole::Dialing(Credential::Family { present: None });

/// How often the live cut sweeps, with room for the pin's debounce and a slow machine.
const SWEEP: Duration = Duration::from_millis(1200);

/// A scratch home, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sw-anch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn home(&self) -> swoosh::home::Home {
        swoosh::home::Home::resolve(Some(self.0.clone())).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running `swoosh serve`, killed and reaped on drop.
struct Served {
    child: Child,
    key: NodeId,
    addr: SocketAddr,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Serve `home` with `entries` over `quirk+noise`, and wait for its banner: the key it answers at and its
/// loopback address.
fn serve(home: &Path, entries: &[&str]) -> Served {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(["serve", "--transport", "quirk+noise"])
        .args(entries)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve spawns");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();
    let deadline = Instant::now() + Duration::from_secs(60);
    let (mut key, mut addr) = (None, None);
    while key.is_none() || addr.is_none() {
        assert!(Instant::now() < deadline, "serve never printed its banner");
        let line = lines
            .next()
            .expect("serve exited before its banner")
            .expect("read the banner");
        let line = line.trim();
        if let Ok(parsed) = line.parse::<NodeId>() {
            key = Some(parsed);
        }
        if let Some(found) = line.strip_suffix("(this machine)") {
            addr = Some(found.trim().parse().expect("a loopback address"));
        }
    }
    Served {
        child,
        key: key.unwrap(),
        addr: addr.unwrap(),
    }
}

/// Run the binary on `home` with `args`, and return its stdout, failing on a refusal.
fn swoosh(home: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    assert!(
        output.status.success(),
        "`swoosh {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The link `grant issue` prints for `args`, once a running `serve` can have seen its ledger row: the
/// ledger is re-read at most once per debounce.
fn issue(home: &Path, args: &[&str]) -> Link {
    let mut full = vec!["grant", "issue"];
    full.extend_from_slice(args);
    let link = swoosh::link::parse(&swoosh(home, &full)).expect("a link");
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(100));
    link
}

/// This machine's key, as `serve` created it: the seed a test signs with as the serving machine.
fn own_seed(home: &Path) -> [u8; 32] {
    std::fs::read(home.join("key"))
        .unwrap()
        .try_into()
        .expect("a plain key file is its 32 bytes")
}

/// A dialer under `seed`, pointed at `served` by a direct hint.
async fn dialer(seed: u8, served: &Served) -> Node<Noise<Endpoint>, impl bifrost::Discovery> {
    let seed = [seed; 32];
    let inner = Endpoint::bind_with_secret(&seed)
        .await
        .expect("bind quirk on loopback");
    let transport = Noise::new(inner, &seed).expect("wrap quirk under its own identity");
    let hint: PeerHint = format!("{}={}", served.key, served.addr).parse().unwrap();
    let discovery = PeerHint::discovery(&transport, [hint], &DIALING).discovery;
    Node::new(transport, discovery)
}

/// The node id a dialer under `seed` proves.
fn dialer_id(seed: u8) -> NodeId {
    NodeId::from_ed25519_secret(&[seed; 32])
}

fn in_an_hour() -> std::time::SystemTime {
    Request::expires_in(Duration::from_secs(3600))
}

/// An open stream on `session`'s service, or `None` when the gate refused it.
async fn open<S: bifrost::Session>(session: &S) -> Option<(S::Write, S::Read)> {
    tokio::time::timeout(Duration::from_secs(15), session.open_bi())
        .await
        .expect("the stream answers within the deadline")
        .ok()
}

/// Whether the stream still echoes a line: `false` once the session ended.
async fn echoes<W, R>(write: &mut W, read: &mut R) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    if write.write_all(b"still here\n").await.is_err() || write.flush().await.is_err() {
        return false;
    }
    let mut back = [0u8; 11];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), read.read_exact(&mut back)).await,
        Ok(Ok(_)) if &back == b"still here\n"
    )
}

/// A connection to the `demo` echo on `served`, presenting `grant` (and `badge` in slot 2) on each stream.
async fn echo_session<T: bifrost::Transport, D: bifrost::Discovery>(
    node: &Node<T, D>,
    served: &Served,
    grant: Link,
    badge: Option<Link>,
) -> ServiceSession<T::Session> {
    let mut connector = Connector::to_node(served.key, "demo".parse().unwrap(), Some(grant));
    if let Some(badge) = badge {
        connector = connector.with_membership(badge);
    }
    connector.open_service(node).await.expect("connect")
}

#[tokio::test]
async fn a_pinless_serve_refuses_a_member_cap_at_its_own_key() {
    let scratch = Scratch::new("pinless");
    let served = serve(&scratch.0, &["demo=echo:"]);
    let own = TestRoot::from_seed(own_seed(&scratch.0));
    let node = dialer(0x41, &served).await;

    let badge = own.device_badge(dialer_id(0x41), in_an_hour()).unwrap();
    let session = echo_session(&node, &served, badge, None).await;
    assert!(
        open(&session).await.is_none(),
        "a machine with no pin admits no member, even one its own key signed"
    );
}

#[tokio::test]
async fn a_node_signed_ssh_grant_opens_a_shell() {
    let scratch = Scratch::new("ssh");
    let served = serve(&scratch.0, &["ssh=sshd:"]);
    let link = issue(&scratch.0, &["ssh"]);
    let node = dialer(0x42, &served).await;

    let session = Connector::to_node(served.key, "ssh".parse().unwrap(), Some(link))
        .open_service(&node)
        .await
        .expect("connect");
    let (_write, mut read) = open(&session)
        .await
        .expect("the gate admits a link this machine signed and the shell takes it");
    let mut greeting = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(10), read.read_exact(&mut greeting))
        .await
        .expect("the shell greets within the deadline")
        .expect("the shell greets");
    assert_eq!(
        &greeting, b"SSH-2.0-",
        "the ssh server greets the admitted link"
    );
}

#[tokio::test]
async fn a_self_slip_revoked_mid_session_is_cut() {
    let scratch = Scratch::new("revoked");
    let served = serve(&scratch.0, &["demo=echo:"]);
    let link = issue(&scratch.0, &["demo"]);
    let node = dialer(0x43, &served).await;

    let session = echo_session(&node, &served, link.clone(), None).await;
    let (mut write, mut read) = open(&session).await.expect("the link is admitted");
    assert!(echoes(&mut write, &mut read).await, "served once admitted");

    let shown = swoosh::link::Link::from(Link::clone(&link)).to_string();
    swoosh(&scratch.0, &["grant", "revoke", &shown]);
    let deadline = Instant::now() + 3 * SWEEP;
    while echoes(&mut write, &mut read).await {
        assert!(
            Instant::now() < deadline,
            "the revoked link's session is cut within a sweep"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn a_self_anchored_session_survives_ten_sweeps_and_a_leave() {
    let scratch = Scratch::new("leave");
    swoosh::config::write_signet(&scratch.home(), TestRoot::seeded(0x51).node_id())
        .await
        .unwrap();
    let served = serve(&scratch.0, &["demo=echo:"]);
    let link = issue(&scratch.0, &["demo"]);
    let node = dialer(0x44, &served).await;

    let session = echo_session(&node, &served, link, None).await;
    let (mut write, mut read) = open(&session).await.expect("the link is admitted");
    std::fs::remove_file(scratch.0.join("signet")).expect("leave: the pin goes");
    for sweep in 0..10 {
        tokio::time::sleep(SWEEP).await;
        assert!(
            echoes(&mut write, &mut read).await,
            "a link session is anchored at this machine's own key, which it always trusts: sweep {sweep}"
        );
    }
}

#[tokio::test]
async fn a_fleet_bob_ssh_session_outlives_ten_sweeps() {
    let scratch = Scratch::new("fleet");
    let served = serve(&scratch.0, &["demo=echo:"]);
    let bob = TestRoot::seeded(0x52);
    let link = issue(
        &scratch.0,
        &["demo", "--for", &format!("fleet:{}", bob.node_id())],
    );
    let node = dialer(0x45, &served).await;
    let badge = bob.device_badge(dialer_id(0x45), in_an_hour()).unwrap();

    let session = echo_session(&node, &served, link, Some(badge)).await;
    let (mut write, mut read) = open(&session)
        .await
        .expect("bob's device is admitted on the fleet link and bob's badge");
    for sweep in 0..10 {
        tokio::time::sleep(SWEEP).await;
        assert!(
            echoes(&mut write, &mut read).await,
            "bob's root is never an anchor, so the session survives sweep {sweep}"
        );
    }
}

#[tokio::test]
async fn a_pin_written_under_serve_is_trusted_without_restart() {
    let scratch = Scratch::new("join");
    let served = serve(&scratch.0, &["demo=echo:"]);
    let root = TestRoot::seeded(0x53);
    let node = dialer(0x46, &served).await;
    let badge = root.device_badge(dialer_id(0x46), in_an_hour()).unwrap();

    let session = echo_session(&node, &served, badge.clone(), None).await;
    assert!(
        open(&session).await.is_none(),
        "before the pin, the root's device is refused"
    );

    swoosh::config::write_signet(&scratch.home(), root.node_id())
        .await
        .unwrap();
    tokio::time::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(200)).await;
    // A fresh connection under the same key: the refused one was torn down.
    drop(session);
    let node = dialer(0x46, &served).await;
    let session = echo_session(&node, &served, badge, None).await;
    let (mut write, mut read) = open(&session)
        .await
        .expect("the pin written while serving is trusted at the next admission");
    assert!(echoes(&mut write, &mut read).await, "and served");
}

/// A fault right after the link is printed (its stdout is a closed pipe) still leaves the row on disk,
/// because the row is appended and synced before the link is printed.
#[test]
fn a_grant_is_on_disk_before_its_link_prints() {
    let scratch = Scratch::new("print");
    swoosh(&scratch.0, &["identity"]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(&scratch.0)
        .args(["grant", "issue", "demo"])
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("grant issue spawns");
    drop(child.stdout.take());
    let status = child.wait().expect("grant issue ends");
    assert!(
        !status.success(),
        "printing to a closed pipe fails the command, the fault this is about"
    );
    let rows = std::fs::read_to_string(scratch.0.join("links")).unwrap_or_default();
    assert_eq!(
        rows.lines().count(),
        1,
        "the row was on disk before the print failed"
    );
}
