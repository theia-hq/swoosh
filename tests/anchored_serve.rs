// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `serve`'s gate end to end: the compiled binary serves a scratch home over `quirk+noise` on loopback,
//! and a dialer in this process reaches it with the credential each case is about.
//!
//! What is proven is what the composition root builds, not a gate assembled here: a machine with no pin
//! admits no member, even one its own key signed; a link `share` signed is admitted through the
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
use std::time::{Instant, SystemTime};

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
/// loopback address, from the transport block `--verbose` adds.
fn serve(home: &Path, entries: &[&str]) -> Served {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(["serve", "--transport", "quirk+noise", "--verbose"])
        .args(entries)
        .env("XDG_RUNTIME_DIR", runtime_dir(home))
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
        if let Some(parsed) = line.strip_prefix("key: ") {
            key = Some(parsed.parse::<NodeId>().expect("the banner's key"));
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

/// A private runtime directory for `home`'s `serve`, inside the scratch home so it goes with it.
fn runtime_dir(home: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = home.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
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

/// The link `share` prints for `args`, once a running `serve` can have seen its ledger row: the
/// ledger is re-read at most once per debounce.
fn issue(home: &Path, args: &[&str]) -> Link {
    let mut full = vec!["share"];
    full.extend_from_slice(args);
    let link = swoosh::link::parse(&swoosh(home, &full)).expect("a link");
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(100));
    link
}

/// This machine's key, as `serve` created it: the seed a test signs with as the serving machine.
fn own_seed(home: &Path) -> [u8; 32] {
    std::fs::read(home.join("machine").join("key"))
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
    let link = issue(&scratch.0, &["ssh", "anyone", "--once"]);
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

/// The running gate holds what this `serve` bound under each name: a link made after `demo` was retargeted
/// in `serve.toml` is made for the new target, and the running reflector refuses it, while a link made for
/// the reflector is admitted.
#[tokio::test]
async fn a_running_serve_admits_a_link_only_to_the_target_it_bound() {
    let scratch = Scratch::new("bound-target");
    let served = serve(&scratch.0, &["demo=echo:"]);
    let made_for_echo = issue(&scratch.0, &["demo", "anyone"]);
    swoosh::serve_toml::ServeToml::update(&swoosh::testkit::lock(), &scratch.home(), |file| {
        file.services = vec!["demo=tcp:localhost:1".to_owned()];
    })
    .unwrap();
    let made_for_forward = issue(&scratch.0, &["demo", "anyone"]);

    let node = dialer(0x47, &served).await;
    let session = echo_session(&node, &served, made_for_echo, None).await;
    let (mut write, mut read) = open(&session)
        .await
        .expect("a link made for the reflector is admitted");
    assert!(echoes(&mut write, &mut read).await, "served once admitted");

    // A dialer of its own: a refusal tears its connection down.
    let node = dialer(0x48, &served).await;
    let session = echo_session(&node, &served, made_for_forward, None).await;
    assert!(
        open(&session).await.is_none(),
        "a link made for the forward is refused by the running reflector"
    );
}

#[tokio::test]
async fn a_self_slip_revoked_mid_session_is_cut() {
    let scratch = Scratch::new("revoked");
    let served = serve(&scratch.0, &["demo=echo:"]);
    let link = issue(&scratch.0, &["demo", "anyone"]);
    let node = dialer(0x43, &served).await;

    let session = echo_session(&node, &served, link.clone(), None).await;
    let (mut write, mut read) = open(&session).await.expect("the link is admitted");
    assert!(echoes(&mut write, &mut read).await, "served once admitted");

    let shown = swoosh::link::Link::from(Link::clone(&link)).to_string();
    swoosh(&scratch.0, &["revoke", &shown]);
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
    swoosh::config::write_signet(
        &swoosh::testkit::lock(),
        &scratch.home(),
        TestRoot::seeded(0x51).node_id(),
    )
    .unwrap();
    let served = serve(&scratch.0, &["demo=echo:"]);
    let link = issue(&scratch.0, &["demo", "anyone"]);
    let node = dialer(0x44, &served).await;

    let session = echo_session(&node, &served, link, None).await;
    let (mut write, mut read) = open(&session).await.expect("the link is admitted");
    std::fs::remove_file(scratch.0.join("root.pub")).expect("leave: the pin goes");
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
    swoosh(
        &scratch.0,
        &["contact", "add", "bob", &bob.node_id().to_string()],
    );
    let link = issue(&scratch.0, &["demo", "bob"]);
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

    swoosh::config::write_signet(&swoosh::testkit::lock(), &scratch.home(), root.node_id())
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
    swoosh(&scratch.0, &["leave", "--new-key"]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(&scratch.0)
        .args(["share", "demo", "anyone"])
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("share spawns");
    drop(child.stdout.take());
    let status = child.wait().expect("share ends");
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

/// Record in `home`'s ledger a link for `ssh` given to `holder`, made when `ssh` served `serves`, with its
/// root id from `id`, ending `expiry`.
fn link_for_ssh(
    home: &swoosh::home::Home,
    serves: Option<&str>,
    holder: &str,
    id: u8,
    expiry: SystemTime,
) -> nauthy::RevocationId {
    let root_id = nauthy::RevocationId::from_bytes(vec![0x5a, id]);
    swoosh::grants::Grants::at(home.links())
        .append(
            &swoosh::testkit::lock(),
            &swoosh::grants::GrantRecord {
                target: "ssh".parse().unwrap(),
                serves: serves.map(|target| target.parse().unwrap()),
                kind: swoosh::grants::GrantKind::Device,
                delegation: swoosh::grants::Delegation::Sealed,
                holder: holder.to_owned(),
                root_id: root_id.clone(),
                expiry,
            },
        )
        .unwrap();
    root_id
}

/// Record in `home`'s ledger a link for `name` to anyone, made when it served `serves`, with its root id from
/// `id`, ending in an hour.
fn anyone_link_for(home: &swoosh::home::Home, name: &str, serves: Option<&str>, id: u8) {
    swoosh::grants::Grants::at(home.links())
        .append(
            &swoosh::testkit::lock(),
            &swoosh::grants::GrantRecord {
                target: name.parse().unwrap(),
                serves: serves.map(|target| target.parse().unwrap()),
                kind: swoosh::grants::GrantKind::Bearer,
                delegation: swoosh::grants::Delegation::Delegable,
                holder: swoosh::grants::ANYONE.to_owned(),
                root_id: nauthy::RevocationId::from_bytes(vec![0x5b, id]),
                expiry: SystemTime::now() + Duration::from_secs(3600),
            },
        )
        .unwrap();
}

/// `serve <entries>` on `home`, as a person runs it, expected to refuse: its exit, stdout and stderr. A
/// `serve` that is still running after a bounded wait started instead of refusing, so it is killed and the
/// test fails, rather than waiting on a node that never stops.
fn serve_once(home: &Path, entries: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(["serve", "--transport", "quirk+noise"])
        .args(entries)
        .env("XDG_RUNTIME_DIR", runtime_dir(home))
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("serve spawns");
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().expect("poll serve").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("serve was still running after 20s: it started instead of refusing");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("serve's output")
}

/// A shell is never bound under a name whose live links were made for another target, or for nothing: the
/// start refuses, exit 1, before it binds or saves anything, says what the links were made for, and names
/// no holder's key.
#[test]
fn serve_refuses_sshd_under_a_name_with_links_for_another_target() {
    let scratch = Scratch::new("shell-over-links");
    let home = scratch.home();
    let later = SystemTime::now() + Duration::from_secs(3600);
    let bob = TestRoot::seeded(0x61).node_id().to_string();
    let carol = TestRoot::seeded(0x62).node_id().to_string();
    link_for_ssh(&home, Some("tcp:localhost:22"), &bob, 1, later);
    link_for_ssh(&home, None, &carol, 2, later);
    link_for_ssh(&home, Some("sshd:"), &carol, 3, later);

    let output = serve_once(&scratch.0, &["ssh=sshd:"]);
    assert_eq!(output.status.code(), Some(1), "exit 1");
    assert!(output.stdout.is_empty(), "no banner: nothing was bound");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim_end(),
        "error: ssh has live links made when it served tcp:localhost:22 or nothing, and they would open a \
         shell: serve the shell under another name, or revoke them first (swoosh status lists them under \
         links you shared)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(&bob) && !stderr.contains(&carol),
        "no holder's key is printed"
    );
    assert!(
        !home.serve_toml().exists(),
        "a start that refused saves nothing"
    );
}

/// A link to anyone made while `ssh` was a forward stops a bare `serve ssh` too, and the refusal names no
/// command that cannot run as printed: `revoke anyone` is no form.
#[test]
fn serve_refuses_a_shell_over_an_anyone_link_and_names_no_revoke_for_it() {
    let scratch = Scratch::new("shell-over-anyone");
    anyone_link_for(&scratch.home(), "ssh", Some("tcp:localhost:22"), 1);
    let output = serve_once(&scratch.0, &["ssh"]);
    assert_eq!(output.status.code(), Some(1), "exit 1");
    assert!(output.stdout.is_empty(), "no banner: nothing was bound");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.trim_end(),
        "error: ssh has live links made when it served tcp:localhost:22, and they would open a shell: \
         serve the shell under another name, or revoke them first (swoosh status lists them under links \
         you shared)"
    );
    assert!(!stderr.contains("swoosh revoke"), "{stderr}");
}

/// The start check is the gate's line: receiving files under a name whose links to anyone were made while
/// it served nothing is refused, as a shell is.
#[test]
fn serve_refuses_recv_under_a_name_with_anyone_links_for_another_target() {
    let scratch = Scratch::new("recv-over-anyone");
    anyone_link_for(&scratch.home(), "drop", None, 1);
    let dir = std::env::temp_dir().join(format!("sw-anch-recv-drop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let entry = format!("drop=recv:{}", dir.display());
    let output = serve_once(&scratch.0, &[&entry]);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(output.status.code(), Some(1), "exit 1");
    assert!(output.stdout.is_empty(), "no banner: nothing was bound");
    let target = format!("recv:{}", dir.display());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim_end(),
        format!(
            "error: drop has live links made when it served nothing, and they would reach {target}: serve \
             {target} under another name, or revoke them first (swoosh status lists them under links you \
             shared)"
        )
    );
}

/// Links made while `ssh` served `sshd:` are the shell's own, so they do not stop it.
#[cfg(feature = "ssh")]
#[test]
fn serve_binds_sshd_when_every_live_link_was_issued_for_sshd() {
    let scratch = Scratch::new("shell-own-links");
    let later = SystemTime::now() + Duration::from_secs(3600);
    let bob = TestRoot::seeded(0x63).node_id().to_string();
    link_for_ssh(&scratch.home(), Some("sshd:"), &bob, 1, later);
    let _served = serve(&scratch.0, &["ssh=sshd:"]);
}

/// Only a live link counts: one past its end, or revoked here, does not stop the shell.
#[cfg(feature = "ssh")]
#[test]
fn an_expired_or_revoked_link_does_not_block_serve() {
    let scratch = Scratch::new("shell-dead-links");
    let home = scratch.home();
    let bob = TestRoot::seeded(0x64).node_id().to_string();
    let earlier = SystemTime::now() - Duration::from_secs(60);
    let later = SystemTime::now() + Duration::from_secs(3600);
    link_for_ssh(&home, Some("tcp:localhost:22"), &bob, 1, earlier);
    let revoked = link_for_ssh(&home, Some("tcp:localhost:22"), &bob, 2, later);
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        &home,
        [nauthy::Revocation::Id(revoked)],
    )
    .unwrap();
    let _served = serve(&scratch.0, &["ssh=sshd:"]);
}

/// The check reads the ledger only for an engine that must never face an open gate: a `serve` that binds
/// none starts over a ledger it cannot read, as it did before, and its gate admits no link this machine
/// signed until it can.
#[test]
fn a_serve_with_nothing_never_public_starts_over_an_unreadable_ledger() {
    let scratch = Scratch::new("no-shell-ledger");
    std::fs::create_dir(scratch.home().links()).unwrap();
    let _served = serve(&scratch.0, &["demo=echo:"]);
}

/// A `serve` that binds such an engine fails closed over a ledger it cannot read: exit 1, nothing bound,
/// whether it is a shell or the default `ping` and `speed`.
#[test]
fn a_serve_of_a_never_public_engine_refuses_over_an_unreadable_ledger() {
    let scratch = Scratch::new("ledger-unreadable");
    std::fs::create_dir(scratch.home().links()).unwrap();
    for entries in [&["ssh"][..], &[][..]] {
        let output = serve_once(&scratch.0, entries);
        assert_eq!(output.status.code(), Some(1), "{entries:?}: exit 1");
        assert!(output.stdout.is_empty(), "{entries:?}: nothing was bound");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.starts_with("error: access the grants ledger"),
            "{entries:?}: {stderr}"
        );
    }
}
