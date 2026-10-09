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
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use bifrost::{Node, NodeId};
use bifrost_noise::Noise;
use bifrost_quirk::Endpoint;
use nauthy::{Link, Request};
use swoosh::credential::Credential;
use swoosh::reaching::BindRole;
use swoosh::serve::CONTROL_STOP_SERVICE;
use swoosh::serve::control_codec::{self, ControlError, Response};
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
    /// Each line it wrote to stderr so far, read on a thread of its own.
    stderr: Arc<Mutex<Vec<String>>>,
}

impl Served {
    /// The first line on its stderr that contains `text`, waiting a bounded time for the reader to catch up.
    fn stderr_line(&self, text: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let lines = self.stderr.lock().unwrap();
            if let Some(line) = lines.iter().find(|line| line.contains(text)) {
                return line.clone();
            }
            assert!(
                Instant::now() < deadline,
                "serve printed no line with {text:?}: {lines:?}"
            );
            drop(lines);
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Served {
    /// Wait a bounded time for it to exit on its own.
    async fn exited(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "serve did not stop");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `swoosh serve` on `home` over `quirk+noise` with `flags` and `entries`, its stderr read line by
/// line on a thread of its own.
fn spawn_serve(home: &Path, flags: &[&str], entries: &[&str]) -> (Child, Arc<Mutex<Vec<String>>>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(["serve", "--transport", "quirk+noise"])
        .args(flags)
        .args(entries)
        .env("XDG_RUNTIME_DIR", runtime_dir(home))
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("serve spawns");
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let reader = BufReader::new(child.stderr.take().expect("piped stderr"));
    let lines_read = Arc::clone(&stderr);
    std::thread::spawn(move || {
        for line in reader.lines().map_while(Result::ok) {
            lines_read.lock().unwrap().push(line);
        }
    });
    (child, stderr)
}

/// Serve `home` with `entries` over `quirk+noise`, and wait for its banner: the key it answers at and its
/// loopback address, from the transport block `--verbose` adds.
fn serve(home: &Path, entries: &[&str]) -> Served {
    let (mut child, stderr) = spawn_serve(home, &["--verbose"], entries);
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
        stderr,
    }
}

/// Serve `home` with `entries` under `--quiet`, which prints no banner: the key and address come from its
/// control socket's status instead, once it answers. Also returns the thread reading its stdout, which yields
/// everything printed once the child has exited.
async fn serve_quiet(home: &Path, entries: &[&str]) -> (Served, std::thread::JoinHandle<String>) {
    use std::io::Read as _;

    let (mut child, stderr) = spawn_serve(home, &["--quiet"], entries);
    let mut pipe = child.stdout.take().expect("piped stdout");
    // Read to EOF, so joining the thread after the child exits yields everything it printed.
    let printed = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = pipe.read_to_string(&mut text);
        text
    });
    let socket = control_socket(home);
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "serve exited before its socket answered"
        );
        assert!(Instant::now() < deadline, "serve's socket never answered");
        if let Ok(Ok(Response::Status(status))) =
            tokio::time::timeout(Duration::from_secs(5), status_of(&socket)).await
        {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let served = Served {
        child,
        key: status.node_id,
        // The status names the bind's first dialable address, which may be a LAN one; the port is the
        // bind's, so dial it on loopback, as the banner's `(this machine)` row does.
        addr: SocketAddr::new(
            core::net::Ipv4Addr::LOCALHOST.into(),
            status.addr.expect("a quirk bind has an address").port(),
        ),
        stderr,
    };
    (served, printed)
}

/// The control socket a `serve` spawned on `home` listens on: on Linux under the runtime directory the
/// harness hands it, on macOS under the per-user root, which ignores `XDG_RUNTIME_DIR`.
fn control_socket(home: &Path) -> PathBuf {
    let home_at = swoosh::home::Home::resolve(Some(home.to_owned())).unwrap();
    #[cfg(target_os = "macos")]
    let leaf = home_at.runtime_dir().unwrap();
    #[cfg(not(target_os = "macos"))]
    let leaf = home_at.runtime_leaf(&runtime_dir(home).join("swoosh"));
    leaf.join("control.sock")
}

/// One status read over the control socket at `socket`.
async fn status_of(socket: &Path) -> Result<Response, ControlError> {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(ControlError::Io)?;
    control_codec::Request::Status
        .write(&mut stream)
        .await
        .map_err(ControlError::Io)?;
    Response::read(&mut stream).await
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
        file.services = Some(vec!["demo=tcp:localhost:1".to_owned()]);
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

/// One of your devices stops a `serve --quiet` over `control.stop`, and the stopped machine still says who
/// did, on stderr: the one trail a stop leaves, so `--quiet` must not take it. The member reads the ack and
/// closes, and the machine exits 0 having printed no banner.
#[tokio::test]
async fn a_quiet_serve_stopped_over_the_wire_says_who_stopped_it() {
    let scratch = Scratch::new("quiet-stop");
    let root = TestRoot::seeded(0x54);
    swoosh::config::write_signet(&swoosh::testkit::lock(), &scratch.home(), root.node_id())
        .unwrap();
    let (mut served, stdout) = serve_quiet(&scratch.0, &["demo=echo:"]).await;
    {
        let node = dialer(0x4c, &served).await;
        let badge = root.device_badge(dialer_id(0x4c), in_an_hour()).unwrap();
        let session = Connector::to_node(
            served.key,
            CONTROL_STOP_SERVICE.parse().unwrap(),
            Some(badge),
        )
        .open_service(&node)
        .await
        .expect("connect");
        let (mut write, mut read) = open(&session)
            .await
            .expect("one of your devices is admitted at control.stop");
        let mut ack = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(10), read.read_exact(&mut ack))
            .await
            .expect("the ack arrives within the deadline")
            .expect("the node acks the stop over a real transport");
        assert_eq!(ack[0], swoosh::serve::STOP_ACK);
        write.shutdown().await.expect("the member closes its side");
    }

    let status = served.exited().await;
    assert!(status.success(), "a stopped serve exits 0: {status}");
    assert_eq!(
        served.stderr_line("Stopped by"),
        format!("Stopped by {}.", dialer_id(0x4c)),
        "the stopped machine names the key that stopped it"
    );
    let printed = stdout.join().expect("the stdout reader joins");
    assert!(
        !printed.contains("key: "),
        "--quiet prints no banner: {printed}"
    );
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

/// A shell bound under a name whose live links were made for another target, or for nothing, is warned of
/// and served: the line says what the links were made for, and names no holder's key.
#[cfg(feature = "ssh")]
#[test]
fn serve_warns_of_sshd_under_a_name_with_links_for_another_target() {
    let scratch = Scratch::new("shell-over-links");
    let home = scratch.home();
    let later = SystemTime::now() + Duration::from_secs(3600);
    let bob = TestRoot::seeded(0x61).node_id().to_string();
    let carol = TestRoot::seeded(0x62).node_id().to_string();
    link_for_ssh(&home, Some("tcp:localhost:22"), &bob, 1, later);
    link_for_ssh(&home, None, &carol, 2, later);
    link_for_ssh(&home, Some("sshd:"), &carol, 3, later);

    let served = serve(&scratch.0, &["ssh=sshd:"]);
    assert_eq!(
        served.stderr_line("live links"),
        "warning: ssh has live links made when it served tcp:localhost:22 or nothing, and they are refused \
         while it serves something else (swoosh status lists them under links you shared)"
    );
    let stderr = served.stderr.lock().unwrap().join("\n");
    assert!(
        !stderr.contains(&bob) && !stderr.contains(&carol),
        "no holder's key is printed"
    );
}

/// A link to anyone made while `ssh` was a forward does not stop a shell served under `ssh`: the start
/// warns, naming no command that cannot run as printed (`revoke anyone` is no form), and the gate refuses
/// the link when it is presented, since it was made for the forward.
#[cfg(feature = "ssh")]
#[tokio::test]
async fn serve_warns_of_a_shell_over_an_anyone_link_and_its_gate_refuses_it() {
    let scratch = Scratch::new("shell-over-anyone");
    swoosh(&scratch.0, &["leave", "--new-key"]);
    swoosh::serve_toml::ServeToml::update(&swoosh::testkit::lock(), &scratch.home(), |file| {
        file.services = Some(vec!["ssh=tcp:localhost:22".to_owned()]);
    })
    .unwrap();
    let link = swoosh::link::parse(&swoosh(&scratch.0, &["share", "ssh", "anyone"])).unwrap();

    let served = serve(&scratch.0, &["ssh=sshd:"]);
    let warning = served.stderr_line("live links");
    assert_eq!(
        warning,
        "warning: ssh has live links made when it served tcp:localhost:22, and they are refused while it \
         serves something else (swoosh status lists them under links you shared)"
    );
    assert!(!warning.contains("swoosh revoke"), "{warning}");

    let node = dialer(0x49, &served).await;
    let session = Connector::to_node(served.key, "ssh".parse().unwrap(), Some(link))
        .open_service(&node)
        .await
        .expect("connect");
    assert!(
        open(&session).await.is_none(),
        "a link made for the forward never reaches the shell"
    );
}

/// The same line for an engine that runs no code: receiving files under a name whose links to anyone were
/// made while it served nothing is warned of, as a shell is.
#[test]
fn serve_warns_of_recv_under_a_name_with_anyone_links_for_another_target() {
    let scratch = Scratch::new("recv-over-anyone");
    anyone_link_for(&scratch.home(), "drop", None, 1);
    let dir = std::env::temp_dir().join(format!("sw-anch-recv-drop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let entry = format!("drop=recv:{}", dir.display());
    let served = serve(&scratch.0, &[&entry]);
    let warning = served.stderr_line("live links");
    drop(served);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        warning,
        "warning: drop has live links made when it served nothing, and they are refused while it serves \
         something else (swoosh status lists them under links you shared)"
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

/// A `serve` that binds such an engine starts over a ledger it cannot read too, whether it is a shell or
/// the default `ping` and `speed`, and says so; its gate admits no link this machine signed while the
/// ledger cannot be read, and admits them again once it can.
#[tokio::test]
async fn a_serve_of_a_never_public_engine_starts_over_an_unreadable_ledger_and_admits_no_link() {
    let scratch = Scratch::new("ledger-unreadable");
    swoosh(&scratch.0, &["leave", "--new-key"]);
    let link = issue(&scratch.0, &["demo", "anyone"]);
    let (links, kept) = (scratch.home().links(), scratch.0.join("links.kept"));
    std::fs::rename(&links, &kept).unwrap();
    std::fs::create_dir(&links).unwrap();

    let served = serve(&scratch.0, &["demo=echo:", "ping"]);
    served.stderr_line("the grants ledger cannot be read");
    let node = dialer(0x4a, &served).await;
    let session = echo_session(&node, &served, link.clone(), None).await;
    assert!(
        open(&session).await.is_none(),
        "no link this machine signed is admitted while the ledger cannot be read"
    );

    std::fs::remove_dir(&links).unwrap();
    std::fs::rename(&kept, &links).unwrap();
    tokio::time::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(200)).await;
    // A dialer of its own: the refusal tore the first one's connection down.
    let node = dialer(0x4b, &served).await;
    let session = echo_session(&node, &served, link, None).await;
    let (mut write, mut read) = open(&session)
        .await
        .expect("the link is admitted once the ledger reads again");
    assert!(echoes(&mut write, &mut read).await, "and served");

    // The default `ping` and `speed` first, since a named start saves its list and a bare one resumes it.
    let scratch = Scratch::new("ledger-unreadable-default");
    std::fs::create_dir(scratch.home().links()).unwrap();
    serve(&scratch.0, &[]).stderr_line("the grants ledger cannot be read");
    #[cfg(feature = "ssh")]
    serve(&scratch.0, &["ssh"]).stderr_line("the grants ledger cannot be read");
}
