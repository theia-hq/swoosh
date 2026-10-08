// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `reach` ends when the host ends its session: the compiled binary serves an echo over iroh with `--local` on
//! loopback, and the compiled binary reaches it, once as `swoosh ssh`'s `ProxyCommand` does (stdin held open)
//! and once forwarding a local port.
//!
//! The holder sends one line, reads it back, then sends nothing. The link it presents expires, the host
//! cuts the session within a sweep, and `reach` must exit then: not on the holder's next keystroke, and not
//! left listening on a port whose session is gone.

use core::time::Duration;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::time::Instant;

/// How long the link lives: room to dial and echo once on a slow machine before it lapses.
const EXPIRES: Duration = Duration::from_secs(6);

/// How often the host's live cut sweeps, with room for a slow machine.
const SWEEP: Duration = Duration::from_millis(1200);

/// How long `reach` may take to exit once the session is cut.
const EXIT: Duration = Duration::from_secs(4);

/// A scratch dir holding the host's and the holder's homes, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sw-cut-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A spawned child killed and reaped on drop, so a failing test never orphans it.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// A running `swoosh serve`: its key and loopback address, from the transport block `--verbose` adds.
struct Served {
    _child: KillOnDrop,
    key: String,
    addr: String,
}

/// Serve `home` with `entries` over iroh with `--local`, and wait for its banner.
fn serve(home: &Path, entries: &[&str]) -> Served {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = home.join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(["serve", "--local", "--verbose"])
        .args(entries)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve spawns");
    let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
    let child = KillOnDrop(child);
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
            key = Some(parsed.to_owned());
        }
        if let Some(found) = line.strip_suffix("(this machine)") {
            addr = Some(found.trim().to_owned());
        }
    }
    Served {
        _child: child,
        key: key.unwrap(),
        addr: addr.unwrap(),
    }
}

/// Read one line from `from`, failing past `deadline` rather than hanging the run.
fn line_within(from: impl std::io::Read + Send + 'static, deadline: Duration) -> String {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(from).read_line(&mut line);
        let _ = sender.send(line);
    });
    receiver
        .recv_timeout(deadline)
        .expect("a line arrives within the deadline")
}

/// A host serving an echo, and a link to it that lapses [`EXPIRES`] from now.
struct Lapsing {
    served: Served,
    link: String,
    lapses: Instant,
}

/// Serve an echo from a home under `scratch` and issue a link to it that lapses after [`EXPIRES`].
fn lapsing(scratch: &Scratch) -> Lapsing {
    let host = scratch.0.join("host");
    let served = serve(&host, &["echo=echo:"]);
    let link = sign_lapsing(&host);
    let lapses = Instant::now() + EXPIRES;
    // A running `serve` re-reads its ledger at most once per debounce.
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(100));
    Lapsing {
        served,
        link: link.trim().to_owned(),
        lapses,
    }
}

/// A link to `host`'s echo that lapses [`EXPIRES`] from now, signed under the host's own key with the
/// ledger row `share` writes for it. `share` makes nothing shorter than an hour, so the link is signed here.
fn sign_lapsing(host: &Path) -> String {
    let seed: [u8; 32] = std::fs::read(host.join("machine").join("key"))
        .unwrap()
        .try_into()
        .expect("a plain key file is its 32 bytes");
    let service: nauthy::Service = "echo".parse().unwrap();
    let expiry = std::time::SystemTime::now() + EXPIRES;
    let cap = swoosh::testkit::TestNode::from_seed(seed)
        .slip(&service, expiry)
        .unwrap();
    let record = swoosh::grants::GrantRecord {
        target: service,
        kind: swoosh::grants::GrantKind::Bearer,
        delegation: swoosh::grants::Delegation::Delegable,
        holder: swoosh::grants::ANYONE.to_owned(),
        root_id: cap.root_revocation_id().unwrap(),
        expiry,
    };
    swoosh::grants::Grants::at(host.join("links"))
        .append(&swoosh::testkit::lock(), &record)
        .unwrap();
    swoosh::link::Link::from(cap.link().unwrap()).to_string()
}

/// Reach the echo `lapsing` serves from a home under `scratch`, presenting its link, with `to` as the sink.
/// Every pipe is piped; stderr is read whole on a thread, returned beside the child.
fn reach(
    scratch: &Scratch,
    lapsing: &Lapsing,
    to: &str,
) -> (KillOnDrop, std::thread::JoinHandle<String>) {
    let hint = format!("{}={}", lapsing.served.key, lapsing.served.addr);
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(scratch.0.join("holder"))
            .args(["reach", "--local", "--peer", &hint, "--to", to])
            .args(["--present", &lapsing.link, &lapsing.served.key, "echo"])
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("reach spawns"),
    );
    let mut err_pipe = child.0.stderr.take().expect("piped stderr");
    let stderr = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err_pipe.read_to_string(&mut text);
        text
    });
    (child, stderr)
}

/// After the cut: `reach` exits nonzero by `lapses` plus a sweep and [`EXIT`], with one connection-lost
/// line on stderr and no reason for the cut.
fn ends_at_the_cut(
    mut reach: KillOnDrop,
    stderr: std::thread::JoinHandle<String>,
    lapses: Instant,
) {
    assert!(
        Instant::now() < lapses,
        "the echo came back before the link lapsed, so the cut below is the expiry's"
    );
    let status = exited_by(&mut reach.0, lapses + SWEEP + EXIT);
    assert!(!status.success(), "a cut session exits nonzero: {status}");
    let printed = stderr.join().expect("the stderr reader");
    assert!(
        printed.starts_with("error: connection lost") && printed.lines().count() == 1,
        "one connection-lost line, with no reason for the cut: {printed:?}"
    );
}

/// Wait for `child` to exit, polling, and fail once `deadline` passes.
fn exited_by(child: &mut Child, deadline: Instant) -> ExitStatus {
    loop {
        if let Some(status) = child.try_wait().expect("poll reach") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "reach is still running after the host cut its session"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn reach_exits_when_the_host_cuts_the_session_while_the_holder_writes_nothing() {
    let scratch = Scratch::new("expiry");
    let lapsing = lapsing(&scratch);
    let (mut reach, stderr) = reach(&scratch, &lapsing, "-");

    // One line there and back: the session is open. Then stdin stays open and silent, as a terminal is.
    let mut stdin = reach.0.stdin.take().expect("piped stdin");
    stdin.write_all(b"still here\n").expect("write to reach");
    stdin.flush().expect("flush to reach");
    let stdout: ChildStdout = reach.0.stdout.take().expect("piped stdout");
    assert_eq!(
        line_within(stdout, EXPIRES),
        "still here\n",
        "the link is admitted and the echo answers before it lapses"
    );

    ends_at_the_cut(reach, stderr, lapsing.lapses);
    drop(stdin);
}

#[test]
fn a_forward_ends_when_the_host_cuts_the_session() {
    let scratch = Scratch::new("forward");
    let lapsing = lapsing(&scratch);
    // A port free a moment ago: the forward binds it once admitted.
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|free| free.local_addr())
        .expect("a free port")
        .port();
    let (mut reach, stderr) = reach(&scratch, &lapsing, &port.to_string());

    // The forward is admitted and listening once its line prints.
    let stdout: ChildStdout = reach.0.stdout.take().expect("piped stdout");
    let banner = line_within(stdout, EXPIRES);
    assert!(
        banner.starts_with(&format!("forwarding 127.0.0.1:{port} to ")),
        "the forward prints its line once admitted: {banner:?}"
    );

    // One line there and back over a forwarded connection, held open and silent after.
    let mut connection = TcpStream::connect(("127.0.0.1", port)).expect("connect to the forward");
    connection
        .write_all(b"still here\n")
        .expect("write to the forward");
    let echoed = connection.try_clone().expect("clone the connection");
    assert_eq!(
        line_within(echoed, EXPIRES),
        "still here\n",
        "the link is admitted and the echo answers before it lapses"
    );

    ends_at_the_cut(reach, stderr, lapsing.lapses);
    drop(connection);
}
