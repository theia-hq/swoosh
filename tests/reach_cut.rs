// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `forward` ends when the host ends its session: the compiled binary serves an echo over iroh with `--local` on
//! loopback, and the compiled binary reaches it, once as `swoosh ssh`'s `ProxyCommand` does (stdin held open)
//! and once forwarding a local port.
//!
//! The holder sends one line, reads it back, then sends nothing. The link it presents expires and the host
//! cuts the session within a sweep. The bridge must exit then, not on the holder's next keystroke; the port
//! stays up, and its next local connection, refused, ends it.
//!
//! The same echo shows that `forward -` writes a service's bytes to stdout as they are, escapes included.

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

/// How long `forward` may take to exit once the session is cut.
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

/// The overall deadline bounds channel receives even when the child's pipe stays open and silent.
fn read_banner(
    lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
    deadline: Instant,
) -> (String, String) {
    let (mut key, mut addr) = (None, None);
    while key.is_none() || addr.is_none() {
        assert!(Instant::now() < deadline, "serve never printed its banner");
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("serve never printed its banner before the deadline")
            .expect("read the banner");
        if key.is_none()
            && let Some(parsed) = line.strip_prefix("  key  ")
        {
            key = Some(parsed.trim().to_owned());
        }
        if let Some(found) = line.trim().strip_suffix("(this machine)") {
            addr = Some(found.trim().to_owned());
        }
    }
    (key.unwrap(), addr.unwrap())
}

#[test]
fn readiness_uses_the_key_fact_row_and_keeps_the_loopback_address() {
    let (sender, lines) = std::sync::mpsc::channel();
    for line in [
        "swoosh is serving",
        "  key            ed01exampleid",
        "  127.0.0.1:1234 (this machine)",
    ] {
        sender.send(Ok(line.to_owned())).unwrap();
    }
    assert_eq!(
        read_banner(lines, Instant::now() + Duration::from_secs(1)),
        ("ed01exampleid".to_owned(), "127.0.0.1:1234".to_owned())
    );
}

#[test]
fn a_service_named_key_does_not_replace_the_first_key_fact() {
    let key = bifrost::NodeId::from_ed25519_secret(&[0x11; 32]).to_string();
    let (sender, lines) = std::sync::mpsc::channel();
    for line in [
        format!("  key            {key}"),
        "  key  your devices  echo:".to_owned(),
        "  127.0.0.1:1234 (this machine)".to_owned(),
    ] {
        sender.send(Ok(line)).unwrap();
    }
    assert_eq!(
        read_banner(lines, Instant::now() + Duration::from_secs(1)),
        (key, "127.0.0.1:1234".to_owned())
    );
}

#[test]
fn readiness_rejects_colon_records_and_a_silent_open_pipe_is_bounded() {
    let (sender, lines) = std::sync::mpsc::channel();
    sender.send(Ok("key: ed01exampleid".to_owned())).unwrap();
    sender
        .send(Ok("127.0.0.1:1234 (this machine)".to_owned()))
        .unwrap();
    drop(sender);
    assert!(
        std::panic::catch_unwind(|| read_banner(lines, Instant::now() + Duration::from_secs(1)))
            .is_err()
    );
    let (_sender, lines) = std::sync::mpsc::channel();
    assert!(
        std::panic::catch_unwind(|| read_banner(lines, Instant::now() + Duration::from_millis(10)))
            .is_err()
    );
}

/// Serve `home` with `entries` over iroh with `--local`, and wait for its banner.
fn serve(home: &Path, entries: &[&str]) -> Served {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = home.join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
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
    let mut child = KillOnDrop(child);
    let stdout = child.0.stdout.take().expect("piped stdout");
    // Bound both the wait and queued output; the pipe reader may block, never the deadline owner.
    let (sender, lines) = std::sync::mpsc::sync_channel(16);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            // Keep draining after readiness, without closing the child's output pipe early.
            let _ = sender.send(line);
        }
    });
    let (key, addr) = read_banner(lines, Instant::now() + Duration::from_secs(60));
    Served {
        _child: child,
        key,
        addr,
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
    let home = swoosh::home::Home::resolve(Some(host.to_path_buf())).unwrap();
    let seed: [u8; 32] = std::fs::read(home.key())
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
        serves: None,
        kind: swoosh::grants::GrantKind::Bearer,
        delegation: swoosh::grants::Delegation::Delegable,
        holder: swoosh::grants::ANYONE.to_owned(),
        root_id: cap.root_revocation_id().unwrap(),
        expiry,
    };
    swoosh::grants::Grants::at(home.links())
        .append(&swoosh::testkit::lock(), &record)
        .unwrap();
    swoosh::link::Link::from(cap.link().unwrap()).to_string()
}

/// Complete stderr bytes or their read error: neither invalid UTF-8 nor an I/O failure can vanish.
type Stderr = std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>;

/// Forward the echo `lapsing` serves from a home under `scratch`, its link typed as the machine, with `to` as
/// the local end.
/// Every pipe is piped; stderr is read a line at a time on a thread, each line handed over as it comes.
fn forward(scratch: &Scratch, lapsing: &Lapsing, to: &str) -> (KillOnDrop, Stderr) {
    let hint = format!("{}={}", lapsing.served.key, lapsing.served.addr);
    let mut child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(scratch.0.join("holder"))
            .args(["forward", "--local", "--peer", &hint])
            .args([lapsing.link.as_str(), "echo", to])
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("forward spawns"),
    );
    let err_pipe = child.0.stderr.take().expect("piped stderr");
    let (sender, stderr) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(err_pipe);
        loop {
            // Preserve the newline too: a prefix or line iterator cannot prove the terminal bytes.
            let mut line = Vec::new();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => return,
                Ok(_) => {
                    if sender.send(Ok(line)).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    return;
                }
            }
        }
    });
    (child, stderr)
}

/// After the cut: `forward` exits nonzero by `lapses` plus a sweep and [`EXIT`], with one connection-lost
/// line on stderr and no reason for the cut.
fn ends_at_the_cut(mut forward: KillOnDrop, stderr: Stderr, lapses: Instant) {
    assert!(
        Instant::now() < lapses,
        "the echo came back before the link lapsed, so the cut below is the expiry's"
    );
    let status = exited_by(&mut forward.0, lapses + SWEEP + EXIT);
    assert_eq!(status.code(), Some(1), "a cut session exits 1: {status}");
    // The child has exited, so its stderr closes and the reader's channel with it. Nothing is filtered.
    let printed = stderr
        .iter()
        .collect::<std::io::Result<Vec<_>>>()
        .expect("read all stderr");
    assert_opaque_cut(&printed.concat());
}

fn assert_opaque_cut(printed: &[u8]) {
    assert_eq!(printed, b"error: connection lost\n", "the cut stays opaque");
}

#[test]
fn the_cut_assertion_rejects_appended_causes_secrets_and_extra_lines() {
    for printed in [
        b"error: connection lost: transport cause\n".as_slice(),
        b"error: connection lost: secret-sentinel\n",
        b"error: connection lost: expired\n",
        b"error: connection lost\nextra diagnostic\n",
        b"error: connection lost",
        b"error: connection lost\n\xff",
    ] {
        assert!(std::panic::catch_unwind(|| assert_opaque_cut(printed)).is_err());
    }
}

/// Wait for `child` to exit, polling, and fail once `deadline` passes.
fn exited_by(child: &mut Child, deadline: Instant) -> ExitStatus {
    loop {
        if let Some(status) = child.try_wait().expect("poll forward") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "forward is still running after the host cut its session"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn forward_exits_when_the_host_cuts_the_session_while_the_holder_writes_nothing() {
    let scratch = Scratch::new("expiry");
    let lapsing = lapsing(&scratch);
    let (mut forward, stderr) = forward(&scratch, &lapsing, "-");

    // One line there and back: the session is open. Then stdin stays open and silent, as a terminal is.
    let mut stdin = forward.0.stdin.take().expect("piped stdin");
    stdin.write_all(b"still here\n").expect("write to forward");
    stdin.flush().expect("flush to forward");
    let stdout: ChildStdout = forward.0.stdout.take().expect("piped stdout");
    assert_eq!(
        line_within(stdout, EXPIRES),
        "still here\n",
        "the link is admitted and the echo answers before it lapses"
    );

    ends_at_the_cut(forward, stderr, lapsing.lapses);
    drop(stdin);
}

/// `forward -` hands a service's bytes to stdout as they are: an escape sequence in the data is data, never
/// stripped as a screen line's style is where it does not show.
#[test]
fn forward_to_stdout_passes_escape_bytes_unchanged() {
    let scratch = Scratch::new("raw");
    let lapsing = lapsing(&scratch);
    let (mut forward, _stderr) = forward(&scratch, &lapsing, "-");

    let data = "\u{1b}[31mred\u{1b}[0m \u{1b}[2K\u{7}\r\n";
    let mut stdin = forward.0.stdin.take().expect("piped stdin");
    stdin.write_all(data.as_bytes()).expect("write to forward");
    stdin.flush().expect("flush to forward");
    let stdout: ChildStdout = forward.0.stdout.take().expect("piped stdout");
    assert_eq!(line_within(stdout, EXPIRES), data);
    drop(stdin);
}

/// A port stays up across the cut, and its next local connection ends the run: the lapsed link is
/// refused, exit 1, with the dial refusal as the run's last line, never `connection lost`.
#[test]
fn a_forward_ends_at_its_next_connection_once_its_link_lapses() {
    let scratch = Scratch::new("forward");
    let lapsing = lapsing(&scratch);
    // A port free a moment ago: the forward binds it once admitted.
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|free| free.local_addr())
        .expect("a free port")
        .port();
    let (mut forward, stderr) = forward(&scratch, &lapsing, &port.to_string());

    // The forward is admitted and listening once its line prints, on stderr. The machine prints whole,
    // since this home holds no name for it; the ctrl-c line is for a terminal, and stderr here is a pipe.
    let started = stderr
        .recv_timeout(EXPIRES)
        .expect("the start line arrives once admitted")
        .expect("read the start line");
    assert_eq!(
        started,
        format!(
            "Forwarding echo on {} to 127.0.0.1:{port}.\n",
            lapsing.served.key
        )
        .into_bytes(),
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

    // Past the lapse and the host's cut: the port still listens.
    assert!(
        Instant::now() < lapsing.lapses,
        "the echo came back before the link lapsed, so the refusal below is the expiry's"
    );
    std::thread::sleep(lapsing.lapses.saturating_duration_since(Instant::now()) + SWEEP);
    assert!(
        forward.0.try_wait().expect("poll forward").is_none(),
        "the forward ended at the cut"
    );
    drop(connection);

    let mut stdout: ChildStdout = forward.0.stdout.take().expect("piped stdout");
    let next = TcpStream::connect(("127.0.0.1", port)).expect("connect after the lapse");
    let status = exited_by(&mut forward.0, Instant::now() + EXIT);
    drop(next);
    assert_eq!(
        status.code(),
        Some(1),
        "a refused connection exits 1: {status}"
    );
    // The child has exited, so its stderr closes and the reader's channel with it.
    let printed = stderr
        .iter()
        .collect::<std::io::Result<Vec<_>>>()
        .expect("read all stderr")
        .concat();
    let printed = String::from_utf8(printed).expect("utf-8 stderr");
    assert!(
        printed.ends_with(
            "error: the link's machine refused echo\n  It does not serve echo, or it does not accept \
             this link.\n"
        ),
        "the run ends with the dial refusal: {printed:?}"
    );
    let mut out = String::new();
    stdout
        .read_to_string(&mut out)
        .expect("read the exited forward's stdout");
    assert_eq!(out, "", "a port forward's stdout carries nothing");
}
