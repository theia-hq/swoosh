// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `reach` ends when the host ends its session: the compiled binary serves an echo over iroh with `--local` on
//! loopback, and the compiled binary reaches it as `swoosh ssh`'s `ProxyCommand` does, stdin held open.
//!
//! The holder writes one line, reads it back, then writes nothing. The link it presents expires, the host
//! cuts the session within a sweep, and `reach` must exit then, not on the holder's next keystroke.

use core::time::Duration;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
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

/// Read one line from `reach`'s stdout, failing past `deadline` rather than hanging the run.
fn echoed(stdout: ChildStdout, deadline: Duration) -> String {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = sender.send(line);
    });
    receiver
        .recv_timeout(deadline)
        .expect("the echo answers within the deadline")
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
    let (host, holder) = (scratch.0.join("host"), scratch.0.join("holder"));
    let served = serve(&host, &["echo=echo:"]);
    let expires = format!("{}s", EXPIRES.as_secs());
    let link = swoosh(&host, &["grant", "issue", "echo", "--expires", &expires]);
    let lapses = Instant::now() + EXPIRES;
    // A running `serve` re-reads its ledger at most once per debounce.
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(100));

    let hint = format!("{}={}", served.key, served.addr);
    let mut reach = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(&holder)
            .args(["reach", "--local", "--peer", &hint])
            .args(["--present", link.trim(), &served.key, "echo"])
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("reach spawns"),
    );
    let mut err_pipe = reach.0.stderr.take().expect("piped stderr");
    let stderr = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err_pipe.read_to_string(&mut text);
        text
    });

    // One line there and back: the session is open. Then stdin stays open and silent, as a terminal is.
    let mut stdin = reach.0.stdin.take().expect("piped stdin");
    stdin.write_all(b"still here\n").expect("write to reach");
    stdin.flush().expect("flush to reach");
    let stdout = reach.0.stdout.take().expect("piped stdout");
    assert_eq!(
        echoed(stdout, EXPIRES),
        "still here\n",
        "the link is admitted and the echo answers before it lapses"
    );
    assert!(
        Instant::now() < lapses,
        "the echo came back before the link lapsed, so the cut below is the expiry's"
    );

    let status = exited_by(&mut reach.0, lapses + SWEEP + EXIT);
    drop(stdin);
    assert!(!status.success(), "a cut session exits nonzero: {status}");
    let printed = stderr.join().expect("the stderr reader");
    assert!(
        printed.starts_with("error: connection lost") && printed.lines().count() == 1,
        "one connection-lost line, with no reason for the cut: {printed:?}"
    );
}
