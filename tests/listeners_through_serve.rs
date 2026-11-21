// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `forward <port>` and `proxy` take the path through a running `swoosh serve`: the compiled binary serves a
//! home, and the compiled binary runs each listener there with a reach flag that only the path through
//! `serve` refuses, so its refusal shows which path the verb took.

use core::time::Duration;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Instant;

/// How long a run may take before the test calls it hung, with room for a slow machine.
const HUNG: Duration = Duration::from_secs(60);

/// A scratch home, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sw-listen-{tag}-{}", std::process::id()));
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

/// Only this test's owned child is killed and reaped, including readiness failures.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Serve `home` over iroh with `--local`, and wait for its banner's key line: its control socket answers
/// by then.
fn serve(home: &Path) -> KillOnDrop {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = home.join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(["serve", "--local", "ping"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve spawns");
    let mut child = KillOnDrop(child);
    let stdout = child.0.stdout.take().expect("piped stdout");
    // Bound the wait; the pipe reader may block, never the deadline owner.
    let (sender, lines) = std::sync::mpsc::sync_channel(16);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            // Keep draining after readiness, without closing the child's output pipe early.
            let _ = sender.send(line);
        }
    });
    let deadline = Instant::now() + HUNG;
    loop {
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("serve never printed its banner before the deadline")
            .expect("read the banner");
        if line.starts_with("  key  ") {
            return child;
        }
    }
}

/// Run the binary on `home` with `args` and wait for it, failing past [`HUNG`] rather than hanging.
fn swoosh(home: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    let deadline = Instant::now() + HUNG;
    while child.try_wait().expect("poll the binary").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "`swoosh {}` was still running after {HUNG:?}",
                args.join(" ")
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("the binary finishes")
}

/// With `serve` running, `forward <port>` and `proxy` take its path: a `--relay` set for a bind they do
/// not make is refused there, exit 1, before anything listens.
#[test]
fn listeners_take_the_path_through_a_running_serve() {
    let scratch = Scratch::new("route");
    let _served = serve(&scratch.0);
    let other = bifrost::NodeId::from_ed25519_secret(&[0x11; 32]).to_string();
    // A free port: the refusal comes before any bind, and a run on the wrong path binds nothing in use.
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    refused_through_serve(&scratch.0, &["forward", &other, "ssh", &port]);
    refused_through_serve(&scratch.0, &["proxy", &other, "http://example.com/x"]);
}

/// Run `verb` on `home` with a `--relay` for a bind it does not make: through the running `serve` that
/// is refused, exit 1, before anything listens.
fn refused_through_serve(home: &Path, verb: &[&str]) {
    let args: Vec<&str> = verb
        .iter()
        .copied()
        .chain(["--relay", "https://relay.example"])
        .collect();
    let output = swoosh(home, &args);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{verb:?}: {stderr}");
    assert!(
        stderr.starts_with(
            "error: --relay or SWOOSH_RELAY does not apply while swoosh serve runs here"
        ),
        "{verb:?}: {stderr}"
    );
    assert!(output.stdout.is_empty(), "{verb:?}: nothing listened");
}
