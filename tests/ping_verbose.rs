// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `ping -v` end to end: the compiled binary serves `ping` over iroh with `--local` on loopback, and the compiled
//! binary pings it with `-v`, presenting a link the host issued.
//!
//! What is proven is the wiring, not the helper: `-v` hands the session's own path stream to the probe run,
//! so the first live line is the path in force, and the probe lines carry no path of their own. On
//! loopback with no relay, iroh's path is direct from the first probe and never moves, so it prints once.

use core::time::Duration;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Instant;

/// How long the `ping` run may take before the test calls it hung, with room for a slow machine.
const HUNG: Duration = Duration::from_secs(60);

/// A scratch dir holding the host's and the holder's homes, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sw-pingv-{tag}-{}", std::process::id()));
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

/// A running `swoosh serve`, killed and reaped on drop, so a failing test never orphans it.
struct Served {
    _child: KillOnDrop,
    key: String,
    addr: String,
}

/// Only this test's owned child is killed and reaped, including readiness failures.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Serve `home` with `entries` over iroh with `--local`, and wait for its banner: the key it answers at and its
/// loopback address, from its `reach` block.
fn serve(home: &Path, entries: &[&str]) -> Served {
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = home.join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(["serve", "--local"])
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
    let (key, addr) =
        swoosh::testkit::banner::read(lines, Instant::now() + Duration::from_secs(60));
    Served {
        _child: child,
        key,
        addr,
    }
}

/// Run the binary on `home` with `args` and wait for it, failing past [`HUNG`] rather than hanging the run.
/// Its output is a few lines, well inside a pipe's buffer, so polling for the exit cannot block the child.
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

/// Run the binary on `home` with `args`, and return its stdout, failing on a refusal.
fn stdout(home: &Path, args: &[&str]) -> String {
    let output = swoosh(home, args);
    assert!(
        output.status.success(),
        "`swoosh {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// `ping -v` prints the path the session reports before the first probe, then the probe lines without a
/// path, over a path that stays `direct` for the whole run.
#[test]
fn ping_v_prints_the_sessions_path_before_its_probes() {
    let scratch = Scratch::new("path");
    let host = scratch.0.join("host");
    let served = serve(&host, &["ping"]);
    let link = stdout(&host, &["share", "ping", "anyone", "--once"]);
    // A running `serve` re-reads its ledger at most once per debounce.
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(100));

    let hint = format!("{}={}", served.key, served.addr);
    let printed = stdout(
        &scratch.0.join("holder"),
        &[
            "ping",
            "--local",
            "--peer",
            &hint,
            "-v",
            "-c",
            "2",
            "-i",
            "0.1",
            // The link is given where the machine goes: it names the host and carries the grant.
            link.trim(),
        ],
    );
    let lines: Vec<&str> = printed.lines().collect();
    // The device block's head is `<label>` alone, unindented: the label the live lines must carry.
    let head = lines
        .iter()
        .find(|line| !line.starts_with(' ') && !line.contains(", "))
        .unwrap_or_else(|| panic!("no device block: {printed}"));
    assert_eq!(
        lines.first().copied(),
        Some(format!("{head}, path: direct").as_str()),
        "the first live line is the path in force: {printed}"
    );
    for seq in 0..2 {
        let probe = lines
            .iter()
            .find(|line| line.starts_with(&format!("{head}, seq {seq} ")))
            .unwrap_or_else(|| panic!("no line for probe {seq}: {printed}"));
        assert!(
            !probe.contains("path:"),
            "a probe line carries no path: {probe}"
        );
    }
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with(&format!("{head}, path:")))
            .count(),
        1,
        "a path that never moves prints once: {printed}"
    );
}
