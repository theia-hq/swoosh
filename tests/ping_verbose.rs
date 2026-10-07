// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `ping -v` end to end: the compiled binary serves `ping` over `quirk+noise` on loopback, and the compiled
//! binary pings it with `-v`, presenting a link the host issued.
//!
//! What is proven is the wiring, not the helper: `-v` hands the session's own path stream to the probe run,
//! so the first live line is the path in force, and the probe lines carry no path of their own. quirk's
//! path never moves (its stream says `direct` once and ends), so the run also proves an ended stream lets
//! every probe finish.

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
    child: Child,
    key: String,
    addr: String,
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
    use std::os::unix::fs::PermissionsExt as _;

    let runtime = home.join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(["serve", "--transport", "quirk+noise", "--verbose"])
        .args(entries)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve spawns");
    let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
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
        child,
        key: key.unwrap(),
        addr: addr.unwrap(),
    }
}

/// Run the binary on `home` with `args` and wait for it, failing past [`HUNG`] rather than hanging the run.
/// Its output is a few lines, well inside a pipe's buffer, so polling for the exit cannot block the child.
fn swoosh(home: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
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
/// path, over a transport whose path stream says `direct` once and ends.
#[test]
fn ping_v_prints_the_sessions_path_before_its_probes() {
    let scratch = Scratch::new("path");
    let host = scratch.0.join("host");
    let served = serve(&host, &["ping"]);
    let link = stdout(&host, &["grant", "issue", "ping"]);
    // A running `serve` re-reads its ledger at most once per debounce.
    std::thread::sleep(nauthy::STAT_DEBOUNCE + Duration::from_millis(100));

    let hint = format!("{}={}", served.key, served.addr);
    let printed = stdout(
        &scratch.0.join("holder"),
        &[
            "ping",
            "--transport",
            "quirk+noise",
            "--peer",
            &hint,
            "--present",
            link.trim(),
            "-v",
            "-c",
            "2",
            "-i",
            "0.1",
            &served.key,
        ],
    );
    let lines: Vec<&str> = printed.lines().collect();
    // The device block's head is `<label> via quirk+noise` alone: the label the live lines must carry.
    let head = lines
        .iter()
        .find(|line| line.ends_with(" via quirk+noise"))
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
