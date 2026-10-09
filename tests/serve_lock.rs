// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! A `serve` holds `<home>/serve.lock` for its whole run, end to end: while the compiled binary serves a
//! scratch home, a second `serve` of it, `leave --new-key` and a `join` beside a `serve --admit` are each
//! refused before they write anything. Only the exact spawned pid is ever signalled.

use core::time::Duration;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Instant, SystemTime};

use bifrost::NodeId;
use swoosh::invite::Invite;
use swoosh::testkit::{TestNode, TestRoot};

/// A spawned child killed and reaped on drop, so a failing test never orphans it.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch base removed on drop: a home and a runtime directory under it.
struct Scratch {
    base: PathBuf,
    home: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("sw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        std::fs::create_dir_all(&home).expect("scratch home");
        Self { base, home }
    }

    /// A private runtime directory named `name`, for `XDG_RUNTIME_DIR`.
    fn run(&self, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let run = self.base.join(name);
        std::fs::create_dir_all(&run).expect("scratch runtime dir");
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("0700 run");
        run
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// `swoosh --home <home> <args>`, run to its end with nothing to read.
fn swoosh(home: &Path, run: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env("XDG_RUNTIME_DIR", run)
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .expect("swoosh runs")
}

/// Start `swoosh serve <args>` on `home`, and wait for its banner.
fn serve(home: &Path, run: &Path, args: &[&str]) -> KillOnDrop {
    let mut serve = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(home)
            .args(["serve", "--transport", "quirk+noise"])
            .args(args)
            .env("XDG_RUNTIME_DIR", run)
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("serve spawns"),
    );
    let mut stdout = serve.0.stdout.take().expect("piped stdout");
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut byte = [0u8; 1];
    while !String::from_utf8_lossy(&seen).contains("ctrl-c to stop") {
        assert!(Instant::now() < deadline, "serve never became ready");
        if stdout.read(&mut byte).expect("read serve's banner") == 0 {
            panic!("serve exited before it was ready");
        }
        seen.push(byte[0]);
    }
    serve
}

/// Whether something holds `path` exclusive now: an exclusive take of it fails.
fn held(path: &Path) -> bool {
    let lock = std::fs::File::open(path).expect("the lock file is there");
    // SAFETY: `lock` owns a valid fd for the whole call; `flock` only attaches an advisory lock, released
    // when `lock` drops. `LOCK_NB` makes a held lock an error rather than a wait.
    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) != 0 }
}

/// What a file holds, or `None` when it is not there.
fn read(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

#[test]
fn a_serve_holds_serve_lock_for_its_run() {
    let scratch = Scratch::new("serve-lock");
    let first = serve(&scratch.home, &scratch.run("run"), &[]);

    // The lock is the home's own `serve.lock`, recording the serve's pid.
    let lock = scratch.home.join("serve.lock");
    assert!(held(&lock), "serve holds <home>/serve.lock");
    let recorded = String::from_utf8(read(&lock).expect("serve.lock")).expect("text");
    assert_eq!(
        recorded.lines().next(),
        Some(first.0.id().to_string().as_str()),
        "serve.lock records the running serve's pid"
    );

    // A second serve of the home refuses, even one that resolves another runtime directory.
    let second = swoosh(
        &scratch.home,
        &scratch.run("elsewhere"),
        &["serve", "--transport", "quirk+noise"],
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(!second.status.success(), "a second serve refuses: {stderr}");
    assert!(
        stderr.contains(&format!(
            "swoosh serve is already running here (pid {}",
            first.0.id()
        )),
        "{stderr}"
    );
}

#[test]
fn leave_new_key_refuses_while_serve_runs() {
    let scratch = Scratch::new("serve-new-key");
    let run = scratch.run("run");
    let _serve = serve(&scratch.home, &run, &[]);

    // Nothing else stops it: the home trusts no root, so without the lock `leave --new-key` would replace
    // the key.
    let key = scratch.home.join("machine").join("key");
    let key_before = read(&key).expect("serve made <home>/machine/key");
    let leave = swoosh(&scratch.home, &run, &["leave", "--new-key"]);
    let stderr = String::from_utf8_lossy(&leave.stderr);
    assert!(!leave.status.success());
    assert_eq!(
        stderr.trim_end(),
        "error: swoosh serve is running; stop it first: swoosh stop",
        "the serving node's lock refuses the new key"
    );
    assert!(leave.stdout.is_empty(), "no new key is printed");
    assert_eq!(
        read(&key),
        Some(key_before),
        "the key serve runs as is unchanged"
    );
}

#[test]
fn join_refuses_while_an_admitting_serve_runs() {
    let scratch = Scratch::new("serve-admit-join");
    let run = scratch.run("run");
    // This machine's key, made before the serve, so an invite can be bound to it.
    let status = swoosh(&scratch.home, &run, &["leave", "--new-key"]);
    assert!(status.status.success());
    let key: NodeId = String::from_utf8(status.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let admitted = TestRoot::seeded(0x31).node_id();
    let _serve = serve(
        &scratch.home,
        &run,
        &["--admit", &format!("root:{admitted}")],
    );

    let root = TestRoot::seeded(0x21);
    let standing = root
        .device_badge(
            key,
            SystemTime::now() + Duration::from_secs(90 * 24 * 60 * 60),
        )
        .unwrap();
    let invite = Invite::bound(
        TestNode::seeded(0x41).node_id(),
        "laptop".parse().unwrap(),
        standing,
    );
    let join = swoosh(&scratch.home, &run, &["join", &invite.to_string()]);
    let stderr = String::from_utf8_lossy(&join.stderr);
    assert!(!join.status.success(), "refused: {stderr}");
    assert_eq!(
        stderr.trim_end(),
        "error: swoosh serve is running; stop it first: swoosh stop"
    );
    for file in ["key.cert", "root.pub", "invited-by"] {
        assert!(!scratch.home.join(file).exists(), "{file} is not written");
    }
}
