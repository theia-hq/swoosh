// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! A plain `serve` holds `<home>/key.lock` shared, end to end: while the compiled binary serves a scratch
//! home, `leave --new-key` on that home is refused before it asks for or writes anything. Only the exact
//! spawned pid is ever signalled.

use core::time::Duration;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

/// A spawned child killed and reaped on drop, so a failing test never orphans it.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch base removed on drop.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_key_is_never_replaced_under_a_running_serve() {
    let scratch = Scratch(std::env::temp_dir().join(format!("sw-lock-{}", std::process::id())));
    let home = scratch.0.join("home");
    std::fs::create_dir_all(&home).expect("scratch home");

    // Not `--resident`: the plain serve, which answers no control socket, is the case a probe missed.
    let mut serve = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(&home)
            .args(["serve", "--transport", "quirk+noise"])
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
    while !String::from_utf8_lossy(&seen).contains("swoosh ready") {
        assert!(Instant::now() < deadline, "serve never became ready");
        if stdout.read(&mut byte).expect("read serve's banner") == 0 {
            panic!("serve exited before it was ready");
        }
        seen.push(byte[0]);
    }

    // The lock is the home's `key.lock`, not the runtime directory's `control.lock`: an exclusive take on
    // it fails while the node serves.
    let lock = std::fs::File::open(home.join("key.lock")).expect("serve made <home>/key.lock");
    // SAFETY: `lock` owns a valid fd for the whole call; `flock` only attaches an advisory lock, released
    // when `lock` drops. `LOCK_NB` makes a held lock an error rather than a wait.
    let taken = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    assert!(!taken, "serve holds <home>/key.lock");
    drop(lock);

    // Nothing else stops it: the home trusts no root, so without the lock `leave --new-key` would replace
    // the key.
    let key_before = std::fs::read(home.join("key")).expect("serve made <home>/key");
    let leave = Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .arg("--home")
        .arg(&home)
        .args(["leave", "--new-key"])
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .output()
        .expect("leave runs");
    let stderr = String::from_utf8_lossy(&leave.stderr);
    assert!(!leave.status.success());
    assert!(
        stderr.contains("stop swoosh serve first"),
        "the serving node's lock refuses the new key: {stderr}"
    );
    assert!(leave.stdout.is_empty(), "no new key is printed");
    assert_eq!(
        std::fs::read(home.join("key")).expect("the key is still there"),
        key_before,
        "the key serve runs as is unchanged"
    );
}
