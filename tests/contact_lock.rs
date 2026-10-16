// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Each `contact` edit holds `<home>/home.lock` from its read of the book to its save, end to end: while
//! the lock a fold writes the book under is held, the compiled binary's `contact add` and `rm`
//! each wait, and once it is released each lands.

use core::time::Duration;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
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

/// `swoosh --home <home> contact <args>`, spawned with nothing to read and nothing shown.
fn contact(home: &Path, args: &[&str]) -> KillOnDrop {
    KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_swoosh"))
            .arg("--home")
            .arg(home)
            .arg("contact")
            .args(args)
            .env_remove("SWOOSH_HOME")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("contact spawns"),
    )
}

#[test]
fn a_contact_edit_waits_for_home_lock() {
    let scratch =
        Scratch(std::env::temp_dir().join(format!("sw-contact-lock-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&scratch.0);
    // A person is saved with a root, typed as `root:` prints it.
    let key = format!("root:{}", bifrost::NodeId::from_ed25519_secret(&[6u8; 32]));

    // The same edit on a home nobody locks finishes by itself. It also pays the first start of a freshly
    // built binary, which on some systems takes seconds, so the timed edits below measure only the wait.
    let free = scratch.0.join("free");
    std::fs::create_dir_all(&free).expect("scratch home");
    let status = contact(&free, &["add", "alice", &key])
        .0
        .wait()
        .expect("contact add exits");
    assert!(status.success(), "contact add lands on an unlocked home");

    for (verb, args) in [
        ("add", ["add", "alice", key.as_str()].as_slice()),
        ("rm", ["rm", "alice"].as_slice()),
    ] {
        let home = scratch.0.join(verb);
        std::fs::create_dir_all(&home).expect("scratch home");

        // Hold the lock the way a fold does.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(home.join("home.lock"))
            .expect("open <home>/home.lock");
        // SAFETY: `lock` owns a valid fd for the whole call; `flock` only attaches an advisory lock,
        // released when `lock` drops. `LOCK_NB` makes a held lock an error rather than a wait.
        let taken = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        assert!(taken, "the test holds <home>/home.lock");

        let mut edit = contact(&home, args);
        // An edit that takes no lock finishes well inside this; one that takes it is still waiting.
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            let exited = edit.0.try_wait().expect("poll the edit");
            assert!(
                exited.is_none(),
                "contact {verb} finished while home.lock was held: {exited:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !home.join("contacts.toml").exists(),
            "contact {verb} writes nothing while home.lock is held"
        );

        drop(lock);
        let status = edit.0.wait().expect("the edit exits");
        assert!(
            status.success(),
            "contact {verb} lands once the lock is free"
        );
        if verb != "rm" {
            let book = std::fs::read_to_string(home.join("contacts.toml")).expect("read the book");
            assert!(book.contains("alice"), "contact {verb} saved alice: {book}");
        }
    }
}
