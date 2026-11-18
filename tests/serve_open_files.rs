// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! A `serve` raises its own open-file limit as it starts, so an Open, which holds two descriptors for its
//! life, is not refused for want of one at the 256 a macOS process starts with. The compiled binary is
//! started at a low soft limit and the limit it runs at is read back: on Linux from `/proc`, and on macOS,
//! which shows no other process's limit, from a child it starts after the raise, the `brew --prefix` a
//! terminal `serve` asks when it names how to keep serving after a reboot, swapped for a stand-in on
//! PATH. Only the exact spawned pid is ever signalled.

use core::time::Duration;
use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use swoosh::serve::OPEN_FILES;

/// The soft limit the serve starts at: macOS's own default, below what a serve asks for.
const LOW: libc::rlim_t = 256;

/// The stand-in `brew`: record the soft open-file limit it inherited, and say this is no brew install.
const FAKE_BREW: &str = r#"#!/bin/sh
ulimit -n > "$SWOOSH_TEST_LIMIT_LOG"
exit 1
"#;

/// A spawned child killed and reaped on drop, so a failing test never orphans it.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch base removed on drop: a home, a private runtime directory, a bin directory and a log.
struct Scratch {
    base: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let base = std::env::temp_dir().join(format!("sw-nofile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        for dir in ["home", "run", "bin"] {
            std::fs::create_dir_all(base.join(dir)).expect("scratch dir");
        }
        std::fs::set_permissions(base.join("run"), std::fs::Permissions::from_mode(0o700))
            .expect("0700 run");
        let brew = base.join("bin").join("brew");
        std::fs::write(&brew, FAKE_BREW).expect("stand-in brew");
        std::fs::set_permissions(&brew, std::fs::Permissions::from_mode(0o755)).expect("0755 brew");
        Self { base }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// This process's hard open-file limit, which the serve inherits.
fn hard_limit() -> libc::rlim_t {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable `rlimit` for the call to fill.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit.rlim_max
}

/// A pseudo-terminal: the controller end, held open, and the end the serve takes as its stderr, so it
/// reads as started from a terminal.
fn terminal() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    use std::os::fd::FromRawFd as _;

    let (mut controller, mut follower) = (0, 0);
    // SAFETY: both pointers name live `c_int`s for the call to fill; the name, settings and size are
    // optional and left null.
    let opened = unsafe {
        libc::openpty(
            &mut controller,
            &mut follower,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(opened, 0, "openpty");
    // SAFETY: `openpty` succeeded, so both are open descriptors this test now owns alone.
    unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(controller),
            std::os::fd::OwnedFd::from_raw_fd(follower),
        )
    }
}

/// Start `swoosh serve --local` on the scratch home at the [`LOW`] soft limit, with stderr on a
/// terminal, no service manager in its environment and the stand-in `brew` first on PATH, and wait for
/// its banner.
fn serve(scratch: &Scratch, stderr: std::os::fd::OwnedFd) -> KillOnDrop {
    use std::os::unix::process::CommandExt as _;

    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![scratch.path("bin")];
    paths.extend(std::env::split_paths(&path));
    let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
    command
        .arg("--home")
        .arg(scratch.path("home"))
        .args(["serve", "--local"])
        .env("XDG_RUNTIME_DIR", scratch.path("run"))
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("SWOOSH_TEST_LIMIT_LOG", scratch.path("limit"))
        .env_remove("SWOOSH_HOME")
        .env_remove("INVOCATION_ID")
        .env_remove("JOURNAL_STREAM")
        .env_remove("XPC_SERVICE_NAME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr));
    let hard = hard_limit();
    // SAFETY: runs in the forked child before exec and calls only `setrlimit`, which is async-signal-safe,
    // on a value built before the fork.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: LOW,
                rlim_max: hard,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut serve = KillOnDrop(command.spawn().expect("serve spawns"));
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

/// The soft open-file limit the running serve at `pid` holds.
#[cfg(target_os = "linux")]
fn soft_limit(_scratch: &Scratch, pid: u32) -> libc::rlim_t {
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).expect("/proc limits");
    let soft = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))
        .expect("an open-files line")
        .split_whitespace()
        .next()
        .expect("a soft limit");
    soft.parse().expect("a number")
}

/// The soft open-file limit the running serve passed to the `brew` it started after its banner's checks.
#[cfg(not(target_os = "linux"))]
fn soft_limit(scratch: &Scratch, _pid: u32) -> libc::rlim_t {
    let read = std::fs::read_to_string(scratch.path("limit")).expect("serve ran the stand-in brew");
    read.trim().parse().expect("a number")
}

/// The soft limit a serve raises itself to.
fn wanted() -> libc::rlim_t {
    OPEN_FILES.min(hard_limit())
}

#[test]
fn serve_starts_at_a_raised_open_file_limit() {
    let scratch = Scratch::new();
    assert!(wanted() > LOW, "the hard limit leaves nothing to raise");
    let (_controller, follower) = terminal();
    let serve = serve(&scratch, follower);
    assert_eq!(soft_limit(&scratch, serve.0.id()), wanted());
}
