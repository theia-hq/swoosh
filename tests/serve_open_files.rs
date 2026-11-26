// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Only Linux shows another process's limit, in `/proc`; macOS shows none, and a `serve` starts no child to
// read it from.
#![cfg(target_os = "linux")]

//! A `serve` raises its own open-file limit as it starts, so an Open, which holds two descriptors for its
//! life, is not refused for want of one at the 256 a macOS process starts with. The compiled binary is
//! started at a low soft limit and the limit it runs at is read back from `/proc`. Only the exact spawned
//! pid is ever signalled.

use core::time::Duration;
use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use swoosh::serve::OPEN_FILES;

/// The soft limit the serve starts at: macOS's own default, below what a serve asks for.
const LOW: libc::rlim_t = 256;

/// A spawned child killed and reaped on drop, so a failing test never orphans it.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch base removed on drop: a home and a private runtime directory.
struct Scratch {
    base: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let base = std::env::temp_dir().join(format!("sw-nofile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        for dir in ["home", "run"] {
            std::fs::create_dir_all(base.join(dir)).expect("scratch dir");
        }
        std::fs::set_permissions(base.join("run"), std::fs::Permissions::from_mode(0o700))
            .expect("0700 run");
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

/// Start `swoosh serve --local` on the scratch home at the [`LOW`] soft limit, and wait for its banner.
fn serve(scratch: &Scratch) -> KillOnDrop {
    use std::os::unix::process::CommandExt as _;

    let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
    command
        .arg("--home")
        .arg(scratch.path("home"))
        .args(["serve", "--local"])
        .env("XDG_RUNTIME_DIR", scratch.path("run"))
        .env_remove("SWOOSH_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
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
    while !String::from_utf8_lossy(&seen).contains("swoosh is serving") {
        assert!(Instant::now() < deadline, "serve never became ready");
        if stdout.read(&mut byte).expect("read serve's banner") == 0 {
            panic!("serve exited before it was ready");
        }
        seen.push(byte[0]);
    }
    serve
}

/// The soft open-file limit the running serve at `pid` holds.
fn soft_limit(pid: u32) -> libc::rlim_t {
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

/// The soft limit a serve raises itself to.
fn wanted() -> libc::rlim_t {
    OPEN_FILES.min(hard_limit())
}

#[test]
fn serve_starts_at_a_raised_open_file_limit() {
    let scratch = Scratch::new();
    assert!(wanted() > LOW, "the hard limit leaves nothing to raise");
    let serve = serve(&scratch);
    assert_eq!(soft_limit(serve.0.id()), wanted());
}
