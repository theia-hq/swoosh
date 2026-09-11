// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! S4 end-to-end: the bare control verbs against a real `serve --resident` child.
//!
//! One child-process run proves the whole bare-verb seam: spawn the compiled binary as a
//! foreground resident under a scratch home, wait for its readiness banner, drive `service ls`,
//! `status`, and `stop` over the real control socket, then assert the resident's clean exit, the
//! unlinked socket, and the released lock. Only the exact spawned pid is ever signalled.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::io::{BufRead as _, BufReader};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use swoosh::home::Home;

/// Serializes scratch base names within this test process; the pid keeps two concurrent runs apart.
static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A scratch dir for the spawned-binary run: a home, a 0700 `XDG_RUNTIME_DIR` stand-in, and one
/// owned base. Drop removes exactly the base it created.
struct Scratch {
    base: PathBuf,
    home_dir: PathBuf,
    xdg: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("sw4-{tag}-{}-{seq}", std::process::id()));
        let home_dir = base.join("home");
        let xdg = base.join("xdg");
        std::fs::create_dir_all(&home_dir).expect("scratch home");
        std::fs::create_dir_all(&xdg).expect("scratch xdg");
        // 0700 on the runtime-root stand-in: the resident chain verifier refuses a looser base.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).expect("0700 base");
        std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o700)).expect("0700 xdg");
        Self {
            base,
            home_dir,
            xdg,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// A spawned child killed and reaped on drop, so a panicking test never orphans it. Skips the kill
/// once the child is already reaped: a recycled pid must never be signalled.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// The per-home runtime leaf the resident resolves for this scratch: on Linux `<xdg>/swoosh/<key>`
/// mirrors `runtime_root()`; on macOS the root ignores `XDG_RUNTIME_DIR` and comes from confstr.
fn runtime_leaf(home: &Home, xdg: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let _ = xdg;
        home.runtime_dir()
            .expect("the per-user runtime root resolves")
    }
    #[cfg(not(target_os = "macos"))]
    {
        home.runtime_leaf(&xdg.join("swoosh"))
    }
}

/// Run the compiled `swoosh` binary under this scratch's home and runtime root, capturing output.
fn swoosh(scratch: &Scratch, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .args(["--home", scratch.home_dir.to_str().expect("utf-8 home")])
        .args(args)
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME")
        .env_remove("SWOOSH_KEY")
        .output()
        .expect("the swoosh binary runs")
}

/// Wait for a child to exit under a deadline, polling so a hung run fails the test instead of
/// blocking CI; the caller's `KillOnDrop` still reaps on the panic path.
fn wait_for_exit(child: &mut Child, deadline: Duration) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll the child") {
            return status;
        }
        assert!(
            started.elapsed() < deadline,
            "the child did not exit within {deadline:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Drain a child pipe into a shared buffer on a thread, so a chatty child can never fill the pipe
/// and wedge while the test waits on it.
fn drain(
    pipe: impl std::io::Read + Send + 'static,
    sink: Arc<Mutex<String>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            sink.lock().expect("the capture lock").push_str(&line);
            line.clear();
        }
    })
}

/// The full bare-verb loop against one real resident: banner, `service ls`, `status`, `stop`, the
/// resident's clean local exit, the unlinked socket, the released lock, and the post-stop teaching
/// error. A stop through any other path would leave the resident running and fail the exit wait.
#[test]
fn bare_stop_stops_the_resident() {
    let scratch = Scratch::new("stop");
    let home = Home::resolve(Some(scratch.home_dir.clone())).expect("the scratch home resolves");
    let leaf = runtime_leaf(&home, &scratch.xdg);
    let socket = leaf.join("control.sock");

    let mut command = Command::new(env!("CARGO_BIN_EXE_swoosh"));
    command
        .arg("--home")
        .arg(&scratch.home_dir)
        .args(["serve", "--resident"])
        .env("XDG_RUNTIME_DIR", &scratch.xdg)
        .env_remove("SWOOSH_HOME")
        .env_remove("SWOOSH_KEY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = KillOnDrop(command.spawn().expect("the resident serve spawns"));
    let pid = child.0.id();
    let stdout = Arc::new(Mutex::new(String::new()));
    let stderr = Arc::new(Mutex::new(String::new()));
    let out_reader = drain(
        child.0.stdout.take().expect("piped stdout"),
        Arc::clone(&stdout),
    );
    let err_reader = drain(
        child.0.stderr.take().expect("piped stderr"),
        Arc::clone(&stderr),
    );

    // Wait for the readiness banner (the resident arm binds its socket before printing it), bounded.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if stdout
            .lock()
            .expect("the capture lock")
            .contains("swoosh ready")
        {
            break;
        }
        if let Some(status) = child.0.try_wait().expect("poll the resident") {
            panic!(
                "the resident exited before its banner: {status}\n{}",
                stderr.lock().expect("the capture lock")
            );
        }
        assert!(
            Instant::now() < deadline,
            "the resident never printed its banner"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(socket.exists(), "the resident binds its control socket");

    // Bare `service ls` reads the live menu over the socket, with the disabled-state column.
    let ls = swoosh(&scratch, &["service", "ls"]);
    let ls_out = String::from_utf8_lossy(&ls.stdout).into_owned();
    assert!(
        ls.status.success(),
        "bare service ls exits 0: {}\n{ls_out}",
        String::from_utf8_lossy(&ls.stderr)
    );
    assert!(
        ls_out.contains("SERVICE") && ls_out.contains("STATE"),
        "{ls_out}"
    );
    assert!(
        ls_out
            .lines()
            .any(|line| line.starts_with("ping") && line.contains("on")),
        "the live table marks a served service on: {ls_out}"
    );

    // Bare `status` is the self-query: the public node shape, never key material.
    let status = swoosh(&scratch, &["status"]);
    let status_out = String::from_utf8_lossy(&status.stdout).into_owned();
    assert!(
        status.status.success(),
        "bare status exits 0: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(
        status_out.starts_with("node "),
        "the node id leads: {status_out}"
    );
    assert!(status_out.contains("up "), "{status_out}");
    assert!(
        status_out.contains("SERVICE") && status_out.contains("STATE"),
        "{status_out}"
    );
    assert!(status_out.contains("warm"), "{status_out}");

    // Bare `stop` stops it, naming the pid the resident recorded in its lock.
    let stop = swoosh(&scratch, &["stop"]);
    assert!(
        stop.status.success(),
        "bare stop exits 0: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&stop.stdout).trim_end(),
        format!("stopped your node (pid {pid})."),
        "the stop confirms the serving pid, no double-fork"
    );

    // The resident exits 0 on the socket stop, prints its local stop line, and unlinks the socket.
    let status = wait_for_exit(&mut child.0, Duration::from_secs(30));
    assert!(
        status.success(),
        "a socket stop exits the resident 0: {status}"
    );
    out_reader.join().expect("the stdout reader joins");
    err_reader.join().expect("the stderr reader joins");
    let resident_out = stdout.lock().expect("the capture lock").clone();
    assert!(
        resident_out.contains("node stopped (local request)."),
        "the resident classifies the socket stop as its local end: {resident_out}"
    );
    assert!(!socket.exists(), "the released socket is unlinked");

    // The flock is released: a fresh exclusive lock on the lock file succeeds.
    let lock = std::fs::File::open(leaf.join("control.lock")).expect("the lock file exists");
    let locked = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(locked, 0, "the resident's flock is released on exit");
    let _ = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };

    // With no resident, the bare stop teaches the fix and exits non-zero.
    let again = swoosh(&scratch, &["stop"]);
    assert!(!again.status.success(), "no resident exits non-zero");
    let again_err = String::from_utf8_lossy(&again.stderr);
    assert!(
        again_err.contains("start one with `swoosh serve --resident`"),
        "the error names the fix: {again_err}"
    );
}
