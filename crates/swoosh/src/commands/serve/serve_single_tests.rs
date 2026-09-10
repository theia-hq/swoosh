//! S2 tests: flock exclusion across processes, stale rebind, the live-probe refusal, per-home split,
//! and graceful release.
//!
//! The cross-process cases re-invoke THIS test binary as a child (`single_lock_child_holds_the_home`)
//! that acquires the home and records its pid; the parent asserts the truth it reads and kills only
//! the exact pid it spawned. The in-process cases thread their own per-test runtime root into
//! `acquire`; nothing here mutates a process-global (`XDG_RUNTIME_DIR` is never touched).

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::{SingleError, acquire};
use crate::home::Home;

/// Serializes scratch base names within this test process; the pid keeps two concurrent runs of the
/// binary apart. Names stay short on purpose: the base sits under the per-user temp dir and the
/// socket path must still fit `sun_path` (104 bytes on macOS).
static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A scratch home plus an isolated runtime root per test, both under one owned base dir. Drop
/// removes exactly that base (`remove_dir_all`), never a parent: on macOS the parent of a scratch
/// leaf would be the real per-user temp dir. The root shape mirrors production: on macOS the base
/// IS the runtime root (whose parent, the per-user temp dir, is the verifier's base); elsewhere
/// `<base>` plays the XDG base and `<base>/run` the runtime root handed to `acquire`.
struct Scratch {
    base: PathBuf,
    root: PathBuf,
    home: Home,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let short: String = name.chars().take(8).collect();
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("sw-{short}-{}-{seq}", std::process::id()));
        #[cfg(target_os = "macos")]
        let root = base.clone();
        #[cfg(not(target_os = "macos"))]
        let root = base.join("run");
        let home_dir = base.join("home");
        std::fs::create_dir_all(&home_dir).expect("scratch home");
        std::fs::create_dir_all(&root).expect("scratch runtime root");
        {
            use std::os::unix::fs::PermissionsExt as _;
            // 0700 on the two dirs the chain verifier stats; the per-home leaf is created 0700 by
            // `acquire` itself.
            let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        let home = Home::resolve(Some(home_dir)).expect("explicit home resolves");
        Self { base, root, home }
    }

    fn home_key(&self) -> String {
        self.home.home_key()
    }

    /// The per-home runtime leaf under this test's root: the same derivation `acquire` uses.
    fn leaf(&self) -> PathBuf {
        self.home.runtime_leaf(&self.root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// The env tag carrying the child's home dir: its presence is what tells
/// [`single_lock_child_holds_the_home`] it is the re-invoked child, not an ordinary test run.
const CHILD_HOME_ENV: &str = "SWOOSH_TEST_SINGLE_CHILD_HOME";
/// The env tag carrying the child's already-verified runtime root.
const CHILD_ROOT_ENV: &str = "SWOOSH_TEST_SINGLE_CHILD_ROOT";
/// The env tag naming the file the child writes its pid to once it holds the lock.
const CHILD_PID_ENV: &str = "SWOOSH_TEST_SINGLE_CHILD_PIDFILE";

/// The child half of the cross-process cases: re-invoked by [`LockChild::spawn`] as
/// `test-bin single_lock_child_holds_the_home --ignored --nocapture`. It acquires the home, records
/// this process's pid for the parent, then holds both the lock and the listener until the parent
/// kills this exact pid. A run without the env tag (an ordinary `--ignored` pass) is a no-op.
#[test]
#[ignore = "re-invoked as a child by the cross-process single-instance tests"]
fn single_lock_child_holds_the_home() {
    let Some(home_dir) = std::env::var_os(CHILD_HOME_ENV) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT_ENV).expect("the child root env"));
    let pid_file = PathBuf::from(std::env::var_os(CHILD_PID_ENV).expect("the child pid env"));
    let home = Home::resolve(Some(PathBuf::from(home_dir))).expect("the child home resolves");
    let held = acquire(&home, &root).expect("the child acquires the free home");
    std::fs::write(&pid_file, std::process::id().to_string()).expect("record the child pid");
    // Hold the lock and the bound listener for life; the parent kills this exact pid.
    let _held = held;
    loop {
        std::thread::park();
    }
}

/// A re-invoked test-binary child that holds a home's lock. Kills and reaps on drop, so a panicking
/// parent never orphans it; `sigkill_and_reap` is the explicit exact-pid crash (and the kill the
/// cross-process cases assert on).
struct LockChild {
    child: std::process::Child,
}

impl LockChild {
    /// Spawn this same test binary as the lock-holding child over `scratch`'s home and root.
    fn spawn(scratch: &Scratch, pid_file: &Path) -> Self {
        let exe = std::env::current_exe().expect("the test binary path");
        let child = std::process::Command::new(exe)
            .arg("single_lock_child_holds_the_home")
            .arg("--ignored")
            .arg("--nocapture")
            .env(CHILD_HOME_ENV, scratch.home.dir())
            .env(CHILD_ROOT_ENV, &scratch.root)
            .env(CHILD_PID_ENV, pid_file)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("re-invoke the test binary as the lock-holding child");
        Self { child }
    }

    /// The pid this handle spawned (the only pid anything here is allowed to signal).
    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for the child to record its pid, bounded, and assert it matches the spawned pid.
    fn await_pid(&mut self, pid_file: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(text) = std::fs::read_to_string(pid_file) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    assert_eq!(pid, self.pid(), "the child recorded its own spawned pid");
                    return pid;
                }
            }
            if let Some(status) = self.child.try_wait().expect("poll the child") {
                panic!("the lock child exited before recording its pid: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "the lock child never recorded its pid at {}",
                pid_file.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Whether the spawned process is still running.
    fn is_alive(&mut self) -> bool {
        self.child.try_wait().expect("poll the child").is_none()
    }

    /// SIGKILL the exact pid this handle spawned, then reap it: the real crash, never a `drop` and
    /// never a name-based kill.
    fn sigkill_and_reap(&mut self) -> std::process::ExitStatus {
        let pid = self.pid() as libc::pid_t;
        // SAFETY: `kill` takes a pid and a signal number and touches no memory; the pid targeted is
        // the one this handle spawned, never a name match.
        let sent = unsafe { libc::kill(pid, libc::SIGKILL) };
        assert_eq!(sent, 0, "SIGKILL the exact spawned pid {pid}");
        self.child.wait().expect("reap the killed child")
    }
}

impl Drop for LockChild {
    fn drop(&mut self) {
        // Never orphan a spawned child, and never signal an already-reaped pid (it may be
        // recycled): reap if it is still running, else leave the cached status alone.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Two starts on one home in two processes: the child acquires, the parent's `acquire` loses at the
/// flock and names the child's pid. A mechanism that never wrote a pid (or returned `process::id()`)
/// could not pass this.
#[test]
fn two_resident_starts_one_home_exactly_one_wins() {
    let scratch = Scratch::new("duel");
    let pid_file = scratch.base.join("child.pid");
    let mut keeper = LockChild::spawn(&scratch, &pid_file);
    let child_pid = keeper.await_pid(&pid_file);

    let refused = acquire(&scratch.home, &scratch.root);
    let loser_pid = match refused {
        Err(SingleError::AlreadyResident { pid }) => pid,
        Err(other) => panic!("the second start must lose at the flock: {other}"),
        Ok(_) => panic!("exactly one start must win, not two"),
    };
    assert_eq!(loser_pid, child_pid, "the loser names the child's pid");
    assert!(
        keeper.is_alive(),
        "the child still holds the home after the refusal"
    );
    let status = keeper.sigkill_and_reap();
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the child died by the exact-pid SIGKILL"
    );
}

/// A dropped-but-not-unlinked listener leaves a stale path: the next start probes, unlinks, rebinds.
#[test]
fn stale_socket_is_probed_then_unlinked_and_rebound() {
    let scratch = Scratch::new("stale");
    // Establish the runtime leaf through one clean acquire first (creating it 0700), then plant
    // the stale socket inside it: the stale-rebind path is under test, not the create path.
    // `drop` the lock WITHOUT `release` (the crash shape) and shut the listener down WITHOUT
    // unlinking the path (the stale plant): both teardowns leave the dead path behind.
    let socket = {
        let (lock, listener) =
            acquire(&scratch.home, &scratch.root).expect("first acquire creates the leaf");
        let socket = lock.socket_path().to_path_buf();
        // Shut the listener DOWN (no more answers) but leave the path: `shutdown` stops the
        // accept queue so the probe gets ECONNREFUSED, while the path stays behind as the stale
        // plant. `drop` alone keeps answering until the fd closes; `forget` never closes.
        // SAFETY: the fd is the live listener's own; `shutdown` only stops new answers.
        let _ = unsafe { libc::shutdown(listener.as_raw_fd(), libc::SHUT_RDWR) };
        drop(listener);
        drop(lock);
        socket
    };
    // The listener is gone (path stale): the next start must succeed and rebind it.
    let (lock, _) = acquire(&scratch.home, &scratch.root).expect("stale socket rebinds");
    assert!(socket.exists(), "the rebound socket exists");
    let _ = lock;
}

/// A LIVE socket at the path with the flock free: the start owns the lock and reaches the real
/// probe, which hears the live listener and bails `ProbeAlive`, never unlinking the path.
#[test]
fn live_socket_under_lock_refuses_start() {
    let scratch = Scratch::new("live");
    // One clean acquire creates and verifies the leaf, then drops both handles: the flock frees and
    // the seed path is removed, so the plant binds a live listener inside the verified leaf.
    let (seed, seed_listener) =
        acquire(&scratch.home, &scratch.root).expect("seed acquire creates the leaf");
    let socket = seed.socket_path().to_path_buf();
    drop(seed);
    drop(seed_listener);
    let _ = std::fs::remove_file(&socket);
    let live = UnixListener::bind(&socket).expect("plant a live listener at the freed path");

    let refused = acquire(&scratch.home, &scratch.root);
    assert!(
        matches!(refused, Err(SingleError::ProbeAlive)),
        "a live socket answers the probe, so the start refuses"
    );
    assert!(socket.exists(), "the live socket is never unlinked");
    drop(live);
}

/// A live listener whose probe answers neither `ENOENT` nor `ECONNREFUSED` refuses start and is
/// never unlinked: only the two proven-stale answers permit the unlink. A mode-000 socket makes
/// connect answer `EACCES`, an outcome the unlink policy must refuse.
#[test]
fn unclassified_probe_refuses_and_never_unlinks() {
    let scratch = Scratch::new("unclassified");
    // The leaf must exist 0700 before the plant binds inside it.
    let (seed, seed_listener) =
        acquire(&scratch.home, &scratch.root).expect("seed acquire creates the leaf");
    let socket = seed.socket_path().to_path_buf();
    drop(seed);
    drop(seed_listener);
    let _ = std::fs::remove_file(&socket);
    let live = UnixListener::bind(&socket).expect("plant a live listener");
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Mode 000: a non-root connect answers EACCES on Linux and macOS, neither a live connect
        // nor one of the two stale errors. A full accept queue (Linux) answers EAGAIN, the other
        // unclassified shape; both land in the same refuse arm.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000))
            .expect("chmod the live socket to 000");
    }
    let refused = acquire(&scratch.home, &scratch.root);
    assert!(
        matches!(refused, Err(SingleError::ProbeUnclassified)),
        "an unclassified probe refuses start"
    );
    assert!(socket.exists(), "the refused socket is never unlinked");
    drop(live);
}

/// A crashing child (a real `SIGKILL`, not a `drop`) releases the flock: the parent's next start
/// succeeds over the stale socket the crash left behind. Kills only the exact spawned pid.
#[test]
fn crash_releases_flock_next_start_rebinds() {
    let scratch = Scratch::new("crash");
    let pid_file = scratch.base.join("child.pid");
    let mut crashed = LockChild::spawn(&scratch, &pid_file);
    let child_pid = crashed.await_pid(&pid_file);
    assert!(
        crashed.is_alive(),
        "the child holds the home before the crash"
    );
    let status = crashed.sigkill_and_reap();
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the child pid {child_pid} died by SIGKILL, not a clean drop"
    );

    // The OS released the flock with the pid; the socket path is still the crash plant, so the next
    // start probes it stale, unlinks, and rebinds.
    let (lock, _) = acquire(&scratch.home, &scratch.root).expect("a hard kill releases the flock");
    assert!(
        lock.socket_path().exists(),
        "the next start rebinds the stale path"
    );
    let _ = lock;
}

/// Two homes never collide: sockets and locks differ, keys differ, and the key is a stable function
/// of the canonical home path across re-resolutions and `dir/sub/..` spellings.
#[test]
fn per_home_paths_never_collide() {
    let first = Scratch::new("home-a");
    let second = Scratch::new("home-b");
    // Resolving one dir twice is one home: the key is stable, not re-rolled per resolution.
    let a = Home::resolve(Some(first.home.dir().to_path_buf())).expect("first home resolves");
    let b = Home::resolve(Some(first.home.dir().to_path_buf())).expect("same dir resolves again");
    assert_eq!(
        a.home_key(),
        b.home_key(),
        "the key is stable across resolutions of the same dir"
    );
    // A `dir/sub/..` spelling canonicalizes to the same home and the same key.
    let sub = first.home.dir().join("sub");
    std::fs::create_dir_all(&sub).expect("scratch sub dir");
    let odd = Home::resolve(Some(sub.join(".."))).expect("dir/sub/.. resolves");
    assert_eq!(
        odd.home_key(),
        a.home_key(),
        "a sub/.. spelling canonicalizes to one home"
    );
    assert_ne!(
        a.home_key(),
        second.home_key(),
        "two homes hash to different keys"
    );
    // The widened full-width hash: 16 lowercase hex chars, never the old 32-bit 8-char key.
    let key = a.home_key();
    assert_eq!(key.len(), 16, "the key renders the full 64 bits: {key}");
    assert!(
        key.chars().all(|c| c.is_ascii_hexdigit()),
        "the key stays lowercase hex: {key}"
    );
    // The widened key adds eight chars but must still fit sun_path on both platforms (104 on
    // macOS, 108 on Linux; assert the tighter one), or the bind would fail on a long temp root.
    let socket = a.runtime_leaf(&first.root).join("control.sock");
    assert!(
        socket.as_os_str().as_bytes().len() < 104,
        "the resident socket path fits sun_path: {}",
        socket.display()
    );
    let (a_lock, _) = acquire(&first.home, &first.root).expect("first home starts");
    let (b_lock, _) = acquire(&second.home, &second.root).expect("second home starts alongside");
    assert_ne!(
        a_lock.socket_path(),
        b_lock.socket_path(),
        "two residents hold different sockets"
    );
    let _ = (a_lock, b_lock);
}

/// A 0755 runtime leaf refuses the start (owner and mode are created AND verified, never assumed).
#[test]
fn runtime_dir_mode_owner_verified() {
    let scratch = Scratch::new("insecure");
    let dir = scratch.leaf();
    std::fs::create_dir_all(&dir).expect("runtime dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Loosen the per-home LEAF (the verifier's target), not the scratch root.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("loosen the dir");
    }
    let refused = acquire(&scratch.home, &scratch.root);
    assert!(
        matches!(refused, Err(SingleError::RuntimeDirInsecure { .. })),
        "a 0755 runtime dir refuses start"
    );
}

/// Graceful teardown unlinks the socket this instance bound: the path identity captured at bind is
/// the same filesystem object `release` stats, so the unlink fires.
#[test]
fn release_unlinks_its_own_socket() {
    let scratch = Scratch::new("release-own");
    let (lock, listener) = acquire(&scratch.home, &scratch.root).expect("resident start");
    let socket = lock.socket_path().to_path_buf();
    assert!(socket.exists(), "the bound socket exists while held");
    lock.release();
    assert!(!socket.exists(), "release unlinks its own socket");
    drop(listener);
}

/// A same-uid swap must not cost the foreign process its file: `release` compares against the path
/// identity captured at bind, and a different inode (a second listener renamed onto the path while
/// both exist, so the inodes are provably distinct) is left alone.
#[test]
fn release_spares_a_foreign_inode_swapped_onto_the_path() {
    let scratch = Scratch::new("release-foreign");
    let (lock, listener) = acquire(&scratch.home, &scratch.root).expect("resident start");
    let socket = lock.socket_path().to_path_buf();
    let foreign_path = scratch.root.join("foreign.sock");
    let foreign = UnixListener::bind(&foreign_path).expect("plant the foreign listener");
    std::fs::rename(&foreign_path, &socket).expect("swap the foreign inode onto the path");
    drop(listener);
    lock.release();
    assert!(socket.exists(), "release never unlinks a foreign inode");
    drop(foreign);
}
