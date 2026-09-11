//! S2 tests: flock exclusion across processes, stale rebind, the live-probe refusal, per-home split,
//! and graceful release.
//!
//! The cross-process cases re-invoke THIS test binary as a child (`single_lock_child_holds_the_home`)
//! that acquires the home and records its pid; the parent asserts the truth it reads and kills only
//! the exact pid it spawned. The in-process cases thread their own per-test runtime root into
//! `acquire`; nothing here mutates a process-global (`XDG_RUNTIME_DIR` is never touched).

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::os::fd::{FromRawFd as _, OwnedFd};
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

/// Plant a socket inode at `path` that never listened: `socket` + `bind` + close, no `listen`. The
/// path is dead the moment it exists, and it stays dead behind: a non-listening socket refuses every
/// connect (`ECONNREFUSED`) even while a forked child holds an inherited fd, so a sibling test's
/// concurrent `Command` spawn cannot turn the plant live under the probe.
fn plant_dead_socket(path: &Path) {
    let (addr, len) = super::sockaddr_un(path).expect("the scratch socket path fits sun_path");
    // SAFETY: `socket` takes no pointers and returns a fresh fd or -1.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket() for the dead plant");
    // SAFETY: `fd` is fresh; `addr`/`len` name a fully-initialized `sockaddr_un`.
    let bound = unsafe { libc::bind(fd, core::ptr::addr_of!(addr).cast(), len) };
    assert_eq!(bound, 0, "bind() the dead plant");
    // SAFETY: `fd` is owned by no other handle; closing it leaves the bound path behind as the dead
    // inode the next `acquire` probes.
    let _ = unsafe { libc::close(fd) };
}

/// A dead socket left at the rendezvous path (bound, never listened, closed without unlinking): the
/// next start probes it stale, unlinks, and rebinds.
#[test]
fn stale_socket_is_probed_then_unlinked_and_rebound() {
    let scratch = Scratch::new("stale");
    // Create the verified 0700 leaf directly (the create-and-verify path has its own tests) instead
    // of seeding it through an `acquire` whose lock is then dropped. A sibling test spawning a child
    // mid-test duplicates this process's fds into that child, and the child holds an inherited flock
    // description until its own `exec` (CLOEXEC closes it there); a drop-then-reacquire therefore
    // races that window and can read the inherited description as a live resident. Production never
    // drops and re-takes: it acquires once and holds for life.
    let leaf = scratch.leaf();
    std::fs::create_dir_all(&leaf).expect("create the runtime leaf");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700))
            .expect("0700 the runtime leaf");
    }
    // Plant the dead socket, then close it without unlinking: the path stays behind as the stale
    // plant, and an inherited fd cannot revive it (a non-listening socket refuses every connect).
    let socket = leaf.join("control.sock");
    plant_dead_socket(&socket);
    let before = super::path_identity(&socket).expect("stat the stale plant");

    // The dead path is probed stale, unlinked, and rebound: the path names a NEW socket inode.
    let (lock, _) = acquire(&scratch.home, &scratch.root).expect("stale socket rebinds");
    assert!(socket.exists(), "the rebound socket exists");
    assert_ne!(
        super::path_identity(&socket).expect("stat the rebound socket"),
        before,
        "the stale inode was unlinked and a new socket was bound"
    );
    let _ = lock;
}

/// A live listener at the path with the flock free: the start owns the lock and reaches the real
/// probe, which hears the listener answer and bails `ProbeAlive` rather than clobbering a responding
/// socket. The flock, not this probe, is what protects a legitimate resident; this is the courtesy
/// refusal for a squatter that answers.
#[test]
fn live_socket_under_lock_refuses_start() {
    let scratch = Scratch::new("live");
    // Create the verified 0700 leaf directly and take the flock exactly ONCE. A seed `acquire` whose
    // lock is dropped and re-taken would race a sibling test's `Command` spawn: the spawned child
    // inherits the fd table and holds the dropped lock's description until its own exec (CLOEXEC),
    // so the re-take could read that window as `AlreadyResident`. Production acquires once and holds.
    let leaf = scratch.leaf();
    std::fs::create_dir_all(&leaf).expect("create the runtime leaf");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700))
            .expect("0700 the runtime leaf");
    }
    let socket = leaf.join("control.sock");
    let live = UnixListener::bind(&socket).expect("plant a live listener");
    let identity = super::path_identity(&socket).expect("stat the live socket");

    let refused = acquire(&scratch.home, &scratch.root);
    assert!(
        matches!(refused, Err(SingleError::ProbeAlive)),
        "a live socket answers the probe, so the start refuses"
    );
    assert!(socket.exists(), "the answering socket is not clobbered");
    assert_eq!(
        super::path_identity(&socket).expect("stat the live socket again"),
        identity,
        "the ProbeAlive refusal never unlinks the answering socket"
    );
    drop(live);
}

/// The legitimate case the reclaim policy must never break: a resident holds the flock AND keeps its
/// bound listener. A second start loses at the flock before it ever probes, so it never touches the
/// path. This is the real invariant (`never take the path from a legitimate resident`), enforced by
/// the flock; the probe cannot enforce it (on macOS a full-queue live listener reads stale).
#[test]
fn legitimate_resident_flock_refuses_second_start_and_keeps_its_socket() {
    let scratch = Scratch::new("legit");
    let (held, listener) = acquire(&scratch.home, &scratch.root).expect("the first resident holds");
    let socket = held.socket_path().to_path_buf();
    let identity = super::path_identity(&socket).expect("stat the held socket");
    assert!(listener.as_raw_fd() >= 0, "the resident keeps its listener");

    let refused = acquire(&scratch.home, &scratch.root);
    match refused {
        Err(SingleError::AlreadyResident { pid }) => {
            assert_eq!(pid, held.pid(), "the loser names the holding pid");
        }
        Err(other) => panic!("the second start must lose at the flock: {other}"),
        Ok(_) => panic!("exactly one resident may hold the home"),
    }
    assert!(
        socket.exists(),
        "the second start never unlinks the legitimate resident's socket"
    );
    assert_eq!(
        super::path_identity(&socket).expect("stat the socket again"),
        identity,
        "the resident's own socket inode is untouched"
    );
    drop(listener);
    drop(held);
}

/// A live listener whose probe answers neither `ENOENT` nor `ECONNREFUSED` refuses start and is
/// never unlinked: only the two answers treated as stale (the crash/squatter reclaim) permit the
/// unlink. A mode-000 socket makes connect answer `EACCES`, an outcome the unlink policy must refuse.
#[test]
fn unclassified_probe_refuses_and_never_unlinks() {
    let scratch = Scratch::new("unclassified");
    // Create the verified 0700 leaf directly and take the flock exactly ONCE: see the live test for
    // the inherited-flock window a seed `acquire` dropped and re-taken would open.
    let leaf = scratch.leaf();
    std::fs::create_dir_all(&leaf).expect("create the runtime leaf");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700))
            .expect("0700 the runtime leaf");
    }
    let socket = leaf.join("control.sock");
    let live = UnixListener::bind(&socket).expect("plant a live listener");
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Mode 000: a non-root connect answers EACCES on Linux and macOS, neither a live connect
        // nor one of the two stale errors. A full accept queue (Linux) answers EAGAIN, the other
        // unclassified shape; both land in the same refuse arm.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000))
            .expect("chmod the live socket to 000");
    }
    let identity = super::path_identity(&socket).expect("stat the mode-000 socket");

    let refused = acquire(&scratch.home, &scratch.root);
    assert!(
        matches!(refused, Err(SingleError::ProbeUnclassified)),
        "an unclassified probe refuses start"
    );
    assert!(socket.exists(), "the refused socket is never unlinked");
    assert_eq!(
        super::path_identity(&socket).expect("stat the mode-000 socket again"),
        identity,
        "the unclassified refusal never unlinks the socket"
    );
    drop(live);
}

/// Bind a listener at `path` with an explicit backlog, so a test can fill its accept queue cheaply.
/// `UnixListener::bind` hardcodes the backlog, so this reaches libc directly and wraps the fd.
fn bind_with_backlog(path: &Path, backlog: libc::c_int) -> UnixListener {
    let (addr, len) = super::sockaddr_un(path).expect("the scratch socket path fits sun_path");
    // SAFETY: `socket` takes no pointers and returns a fresh fd or -1.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket() for the backlog listener");
    // SAFETY: `fd` is fresh; `addr`/`len` name a fully-initialized `sockaddr_un`.
    let bound = unsafe { libc::bind(fd, core::ptr::addr_of!(addr).cast(), len) };
    assert_eq!(bound, 0, "bind() the backlog listener");
    // SAFETY: `fd` is a bound AF_UNIX stream socket; `listen` sets its queue length.
    let listening = unsafe { libc::listen(fd, backlog) };
    assert_eq!(listening, 0, "listen() the backlog listener");
    // SAFETY: `fd` is owned by no other handle; the `UnixListener` becomes its sole owner.
    UnixListener::from(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Fill `path`'s accept queue with nonblocking clients, keeping them alive, until the kernel refuses
/// the next connect: `EAGAIN` on Linux, `ECONNREFUSED` on macOS, the platform asymmetry the caller
/// pins. The accepted connections are returned held open so the queue stays full.
fn fill_accept_queue(path: &Path) -> Vec<std::os::unix::net::UnixStream> {
    let (addr, len) = super::sockaddr_un(path).expect("the scratch socket path fits sun_path");
    let mut held = Vec::new();
    for _ in 0..1024 {
        // SAFETY: `socket` takes no pointers and returns a fresh fd or -1.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "socket() for a queue filler");
        // SAFETY: `fd` is open and owned here; `F_SETFL` only sets a status flag on it.
        let nonblocking = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        assert!(nonblocking >= 0, "set O_NONBLOCK on a queue filler");
        // SAFETY: `fd` is fresh and `addr`/`len` name a fully-initialized `sockaddr_un`.
        let connected = unsafe { libc::connect(fd, core::ptr::addr_of!(addr).cast(), len) };
        if connected == 0 {
            // SAFETY: `fd` is owned by no other handle; the stream becomes its sole owner.
            held.push(std::os::unix::net::UnixStream::from(unsafe {
                OwnedFd::from_raw_fd(fd)
            }));
            continue;
        }
        let errno = std::io::Error::last_os_error().raw_os_error();
        // SAFETY: `fd` is still open and owned here (the failed connect took no handle).
        let _ = unsafe { libc::close(fd) };
        assert!(
            matches!(errno, Some(libc::EAGAIN | libc::ECONNREFUSED)),
            "the accept queue must fill with EAGAIN (Linux) or ECONNREFUSED (macOS), got {errno:?}"
        );
        return held;
    }
    panic!("the accept queue never filled within 1024 clients");
}

/// The platform asymmetry the B1 re-gate reproduced: a live listener with a FULL accept queue
/// answers the nonblocking probe differently per kernel. Linux answers `EAGAIN`, not a stale answer,
/// so the probe refuses `ProbeUnclassified` and never unlinks. macOS answers `ECONNREFUSED`, the
/// same errno a dead path returns, so `acquire` reclaims it (unlink + rebind) exactly as crash
/// recovery requires; the listener does not hold the lock, so it is the squatter the reclaim is for.
/// The flock, not this probe, is what keeps a legitimate resident's path safe. `acquire` runs on a
/// bounded worker so deleting the probe's `O_NONBLOCK` (a blocking connect parks on Linux) fails the
/// bounded wait instead of hanging the suite.
#[test]
fn full_accept_queue_is_classified_per_platform() {
    let scratch = Scratch::new("backlog");
    // Create the verified leaf directly (0700, as `acquire` would) instead of seeding it through a
    // first `acquire`: the test needs a leaf for the planted listener, not a lock holder.
    let leaf = scratch.leaf();
    std::fs::create_dir_all(&leaf).expect("create the runtime leaf");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700))
            .expect("0700 the runtime leaf");
    }
    let socket = leaf.join("control.sock");
    let _listener = bind_with_backlog(&socket, 1);
    let before = super::path_identity(&socket).expect("stat the planted socket");
    let _clients = fill_accept_queue(&socket);

    let home = Home::resolve(Some(scratch.home.dir().to_path_buf())).expect("re-resolve the home");
    let root = scratch.root.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(acquire(&home, &root));
    });
    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the probe must not park on a full accept queue");

    #[cfg(target_os = "linux")]
    {
        assert!(
            matches!(result, Err(SingleError::ProbeUnclassified)),
            "a full queue answers EAGAIN on Linux, so the probe refuses rather than reclaim"
        );
        assert_eq!(
            super::path_identity(&socket).expect("stat the socket"),
            before,
            "the unclassified live socket is never unlinked"
        );
    }
    #[cfg(target_os = "macos")]
    {
        let acquired =
            result.expect("a full queue answers ECONNREFUSED on macOS, so it reads stale");
        assert_ne!(
            super::path_identity(&socket).expect("stat the rebound socket"),
            before,
            "the macOS stale answer unlinks and rebinds the path"
        );
        drop(acquired);
    }
    drop(_listener);
    worker.join().expect("the acquire worker joins");
}

/// `await_probe` polls the in-flight connect and reads `SO_ERROR`: a connected socket is writable
/// and reports no error, so it classifies `Live`. This drives the helper directly (an AF_UNIX
/// connect never actually takes the `EINPROGRESS` arm on Linux/macOS), so deleting the `poll` call,
/// which leaves `revents` at 0 and returns `Unknown`, fails this test.
#[test]
fn await_probe_reads_so_error_from_a_connected_socket() {
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().expect("a socketpair");
    // SAFETY: `dup` returns a fresh fd or -1; the dup is owned by no other handle.
    let dup = unsafe { libc::dup(stream.as_raw_fd()) };
    assert!(dup >= 0, "dup the connected fd");
    // SAFETY: `dup` is a fresh fd owned by no other handle.
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    assert_eq!(
        super::await_probe(&owned),
        super::Probe::Live,
        "a connected socket is poll-ready and error-free, so the in-flight probe reads Live"
    );
}

/// The poll is a bounded WAIT, not a grab at `SO_ERROR`: a socket whose send buffer is full is not
/// writable, so `poll` does not fire within [`super::PROBE_POLL_MS`] and `await_probe` reads
/// `Unknown` (it never falls through to a stale `Live`). A poll replaced by a hardcoded ready, or
/// one whose deadline is ignored, would read `SO_ERROR` = 0 and return `Live`, failing this.
#[test]
fn await_probe_times_out_on_a_write_blocked_socket() {
    use std::io::Write as _;

    let (mut writer, _reader) = std::os::unix::net::UnixStream::pair().expect("a socketpair");
    writer
        .set_nonblocking(true)
        .expect("the filler is nonblocking");
    // Fill the send buffer until a write would block: now the socket is not writable, so POLLOUT
    // does not fire. The peer stays open and unread, so the buffer never drains.
    let chunk = [0u8; 4096];
    loop {
        match writer.write(&chunk) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => break,
            Err(error) => panic!("fill the send buffer: {error}"),
        }
    }
    // SAFETY: `dup` returns a fresh fd or -1; the dup is owned by no other handle.
    let dup = unsafe { libc::dup(writer.as_raw_fd()) };
    assert!(dup >= 0, "dup the write-blocked fd");
    // SAFETY: `dup` is a fresh fd owned by no other handle.
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    assert_eq!(
        super::await_probe(&owned),
        super::Probe::Unknown,
        "a socket that never polls ready within the deadline must refuse, never read as live"
    );
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
