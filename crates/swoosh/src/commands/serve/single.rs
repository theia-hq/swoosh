//! Single-instance for `serve --resident`: the flock truth plus the socket rendezvous.
//!
//! The LOCK FILE is the truth; the SOCKET is the rendezvous. Start: create and verify the 0700
//! runtime chain, take `LOCK_EX | LOCK_NB` on `control.lock`, then connect-probe the socket. The
//! flock is what protects a legitimate resident: a resident holds it for life, so a second start
//! loses at the flock and never reaches the probe, and that resident's path is never touched. Under
//! OUR lock, the socket at the path is a crash plant or a same-uid squatter, so `ENOENT` and
//! `ECONNREFUSED` reclaim it (unlink, rebind, record our pid) and a connect that completes (a
//! listener that answers) refuses [`SingleError::ProbeAlive`]. The probe cannot prove death, and on
//! macOS a live listener with a full accept queue answers `ECONNREFUSED`; that listener does not
//! hold the lock, so it is the squatter this reclaim is for. The probe connect is nonblocking, so
//! that same full queue cannot park startup. Hold the fd for life: a crash releases the flock by
//! itself, and the next start recovers through the probe, no reaper.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::home::Home;

/// Why a resident start was refused.
#[derive(Debug, thiserror::Error)]
pub enum SingleError {
    /// Another resident already holds this home's lock: the truth, read off the lock file.
    #[error("a node is already resident here (pid {pid}); use --home for a second node")]
    AlreadyResident {
        /// The pid recorded in the lock file by the holder.
        pid: u32,
    },
    /// A runtime-chain component is not this user's 0700 dir: created AND verified, never assumed.
    #[error("refusing insecure runtime dir {path}: want uid {want} mode 700")]
    RuntimeDirInsecure {
        /// The offending dir.
        path: PathBuf,
        /// The uid that must own it.
        want: u32,
    },
    /// Opening, stat-ing, or flocking `control.lock` failed: an fd limit, a real lock error, a
    /// symlinked or non-regular lock path.
    #[error("could not take the control lock at {path}")]
    LockFailed {
        /// The lock path the open, stat, or flock was attempted on.
        path: PathBuf,
        /// The underlying OS failure.
        #[source]
        source: std::io::Error,
    },
    /// The socket answered a connect while we hold the lock: a squatter that is listening. A live
    /// node would hold the lock, so we would have lost at the flock and never probed; refuse loudly
    /// rather than clobber a socket that answers.
    #[error("the control socket is live under our lock; refusing to steal it")]
    ProbeAlive,
    /// The connect probe neither completed nor answered `ENOENT`/`ECONNREFUSED` (`EACCES`,
    /// `EAGAIN`, `EINTR`, a poll timeout): not one of the two answers treated as stale, so refuse
    /// rather than guess at reclaiming a path we cannot classify.
    #[error("the control socket did not answer a clean probe; refusing to steal it")]
    ProbeUnclassified,
    /// Binding the socket after a stale probe failed.
    #[error("could not bind the control socket")]
    BindFailed(#[source] std::io::Error),
}

/// The held single-instance lock: the flock fd plus the socket it guards and that socket PATH's
/// identity. Dropping it releases the flock (the crash path); the graceful path unlinks the socket
/// first via [`release`](InstanceLock::release). Owns the fd for process life.
///
/// There is no `Drop` impl that unlinks: a plain drop leaves the socket path behind (the crash
/// plant the next start recovers through its probe), and only the explicit `release` unlinks, so
/// the two teardown shapes stay visibly distinct at the call site.
pub struct InstanceLock {
    /// The lock fd: held open, flocked, for the life of the resident.
    file: std::fs::File,
    /// The socket this instance bound (for the graceful unlink).
    socket: PathBuf,
    /// The `(dev, ino)` of the bound socket PATH, captured at bind, kept so `release` can prove the
    /// path still names it (a same-uid swap must not cost another process its file). A listener
    /// fd's own `fstat` reports a different namespace (macOS `st_dev = -1`, a sockfs inode on
    /// Linux), so the fd identity can never match a path stat and is deliberately not what is kept.
    socket_id: (u64, u64),
    /// This instance's pid, recorded in the lock file.
    pid: u32,
}

impl InstanceLock {
    /// The pid this instance recorded.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The socket path this instance bound.
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// Graceful teardown: unlink the socket ONLY while the path still names the socket this instance
    /// bound (stat without following links, compare `(dev, ino)` against the identity captured at
    /// bind), release the flock, then drop the fd. A blind by-path unlink could remove a file a
    /// same-uid process swapped in.
    pub fn release(self) {
        if path_identity(&self.socket).is_ok_and(|id| id == self.socket_id) {
            let _ = std::fs::remove_file(&self.socket);
        }
        // Explicit unlock before the fd drops: the teardown reads the held lock fd, and the flock
        // release is visible here rather than inferred from Drop.
        release_flock(&self.file);
        drop(self);
    }
}

/// The verified runtime chain for a resident: the per-user base, the `swoosh`/`swoosh-<uid>`
/// component, and the per-home leaf. The chain is created 0700 and verified (owner and mode) with
/// the leaf opened `O_NOFOLLOW`; a wrong owner, a wrong mode, or a symlinked component is
/// [`SingleError::RuntimeDirInsecure`], never silently repaired.
///
/// The verified leaf is held by PATH, not by an open fd: a same-uid swap between the verify and the
/// lock/socket open is outside this threat model (the 0700 dir plus the peer-credential check carry
/// it), so the type does not claim to hold a verification the fd would.
pub struct RuntimeDir {
    /// The verified leaf.
    dir: PathBuf,
}

impl RuntimeDir {
    /// Create (0700) and verify the runtime chain for `home` under the already-resolved runtime
    /// `root`, which is threaded in as a value by the composition edge: this module never reads
    /// `XDG_RUNTIME_DIR`/`confstr`. An existing dir keeps its mode (verified below, never silently
    /// repaired by the create path): only a dir WE create gets the explicit 0700 set, so a
    /// pre-loosened dir still refuses.
    pub fn acquire(home: &Home, root: &Path) -> Result<Self, SingleError> {
        let dir = home.runtime_leaf(root);
        let (root_fresh, leaf_fresh) = (!root.exists(), !dir.exists());
        // SAFETY: `DirBuilder::mode` only sets the mode argument for the mkdir syscall; no raw
        // pointer crosses the boundary.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(&dir).map_err(|_| insecure(&dir))?;
            // A umask-built component (or a stale 0755 one the OS left behind) would fail the
            // verify below on its mode alone. Repair ONLY a path we just created: a PRE-EXISTING
            // loosened dir is the attack the verifier refuses, so it must not be silently fixed.
            if root_fresh {
                let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700));
            }
            if leaf_fresh {
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&dir).map_err(|_| insecure(&dir))?;
        }
        verify_runtime_chain(root, &dir)?;
        Ok(Self { dir })
    }

    /// The verified leaf dir.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// `<leaf>/control.lock`: the flock truth, inside the verified leaf.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("control.lock")
    }

    /// `<leaf>/control.sock`: the rendezvous, inside the verified leaf.
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join("control.sock")
    }
}

/// Acquire single-instance for `home` under the already-resolved runtime `root`: create and verify
/// the runtime chain, take the exclusive nonblocking flock, connect-probe-then-unlink-bind the
/// socket, record our pid, and return the held lock plus the bound listener. The probe/unlink/bind
/// sequence runs UNDER the flock; the chain verify precedes it because the lock lives inside the
/// leaf it verifies. A second holder gets [`SingleError::AlreadyResident`] naming the winner's pid
/// and never touches the winner's socket: the flock, not the probe, is what keeps a legitimate
/// resident's path safe. Under our own lock a socket that answers a connect is
/// [`SingleError::ProbeAlive`], and any answer that is neither live nor one of the two stale
/// answers is [`SingleError::ProbeUnclassified`].
pub fn acquire(
    home: &Home,
    root: &Path,
) -> Result<(InstanceLock, std::os::unix::net::UnixListener), SingleError> {
    let runtime = RuntimeDir::acquire(home, root)?;
    let lock_path = runtime.lock_path();
    let socket_path = runtime.socket_path();
    // Open (creating) the lock file with O_NOFOLLOW and stat it as a regular file: a symlink or a
    // special file planted inside the leaf never becomes the flock.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|source| SingleError::LockFailed {
            path: lock_path.clone(),
            source,
        })?;
    if !file
        .metadata()
        .map_err(|source| SingleError::LockFailed {
            path: lock_path.clone(),
            source,
        })?
        .is_file()
    {
        return Err(SingleError::LockFailed {
            path: lock_path,
            source: std::io::Error::other("the control lock is not a regular file"),
        });
    }
    // SAFETY: `file` owns a valid fd for the duration of the call; `flock` only associates an
    // advisory lock with it. A nonzero return with `EWOULDBLOCK` means a live holder.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        let held = std::io::Error::last_os_error();
        if held.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(SingleError::AlreadyResident {
                pid: read_lock_pid(&lock_path).unwrap_or(0),
            });
        }
        return Err(SingleError::LockFailed {
            path: lock_path,
            source: held,
        });
    }
    // Connect-probe UNDER the lock: the flock already proved no legitimate resident holds this
    // home (a real resident would have won the flock and we would have returned AlreadyResident),
    // so the socket here is a crash plant or a same-uid squatter. `ENOENT`/`ECONNREFUSED` reclaim
    // it (unlink, bind, continue); a connect that completes (a socket that answers) refuses
    // `ProbeAlive`; every other answer refuses `ProbeUnclassified`. The probe is a courtesy that
    // avoids clobbering a responding socket, never the guarantee: the flock is what protects a
    // legitimate resident.
    let probe = probe_socket(&socket_path);
    if !matches!(probe, Probe::Stale) {
        // Release before returning so a probe refusal does not strand the flock.
        release_flock(&file);
        return Err(match probe {
            Probe::Live => SingleError::ProbeAlive,
            Probe::Stale | Probe::Unknown => SingleError::ProbeUnclassified,
        });
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener =
        std::os::unix::net::UnixListener::bind(&socket_path).map_err(SingleError::BindFailed)?;
    let socket_id = path_identity(&socket_path).map_err(SingleError::BindFailed)?;
    // Defense in depth: the dir + peer-cred carry the weight (the mode is moot on macOS), but a
    // 0600 socket costs nothing.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
    }
    // Record our pid through the already-open lock fd (truncate + write), never a second by-path
    // open a symlink planted inside the leaf could redirect.
    let pid = std::process::id();
    {
        use std::io::{Seek as _, SeekFrom, Write as _};
        let mut handle = &file;
        let _ = handle.set_len(0);
        let _ = handle.seek(SeekFrom::Start(0));
        let _ = writeln!(handle, "{pid}");
    }
    Ok((
        InstanceLock {
            file,
            socket: socket_path,
            socket_id,
            pid,
        },
        listener,
    ))
}

/// The deadline for a connect left `EINPROGRESS`. A local listener admits at once; a full accept
/// queue that never frees is exactly the park a nonblocking connect avoids, so this bounds only an
/// in-flight connect, never startup.
const PROBE_POLL_MS: libc::c_int = 200;

/// What a connect probe of the rendezvous path found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Probe {
    /// A connect completed: a listener is answering at the path. A legitimate resident would hold
    /// the flock, so we would have lost at the flock and never probed: this is a same-uid squatter.
    Live,
    /// `ENOENT` or `ECONNREFUSED`: the two answers treated as stale, so unlink and rebind. On macOS
    /// a live listener with a full accept queue also answers `ECONNREFUSED`, and it is reclaimed
    /// like a crash: under our lock it is the squatter (or crash) the reclaim is for, never a
    /// legitimate resident.
    Stale,
    /// Any other answer (`EACCES`, `EAGAIN`, `EINTR`, a poll timeout): not classifiable as stale,
    /// so refuse rather than guess at reclaiming it.
    Unknown,
}

/// Probe the socket at `path` with a nonblocking connect. The connect MUST be nonblocking: a
/// blocking connect to a live AF_UNIX listener with a full accept queue parks in the kernel until a
/// slot frees, which a squatter can deny for the life of the process. An in-flight connect is
/// polled to `SO_ERROR` within [`PROBE_POLL_MS`]; everything but `ENOENT`/`ECONNREFUSED` refuses.
fn probe_socket(path: &Path) -> Probe {
    let Some((addr, len)) = sockaddr_un(path) else {
        return Probe::Unknown;
    };
    // SAFETY: `socket` takes no pointers and returns a fresh fd or -1.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Probe::Unknown;
    }
    // SAFETY: `fd` was just returned by `socket` and is owned by no other handle, so `OwnedFd`
    // becomes its sole owner and closes it on drop.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // `SOCK_NONBLOCK`/`SOCK_CLOEXEC` are Linux `socket()` flags; set both portably after creation.
    // SAFETY: `fd` is open and owned here; `F_SETFL`/`F_SETFD` only set status flags on that fd.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
    {
        return Probe::Unknown;
    }
    // SAFETY: `addr` is fully initialized by `sockaddr_un` and `len` names its whole extent; the
    // cast to `*const sockaddr` is valid for a `sockaddr_un` and `connect` reads only that much.
    let connected = unsafe { libc::connect(fd.as_raw_fd(), core::ptr::addr_of!(addr).cast(), len) };
    if connected == 0 {
        return Probe::Live;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT | libc::ECONNREFUSED) => Probe::Stale,
        Some(libc::EINPROGRESS) => await_probe(&fd),
        _ => Probe::Unknown,
    }
}

/// Wait out an in-flight connect for at most [`PROBE_POLL_MS`], then read `SO_ERROR`: 0 is a live
/// connect, the two stale errors stay stale, and a timeout or any other answer refuses (the path
/// might still be a live listener that has not admitted us yet).
fn await_probe(fd: &OwnedFd) -> Probe {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: `pollfd` is a live one-entry array; `poll` reads `events` and writes `revents` only.
    let ready = unsafe { libc::poll(&mut pollfd, 1, PROBE_POLL_MS) };
    if ready <= 0 {
        return Probe::Unknown;
    }
    let mut error: libc::c_int = 0;
    let mut len = core::mem::size_of_val(&error) as libc::socklen_t;
    // SAFETY: `error` is a live `c_int` and `len` names its size; `getsockopt` writes at most
    // `len` bytes through the pointer.
    let got = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            core::ptr::addr_of_mut!(error).cast(),
            &mut len,
        )
    };
    if got != 0 {
        return Probe::Unknown;
    }
    match error {
        0 => Probe::Live,
        libc::ENOENT | libc::ECONNREFUSED => Probe::Stale,
        _ => Probe::Unknown,
    }
}

/// Build the `sockaddr_un` for `path`, or `None` when the path does not fit `sun_path` (an
/// unclassifiable probe refuses rather than address a truncated path).
fn sockaddr_un(path: &Path) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    // SAFETY: `sockaddr_un` is plain C data (integers plus a byte array); all-zero is a valid
    // initial value and every field the kernel reads is set below.
    let mut addr: libc::sockaddr_un = unsafe { core::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() {
        return None;
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    Some((addr, core::mem::size_of_val(&addr) as libc::socklen_t))
}

/// Release this fd's advisory flock, so a refusal never strands the lock for process life.
fn release_flock(file: &std::fs::File) {
    // SAFETY: `file` owns a valid fd for the duration of the call; `LOCK_UN` only drops this fd's
    // advisory lock.
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

/// The most bytes [`read_lock_pid`] reads from the lock file: a u32 pid is at most ten digits plus
/// a newline, so sixteen covers the record with room to spare.
const LOCK_PID_READ_CAP: u64 = 16;

/// Read the pid recorded in the lock file, if any. Only [`LOCK_PID_READ_CAP`] bytes are read, never
/// the whole file: a same-uid process can grow the lock file, and the reader must not allocate it
/// on demand.
fn read_lock_pid(path: &Path) -> Option<u32> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).ok()?;
    let mut reader = file.take(LOCK_PID_READ_CAP);
    let mut text = String::new();
    reader.read_to_string(&mut text).ok()?;
    text.split_whitespace().next()?.parse().ok()
}

/// The `(dev, ino)` of the socket PATH, from `symlink_metadata` (a symlink planted at the path
/// reports its own inode, never the target's): the filesystem-namespace identity
/// [`InstanceLock::release`] compares before unlinking. A bound listener fd lives in a DIFFERENT
/// namespace (macOS `fstat` reports `st_dev = -1` and a sockfs inode; Linux the same shape), so an
/// fd identity can never match a path stat and must not be what the guard captures.
fn path_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::symlink_metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

/// Verify the runtime chain that guards the rendezvous, from the per-user base down: the base, the
/// `swoosh`/`swoosh-<uid>` component, and the per-home leaf must each be a directory owned by this
/// user with mode 0700. The base is followed (a caller may point `XDG_RUNTIME_DIR` through a
/// symlink at the real per-user dir); the component is checked with `symlink_metadata` and the leaf
/// is opened `O_NOFOLLOW | O_DIRECTORY`, so a planted symlink cannot pass by pointing at an
/// accepted target.
fn verify_runtime_chain(root: &Path, leaf: &Path) -> Result<(), SingleError> {
    if let Some(base) = root.parent() {
        verify_dir(std::fs::metadata(base), base)?;
    }
    verify_dir(std::fs::symlink_metadata(root), root)?;
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(leaf)
        .map_err(|_| insecure(leaf))?;
    verify_dir(handle.metadata(), leaf)
}

/// Check one stat result against the chain invariant: a directory, owned by euid, mode 0700. A
/// stat failure or any mismatch is insecure: what cannot be proven is refused.
fn verify_dir(meta: std::io::Result<std::fs::Metadata>, path: &Path) -> Result<(), SingleError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let want = euid();
    let meta = meta.map_err(|_| insecure(path))?;
    if !meta.is_dir() || meta.uid() != want || meta.permissions().mode() & 0o777 != 0o700 {
        return Err(insecure(path));
    }
    Ok(())
}

/// The refusal for a runtime-chain path that is not this user's 0700 directory.
fn insecure(path: &Path) -> SingleError {
    SingleError::RuntimeDirInsecure {
        path: path.to_owned(),
        want: euid(),
    }
}

/// The effective uid: the owner every runtime path must verify against.
fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
#[path = "serve_single_tests.rs"]
mod single_tests;
