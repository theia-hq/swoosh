//! Single-instance for `serve`: the flock truth plus the socket rendezvous, one per home.
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
//! itself, and the next start recovers through the probe, no reaper. A clean exit removes what it made:
//! the socket, then the lock file, then the leaf directory, so a stopped home leaves nothing in the
//! runtime root.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::home::Home;
use crate::node_client::read_lock_pid;

/// Why a resident start was refused.
#[derive(Debug, thiserror::Error)]
pub enum SingleError {
    /// The socket path would not fit `sun_path` (104 bytes on macOS, 108 on Linux): binding it would
    /// truncate it to a path another home could share.
    #[error(
        "the runtime directory's path is too long for a socket: set XDG_RUNTIME_DIR to a shorter one."
    )]
    SocketPathTooLong {
        /// The socket path that does not fit.
        path: PathBuf,
    },
    /// Another `serve` already holds this home's lock: the truth, read off the lock file.
    #[error("swoosh serve is already running for this home (pid {pid})")]
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
/// identity. Dropping it unlinks the socket it bound, then the lock file, releases the flock, and
/// removes the leaf directory, so a `serve` that refuses after the claim, or stops, leaves nothing for
/// a later `status` to find. Only a process that dies without unwinding (a `SIGKILL`, an abort) leaves
/// the leaf behind, the crash plant the next start of that home recovers through its probe. Owns the
/// fd for process life.
pub struct InstanceLock {
    /// The lock fd: held open, flocked, for the life of the resident.
    file: std::fs::File,
    /// The lock file's path, unlinked on the way out.
    lock: PathBuf,
    /// The `(dev, ino)` of the locked file, so the unlink on the way out removes only the file this
    /// instance holds, never one a later start made at the path.
    lock_id: (u64, u64),
    /// The runtime leaf holding the lock and the socket, removed last when it is empty.
    leaf: PathBuf,
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

    /// Graceful teardown, the same as dropping it: see the [`Drop`] impl.
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for InstanceLock {
    /// Unlink the socket ONLY while the path still names the socket this instance bound (stat
    /// without following links, compare `(dev, ino)` against the identity captured at bind), then the
    /// lock file on the same rule, still under the flock so no start can take the file on its way
    /// out. Then release the flock and remove the leaf, which `remove_dir` does only when it is
    /// empty, so a start that got in after the unlink keeps its files. A blind by-path unlink could
    /// remove a file a same-uid process swapped in.
    fn drop(&mut self) {
        if path_identity(&self.socket).is_ok_and(|id| id == self.socket_id) {
            let _ = std::fs::remove_file(&self.socket);
        }
        if path_identity(&self.lock).is_ok_and(|id| id == self.lock_id) {
            let _ = std::fs::remove_file(&self.lock);
        }
        release_flock(&self.file);
        let _ = std::fs::remove_dir(&self.leaf);
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
    // Before anything is created: a path `sun_path` cannot hold would be bound truncated, or not at all.
    let socket_path = home.runtime_leaf(root).join("control.sock");
    if sockaddr_un(&socket_path).is_none() {
        return Err(SingleError::SocketPathTooLong { path: socket_path });
    }
    // A resident on its way out unlinks its lock file and removes the leaf under its flock, so a start
    // racing it can open the file just unlinked, or find the leaf gone. Each is a fresh try: the
    // chain is made again and the lock taken on the file the path names now.
    let mut tries = 0;
    let (runtime, file, lock_id) = loop {
        let runtime = RuntimeDir::acquire(home, root)?;
        if let Some(taken) = take_lock(&runtime.lock_path())? {
            break (runtime, taken.file, taken.id);
        }
        tries += 1;
        if tries == LOCK_TRIES {
            return Err(SingleError::LockFailed {
                path: runtime.lock_path(),
                source: std::io::Error::other(
                    "the control lock was removed each time it was taken",
                ),
            });
        }
    };
    let lock_path = runtime.lock_path();
    let socket_path = runtime.socket_path();
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
            lock: lock_path,
            lock_id,
            leaf: runtime.path().to_owned(),
            socket: socket_path,
            socket_id,
            pid,
        },
        listener,
    ))
}

/// How many times a start takes the lock before it gives up on a file removed under it each time.
const LOCK_TRIES: u32 = 3;

/// A lock file taken: the flocked handle and the `(dev, ino)` the path named when it was taken.
struct Taken {
    /// The flocked lock file.
    file: std::fs::File,
    /// Its `(dev, ino)`.
    id: (u64, u64),
}

/// Open (creating, `0600`) the lock file at `path` with `O_NOFOLLOW`, check it is a regular file, and
/// take the exclusive nonblocking flock. `None` when the file was removed before or while it was taken
/// (a resident leaving): the path no longer names the locked file, so the flock guards nothing and is
/// dropped. A live holder is [`SingleError::AlreadyResident`].
// `core::io::ErrorKind` is still unstable, so the error kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn take_lock(path: &Path) -> Result<Option<Taken>, SingleError> {
    use std::os::unix::fs::MetadataExt as _;

    let failed = |source| SingleError::LockFailed {
        path: path.to_owned(),
        source,
    };
    // Open (creating) the lock file with O_NOFOLLOW and stat it as a regular file: a symlink or a
    // special file planted inside the leaf never becomes the flock.
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path);
    let file = match opened {
        Ok(file) => file,
        // The leaf went with a resident that was leaving.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(failed(error)),
    };
    let meta = file.metadata().map_err(failed)?;
    if !meta.is_file() {
        return Err(failed(std::io::Error::other(
            "the control lock is not a regular file",
        )));
    }
    // SAFETY: `file` owns a valid fd for the duration of the call; `flock` only associates an
    // advisory lock with it. A nonzero return with `EWOULDBLOCK` means a live holder.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        let held = std::io::Error::last_os_error();
        if held.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(SingleError::AlreadyResident {
                pid: read_lock_pid(path).unwrap_or(0),
            });
        }
        return Err(failed(held));
    }
    let id = (meta.dev(), meta.ino());
    if path_identity(path).ok() != Some(id) {
        release_flock(&file);
        return Ok(None);
    }
    Ok(Some(Taken { file, id }))
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
