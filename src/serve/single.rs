//! Single-instance for `serve`: `serve.lock` in the home is the truth, the socket is the rendezvous.
//!
//! Start: take `serve.lock` exclusive without waiting, under `home.lock`, and record this process in it;
//! then create and verify the 0700 runtime chain and connect-probe the socket. The lock is what protects a
//! legitimate resident: a resident holds it for life, so a second start loses at the lock and never
//! reaches the probe, and that resident's socket is never touched. It sits in the home, so two starts that
//! resolve different runtime directories, or that name one home by two paths, still meet at it. Under OUR
//! lock, the socket at the path is a crash plant or a same-uid squatter, so `ENOENT` and `ECONNREFUSED`
//! reclaim it (unlink, rebind) and a connect that completes (a listener that answers) refuses
//! [`SingleError::ProbeAlive`]. The probe cannot prove death, and on macOS a live listener with a full
//! accept queue answers `ECONNREFUSED`; that listener does not hold the lock, so it is the squatter this
//! reclaim is for. The probe connect is nonblocking, so that same full queue cannot park startup. A crash
//! releases the lock by itself, and the next start recovers through the probe, no reaper. A clean exit
//! removes what it made in the runtime root, the socket and then the leaf directory, before it lets the
//! lock go, so a stopped home leaves nothing there and a start that follows finds the leaf its own.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::home::{Home, HomeWrite, ServeLock, ServeLockError};

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
    #[error("swoosh serve is already running here (pid {pid})")]
    AlreadyResident {
        /// The pid recorded in the lock file by the holder.
        pid: u32,
    },
    /// A command replacing this machine's key holds this home's lock.
    #[error("this machine's key is being replaced; when that has finished: swoosh serve")]
    KeyChanging,
    /// A runtime-chain component is not this user's 0700 dir: created AND verified, never assumed.
    #[error("refusing insecure runtime dir {path}: want uid {want} mode 700")]
    RuntimeDirInsecure {
        /// The offending dir.
        path: PathBuf,
        /// The uid that must own it.
        want: u32,
    },
    /// Opening, stat-ing, flocking or writing `home.lock` or `serve.lock` failed: an fd limit, a real
    /// lock error, a symlinked or non-regular lock path.
    #[error(transparent)]
    LockFailed(#[from] crate::home::LockError),
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

/// The held single-instance lock: `serve.lock` plus the socket it guards and that socket PATH's identity.
/// Dropping it unlinks the socket it bound, removes the leaf directory, then empties and releases
/// `serve.lock`, so a `serve` that refuses after the claim, or stops, leaves nothing for a later `status`
/// to find. Only a process that dies without unwinding (a `SIGKILL`, an abort) leaves the leaf behind, the
/// crash plant the next start of that home recovers through its probe. Owns the lock for process life.
pub struct InstanceLock {
    /// The runtime leaf holding the socket, removed when it is empty.
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
    /// `serve.lock`, held for the run; dropped after the socket and the leaf are gone.
    serve: ServeLock,
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

    /// `serve.lock`, held for this run, to record the root it admits under `--admit`.
    pub fn serve_lock(&self) -> &ServeLock {
        &self.serve
    }

    /// Graceful teardown, the same as dropping it: see the [`Drop`] impl.
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for InstanceLock {
    /// Unlink the socket ONLY while the path still names the socket this instance bound (stat without
    /// following links, compare `(dev, ino)` against the identity captured at bind), then remove the leaf,
    /// which `remove_dir` does only when it is empty. Both happen while `serve.lock` is still held, so no
    /// start of this home can make the leaf meanwhile; the lock goes after, as the fields drop. A blind
    /// by-path unlink could remove a file a same-uid process swapped in.
    fn drop(&mut self) {
        if path_identity(&self.socket).is_ok_and(|id| id == self.socket_id) {
            let _ = std::fs::remove_file(&self.socket);
        }
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
    /// pre-loosened dir still refuses. `None` when the leaf was removed between its create and its verify,
    /// as a resident on its way out removes it: the caller tries again.
    pub fn acquire(home: &Home, root: &Path) -> Result<Option<Self>, SingleError> {
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
        Ok(match verify_runtime_chain(root, &dir)? {
            Chain::Verified => Some(Self { dir }),
            Chain::Vanished => None,
        })
    }

    /// The verified leaf dir.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// `<leaf>/control.sock`: the rendezvous, inside the verified leaf.
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join("control.sock")
    }
}

/// Acquire single-instance for `home` under the already-resolved runtime `root`: take `serve.lock`
/// exclusive without waiting, under `home.lock`, and record our pid in it; then create and verify the
/// runtime chain, connect-probe-then-unlink-bind the socket, and return the held lock plus the bound
/// listener. A second holder gets [`SingleError::AlreadyResident`] naming the winner's pid and never
/// touches the winner's socket: the lock, not the probe, is what keeps a legitimate resident's path safe.
/// Under our own lock a socket that answers a connect is [`SingleError::ProbeAlive`], and any answer that
/// is neither live nor one of the two stale answers is [`SingleError::ProbeUnclassified`].
///
/// # Errors
///
/// [`SingleError`], as above, and for a socket path too long to bind or an insecure runtime directory.
pub async fn acquire(
    home: &Home,
    root: &Path,
) -> Result<(InstanceLock, std::os::unix::net::UnixListener), SingleError> {
    // Before anything is created: a path `sun_path` cannot hold would be bound truncated, or not at all.
    let socket_path = home.runtime_leaf(root).join("control.sock");
    if sockaddr_un(&socket_path).is_none() {
        return Err(SingleError::SocketPathTooLong { path: socket_path });
    }
    let serve = {
        let home_lock = HomeWrite::take(home).await?;
        let serve = match ServeLock::take(&home_lock, home) {
            Ok(serve) => serve,
            Err(ServeLockError::Held) => {
                return Err(match ServeLock::recorded(home).pid {
                    Some(pid) => SingleError::AlreadyResident { pid },
                    None => SingleError::KeyChanging,
                });
            }
            Err(ServeLockError::Lock(error)) => return Err(error.into()),
        };
        serve
            .record(&home_lock, None)
            .map_err(|source| crate::home::LockError {
                path: home.serve_lock(),
                source,
            })?;
        serve
    };
    // Under `serve.lock` no other start of this home makes or removes the leaf, and a resident on its way
    // out removed it before it let the lock go.
    let runtime = match RuntimeDir::acquire(home, root)? {
        Some(runtime) => runtime,
        None => return Err(insecure(&home.runtime_leaf(root))),
    };
    let socket_path = runtime.socket_path();
    // Connect-probe UNDER the lock: the lock already proved no legitimate resident holds this home (a
    // real resident would have won the lock and we would have returned AlreadyResident), so the socket
    // here is a crash plant or a same-uid squatter. `ENOENT`/`ECONNREFUSED` reclaim it (unlink, bind,
    // continue); a connect that completes (a socket that answers) refuses `ProbeAlive`; every other answer
    // refuses `ProbeUnclassified`. The probe is a courtesy that avoids clobbering a responding socket,
    // never the guarantee: the lock is what protects a legitimate resident.
    match probe_socket(&socket_path) {
        Probe::Stale => {}
        Probe::Live => return Err(SingleError::ProbeAlive),
        Probe::Unknown => return Err(SingleError::ProbeUnclassified),
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
    Ok((
        InstanceLock {
            leaf: runtime.path().to_owned(),
            socket: socket_path,
            socket_id,
            pid: std::process::id(),
            serve,
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
/// accepted target. A leaf that is not there at all is [`Chain::Vanished`], not a refusal.
// `core::io::ErrorKind` is still unstable, so the error kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn verify_runtime_chain(root: &Path, leaf: &Path) -> Result<Chain, SingleError> {
    if let Some(base) = root.parent() {
        verify_dir(std::fs::metadata(base), base)?;
    }
    verify_dir(std::fs::symlink_metadata(root), root)?;
    let handle = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(leaf)
    {
        Ok(handle) => handle,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Chain::Vanished),
        Err(_) => return Err(insecure(leaf)),
    };
    verify_dir(handle.metadata(), leaf)?;
    Ok(Chain::Verified)
}

/// What a verify of the runtime chain found, short of a refusal.
#[derive(Debug, PartialEq, Eq)]
enum Chain {
    /// Every component is this user's 0700 directory.
    Verified,
    /// The leaf is gone: a resident on its way out removed it after it was made.
    Vanished,
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
