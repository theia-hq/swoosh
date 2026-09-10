//! Single-instance for `serve --resident`: the flock truth plus the socket rendezvous.
//!
//! The LOCK FILE is the truth; the SOCKET is the rendezvous. Start, all under one exclusive flock:
//! verify the 0700 runtime dir, take `LOCK_EX | LOCK_NB` on `control.lock`, connect-probe the socket
//! (a live answer means a squatter or a live node on a borrowed lock: refuse, never unlink a live
//! socket), else unlink the stale path, rebind, and record our pid. Hold the fd for life: a crash
//! releases the flock by itself, and the next start recovers through the probe, no reaper.

use std::os::unix::io::AsRawFd as _;
use std::path::PathBuf;

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
    /// The runtime dir is not the 0700 dir of this user: created AND verified, never assumed.
    #[error("refusing insecure runtime dir {path}: want uid {want} mode 700")]
    RuntimeDirInsecure {
        /// The offending dir.
        path: PathBuf,
        /// The uid that must own it.
        want: u32,
    },
    /// The socket answered while we hold the lock: a live node or a squatter, never unlink it.
    #[error("the control socket is live under our lock; refusing to steal it")]
    ProbeAlive,
    /// Binding the socket after a stale probe failed.
    #[error("could not bind the control socket")]
    BindFailed(#[source] std::io::Error),
}

/// The held single-instance lock: the flock fd plus the paths it guards. Dropping it releases the
/// flock (the crash path); the graceful path unlinks the socket first via
/// [`release`](InstanceLock::release). Owns the fd for process life.
///
/// There is no `Drop` impl that unlinks: a plain drop leaves the socket path behind (the crash
/// plant the next start recovers through its probe), and only the explicit `release` unlinks, so
/// the two teardown shapes stay visibly distinct at the call site. The `file`/`dir` fields are the
/// held flock fd and the runtime dir: read by the OS (the lock) and by `release` (the unlink), so
/// no accessor is needed.
#[allow(dead_code)]
pub struct InstanceLock {
    /// The lock fd: held open, flocked, for the life of the resident.
    file: std::fs::File,
    /// The runtime dir this lock lives in (for the graceful unlink).
    dir: PathBuf,
    /// The socket this instance bound (for the graceful unlink).
    socket: PathBuf,
    /// This instance's pid, recorded in the lock file.
    pid: u32,
}

impl InstanceLock {
    /// The pid this instance recorded.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The socket path this instance bound.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket
    }

    /// Graceful teardown: unlink the socket, then drop the lock fd (releasing the flock).
    pub fn release(self) {
        let _ = std::fs::remove_file(&self.socket);
        drop(self);
    }
}

/// The verified runtime dir root for a resident: created 0700, then `stat`ed for owner and mode.
/// Understands being pointed at an existing dir (re-verify) or nothing (create). A wrong owner or
/// a wrong mode is [`SingleError::RuntimeDirInsecure`], never silently repaired.
pub struct RuntimeDir {
    /// The verified dir.
    dir: PathBuf,
}

impl RuntimeDir {
    /// Create (0700) and verify the per-home runtime dir for `home`. An existing dir keeps its
    /// mode (verified below, never silently repaired by the create path): only a dir WE create
    /// gets the explicit 0700 set, so a pre-loosened dir still refuses.
    pub fn acquire(home: &Home) -> Result<Self, SingleError> {
        let dir = home
            .runtime_dir()
            .map_err(|_| SingleError::RuntimeDirInsecure {
                path: PathBuf::from("<unresolved runtime root>"),
                want: euid(),
            })?;
        let fresh = !dir.exists();
        // SAFETY: `DirBuilder::mode` only sets the mode argument for the mkdir syscall; no raw
        // pointer crosses the boundary.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(&dir)
                .map_err(|_| SingleError::RuntimeDirInsecure {
                    path: dir.clone(),
                    want: euid(),
                })?;
            // A umask-built leaf (or a stale 0755 leaf the OS left behind) would fail the verify
            // below on its mode alone. Repair ONLY a dir we just created: a PRE-EXISTING loosened
            // dir is the attack the verifier refuses, so it must not be silently fixed here.
            if fresh {
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&dir).map_err(|_| SingleError::RuntimeDirInsecure {
                path: dir.clone(),
                want: euid(),
            })?;
        }
        verify_runtime_dir(&dir)?;
        Ok(Self { dir })
    }

    /// The verified dir.
    pub fn path(&self) -> &std::path::Path {
        &self.dir
    }

    /// The lock path inside this dir.
    pub fn lock_path(&self, home: &Home) -> Result<PathBuf, SingleError> {
        home.control_lock()
            .map_err(|_| SingleError::RuntimeDirInsecure {
                path: self.dir.clone(),
                want: euid(),
            })
    }

    /// The socket path inside this dir.
    pub fn socket_path(&self, home: &Home) -> Result<PathBuf, SingleError> {
        home.control_socket()
            .map_err(|_| SingleError::RuntimeDirInsecure {
                path: self.dir.clone(),
                want: euid(),
            })
    }
}

/// Acquire single-instance for `home`: verify the runtime dir, take the exclusive nonblocking flock,
/// connect-probe-then-unlink-bind the socket, record our pid, and return the held lock plus the bound
/// listener. The whole sequence runs UNDER the flock; the lock outlives the return (held by the
/// caller for process life). A second holder gets [`SingleError::AlreadyResident`] naming the
/// winner's pid; a live socket under our own lock is [`SingleError::ProbeAlive`].
pub fn acquire(
    home: &Home,
) -> Result<(InstanceLock, std::os::unix::net::UnixListener), SingleError> {
    let runtime = RuntimeDir::acquire(home)?;
    let lock_path = runtime.lock_path(home)?;
    let socket_path = runtime.socket_path(home)?;
    // Open (creating) the lock file, then take the EXCLUSIVE NONBLOCKING flock: the truth.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|_| SingleError::RuntimeDirInsecure {
            path: lock_path.clone(),
            want: euid(),
        })?;
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
        return Err(SingleError::RuntimeDirInsecure {
            path: lock_path,
            want: euid(),
        });
    }
    // Connect-probe UNDER the lock: a live answer means a squatter or a live node on a borrowed
    // lock, so bail LOUD and never unlink a live socket. `ECONNREFUSED`/`ENOENT` is stale: unlink,
    // bind, and continue. Any other probe error is treated as stale too (nothing answered).
    if probe_live(&socket_path) {
        // Release before returning so a probe refusal does not strand the flock.
        // SAFETY: same valid-fd contract as above; `LOCK_UN` only drops this fd's advisory lock.
        let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return Err(SingleError::ProbeAlive);
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener =
        std::os::unix::net::UnixListener::bind(&socket_path).map_err(SingleError::BindFailed)?;
    // Defense in depth: the dir + peer-cred carry the weight (the mode is moot on macOS), but a
    // 0600 socket costs nothing.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
    }
    // Record our pid in the lock file (truncate + write), so the next contender names us.
    let pid = std::process::id();
    {
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).truncate(true);
        if let Ok(mut handle) = options.open(&lock_path) {
            let _ = writeln!(handle, "{pid}");
        }
    }
    Ok((
        InstanceLock {
            file,
            dir: runtime.dir,
            socket: socket_path,
            pid,
        },
        listener,
    ))
}

/// Whether the socket at `path` answers a connect: `Ok` (connected) means LIVE. `ENOENT` (nothing
/// there) and `ECONNREFUSED` (a dead listener's leftover path) both mean stale. Any other outcome
/// (permissions, odd states) is treated as not-live: the bind step decides, loudly.
fn probe_live(path: &std::path::Path) -> bool {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => true,
        // `std::io::ErrorKind` is still unstable in `core`, so the NotFound check reads from `std`.
        #[allow(clippy::std_instead_of_core)]
        Err(error) => {
            !matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) && probe_connect_succeeded_despite_kind(error)
        }
    }
}

/// A connect that failed with an unclassified kind still answered if the OS reports the socket as
/// accepting: conservatively treat every non-NotFound/non-Refused error as NOT live (stale), so a
/// wedged path never blocks a fresh bind. Returns false always: the name documents the policy at
/// the call site.
fn probe_connect_succeeded_despite_kind(_error: std::io::Error) -> bool {
    false
}

/// Read the pid recorded in the lock file, if any.
fn read_lock_pid(path: &std::path::Path) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    text.split_whitespace().next()?.parse().ok()
}

/// Verify the runtime dir is owned by this user and is mode 0700. Created AND verified, never
/// assumed: a foreign-owned or group-readable dir refuses the start.
fn verify_runtime_dir(dir: &std::path::Path) -> Result<(), SingleError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let meta = std::fs::metadata(dir).map_err(|_| SingleError::RuntimeDirInsecure {
        path: dir.to_owned(),
        want: euid(),
    })?;
    let want = euid();
    if meta.uid() != want || meta.permissions().mode() & 0o777 != 0o700 {
        return Err(SingleError::RuntimeDirInsecure {
            path: dir.to_owned(),
            want,
        });
    }
    Ok(())
}

/// The effective uid: the owner every runtime path must verify against.
fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
#[path = "serve_single_tests.rs"]
mod single_tests;
