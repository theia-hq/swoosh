//! The home's two locks: `home.lock`, held for a moment by every change to the home, and `serve.lock`, held
//! by a running `serve`.
//!
//! `home.lock` is a value, [`HomeWrite`]. Every function that writes the home takes it as an argument, so a
//! write without it does not compile and nothing below the function that took it takes it again. Taking it
//! twice would never return: a second flock on one file in one process waits on the first. It is never held
//! across a prompt or a network wait, and an async taker waits without blocking its thread.
//!
//! `serve.lock` is held exclusive by `swoosh serve` for its whole run, and records its pid and, under
//! `--admit`, the root it admits. A command that replaces this machine's key takes it too, without waiting,
//! so a key is never replaced under a serve running as it. It is taken and probed only under `home.lock`, so
//! a probe never makes a starting serve refuse, and what it records is never read half written.
//!
//! Both files are opened `O_NOFOLLOW`, owner-only, and never removed or replaced by a rename, so every holder
//! locks the same inode.

use core::time::Duration;
use std::fs::File;
use std::io::{self, Read as _, Seek as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use bifrost::NodeId;

use super::Home;
use crate::escape::EscapedPath;

/// How long an async taker waits between two tries while another process holds `home.lock`.
const RETRY: Duration = Duration::from_millis(10);

/// The most bytes read from `serve.lock`: a pid, a key and two newlines, with room to spare.
const RECORD_CAP: u64 = 256;

/// A lock file could not be opened or taken.
#[derive(Debug, thiserror::Error)]
#[error("{}: {source}", EscapedPath(.path))]
pub struct LockError {
    /// The lock file.
    pub path: PathBuf,
    /// Why.
    #[source]
    pub source: io::Error,
}

/// `<home>/home.lock`, held: a change to the home is under way. Released when this drops.
#[derive(Debug)]
#[must_use = "the home is held only while this value lives"]
pub struct HomeWrite {
    /// Held, never read: the lock lives exactly as long as this open file does.
    _held: File,
}

impl HomeWrite {
    /// Take `home.lock`, making the home if it is not there yet, and wait for any other change to finish.
    /// It waits without blocking the thread, so a task of this process holding it can finish meanwhile.
    ///
    /// # Errors
    ///
    /// [`LockError`] when the home or its lock file cannot be made or opened, or the lock fails.
    pub async fn take(home: &Home) -> Result<Self, LockError> {
        let path = home.home_lock();
        let file = open(home, &path)?;
        loop {
            if try_lock(&file, libc::LOCK_EX).map_err(|source| failed(&path, source))? {
                return Ok(Self { _held: file });
            }
            tokio::time::sleep(RETRY).await;
        }
    }

    /// [`take`](Self::take) for a synchronous verb, which waits on its own thread. Never called on a tokio
    /// worker.
    ///
    /// # Errors
    ///
    /// As [`take`](Self::take).
    pub fn wait(home: &Home) -> Result<Self, LockError> {
        let path = home.home_lock();
        let file = open(home, &path)?;
        flock(&file, libc::LOCK_EX).map_err(|source| failed(&path, source))?;
        Ok(Self { _held: file })
    }
}

/// Why `serve.lock` was not taken.
#[derive(Debug, thiserror::Error)]
pub enum ServeLockError {
    /// A running `serve` holds it, or a command replacing this machine's key does.
    #[error("swoosh serve is running; stop it first: swoosh stop")]
    Held,
    /// It could not be opened or taken.
    #[error(transparent)]
    Lock(#[from] LockError),
}

/// `<home>/serve.lock`, held exclusive: by a `serve` for its whole run, or by a command replacing this
/// machine's key while it runs. Emptied and released when this drops.
#[derive(Debug)]
#[must_use = "the lock is held only while this value lives"]
pub struct ServeLock {
    /// The flocked lock file, written through to record the holder.
    file: File,
}

/// What `serve.lock` records: the pid of the `serve` that wrote it, and the root it admits under `--admit`.
/// Read without the lock, so it can name a `serve` that has since stopped; [`serve_running`] asks first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Recorded {
    /// The pid of the `serve` that wrote it.
    pub pid: Option<u32>,
    /// The root it admits, under `--admit`.
    pub admit: Option<NodeId>,
}

impl ServeLock {
    /// Take `serve.lock` exclusive without waiting, under `home.lock`, and empty it: what it records is now
    /// this holder's.
    ///
    /// # Errors
    ///
    /// [`ServeLockError::Held`] while a `serve` or a key replacement holds it; [`ServeLockError::Lock`] when
    /// it cannot be opened or taken.
    pub fn take(_home_lock: &HomeWrite, home: &Home) -> Result<Self, ServeLockError> {
        let path = home.serve_lock();
        let file = open(home, &path)?;
        if !try_lock(&file, libc::LOCK_EX).map_err(|source| failed(&path, source))? {
            return Err(ServeLockError::Held);
        }
        file.set_len(0).map_err(|source| failed(&path, source))?;
        Ok(Self { file })
    }

    /// Record this process as the running `serve`, admitting `admit` under `--admit`. Called under
    /// `home.lock`, so a `join` reading it sees all of it or none.
    ///
    /// # Errors
    ///
    /// The write failed.
    pub fn record(&self, _home_lock: &HomeWrite, admit: Option<NodeId>) -> io::Result<()> {
        let mut text = format!("{}\n", std::process::id());
        if let Some(root) = admit {
            text.push_str(&format!("{root}\n"));
        }
        let mut file = &self.file;
        file.set_len(0)?;
        file.rewind()?;
        file.write_all(text.as_bytes())?;
        file.sync_data()
    }

    /// The root a running `serve --admit` admits, or `None` when no `serve` holds the lock or the one that
    /// does admits none. Asked under `home.lock`, which every holder takes the lock under, so the answer
    /// holds until the caller lets `home.lock` go.
    ///
    /// # Errors
    ///
    /// [`LockError`] when the lock file cannot be opened or probed.
    pub fn admitting(_home_lock: &HomeWrite, home: &Home) -> Result<Option<NodeId>, LockError> {
        let path = home.serve_lock();
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(failed(&path, source)),
        };
        if try_lock(&file, libc::LOCK_SH).map_err(|source| failed(&path, source))? {
            return Ok(None);
        }
        Ok(parse(&file).admit)
    }

    /// What `serve.lock` records, read without the lock: an absent or unreadable file records nothing.
    pub fn recorded(home: &Home) -> Recorded {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(home.serve_lock())
            .map(|file| parse(&file))
            .unwrap_or_default()
    }
}

impl Drop for ServeLock {
    /// Empty the file before the lock goes, so a stopped `serve` leaves no pid or root behind.
    fn drop(&mut self) {
        let _ = self.file.set_len(0);
    }
}

/// Whether a `serve` runs on `home` now: asked over its control socket first, then read from the pid
/// `serve.lock` records. The answer can be stale by the time it is read, so it only chooses what a line
/// says; a command that must not run beside a `serve` takes [`ServeLock`] instead.
pub async fn serve_running(home: &Home) -> bool {
    use crate::node_client::{ControlClient, NodeClient as _};

    if let Ok(client) = ControlClient::resolve(home)
        && client.services().await.is_ok()
    {
        return true;
    }
    ServeLock::recorded(home).pid.is_some_and(alive)
}

/// Whether the process `pid` is alive: a signal 0 to it is delivered, or refused only for permission.
fn alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks that `pid` names a process this one may signal; nothing is delivered.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Parse what `serve.lock` records: the pid on its first line, the admitted root on its second.
fn parse(file: &File) -> Recorded {
    let mut text = String::new();
    if file.take(RECORD_CAP).read_to_string(&mut text).is_err() {
        return Recorded::default();
    }
    let mut lines = text.lines();
    Recorded {
        pid: lines.next().and_then(|line| line.trim().parse().ok()),
        admit: lines.next().and_then(|line| line.trim().parse().ok()),
    }
}

/// Open (creating) the lock file at `path` in `home`, owner-only, never following a link at its name, and
/// check it is a regular file.
fn open(home: &Home, path: &Path) -> Result<File, LockError> {
    crate::config::create_store_dir(home.dir()).map_err(|source| failed(home.dir(), source))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| failed(path, source))?;
    let meta = file.metadata().map_err(|source| failed(path, source))?;
    if !meta.is_file() {
        return Err(failed(path, io::Error::other("not a regular file")));
    }
    Ok(file)
}

/// Take `operation` on `file` without waiting: `true` when taken, `false` when another holder has it.
fn try_lock(file: &File, operation: libc::c_int) -> io::Result<bool> {
    match flock(file, operation | libc::LOCK_NB) {
        Ok(()) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::EWOULDBLOCK) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The one flock call: `operation` on `file`.
fn flock(file: &File, operation: libc::c_int) -> io::Result<()> {
    // SAFETY: `file` owns a valid fd for the whole call, and `flock` only attaches an advisory lock to it,
    // released when the file is closed.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Name `path` on a failed lock.
fn failed(path: &Path, source: io::Error) -> LockError {
    LockError {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
