//! The home lock: a running node and a restore never share a home.
//!
//! A node loads its key once and serves as it for the rest of its life, so replacing the key file under it
//! leaves a node serving an identity the disk no longer names, and after `restore --force` its memory holds
//! the last copy of the key it displaced. Asking whether a node is running cannot close that: a plain
//! `serve` answers nothing, and the answer is stale by the time the restore lands. So every serving node
//! holds this lock SHARED for its whole life, and a restore takes it EXCLUSIVE for its whole run: whichever
//! comes second is refused, and neither can slip between the other's check and its write.
//!
//! `protect` holds it shared too. It rewrites the key file but never changes the key, so it is safe beside
//! a running node, and holding the lock keeps it from interleaving with a restore.

use std::io;
use std::os::fd::AsRawFd as _;

use crate::home::Home;

/// How many times a holder tries a lock someone else holds before refusing.
const TRIES: u32 = 4;

/// How long a holder waits between tries: long enough to outlast an [`HomeLock::is_held`] probe, short
/// enough that the refusal beside a real holder (a node or a restore, held for its whole run) still comes
/// at once.
const RETRY: core::time::Duration = core::time::Duration::from_millis(25);

/// A held home lock. The lock is released when this drops, or when the process ends however it ends.
#[derive(Debug)]
#[must_use = "the home lock is held only while this value lives"]
pub struct HomeLock {
    /// Held, never read: the lock lives exactly as long as this open file does.
    _held: std::fs::File,
}

/// How a holder uses the home's key.
#[derive(Clone, Copy)]
enum Hold {
    /// Reads or rewrites the key without changing it: a serving node, `protect`.
    Shared,
    /// Replaces the key: `restore`.
    Exclusive,
}

impl HomeLock {
    /// Hold the lock for as long as a node serves this home. Refused while a restore runs.
    pub fn serving(home: &Home) -> eyre::Result<Self> {
        Self::take(home, Hold::Shared).map_err(|_| {
            eyre::eyre!(
                "an identity restore is running on {}; start the node when it has finished",
                home.dir().display()
            )
        })
    }

    /// Hold the lock while the key file is rewritten under the same key. Refused while a restore runs.
    pub(super) fn rewriting(home: &Home) -> eyre::Result<Self> {
        Self::take(home, Hold::Shared).map_err(|_| {
            eyre::eyre!(
                "an identity restore is running on {}; try again when it has finished",
                home.dir().display()
            )
        })
    }

    /// Hold the lock while the key is replaced. Refused while a node serves this home, or while anything
    /// else holds it.
    pub(super) fn replacing(home: &Home) -> eyre::Result<Self> {
        Self::take(home, Hold::Exclusive).map_err(|_| {
            eyre::eyre!(
                "a node is running on {}, or another identity command is; stop it (`swoosh stop`, or \
                 Ctrl-C where it runs), then restore",
                home.dir().display()
            )
        })
    }

    /// Whether a node serves this home now: something holds its lock. Asked without waiting, and the
    /// answer can be stale by the time it is read, so it only chooses what a line says. The probe holds
    /// the lock for an instant, which [`take`](Self::take) outlasts, so it never makes a holder refuse.
    pub fn is_held(home: &Home) -> bool {
        let Ok(file) = std::fs::File::open(home.identity_lock()) else {
            return false;
        };
        // SAFETY: `file` owns a valid fd for the whole call, and `flock` only attaches an advisory lock to
        // it, released when `file` drops at the end of this function. `LOCK_NB` makes a held lock an error.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) != 0 }
    }

    /// Open (creating) the lock file owner-only and take the lock, trying again a few times over a moment
    /// so that [`is_held`](Self::is_held)'s brief probe never makes a holder refuse. `Err` means someone
    /// holds it in a way that excludes `hold` for longer than that, or the lock itself failed; either way
    /// the caller refuses.
    fn take(home: &Home, hold: Hold) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;

        crate::config::create_store_dir(home.dir())?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(home.identity_lock())?;
        let operation = match hold {
            Hold::Shared => libc::LOCK_SH,
            Hold::Exclusive => libc::LOCK_EX,
        };
        let mut tries = TRIES;
        loop {
            // SAFETY: `file` owns a valid fd for the whole call, and `flock` only attaches an advisory lock
            // to it. `LOCK_NB` makes a contended lock an error rather than a wait.
            if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
                return Ok(Self { _held: file });
            }
            let error = io::Error::last_os_error();
            tries -= 1;
            if tries == 0 || error.kind() != io::ErrorKind::WouldBlock {
                return Err(error);
            }
            std::thread::sleep(RETRY);
        }
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
