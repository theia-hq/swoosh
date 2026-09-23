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

    /// Open (creating) the lock file owner-only and take the lock without waiting. `Err` means someone
    /// holds it in a way that excludes `hold`, or the lock itself failed; either way the caller refuses.
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
        // SAFETY: `file` owns a valid fd for the whole call, and `flock` only attaches an advisory lock to
        // it. `LOCK_NB` makes a contended lock an error rather than a wait.
        if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { _held: file })
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
