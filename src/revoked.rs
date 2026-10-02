//! `<home>/revoked`: everything this machine refuses for good, in one grow-only file. The links it took
//! back, the device keys it no longer admits and the roots it no longer trusts are all entries of one
//! [`Denylist`], and `<home>/revoked.written` is its one witness: how many entries the file held after its
//! last write, so a file that lost entries reads as damaged rather than as fewer revocations.
//!
//! [`open`] is the one reader: the `serve` gate, a sync choosing whom to dial, a root act bringing its
//! records forward and every check of a pin all read the file through it, so each sees the same set on the
//! same rules. [`add`] is the one writer, under `home.lock`, which the caller holds. No write removes an
//! entry.

use std::io;
use std::path::PathBuf;

use nauthy::{Denylist, DenylistError, Revocation, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;

use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite, LooseFile};

/// Why `<home>/revoked` could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum RevokedError {
    /// The file, or its witness, exists but could not be read or written.
    #[error("could not use {}", EscapedPath(path))]
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// Another user owns the file, or others can write it.
    #[error(transparent)]
    Loose(#[from] LooseFile),
    /// A line of the file is not an entry.
    #[error("{} line {line} is not a revocation", EscapedPath(path))]
    Parse {
        /// The file.
        path: PathBuf,
        /// The first line that is not an entry, from 1.
        line: u32,
    },
    /// The file is larger than a list of revocations can be.
    #[error("{} is larger than a list of revocations can be", EscapedPath(path))]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// The file holds fewer entries than its witness says a write left there (an absent file holds none).
    /// No write shrinks it, so entries were lost to a deletion, a truncation or a crash, and reading it would
    /// admit them again. Whether to restore the file or accept the loss is the person's call, so the line
    /// names no command.
    #[error(
        "{} has lost revocations: it holds {found} where it held {expected}, and swoosh will not read it with entries missing",
        EscapedPath(path)
    )]
    Lost {
        /// The file.
        path: PathBuf,
        /// The count the witness records.
        expected: u64,
        /// The count the file holds now.
        found: u64,
    },
}

impl RevokedError {
    /// Name nauthy's refusal for the file at `path`, so every line prints the path through the escaper.
    fn of(path: PathBuf, error: DenylistError) -> Self {
        match error {
            DenylistError::Io(source) => Self::Io { path, source },
            DenylistError::Parse { line } => Self::Parse { path, line },
            DenylistError::TooLarge => Self::TooLarge { path },
            DenylistError::Lost {
                expected, found, ..
            } => Self::Lost {
                path,
                expected,
                found,
            },
            // `home.lock` guards every file in the home, so a write under it is never refused for its lock;
            // the arm stays for a refusal nauthy adds later.
            other => Self::Io {
                path,
                source: io::Error::other(other),
            },
        }
    }
}

/// Read `<home>/revoked`: the one reader. An absent file holds nothing while its witness is absent too.
///
/// The store it returns re-reads the file when it changes and only ever adds what it reads, so a running
/// reader keeps every entry it has seen, whatever happens to the file.
///
/// # Errors
///
/// A file another user owns or others can write, one that cannot be read, is too large, holds a line that
/// is not an entry, or holds fewer entries than its witness. Each fails closed: a reader never goes on with
/// a set that may be missing a revocation.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub fn open(home: &Home) -> Result<Denylist, RevokedError> {
    let path = home.revoked();
    match crate::home::open_trust_file(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(match loose_file(error) {
                Ok(loose) => RevokedError::Loose(loose),
                Err(source) => RevokedError::Io { path, source },
            });
        }
    }
    Denylist::load(path.clone()).map_err(|error| RevokedError::of(path, error))
}

/// Add `entries` to `<home>/revoked` and raise its witness, under `home.lock`, which the caller holds.
///
/// The write re-reads the file and writes the union, so it never drops an entry another writer added, and a
/// file that lost entries is written back with what it holds plus `entries`: a revocation always lands,
/// while [`open`] goes on refusing the file until it holds what it once did. An entry the file holds already
/// writes nothing.
///
/// Never this machine's own key, whichever writer names it: a key in `revoked` refuses every link rooted at
/// it, and the links this machine signed let people reach it, whoever revoked it as a device. A copy of an
/// old root folded here, or a revoke of this machine's own standing, could otherwise close every one of
/// them, the way back in included. The root still ends the membership: the pick-up refuses a standing whose
/// key an update revokes.
///
/// # Errors
///
/// The file could not be read or written, or the union would be larger than the file can be; or an entry
/// is a key and this machine's key file could not be read.
pub fn add(
    home_lock: &HomeWrite,
    home: &Home,
    entries: impl IntoIterator<Item = Revocation>,
) -> Result<(), RevokedError> {
    let mut entries: Vec<Revocation> = entries.into_iter().collect();
    if entries
        .iter()
        .any(|entry| matches!(entry, Revocation::Key(_)))
        && let Some(own) = own_key(home)?
    {
        entries.retain(|entry| !matches!(entry, Revocation::Key(key) if *key == own));
    }
    if entries.is_empty() {
        return Ok(());
    }
    let path = home.revoked();
    Denylist::for_repair(path.clone())
        .revoke(home_lock, entries)
        .map_err(|error| RevokedError::of(path, error))
}

/// This machine's key, from its key file's header; `None` when it has none, or the header is not a usable
/// key.
fn own_key(home: &Home) -> Result<Option<VerifyKey>, RevokedError> {
    let file = keystore::KeyFile::device(home.key());
    let stored = file.load().map_err(|error| RevokedError::Io {
        path: home.key(),
        source: io::Error::other(error),
    })?;
    Ok(stored.and_then(|stored| {
        crate::identity::key_of(&file, &stored)
            .ok()?
            .verify_key()
            .ok()
    }))
}

/// The [`LooseFile`] an error from [`open_trust_file`](crate::home::open_trust_file) carries, or the error.
fn loose_file(error: io::Error) -> Result<LooseFile, io::Error> {
    if crate::home::loose_in(&error).is_none() {
        return Err(error);
    }
    match error.into_inner() {
        Some(inner) => inner
            .downcast::<LooseFile>()
            .map(|loose| *loose)
            .map_err(io::Error::other),
        None => Err(io::Error::other("a loose file")),
    }
}
