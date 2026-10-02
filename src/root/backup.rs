//! `root backup <dir>`: copy the root kept on this machine to a directory of its own.
//!
//! A copy is the root's two files, `root.key` and `devices`, and nothing else, so `--root <dir>`, `root forget
//! <dir>` and `root restore <dir>` all name the same directory. The key is copied as it is stored, locked
//! with its passphrase: nothing is unlocked and nothing is asked. `devices` is written first and `root.key`
//! last, each through the one write routine, so a run killed between them leaves a directory with no key,
//! which running it again finishes.

use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use tightbeam::identity::AsVerifyKey as _;

use super::{KEY_FILE, LIST_FILE, RootError, header_key, read_header, read_list};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::standing::Standing;

/// The most bytes of a key file a copy reads, as the key store caps its own read: a sealed root key is a few
/// hundred bytes.
const KEY_CAP: u64 = 4096;

/// Why a root could not be copied.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// This machine keeps no root.
    #[error(
        "this machine holds no root, so there is nothing to back up. A lost device is replaced, not restored: \
         invite a new one."
    )]
    NoRoot,
    /// `<dir>` holds something other than a copy of this root.
    #[error(
        "{} is not empty; name a new directory: swoosh root backup {}",
        EscapedPath(.dir),
        EscapedPath(&.dir.join("swoosh-root"))
    )]
    NotEmpty {
        /// The directory named.
        dir: PathBuf,
    },
    /// The copy, read back, is not this root's.
    #[error("the copy in {} did not read back as your root", EscapedPath(.dir))]
    ReadBack {
        /// The directory named.
        dir: PathBuf,
    },
    /// The root, its records, or a file failed.
    #[error(transparent)]
    Root(#[from] RootError),
}

/// Copy the root kept on this machine into `dir`: a new directory, made owner-only, or one holding a copy
/// of this same root, which is brought up to date. Asks for nothing and unlocks nothing.
///
/// # Errors
///
/// No root is kept here; `dir` holds anything else; or a read or a write failed.
pub async fn backup(home: &Home, dir: &Path) -> Result<(), BackupError> {
    let root = match Standing::read(home).await.map_err(RootError::from)? {
        Standing::HoldsRoot { pin, .. } => pin,
        Standing::InterruptedMint { root_key } => {
            return Err(RootError::Unfinished { root: root_key }.into());
        }
        Standing::Device { .. } | Standing::Unpinned => return Err(BackupError::NoRoot),
    };
    let pin = root.verify_key().map_err(RootError::from)?;
    // Under `home.lock`, so the key and the list are copied as one root act would leave them.
    let home_lock = HomeWrite::take(home).await.map_err(RootError::from)?;
    let held = copy_of_this_root(dir, root)?;
    crate::config::create_store_dir(dir).map_err(super::io_at(dir))?;
    let list = read_list(home, None, pin)?;
    let copied = held.as_ref().and_then(|held| held.list.as_ref());
    // A copy's list is only ever replaced by a newer one: a copy used with `--root` may be ahead of this
    // machine, and an older list over it would lose what it signed.
    if let Some(list) = &list
        && copied.is_none_or(|copied| copied.epoch() < list.epoch())
    {
        let bytes = std::fs::read(home.devices()).map_err(super::io_at(&home.devices()))?;
        write(&home_lock, &dir.join(LIST_FILE), &bytes)?;
    }
    if !held.as_ref().is_some_and(|held| held.keyed) {
        write(
            &home_lock,
            &dir.join(KEY_FILE),
            &read_key(&home.root_key())?,
        )?;
    }
    drop(home_lock);
    // Read back by its header alone, and its list verified under the root: the copy is this root's.
    let key = dir.join(KEY_FILE);
    let back = read_header(&key).and_then(|locked| header_key(&key, &locked));
    if !matches!(back, Ok(back) if back == root) || read_list(home, Some(dir), pin).is_err() {
        return Err(BackupError::ReadBack {
            dir: dir.to_path_buf(),
        });
    }
    Ok(())
}

/// What a directory named for a copy already holds of this root.
struct Held {
    /// Whether `root.key` is there.
    keyed: bool,
    /// The list beside it, verified under the root, when there is one.
    list: Option<crate::roster::RosterDoc>,
}

/// What `dir` already holds, when it is a copy of `root` or nothing: `None` for a directory that is absent
/// or empty. Anything else in it (another file, another root's key, a list this root did not sign) refuses,
/// so a backup never writes into a directory that holds something else.
fn copy_of_this_root(dir: &Path, root: bifrost::NodeId) -> Result<Option<Held>, BackupError> {
    let not_empty = || BackupError::NotEmpty {
        dir: dir.to_path_buf(),
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(not_empty()),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| not_empty())?;
        names.push(entry.file_name());
    }
    if names.is_empty() {
        return Ok(None);
    }
    // A run killed mid-write leaves its unique temp beside the file it was writing; it is ours to write over.
    let ours = |name: &std::ffi::OsStr| {
        let name = name.to_string_lossy();
        [KEY_FILE, LIST_FILE]
            .iter()
            .any(|file| name == *file || name.starts_with(&format!("{file}.tmp.")))
    };
    if !names.iter().all(|name| ours(name)) {
        return Err(not_empty());
    }
    let pin = root.verify_key().map_err(RootError::from)?;
    let key = dir.join(KEY_FILE);
    let keyed = key.exists();
    if keyed {
        let held = read_header(&key).and_then(|locked| header_key(&key, &locked));
        if !matches!(held, Ok(held) if held == root) {
            return Err(not_empty());
        }
    }
    let list = read_list_in(dir, pin).map_err(|_| not_empty())?;
    if !keyed && list.is_none() {
        return Err(not_empty());
    }
    Ok(Some(Held { keyed, list }))
}

/// The list in the copy at `dir`, verified under `pin`.
fn read_list_in(
    dir: &Path,
    pin: nauthy::VerifyKey,
) -> Result<Option<crate::roster::RosterDoc>, RootError> {
    let path = dir.join(LIST_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => crate::roster::verify(&bytes, pin)
            .map(Some)
            .map_err(|_| RootError::Damaged { path }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(RootError::Io { path, source }),
    }
}

/// The root key file's bytes, as stored: locked with its passphrase.
fn read_key(path: &Path) -> Result<Vec<u8>, RootError> {
    let file = std::fs::File::open(path).map_err(super::io_at(path))?;
    let mut bytes = Vec::new();
    file.take(KEY_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(super::io_at(path))?;
    if bytes.len() as u64 > KEY_CAP {
        return Err(RootError::Io {
            path: path.to_path_buf(),
            source: io::ErrorKind::InvalidData.into(),
        });
    }
    Ok(bytes)
}

/// Write one file of the copy through the one write routine.
fn write(home_lock: &HomeWrite, path: &Path, bytes: &[u8]) -> Result<(), RootError> {
    crate::config::write_private_atomic(home_lock, path, bytes).map_err(super::io_at(path))
}
