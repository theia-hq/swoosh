//! `root backup <dir>`: copy the root kept on this machine to a directory of its own.
//!
//! A copy is the root's two files, `root.key` and `devices`, and nothing else, so `--root <dir>`, `root forget
//! <dir>` and `root restore <dir>` all name the same directory. The key is copied as it is stored, locked
//! with its passphrase: nothing is unlocked and nothing is asked. `devices` is written first and `root.key`
//! last, each through the one write routine, so a run killed between them leaves a directory with no key,
//! which running it again finishes.

use std::io::{self, Read as _};
use std::os::unix::fs::PermissionsExt as _;
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
    /// This machine keeps no root and is no root's device.
    #[error(
        "this machine holds no root, so there is nothing to back up. A lost device is replaced, not restored: \
         invite a new one."
    )]
    NoRoot,
    /// This machine is a device of a root kept elsewhere.
    #[error("your root is not on this machine; back it up on the machine that keeps it.")]
    NotHere,
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
    /// `<dir>` could not be read.
    #[error("could not read {}", EscapedPath(.dir))]
    Unreadable {
        /// The directory named.
        dir: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// The copy, read back, is not this root's.
    #[error(
        "the copy in {} does not read back as your root; do not rely on it. Your root is still on this machine.",
        EscapedPath(.dir)
    )]
    ReadBack {
        /// The directory named.
        dir: PathBuf,
    },
    /// The root, its records, or a file failed.
    #[error(transparent)]
    Root(#[from] RootError),
}

/// What a backup did with the copy's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a key replaced in the copy is said"]
pub enum Copied {
    /// The copy held no key: this machine's was written.
    New,
    /// The copy held this machine's key, byte for byte, and kept it.
    Kept,
    /// The copy held another key file of this root, locked differently or damaged: this machine's replaced
    /// it, so the copy now opens with the passphrase this machine's key opens with.
    Replaced,
}

/// Copy the root kept on this machine into `dir`: a new directory, made owner-only, an empty one, made
/// owner-only, or one holding a copy of this same root, which is brought up to date. Asks for nothing and
/// unlocks nothing.
///
/// # Errors
///
/// No root is kept here; `dir` holds anything else; or a read or a write failed.
pub async fn backup(home: &Home, dir: &Path) -> Result<Copied, BackupError> {
    let root = match Standing::read(home).await.map_err(RootError::from)? {
        Standing::HoldsRoot { pin, .. } => pin,
        Standing::InterruptedMint { root_key } => {
            return Err(RootError::Unfinished { root: root_key }.into());
        }
        Standing::Device { .. } => return Err(BackupError::NotHere),
        Standing::Unpinned => return Err(BackupError::NoRoot),
    };
    let pin = root.verify_key().map_err(RootError::from)?;
    // Read before `home.lock` is taken: what a planted directory holds is judged with nobody waiting on it.
    let held = copy_of_this_root(dir, root)?;
    // Under `home.lock`, so the key and the list are copied as one root act would leave them.
    let home_lock = HomeWrite::take(home).await.map_err(RootError::from)?;
    crate::config::create_store_dir(dir).map_err(super::io_at(dir))?;
    if held.is_new() {
        // A directory that was already there, empty, is made owner-only as a new one is.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(super::io_at(dir))?;
    }
    let list = read_list(home, None, pin)?;
    // A copy's list is only ever replaced by a newer one: a copy used with `--root` may be ahead of this
    // machine, and an older list over it would lose what it signed.
    if let Some(list) = &list
        && held
            .list
            .as_ref()
            .is_none_or(|copied| copied.epoch() < list.epoch())
    {
        let bytes = std::fs::read(home.devices()).map_err(super::io_at(&home.devices()))?;
        write(&home_lock, &dir.join(LIST_FILE), &bytes)?;
    }
    // The key is kept only when it is this machine's, byte for byte: a damaged or a different key in the copy
    // is replaced, never reported as copied.
    let key_bytes = read_key(&home.root_key())?;
    let copied = match held.key.as_deref() {
        None => Copied::New,
        Some(kept) if kept == key_bytes.as_slice() => Copied::Kept,
        Some(_) => Copied::Replaced,
    };
    match copied {
        Copied::Kept => {}
        Copied::New | Copied::Replaced => write(&home_lock, &dir.join(KEY_FILE), &key_bytes)?,
    }
    for temp in &held.temps {
        let _ = std::fs::remove_file(temp);
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
    Ok(copied)
}

/// What a directory named for a copy already holds of this root.
#[derive(Default)]
struct Held {
    /// The bytes of `root.key`, when it is there.
    key: Option<Vec<u8>>,
    /// The list beside it, verified under the root, when there is one.
    list: Option<crate::roster::RosterDoc>,
    /// The temps a run killed mid-write left, removed once the copy is whole.
    temps: Vec<PathBuf>,
}

impl Held {
    /// Whether the directory holds no part of a copy: absent, empty, or temps alone.
    fn is_new(&self) -> bool {
        self.key.is_none() && self.list.is_none()
    }
}

/// What `dir` already holds, when it is a copy of `root` or nothing. Anything else in it (another file, another
/// root's key, a list this root did not sign) refuses, so a backup never writes into a directory that holds
/// something else. A directory of temps alone, which a run killed during its first write leaves, is empty.
fn copy_of_this_root(dir: &Path, root: bifrost::NodeId) -> Result<Held, BackupError> {
    let not_empty = || BackupError::NotEmpty {
        dir: dir.to_path_buf(),
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Held::default()),
        Err(source) => {
            return Err(BackupError::Unreadable {
                dir: dir.to_path_buf(),
                source,
            });
        }
    };
    let mut held = Held::default();
    let (mut keyed, mut listed) = (false, false);
    // Stops at the first name that is not the copy's: a planted directory is not read through.
    for entry in entries {
        let entry = entry.map_err(|source| BackupError::Unreadable {
            dir: dir.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == KEY_FILE {
            keyed = true;
        } else if name == LIST_FILE {
            listed = true;
        } else if [KEY_FILE, LIST_FILE]
            .iter()
            .any(|file| name.starts_with(&format!("{file}.tmp.")))
            && entry
                .path()
                .symlink_metadata()
                .is_ok_and(|meta| meta.is_file())
        {
            // A run killed mid-write leaves its unique temp beside the file it was writing.
            held.temps.push(entry.path());
        } else {
            return Err(not_empty());
        }
    }
    let pin = root.verify_key().map_err(RootError::from)?;
    if keyed {
        let key = dir.join(KEY_FILE);
        let header = read_header(&key).and_then(|locked| header_key(&key, &locked));
        if !matches!(header, Ok(header) if header == root) {
            return Err(not_empty());
        }
        held.key = Some(read_key(&key)?);
    }
    if listed {
        held.list = super::read_list_at(&dir.join(LIST_FILE), pin)
            .map_err(|_| not_empty())?
            .map(|(list, _)| list);
    }
    Ok(held)
}

/// The root key file's bytes, as stored: locked with its passphrase. A regular file only, read with a cap.
fn read_key(path: &Path) -> Result<Vec<u8>, RootError> {
    let file = std::fs::File::open(path).map_err(super::io_at(path))?;
    if !file.metadata().map_err(super::io_at(path))?.is_file() {
        return Err(RootError::Io {
            path: path.to_path_buf(),
            source: io::ErrorKind::InvalidData.into(),
        });
    }
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
