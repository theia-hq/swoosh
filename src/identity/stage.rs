//! Putting a sealed key file in place: written whole beside its target, read back, then published.
//!
//! The key file store writes a HOME key, on the home's own disk. A backup goes somewhere else, usually a
//! removable stick formatted FAT or exFAT, which has no hard links and no file modes. So `export` and
//! `restore` move sealed bytes the store has already sealed or verified, and this module is how those
//! bytes land: never over a file unasked, never torn, never over a file that changed since it was
//! compared, and never left behind as a stray copy.
//!
//! Only sealed bytes pass through here. A sealed file is encrypted, so moving it needs none of the
//! owner-only care a plain seed does; the home key it becomes is still created owner-only, and the store
//! still refuses a home key anyone else can read.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use eyre::WrapErr as _;
use keystore::{KeyFile, Passphrase, Protection};
use zeroize::Zeroizing;

/// The most a backup is read before it is refused: far above a sealed file's length, far below anything
/// that costs a restore to hold.
const READ_CAP: u64 = 4096;

/// What a stage's name carries after its target's: `<target>.swoosh.<pid>.<16 hex digits>`.
const STAGE_TAG: &str = ".swoosh.";

/// A sealed file written beside its target and read back, not yet in place. Dropped unpublished, it
/// removes itself; the target was never touched.
pub(super) struct Stage {
    path: PathBuf,
    published: bool,
}

impl Stage {
    /// Seal `secret` under `passphrase` beside `target` through the key file store, which reads the file
    /// back and unlocks it before this returns. The stage and its bytes, for publishing elsewhere.
    pub(super) fn seal(
        target: &Path,
        secret: &keystore::Secret,
        passphrase: &Passphrase,
    ) -> eyre::Result<(Self, Zeroizing<Vec<u8>>)> {
        sweep(target);
        let stage = Self {
            path: sibling(target),
            published: false,
        };
        KeyFile::device(stage.path.as_path()).write(secret, Protection::Passphrase(passphrase))?;
        let bytes = Zeroizing::new(fs::read(&stage.path)?);
        Ok((stage, bytes))
    }

    /// Write `bytes` to a fresh owner-only sibling of `target`, sync it, and read it back: the copy that
    /// will be published is the copy that was verified, on the disk it will live on.
    pub(super) fn write(target: &Path, bytes: &[u8]) -> eyre::Result<Self> {
        sweep(target);
        let stage = Self {
            path: sibling(target),
            published: false,
        };
        create_verified(&stage.path, bytes)?;
        Ok(stage)
    }

    /// Where the stage is.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Publish into absence. A hard link is the no-clobber publish: it fails if anything is at `target`,
    /// decided by the filesystem at that instant. A filesystem with no hard links (FAT, exFAT) gets the same
    /// guarantee from an exclusive create (`O_EXCL`), written, synced, and read back there.
    pub(super) fn publish_new(self, target: &Path, bytes: &[u8]) -> eyre::Result<()> {
        self.publish_new_with(target, bytes, |from, to| fs::hard_link(from, to))
    }

    /// [`publish_new`](Self::publish_new) over the given `link`, so a test can stand in a filesystem
    /// that has no hard links.
    fn publish_new_with(
        mut self,
        target: &Path,
        bytes: &[u8],
        link: impl FnOnce(&Path, &Path) -> io::Result<()>,
    ) -> eyre::Result<()> {
        match link(&self.path, target) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(occupied(target));
            }
            Err(error) if no_hard_links(&error) => create_verified(target, bytes)?,
            Err(error) => {
                return Err(error)
                    .wrap_err_with(|| format!("could not write {}", target.display()));
            }
        }
        // In place under its own name, so the stage's name goes before the directory is synced.
        let _ = fs::remove_file(&self.path);
        self.published = true;
        sync_dir(target)
    }

    /// Publish over `target`, which must still be the file `expected` describes: something that replaced
    /// or rewrote it since it was compared is left as it now is, never overwritten with a key chosen
    /// against the old one.
    pub(super) fn publish_over(mut self, target: &Path, expected: Seen) -> eyre::Result<()> {
        if Seen::of(target)? != expected {
            eyre::bail!(
                "{} changed while it was being replaced; it was left as it now is",
                target.display()
            );
        }
        fs::rename(&self.path, target)
            .wrap_err_with(|| format!("could not replace {}", target.display()))?;
        self.published = true;
        sync_dir(target)
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Which file a path named when it was compared: enough to tell, just before a replace, whether the
/// path still names that file unchanged. The change time is one a writer cannot set back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Seen {
    /// Nothing was there.
    Absent,
    /// This file: device, inode, length, and change time.
    File {
        file: (u64, u64),
        len: u64,
        changed: (i64, i64),
    },
}

impl Seen {
    /// What `path` names now.
    // `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    pub(super) fn of(path: &Path) -> eyre::Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Self::File {
                file: (metadata.dev(), metadata.ino()),
                len: metadata.len(),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::Absent),
            Err(error) => Err(error).wrap_err_with(|| format!("could not read {}", path.display())),
        }
    }
}

/// A backup's bytes, and its mode when that lets others read it.
pub(super) struct Backup {
    pub(super) bytes: Zeroizing<Vec<u8>>,
    pub(super) loose: Option<u32>,
}

/// Read the backup at `path` as a restore source: a regular file, of a key file's size, owned by this user
/// or root. Its mode is NOT held to owner-only, unlike a home key's: a backup is sealed, so its passphrase
/// is what protects it, and the removable media backups live on (FAT, exFAT) report every file as readable
/// by all, with no `chmod` that changes it. A loose mode is returned so the caller can say so.
pub(super) fn read_backup(path: &Path) -> eyre::Result<Backup> {
    let unreadable = || format!("could not read the backup {}", path.display());
    // Judged before opening: opening a pipe for reading blocks until a writer appears.
    if !fs::metadata(path).wrap_err_with(unreadable)?.is_file() {
        eyre::bail!("{} is not a regular file", path.display());
    }
    let mut file = File::open(path).wrap_err_with(unreadable)?;
    let metadata = file.metadata().wrap_err_with(unreadable)?;
    if !metadata.is_file() {
        eyre::bail!("{} is not a regular file", path.display());
    }
    let owner = metadata.uid();
    if owner != crate::node_client::euid() && owner != 0 {
        eyre::bail!(
            "the backup {} is owned by uid {owner}, not by this user or root",
            path.display()
        );
    }
    if metadata.len() > READ_CAP {
        eyre::bail!(
            "{} is {} bytes, far larger than a backup",
            path.display(),
            metadata.len()
        );
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(READ_CAP as usize));
    (&mut file)
        .take(READ_CAP)
        .read_to_end(&mut bytes)
        .wrap_err_with(unreadable)?;
    let mode = metadata.mode() & 0o7777;
    Ok(Backup {
        bytes,
        loose: (mode & 0o077 != 0).then_some(mode),
    })
}

/// Create `path` new and owner-only, write `bytes`, sync, and read them back. Removes the file again if
/// anything after its creation fails, since this call made it.
fn create_verified(path: &Path, bytes: &[u8]) -> eyre::Result<()> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Err(occupied(path)),
        Err(error) => {
            return Err(error).wrap_err_with(|| format!("could not write {}", path.display()));
        }
    };
    // From here the file is this call's own, so removing it on failure removes nothing else.
    let landed = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::read(path).map(Zeroizing::new));
    match landed {
        Ok(read) if read.as_slice() == bytes => Ok(()),
        Ok(_) => {
            let _ = fs::remove_file(path);
            eyre::bail!(
                "{} did not read back as written; it was removed",
                path.display()
            )
        }
        Err(error) => {
            let _ = fs::remove_file(path);
            Err(error).wrap_err_with(|| format!("could not write {}", path.display()))
        }
    }
}

/// A file that appeared at a path being written into absence.
fn occupied(path: &Path) -> eyre::Report {
    eyre::eyre!("{} already exists; it was left as it is", path.display())
}

/// Whether a hard link failed because the filesystem has none, rather than for a reason worth reporting.
/// FAT and exFAT answer `ENOTSUP` on macOS and `EPERM` on Linux. The codes are compared, not matched as
/// patterns, because `ENOTSUP` and `EOPNOTSUPP` are the same number on Linux and differ on macOS.
fn no_hard_links(error: &io::Error) -> bool {
    error
        .raw_os_error()
        .is_some_and(|code| [libc::ENOTSUP, libc::EOPNOTSUPP, libc::EPERM].contains(&code))
}

/// A stage name beside `target`, unique to this process and this call.
fn sibling(target: &Path) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        "{STAGE_TAG}{}.{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    target.with_file_name(name)
}

/// Sync `target`'s directory, so a publish survives a power loss.
fn sync_dir(target: &Path) -> eyre::Result<()> {
    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .wrap_err_with(|| format!("could not sync {}", dir.display()))
}

/// Remove stages a killed run left beside `target`. A stage is only ever sealed, but it is sealed under
/// whatever passphrase it was written with, and a stray copy under an old passphrase is still a copy.
/// Only a regular file of the exact stage shape that this user owns is removed; best effort.
fn sweep(target: &Path) {
    let (Some(name), Some(dir)) = (target.file_name(), target.parent()) else {
        return;
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let euid = crate::node_client::euid();
    for entry in entries.flatten() {
        if !is_stage_of(name, &entry.file_name()) {
            continue;
        }
        let Ok(metadata) = entry.path().symlink_metadata() else {
            continue;
        };
        if metadata.is_file() && metadata.uid() == euid {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Whether `sibling` has the exact shape of a stage of `name`, as [`sibling`] builds it.
fn is_stage_of(name: &OsStr, sibling: &OsStr) -> bool {
    let (Some(name), Some(sibling)) = (name.to_str(), sibling.to_str()) else {
        return false;
    };
    let Some(rest) = sibling
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix(STAGE_TAG))
    else {
        return false;
    };
    let Some((pid, nonce)) = rest.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && nonce.len() == 16
        && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "stage_tests.rs"]
mod stage_tests;
