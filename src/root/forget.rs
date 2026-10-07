//! `root forget <dir>`: remove the root from this machine, once a copy in `<dir>` is checked.
//!
//! There is no move. `root backup` copies, and this deletes `root.key` on this machine only after six checks,
//! each a refusal that writes nothing:
//!
//! 1. a terminal, since there is no `--yes`;
//! 2. the root is on this machine;
//! 3. `<dir>`, as named, holds a copy: never found by searching;
//! 4. the copy is not one this machine keeps: on the home's disk, or in memory, it dies with the machine,
//!    unless the cloud holds both of its files (dataless);
//! 5. the copy opens under a passphrase typed now, as this root, re-locked or not;
//! 6. the copy's list is at least as new as this machine's, or is made so.
//!
//! Check 4 runs before check 5's read, because reading a dataless file downloads it and clears the flag.
//! Check 5's prompt, and any download, come before `home.lock`; under the lock checks 2 and 3 run again, the
//! copy's two files are confirmed by device and inode (never by the flag again), the copy is read again,
//! and check 6 runs. When check 6 writes into a synced copy, the run stops there: the update must reach the
//! cloud, and the file be evicted again, before the next run passes check 4. A crash after check 6's write
//! leaves the root here and the copy up to date; running it again finishes.

use std::path::{Path, PathBuf};

use keystore::Unlock;
use tightbeam::identity::AsVerifyKey as _;

use super::{KEY_FILE, LIST_FILE, RootError, header_key, read_header, read_list};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::passphrase::{Asked, Prompt};
use crate::standing::Standing;

/// The flag macOS sets on a file whose bytes are in the cloud and not on this disk (`SF_DATALESS`).
#[cfg(target_os = "macos")]
const SF_DATALESS: u32 = 0x4000_0000;

/// `statfs`'s `f_type` for a tmpfs, a filesystem kept in memory.
#[cfg(target_os = "linux")]
const TMPFS_MAGIC: i64 = 0x0102_1994;

/// `statfs`'s `f_type` for a ramfs, a filesystem kept in memory.
#[cfg(target_os = "linux")]
const RAMFS_MAGIC: i64 = 0x8584_58f6;

/// What check 4 reads of one file: where it is, and whether its bytes are only in the cloud or only in
/// memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    /// The filesystem it is on (`st_dev`).
    pub dev: u64,
    /// The file on that filesystem (`st_ino`).
    pub ino: u64,
    /// Whether its bytes are in the cloud, not on this disk.
    pub dataless: bool,
    /// Whether its filesystem is kept in memory.
    pub in_memory: bool,
    /// Whether it is under `/tmp` or `/var/tmp`, emptied at boot or aged out on most systems, whatever
    /// filesystem holds it.
    pub emptied: bool,
}

/// Where check 4 reads a file's place from: the filesystem, or a test's stand-in.
pub trait Disk {
    /// The place of `path`, every symbolic link on the way followed.
    ///
    /// # Errors
    ///
    /// The file could not be read.
    fn place(&self, path: &Path) -> std::io::Result<Place>;
}

/// The filesystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealDisk;

impl Disk for RealDisk {
    fn place(&self, path: &Path) -> std::io::Result<Place> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = std::fs::metadata(path)?;
        Ok(Place {
            dev: metadata.dev(),
            ino: metadata.ino(),
            dataless: dataless(&metadata),
            in_memory: in_memory(path)?,
            emptied: emptied(path),
        })
    }
}

/// Whether `path`, every link followed, is under `/tmp` or `/var/tmp`: emptied at boot or aged out on most
/// systems, on whatever disk they sit (`/private` is where macOS keeps both).
fn emptied(path: &Path) -> bool {
    let Ok(resolved) = std::fs::canonicalize(path) else {
        return false;
    };
    ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"]
        .iter()
        .any(|temp| resolved.starts_with(temp))
}

/// Whether the file's bytes are in the cloud and not on this disk.
#[cfg(target_os = "macos")]
fn dataless(metadata: &std::fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt as _;

    metadata.st_flags() & SF_DATALESS != 0
}

/// No other platform marks a file whose bytes are elsewhere.
#[cfg(not(target_os = "macos"))]
fn dataless(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Whether `path` is on a filesystem kept in memory. On macOS `/tmp` is on the home's disk, which the
/// same-disk check already refuses.
#[cfg(target_os = "linux")]
fn in_memory(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::ffi::OsStrExt as _;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `statfs` is a plain C struct for which all-zero bytes are a valid value, and the call fully
    // overwrites it before it is read.
    let mut fs: libc::statfs = unsafe { core::mem::zeroed() };
    // SAFETY: `c_path` is a live NUL-terminated string, and `fs` is a live, writable `statfs`.
    if unsafe { libc::statfs(c_path.as_ptr(), &mut fs) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[allow(clippy::useless_conversion)]
    let kind = i64::from(fs.f_type);
    Ok(kind == TMPFS_MAGIC || kind == RAMFS_MAGIC)
}

/// No memory filesystem is told apart here beyond the same-disk check.
#[cfg(not(target_os = "linux"))]
fn in_memory(_path: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// Why the root was not removed from this machine. Each refusal wrote nothing, but [`ForgetError::Synced`],
/// which says what it wrote.
#[derive(Debug, thiserror::Error)]
pub enum ForgetError {
    /// Check 1: no terminal.
    #[error(
        "this removes your root from this machine, so it needs a terminal: over swoosh ssh, add -t after --"
    )]
    NoTerminal,
    /// Check 2: no root here.
    #[error("your root is not on this machine.")]
    NotHere,
    /// Check 3: no copy in `<dir>`.
    #[error(
        "{} holds no copy of your root; make one first: swoosh root backup {}",
        EscapedPath(.dir),
        EscapedPath(.dir)
    )]
    NoCopy {
        /// The directory named.
        dir: PathBuf,
    },
    /// Check 4: the copy is on the home's disk.
    #[error("{}", same_disk(.dir))]
    SameDisk {
        /// The directory named.
        dir: PathBuf,
    },
    /// Check 4: the copy is in memory.
    #[error(
        "{} is kept in memory and is emptied when this machine restarts; copy your root to another disk first.",
        EscapedPath(.dir)
    )]
    InMemory {
        /// The directory named.
        dir: PathBuf,
    },
    /// Check 4: the copy is under `/tmp` or `/var/tmp`, emptied at boot or aged out on most systems.
    #[error(
        "{} is under /tmp or /var/tmp, which are for temporary files; copy your root to a directory outside \
         them first.",
        EscapedPath(.dir)
    )]
    Emptied {
        /// The directory named.
        dir: PathBuf,
    },
    /// Check 5: the passphrase did not open the copy.
    #[error(
        "that passphrase does not open the copy in {}; your root is still on this machine.",
        EscapedPath(.dir)
    )]
    Wrong {
        /// The directory named.
        dir: PathBuf,
    },
    /// Check 5: the copy is another root.
    #[error(
        "the copy in {} is root:{}, and yours is root:{}; your root is still on this machine.",
        EscapedPath(.dir),
        crate::credential::short(.copy),
        crate::credential::short(.root)
    )]
    AnotherRoot {
        /// The directory named.
        dir: PathBuf,
        /// The copy's root.
        copy: bifrost::NodeId,
        /// The root on this machine.
        root: bifrost::NodeId,
    },
    /// Under the lock: a file of the copy is not the one check 4 read.
    #[error(
        "the copy in {} changed during the checks; your root is still on this machine. Run it again: swoosh \
         root forget {}",
        EscapedPath(.dir),
        EscapedPath(.dir)
    )]
    Changed {
        /// The directory named.
        dir: PathBuf,
    },
    /// Check 6 wrote this machine's list into a synced copy, and the run stops until it is evicted again:
    /// one line, saying what landed and what did not.
    #[error(
        "brought the copy in {} up to date; your root is still on this machine. {} is in a synced folder: \
         once the update reaches the cloud, choose Remove Download on {}, then run it again: swoosh root \
         forget {}",
        EscapedPath(.dir),
        EscapedPath(.dir),
        EscapedPath(.dir),
        EscapedPath(.dir)
    )]
    Synced {
        /// The directory named.
        dir: PathBuf,
    },
    /// The root, its records, or a file failed.
    #[error(transparent)]
    Root(#[from] RootError),
}

/// Check 4's same-disk refusal, with the line macOS adds for a synced folder.
fn same_disk(dir: &Path) -> String {
    let line = format!(
        "{} is on the same disk as this machine's home, so if this disk is lost, your root is lost with it. \
         Copy your root to another disk first.",
        EscapedPath(dir)
    );
    if cfg!(target_os = "macos") {
        format!(
            "{line}\nIf {} is in iCloud Drive or another synced folder, choose Remove Download on it, then: \
             swoosh root forget {}",
            EscapedPath(dir),
            EscapedPath(dir)
        )
    } else {
        line
    }
}

/// What a forget did, for its lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forgot {
    /// Whether check 6 wrote this machine's list into the copy first.
    pub updated: bool,
    /// Whether the copy passed check 4 as dataless: the cloud holds it.
    pub synced: bool,
}

/// Remove the root kept on this machine, after the six checks on the copy in `dir`. Prints check 6's line
/// on `out` when it writes. Check 4 reads places through `disk`.
///
/// # Errors
///
/// Each check's refusal; or a read, the prompt, or a write failed.
pub async fn forget(
    home: &Home,
    dir: &Path,
    prompt: &mut impl Prompt,
    disk: &impl Disk,
    out: &mut impl std::io::Write,
) -> Result<Forgot, ForgetError> {
    // 1. A terminal, before anything is read.
    if !prompt.terminal() {
        return Err(ForgetError::NoTerminal);
    }
    // 2. The root is on this machine.
    let root = held(home).await?;
    // 3. `<dir>` holds a copy: both files, as named.
    let (key, list) = (dir.join(KEY_FILE), dir.join(LIST_FILE));
    if !key.is_file() || !list.is_file() {
        return Err(ForgetError::NoCopy {
            dir: dir.to_path_buf(),
        });
    }
    // 4. The copy is not one this machine keeps, read before anything reads the copy's bytes.
    let (key_place, list_place) = (place(disk, &key)?, place(disk, &list)?);
    let home_dev = place(disk, home.dir())?.dev;
    let synced = key_place.dataless && list_place.dataless;
    // The copy's key is never the root's own file here, whatever else passes.
    let own_file = place(disk, &home.root_key())?;
    if (key_place.dev, key_place.ino) == (own_file.dev, own_file.ino) {
        return Err(ForgetError::SameDisk {
            dir: dir.to_path_buf(),
        });
    }
    if !synced {
        if key_place.dev == home_dev || list_place.dev == home_dev {
            return Err(ForgetError::SameDisk {
                dir: dir.to_path_buf(),
            });
        }
        if key_place.in_memory || list_place.in_memory {
            return Err(ForgetError::InMemory {
                dir: dir.to_path_buf(),
            });
        }
    }
    // After the disk: for the layouts the disk check misses (a subvolume, a separate `/home`), `/tmp` and
    // `/var/tmp`, emptied at boot or aged out on most systems, are refused whatever filesystem holds them.
    if key_place.emptied || list_place.emptied {
        return Err(ForgetError::Emptied {
            dir: dir.to_path_buf(),
        });
    }
    // 5. The copy opens under a passphrase typed now, as this root. Its header names another root before
    // anything is asked; the unlock proves the key.
    // The bytes this check opens are kept: the copy confirmed under the lock is these, byte for byte.
    let opened_bytes = read_key_bytes(&key)?;
    let locked = read_header(&key)?;
    let claimed = header_key(&key, &locked)?;
    if claimed != root {
        return Err(ForgetError::AnotherRoot {
            dir: dir.to_path_buf(),
            copy: claimed,
            root,
        });
    }
    let opened = crate::passphrase::unlock(prompt, Asked::Copy(dir), |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase))
    });
    let secret = match opened {
        Ok((secret, _)) => secret,
        Err(report) if report.downcast_ref::<crate::passphrase::Wrong>().is_some() => {
            return Err(ForgetError::Wrong {
                dir: dir.to_path_buf(),
            });
        }
        Err(report) => return Err(RootError::Prompt(format!("{report:#}")).into()),
    };
    let opened = secret.with_bytes(bifrost::NodeId::from_ed25519_secret);
    if opened != root {
        return Err(ForgetError::AnotherRoot {
            dir: dir.to_path_buf(),
            copy: opened,
            root,
        });
    }
    drop(secret);
    if read_key_bytes(&key)? != opened_bytes {
        return Err(ForgetError::Changed {
            dir: dir.to_path_buf(),
        });
    }

    // Under `home.lock`, from here to the last write.
    let home_lock = HomeWrite::take(home).await.map_err(RootError::from)?;
    if held(home).await? != root {
        return Err(ForgetError::NotHere);
    }
    if !key.is_file() || !list.is_file() {
        return Err(ForgetError::NoCopy {
            dir: dir.to_path_buf(),
        });
    }
    let changed = || ForgetError::Changed {
        dir: dir.to_path_buf(),
    };
    let same = |was: Place, now: Place| was.dev == now.dev && was.ino == now.ino;
    if !same(key_place, place(disk, &key)?) || !same(list_place, place(disk, &list)?) {
        return Err(changed());
    }
    if read_key_bytes(&key)? != opened_bytes {
        return Err(changed());
    }
    // 6. The copy's list is at least as new as this machine's.
    let pin = root.verify_key().map_err(RootError::from)?;
    let copied = read_list(home, Some(dir), pin)?;
    let here = read_list(home, None, pin)?;
    let behind = match (&copied, &here) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(copied), Some(here)) => copied.epoch() < here.epoch(),
    };
    if behind {
        let bytes = std::fs::read(home.devices()).map_err(super::io_at(&home.devices()))?;
        crate::config::write_private_atomic(&home_lock, &list, &bytes)
            .map_err(super::io_at(&list))?;
        // A synced copy stops here, in one line that says what landed.
        if synced {
            return Err(ForgetError::Synced {
                dir: dir.to_path_buf(),
            });
        }
    }
    // The copy is made durable before the one step that cannot be taken back.
    for path in [&key, &list] {
        std::fs::File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(super::io_at(path))?;
    }
    sync_dir(dir)?;
    super::remove_file(&home.root_key())?;
    sync_dir(home.dir())?;
    sweep_stages(home);
    drop(home_lock);
    // Said after the delete, so a line that states an effect never comes before a refusal.
    if behind {
        let _ = writeln!(
            out,
            "brought the copy in {} up to date with this machine's list of your devices.",
            EscapedPath(dir)
        );
    }
    Ok(Forgot {
        updated: behind,
        synced,
    })
}

/// The root kept on this machine: check 2.
async fn held(home: &Home) -> Result<bifrost::NodeId, ForgetError> {
    match Standing::read(home).await.map_err(RootError::from)? {
        Standing::HoldsRoot { pin, .. } => Ok(pin),
        Standing::InterruptedMint { root_key } => {
            Err(RootError::Unfinished { root: root_key }.into())
        }
        Standing::Device { .. } | Standing::Unpinned => Err(ForgetError::NotHere),
    }
}

/// The bytes of the copy's `root.key`, read with a cap.
fn read_key_bytes(path: &Path) -> Result<Vec<u8>, RootError> {
    use std::io::Read as _;

    /// A sealed root key is a few hundred bytes; the key store reads no more than this.
    const CAP: u64 = 4096;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(CAP + 1).read_to_end(&mut bytes))
        .map_err(super::io_at(path))?;
    Ok(bytes)
}

/// Sync a directory, so the names in it are durable.
fn sync_dir(dir: &Path) -> Result<(), RootError> {
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(super::io_at(dir))
}

/// Remove the stage files a killed key write left beside `root.key` here (`root.key.tmp.<pid>.<n>`): with the
/// root gone, a stage is the one copy of it left in the home. Only regular files, best effort.
fn sweep_stages(home: &Home) {
    let Ok(entries) = std::fs::read_dir(home.dir()) else {
        return;
    };
    let stage = format!("{KEY_FILE}.tmp.");
    for entry in entries.flatten() {
        let is_stage = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(&stage));
        if is_stage
            && entry
                .path()
                .symlink_metadata()
                .is_ok_and(|meta| meta.is_file())
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// The place of `path`, or the read's failure naming it.
fn place(disk: &impl Disk, path: &Path) -> Result<Place, RootError> {
    disk.place(path).map_err(super::io_at(path))
}
