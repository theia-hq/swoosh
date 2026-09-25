//! A machine's standing: which root it trusts, whether it is that root's device, and whether it holds the
//! root itself.
//!
//! Every verb that depends on the answer asks [`Standing::read`] once and matches on the result, so no two
//! verbs can read one home two ways. The read never prompts: it looks only at public files and at the
//! header of a root key, never inside a sealed one.
//!
//! **A half-finished retirement or move is finished by the read, not refused.** A move off this machine
//! and a root's retirement each rename the root's directory away before they delete anything, so a crash
//! leaves a directory whose name says what was under way. The read completes it, and says so through
//! [`Read::finished`]. A finisher never races the command still doing the work: it takes the directory's
//! `lock` without waiting first, leaves a held directory alone, and checks under the lock that the
//! directory is still the one it read.
//!
//! **Any other disagreement is refused** as [`StandingError::Damaged`], naming what disagrees. Among them
//! is a home made before a root had its own key: its badge was signed by this machine's own key, with no
//! pin or with a pin naming that same key, and either shape reads as damaged rather than as a standing.

use core::fmt;
use std::io;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::KeyFile;
use nauthy::{DisabledRoots, DisabledRootsError, Link};
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};

use crate::home::Home;

/// What this machine is to a root. Built only by [`Standing::read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// This machine trusts no root. A pin to a root revoked here counts as none.
    Unpinned,
    /// This machine trusts `pin` and is not one of its devices.
    PinOnly {
        /// The root this machine trusts.
        pin: NodeId,
    },
    /// This machine trusts `pin` and is its device until `until`, and holds no root.
    Device {
        /// The root this machine trusts.
        pin: NodeId,
        /// When this machine's device standing ends.
        until: SystemTime,
    },
    /// This machine holds the root it trusts, and is that root's device until `until`, live or lapsed.
    HoldsRoot {
        /// The root this machine trusts and holds.
        pin: NodeId,
        /// When this machine's device standing ends.
        until: SystemTime,
    },
    /// A root is here with no pin: a mint or a restore stopped before its last step. The next one
    /// finishes it. A revoked root is never one of these: the read retires it instead.
    InterruptedMint {
        /// The key the root's header names.
        root_key: NodeId,
    },
}

/// What [`Standing::read`] found, and each crash state it finished on the way. A verb prints every
/// [`Finished`] line on stderr before it goes on.
#[derive(Debug)]
#[must_use = "a finished crash state must be reported, and the standing matched on"]
pub struct Read {
    /// The standing this home reads as, once finished.
    pub standing: Standing,
    /// The crash states the read finished, in the order it finished them.
    pub finished: Vec<Finished>,
}

/// A crash state the read finished. Its [`Display`](fmt::Display) is the line a verb prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finished {
    /// A move of the root off this machine had copied and verified it, renamed it away, and stopped
    /// before deleting it. The read deleted it.
    Moved,
    /// A retirement of `root` on this machine had stopped part way. The read removed the root's
    /// directory, this machine's device standing, the update files and the pin, the pin last.
    Retired {
        /// The retired root, when its key file or the pin still named it.
        root: Option<NodeId>,
    },
}

impl fmt::Display for Finished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Moved => formatter.write_str("finished moving your root off this machine."),
            Self::Retired { root: Some(root) } => write!(
                formatter,
                "finished retiring root {}… on this machine.",
                root.short()
            ),
            Self::Retired { root: None } => {
                formatter.write_str("finished retiring a root on this machine.")
            }
        }
    }
}

/// Why a standing could not be read.
#[derive(thiserror::Error, Debug)]
pub enum StandingError {
    /// The home's files disagree about which root this machine trusts. Its one way out is to leave, which
    /// keeps any root held here.
    #[error("this machine's records disagree ({0})")]
    Damaged(Disagreement),
    /// This machine's own key file could not be read, so a pin naming it could not be told apart from
    /// a root.
    #[error("could not read this machine's key")]
    OwnKey(#[source] keystore::Error),
    /// The roots revoked here could not be read. Fails closed: a revoked root is never read as live.
    #[error("could not read the roots revoked on this machine")]
    Revoked(#[source] DisabledRootsError),
    /// A file the standing is read from could not be read.
    #[error("could not read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// A crash state could not be finished. What was removed before the failure stays removed, and the
    /// next read goes on from there.
    #[error("could not finish an interrupted change at {}", path.display())]
    Finish {
        /// The path that could not be removed or renamed.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
}

/// What disagrees in a damaged home, in the words a person reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disagreement {
    /// The pin names this machine's own key. Only a home from before roots had their own keys holds one,
    /// and a root is never its own device's pin.
    OwnKeyPinned {
        /// This machine's key.
        key: NodeId,
    },
    /// A root is held here, and the pin names another.
    RootNotPinned {
        /// The root held here.
        root: NodeId,
        /// The root the pin names.
        pin: NodeId,
    },
    /// A root is held here and pinned, and this machine has no device standing from it.
    RootWithoutStanding {
        /// The root held here.
        root: NodeId,
    },
    /// A device standing is here with no pin and no root.
    StandingWithoutPin {
        /// The root that signed the standing.
        standing_root: NodeId,
    },
    /// The device standing was signed by a root other than the one pinned.
    StandingFromAnotherRoot {
        /// The root that signed the standing.
        standing_root: NodeId,
        /// The root the pin names.
        pin: NodeId,
    },
    /// The pin is not exactly one key.
    UnreadablePin {
        /// The pin file.
        path: PathBuf,
    },
    /// The device standing is not a signed standing with an end date.
    UnreadableStanding {
        /// The standing file.
        path: PathBuf,
    },
    /// The device standing names a key other than this machine's: copied from another device, or left
    /// from a key this machine has since replaced.
    StandingForAnotherKey {
        /// The standing file.
        path: PathBuf,
    },
    /// The root's directory holds no key file whose header can be read.
    UnreadableRoot {
        /// The key file.
        path: PathBuf,
    },
}

impl fmt::Display for Disagreement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnKeyPinned { key } => write!(
                formatter,
                "this machine trusts its own key {}… as a root",
                key.short()
            ),
            Self::RootNotPinned { root, pin } => write!(
                formatter,
                "this machine holds root {}…, and trusts {}…",
                root.short(),
                pin.short()
            ),
            Self::RootWithoutStanding { root } => write!(
                formatter,
                "this machine holds root {}… and has no device record from it",
                root.short()
            ),
            Self::StandingWithoutPin { standing_root } => write!(
                formatter,
                "this machine's device record is from root {}…, and this machine trusts no root",
                standing_root.short()
            ),
            Self::StandingFromAnotherRoot { standing_root, pin } => write!(
                formatter,
                "this machine's device record is from root {}…, and this machine trusts {}…",
                standing_root.short(),
                pin.short()
            ),
            Self::UnreadablePin { path } => {
                write!(formatter, "{} is not one root key", path.display())
            }
            Self::UnreadableStanding { path } => write!(
                formatter,
                "{} is not a device record with an end date",
                path.display()
            ),
            Self::StandingForAnotherKey { path } => write!(
                formatter,
                "{} is a device record for a key other than this machine's",
                path.display()
            ),
            Self::UnreadableRoot { path } => {
                write!(formatter, "{} is not a readable root key", path.display())
            }
        }
    }
}

impl Standing {
    /// Read this home's standing, finishing any crash state first. Never prompts.
    ///
    /// The crash states, in the order they are finished:
    ///
    /// 1. `root.new/` beside a `root/` is a stale leftover and is removed. Alone, it is left for the next
    ///    mint or restore, which removes it.
    /// 2. `root.moving/` is a verified copy's source, renamed away, and is deleted.
    /// 3. `root.revoking/` is a retirement that stopped part way, and is finished.
    /// 4. A `root/` whose key is revoked here is renamed to `root.revoking/` and finished, so a revoked
    ///    root is never read as an interrupted mint.
    /// 5. A pin whose key is revoked here is removed, after the device standing and the update files.
    pub async fn read(home: &Home) -> Result<Read, StandingError> {
        let own = own_key(home)?;
        let revoked = DisabledRoots::load(home.disabled_roots())
            .await
            .map_err(StandingError::Revoked)?;
        let mut finished = Vec::new();

        remove_stray_root_new(home).await?;
        if finish_move(home).await? {
            finished.push(Finished::Moved);
        }
        if let Some(lock) = DirLock::try_take(&home.root_revoking()) {
            finished.push(finish_retirement(home, &revoked, lock).await?);
        }
        if let Some(retired) = retire_revoked_root(home, &revoked).await? {
            finished.push(retired);
        }

        let mut pin = read_pin(home).await?;
        if let Some(key) = pin {
            if own == Some(key) {
                return Err(StandingError::Damaged(Disagreement::OwnKeyPinned { key }));
            }
            if revoked.is_disabled(key.verify_key()) {
                strip(home).await?;
                finished.push(Finished::Retired { root: Some(key) });
                pin = None;
            }
        }

        let standing = classify(home, own, pin, held_root(home, &revoked).await?).await?;
        Ok(Read { standing, finished })
    }
}

/// Classify a home whose crash states are finished, from its pin and the root held here.
///
/// A root with no pin is an interrupted mint whatever the badge holds, so the badge is read only where
/// it decides something: a torn badge beside an interrupted mint is the mint's to replace.
async fn classify(
    home: &Home,
    own: Option<NodeId>,
    pin: Option<NodeId>,
    root: Option<NodeId>,
) -> Result<Standing, StandingError> {
    let damaged = |disagreement| Err(StandingError::Damaged(disagreement));
    match (root, pin) {
        (Some(root_key), None) => Ok(Standing::InterruptedMint { root_key }),
        (Some(root), Some(pin)) if root != pin => {
            damaged(Disagreement::RootNotPinned { root, pin })
        }
        (Some(root), Some(pin)) => match read_badge(home, own, pin).await? {
            None => damaged(Disagreement::RootWithoutStanding { root }),
            Some(until) => Ok(Standing::HoldsRoot { pin, until }),
        },
        (None, None) => match load_badge(home).await? {
            None => Ok(Standing::Unpinned),
            Some(badge) => damaged(Disagreement::StandingWithoutPin {
                standing_root: badge.root().node_id(),
            }),
        },
        (None, Some(pin)) => match read_badge(home, own, pin).await? {
            None => Ok(Standing::PinOnly { pin }),
            Some(until) => Ok(Standing::Device { pin, until }),
        },
    }
}

/// This machine's own key, from its key file's header. `None` when the home has no key yet.
fn own_key(home: &Home) -> Result<Option<NodeId>, StandingError> {
    KeyFile::device(home.identity_key())
        .load()
        .map(|stored| stored.map(|stored| stored.node_id()))
        .map_err(StandingError::OwnKey)
}

/// The key the root held here names, or `None` when no root is held here or the one held here is
/// revoked. A revoked root is only ever here while the command retiring it holds its lock, and it is
/// that command's to remove, never a standing.
async fn held_root(home: &Home, revoked: &DisabledRoots) -> Result<Option<NodeId>, StandingError> {
    let dir = home.root();
    if !exists(&dir).await? {
        return Ok(None);
    }
    let root = root_key(&dir).map_err(StandingError::Damaged)?;
    Ok((!revoked.is_disabled(root.verify_key())).then_some(root))
}

/// The key a root directory's `root.key` header names, read without unlocking it.
fn root_key(dir: &Path) -> Result<NodeId, Disagreement> {
    let path = dir.join("root.key");
    match KeyFile::root(&path).load() {
        Ok(Some(stored)) => Ok(stored.node_id()),
        Ok(None) | Err(_) => Err(Disagreement::UnreadableRoot { path }),
    }
}

/// Remove `root.new/` when `root/` is also here: a write that never became the root. Silent, and left
/// alone while a command holds its lock.
async fn remove_stray_root_new(home: &Home) -> Result<(), StandingError> {
    if !exists(&home.root()).await? {
        return Ok(());
    }
    let Some(_lock) = DirLock::try_take(&home.root_new()) else {
        return Ok(());
    };
    remove_dir(home.root_new()).await
}

/// Delete `root.moving/`, when it is here and no command holds it. Its contents were copied and read
/// back before the rename that made it, so nothing is lost.
async fn finish_move(home: &Home) -> Result<bool, StandingError> {
    let Some(_lock) = DirLock::try_take(&home.root_moving()) else {
        return Ok(false);
    };
    remove_dir(home.root_moving()).await?;
    Ok(true)
}

/// Rename a `root/` whose key is revoked here to `root.revoking/`, and finish retiring it.
///
/// The rename comes first, with its directory synced, so that from here on a crash leaves
/// `root.revoking/` rather than a root that could read as an interrupted mint.
async fn retire_revoked_root(
    home: &Home,
    revoked: &DisabledRoots,
) -> Result<Option<Finished>, StandingError> {
    let dir = home.root();
    if !exists(&dir).await? {
        return Ok(None);
    }
    let Ok(root) = root_key(&dir) else {
        return Ok(None);
    };
    if !revoked.is_disabled(root.verify_key()) {
        return Ok(None);
    }
    // The lock is on the file inside the directory, so it moves with the rename and stays held.
    let Some(lock) = DirLock::try_take(&dir) else {
        return Ok(None);
    };
    // Checked again under the lock: the directory read above may have been retired since, and a new
    // root made in its place, which is no retirement's to touch.
    match root_key(&dir) {
        Ok(held) if revoked.is_disabled(held.verify_key()) => {}
        Ok(_) | Err(_) => return Ok(None),
    }
    seam(Seam::BeforeRetireRename, &dir);
    if !rename(&dir, &home.root_revoking()).await? {
        return Ok(None);
    }
    sync_dir(home.dir())?;
    finish_retirement(home, revoked, lock).await.map(Some)
}

/// Finish a retirement: remove this machine's standing under the retired root, then `root.revoking/`.
///
/// A key is retired when `root.revoking/` names it or it is revoked here: a retirement records the
/// revocation before it renames anything, so a key file too torn to read still leaves its root
/// revoked. The standing is removed only when it is under a retired key: a pin naming one, or no pin and
/// a badge from one, or no pin and no badge. Anything else is a standing this machine took since, or a
/// damage the read must still report, and a leftover directory is no reason to drop either.
async fn finish_retirement(
    home: &Home,
    revoked: &DisabledRoots,
    _lock: DirLock,
) -> Result<Finished, StandingError> {
    let root = root_key(&home.root_revoking()).ok();
    let retired = |key: NodeId| root == Some(key) || revoked.is_disabled(key.verify_key());
    let (under_retired, pin) = match read_pin(home).await {
        Ok(Some(pin)) => (retired(pin), retired(pin).then_some(pin)),
        Ok(None) => match load_badge(home).await {
            Ok(None) => (true, None),
            Ok(Some(badge)) => (retired(badge.root().node_id()), None),
            Err(_) => (false, None),
        },
        Err(_) => (false, None),
    };
    if under_retired {
        strip(home).await?;
    }
    remove_dir(home.root_revoking()).await?;
    Ok(Finished::Retired { root: root.or(pin) })
}

/// Remove this machine's standing under its root: the device standing, the update files, then the pin.
///
/// The pin goes last. It is what makes the rest mean anything, so a crash part way leaves a pin with
/// less beneath it, which the next read finishes, never a device standing with no pin, which reads as
/// damaged.
async fn strip(home: &Home) -> Result<(), StandingError> {
    for path in [
        home.badge(),
        home.roster(),
        home.roster_synced(),
        home.roster_seed(),
        home.roster_fork(),
        home.signet(),
    ] {
        remove_file(path).await?;
    }
    Ok(())
}

/// The pin, or `None` when there is none. A file that is not exactly one key is damaged.
async fn read_pin(home: &Home) -> Result<Option<NodeId>, StandingError> {
    let path = home.signet();
    let Some(text) = read_text(&path).await? else {
        return Ok(None);
    };
    match text.and_then(|text| text.trim().parse::<NodeId>().ok()) {
        Some(pin) => Ok(Some(pin)),
        None => Err(StandingError::Damaged(Disagreement::UnreadablePin { path })),
    }
}

/// The device standing, rooted at `pin` and naming this machine's key `own`: its end date, or `None`
/// when there is none.
async fn read_badge(
    home: &Home,
    own: Option<NodeId>,
    pin: NodeId,
) -> Result<Option<SystemTime>, StandingError> {
    let Some(badge) = load_badge(home).await? else {
        return Ok(None);
    };
    let standing_root = badge.root().node_id();
    if standing_root != pin {
        return Err(StandingError::Damaged(
            Disagreement::StandingFromAnotherRoot { standing_root, pin },
        ));
    }
    let until = match badge.cap().expiry() {
        Ok(Some(until)) => until,
        Ok(None) | Err(_) => return Err(unreadable_badge(home)),
    };
    // Checked at the standing's own end date, so a lapsed standing still reads as this machine's.
    let ours = own.is_some_and(|own| {
        badge
            .cap()
            .verify_member_at_root_without_revocation(until, own.verify_key(), pin.verify_key())
            .is_ok()
    });
    if !ours {
        return Err(StandingError::Damaged(
            Disagreement::StandingForAnotherKey { path: home.badge() },
        ));
    }
    Ok(Some(until))
}

/// The device standing as a verified link, or `None` when there is none. A file that is not one is
/// damaged: a torn write reads this way.
async fn load_badge(home: &Home) -> Result<Option<Link>, StandingError> {
    let Some(text) = read_text(&home.badge()).await? else {
        return Ok(None);
    };
    text.and_then(|text| text.trim().parse::<Link>().ok())
        .map(Some)
        .ok_or_else(|| unreadable_badge(home))
}

fn unreadable_badge(home: &Home) -> StandingError {
    StandingError::Damaged(Disagreement::UnreadableStanding { path: home.badge() })
}

/// A small text file: `None` when it is absent, `Some(None)` when its bytes are not text.
// `core::io::ErrorKind` is still unstable, so the kinds read from `std`.
#[allow(clippy::std_instead_of_core)]
async fn read_text(path: &Path) -> Result<Option<Option<String>>, StandingError> {
    match tokio::fs::read_to_string(path).await {
        Ok(text) => Ok(Some(Some(text))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(Some(None)),
        Err(source) => Err(StandingError::Read {
            path: path.to_owned(),
            source,
        }),
    }
}

async fn exists(path: &Path) -> Result<bool, StandingError> {
    tokio::fs::try_exists(path)
        .await
        .map_err(|source| StandingError::Read {
            path: path.to_owned(),
            source,
        })
}

/// Remove a file. Already gone is done: a command racing this one may have removed it first.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn remove_file(path: PathBuf) -> Result<(), StandingError> {
    match tokio::fs::remove_file(&path).await {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(StandingError::Finish {
            path,
            source: error,
        }),
        _ => Ok(()),
    }
}

/// Remove a directory and everything in it. Already gone is done.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn remove_dir(path: PathBuf) -> Result<(), StandingError> {
    match tokio::fs::remove_dir_all(&path).await {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(StandingError::Finish {
            path,
            source: error,
        }),
        _ => Ok(()),
    }
}

/// Rename `from` to `to`: `false` when `from` is already gone, which a command racing this one may have
/// done first.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn rename(from: &Path, to: &Path) -> Result<bool, StandingError> {
    match tokio::fs::rename(from, to).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(StandingError::Finish {
            path: from.to_owned(),
            source,
        }),
    }
}

/// Make a rename in `dir` durable, so a power cut cannot bring the old name back.
fn sync_dir(dir: &Path) -> Result<(), StandingError> {
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|source| StandingError::Finish {
            path: dir.to_owned(),
            source,
        })
}

/// A held `<dir>/lock`, the lock every command that works on a root's directory takes. Released on drop.
pub(crate) struct DirLock {
    /// Held, never read: the lock lives exactly as long as this open file does.
    _held: std::fs::File,
}

/// Why `<dir>/lock` was not taken.
#[derive(Debug)]
pub(crate) enum LockError {
    /// Another command holds it, or the directory was replaced while it was being taken.
    Held,
    /// It could not be opened or created.
    Io(io::Error),
}

impl DirLock {
    /// Take `<dir>/lock` without waiting, creating it if it is not there. `None` when the directory is
    /// not here, when another command holds the lock, or when it cannot be taken at all: in each case
    /// the directory is not the read's to touch.
    fn try_take(dir: &Path) -> Option<Self> {
        if !dir.is_dir() {
            return None;
        }
        Self::take(dir).ok()
    }

    /// Take `<dir>/lock` without waiting, creating it if it is not there.
    ///
    /// The lock taken is checked to still be `<dir>/lock` once held. Opening and locking are two steps,
    /// and between them the directory can be removed and another made at its name, whose lock this
    /// open file is not.
    pub(crate) fn take(dir: &Path) -> Result<Self, LockError> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join("lock"))
            .map_err(LockError::Io)?;
        seam(Seam::LockOpened, dir);
        // SAFETY: `file` owns a valid fd for the whole call, and `flock` only attaches an advisory lock to
        // it. `LOCK_NB` makes a held lock an error rather than a wait.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::EWOULDBLOCK) => LockError::Held,
                _ => LockError::Io(error),
            });
        }
        let held = file.metadata().map_err(LockError::Io)?;
        let named = std::fs::metadata(dir.join("lock")).map_err(LockError::Io)?;
        if held.dev() != named.dev() || held.ino() != named.ino() {
            return Err(LockError::Held);
        }
        Ok(Self { _held: file })
    }
}

/// A point in the read where a test steps in, to change the home between two of the read's steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seam {
    /// `<dir>/lock` is open and not yet locked.
    LockOpened,
    /// A revoked `root/` is locked and checked, and not yet renamed.
    BeforeRetireRename,
}

/// A test's step at a [`Seam`].
#[cfg(test)]
type SeamStep = Box<dyn FnMut(Seam, &Path)>;

#[cfg(test)]
thread_local! {
    /// The test's step at each [`Seam`], on the thread the read runs on.
    static SEAM: core::cell::RefCell<Option<SeamStep>> = const { core::cell::RefCell::new(None) };
}

/// Run the test's step at `at`, on `path`. Nothing outside tests.
fn seam(at: Seam, path: &Path) {
    #[cfg(test)]
    SEAM.with_borrow_mut(|step| {
        if let Some(step) = step.as_mut() {
            step(at, path);
        }
    });
    #[cfg(not(test))]
    let _ = (at, path);
}

#[cfg(test)]
#[path = "standing_tests.rs"]
mod standing_tests;
