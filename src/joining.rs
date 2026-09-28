//! Joining a root and leaving it: the writes, in the order that keeps a crash readable, and the lock that
//! keeps `join` and an admitting `serve` apart.
//!
//! The pin is written last on a join and removed last on a leave. It is what makes the other files mean
//! anything, so a crash part way leaves a home [`Standing::read`](crate::standing::Standing::read) reads as
//! damaged, naming `swoosh leave`, never one that trusts a root with a standing from another.

use std::io::{self, Read as _, Seek as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::time::SystemTime;

use bifrost::NodeId;
use nauthy::{Link, Revocations as _};
use tightbeam::identity::AsVerifyKey as _;

use crate::contacts::{ContactsStore, DeviceLabel};
use crate::gate::KeyedDenylist;
use crate::home::Home;
use crate::roster::RosterLock;
use crate::standing::Standing;

/// What a join writes: this machine's standing from the root, and the hints the invite carried.
#[derive(Debug)]
pub struct Join<'a> {
    /// The root the standing is from: the pin.
    pub root: NodeId,
    /// This machine's standing, signed by the root.
    pub standing: &'a Link,
    /// This machine's key.
    pub own: NodeId,
    /// This machine's name, as the invite gave it: a hint until the first fold.
    pub name: DeviceLabel,
    /// The machine that made the invite: the first device a sync asks.
    pub from: NodeId,
    /// Whether the pin changes: a first join, or a switch to another root.
    pub pin_changes: bool,
}

/// Write a join, under `roster.lock`: on a pin change, the old root's update files and devices go and
/// `roster.seed` is written; this machine's own entry is laid under `me`; then the standing; then, on a pin
/// change, the pin. A join to the root already pinned is the same-root write, and leaves the pin as it is.
pub async fn join(home: &Home, join: Join<'_>) -> eyre::Result<()> {
    let _lock = RosterLock::take(&home.roster_lock()).await?;
    let mut contacts = ContactsStore::open(home.contacts()).await?;
    if join.pin_changes {
        for path in [home.roster(), home.roster_synced(), home.roster_fork()] {
            remove(path)?;
        }
        contacts.contacts_mut().clear_me();
        crate::config::write_private_atomic(
            &home.roster_seed(),
            format!("{}\n", join.from).as_bytes(),
        )
        .await?;
    }
    contacts.contacts_mut().seed_me(join.name, join.own);
    contacts.save().await?;
    same_root_write(home, join.standing).await?;
    if join.pin_changes {
        crate::config::write_signet(home, join.root).await?;
    }
    Ok(())
}

/// Take a renewed standing that one of your devices handed this machine, under `roster.lock`, through the
/// same-root write a join makes: only one bound to this machine's key, rooted at the pin, ending after the
/// one held, and neither its id nor this key revoked here. When it ends, if it was taken.
///
/// It never writes the pin, so a standing fetched from the network can renew this machine and never move
/// it to another root.
pub async fn take_renewal(home: &Home, standing: &Link) -> eyre::Result<Option<SystemTime>> {
    let _lock = RosterLock::take(&home.roster_lock()).await?;
    let (pin, held) = match Standing::read(home).await?.standing {
        Standing::Device { pin, until } | Standing::HoldsRoot { pin, until } => (pin, until),
        Standing::Unpinned | Standing::InterruptedMint { .. } => return Ok(None),
    };
    let Some(own) = keystore::KeyFile::device(home.key())
        .load()?
        .map(|stored| stored.node_id())
    else {
        return Ok(None);
    };
    let cap = standing.cap();
    let Ok(Some(until)) = cap.expiry() else {
        return Ok(None);
    };
    let (own, pin) = (own.verify_key()?, pin.verify_key()?);
    let bound = cap
        .verify_member_at_root_without_revocation(SystemTime::now(), own, pin)
        .is_ok();
    let revocations = KeyedDenylist::load(home).await?;
    let blocked = revocations.is_revoked(cap) || revocations.is_revoked_peer(&own);
    if !bound || until <= held || blocked {
        return Ok(None);
    }
    same_root_write(home, standing).await?;
    Ok(Some(until))
}

/// The write a standing from the root already pinned takes: the standing, atomically. The pin already
/// names that root, so it is not touched.
async fn same_root_write(home: &Home, standing: &Link) -> eyre::Result<()> {
    crate::config::write_badge(home, standing).await
}

/// Leave the root this machine trusts, under `roster.lock`: the standing, the update files and the
/// devices under `me` go, then the pin, last. The revocations this machine learned stay, and so does a
/// root kept here.
pub async fn leave(home: &Home) -> eyre::Result<()> {
    let _lock = RosterLock::take(&home.roster_lock()).await?;
    for path in [
        home.badge(),
        home.roster(),
        home.roster_synced(),
        home.roster_seed(),
        home.roster_fork(),
    ] {
        remove(path)?;
    }
    let mut contacts = ContactsStore::open(home.contacts()).await?;
    contacts.contacts_mut().clear_me();
    contacts.save().await?;
    remove(home.signet())?;
    Ok(())
}

/// Remove a file. Already gone is done.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn remove(path: PathBuf) -> io::Result<()> {
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// `<home>/admit.lock`, held: by a `serve --admit` for its whole run, or by a `join` while it writes.
#[derive(Debug)]
#[must_use = "the lock is held only while this value lives"]
pub struct AdmitLock {
    /// Held, never read: the lock lives exactly as long as this open file does.
    _held: std::fs::File,
}

/// Why `<home>/admit.lock` was not taken.
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    /// A `serve --admit` or a `join` holds it.
    #[error("held")]
    Held,
    /// It could not be opened or written.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl AdmitLock {
    /// Hold the lock for a `serve --admit` run, and record `root` in it for `status`.
    pub fn admitting(home: &Home, root: NodeId) -> Result<Self, AdmitError> {
        let mut file = take(home)?;
        file.set_len(0)?;
        file.rewind()?;
        file.write_all(format!("{root}\n").as_bytes())?;
        file.sync_all()?;
        Ok(Self { _held: file })
    }

    /// Hold the lock while `join` writes, or a root is made here, so no `serve --admit` starts meanwhile.
    /// It empties the file, so `status` never reads a root an earlier `serve --admit` left in it.
    pub fn joining(home: &Home) -> Result<Self, AdmitError> {
        let file = take(home)?;
        file.set_len(0)?;
        Ok(Self { _held: file })
    }

    /// The root a running `serve --admit` admits, or `None` when none runs. Asked without waiting, so
    /// it can be stale by the time it is read: `join` takes the lock instead of asking.
    pub fn admitted(home: &Home) -> Option<NodeId> {
        let mut file = std::fs::File::open(home.admit_lock()).ok()?;
        // SAFETY: `file` owns a valid fd for the whole call; `flock` only attaches an advisory lock,
        // released when `file` drops. `LOCK_NB` makes a held lock an error rather than a wait.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
            return None;
        }
        let mut text = String::new();
        file.read_to_string(&mut text).ok()?;
        text.trim().parse().ok()
    }
}

/// Open `<home>/admit.lock`, making the home if it is not there yet, and take it exclusive without waiting.
/// A link at that name is refused, never followed.
fn take(home: &Home) -> Result<std::fs::File, AdmitError> {
    crate::config::create_store_dir(home.dir())?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(home.admit_lock())?;
    // SAFETY: as in `admitted`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) => AdmitError::Held,
            _ => AdmitError::Io(error),
        });
    }
    Ok(file)
}
