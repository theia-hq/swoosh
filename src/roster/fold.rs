//! The fold: how an update reaches this machine's files, whoever carried it.
//!
//! A root act's own cut, an update taken in an exchange, and one given to this machine in an exchange all
//! fold here, and nowhere else writes `roster`. The fold verifies the update under the pin, compares it with
//! the one held, and only ever adds: a revoked id or key it learns is written to the files the gate reads,
//! and none is ever removed.
//!
//! Every fold holds `<home>/roster.lock` from the read of the held update to its last write, so two folds
//! never both read one floor and both write.

use core::time::Duration;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use nauthy::{DenylistError, FileDenylist, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;

use super::{ArtifactError, Epoch, MAX_ROSTER_BLOB, RosterDoc, RosterVerifyError};
use crate::contacts::ContactsStore;
use crate::gate::RevokedKeysError;
use crate::home::Home;
use crate::standing::{Standing, StandingError};

/// What a fold did with an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Folded {
    /// Below the update held here: nothing written.
    NotNewer,
    /// The update held here, byte for byte: nothing written.
    Same,
    /// Another update at the number of the one held here: two copies of the root both signed. Its
    /// revocations were added, it was kept as `roster.fork`, and `roster` was left as it was.
    Fork {
        /// The number of the update held here.
        floor: Epoch,
    },
    /// Newer than the update held here: it is now the one held.
    Newer,
}

/// Why an update was not folded.
#[derive(Debug, thiserror::Error)]
pub enum FoldError {
    /// This machine is not a device of a root, so it takes no update.
    #[error("this machine is not one of your devices")]
    NotADevice,
    /// The standing could not be read.
    #[error(transparent)]
    Standing(#[from] StandingError),
    /// The update is larger than any update can be.
    #[error("the update is larger than any update can be")]
    TooLarge,
    /// The update is not one the pinned root signed.
    #[error(transparent)]
    Verify(#[from] RosterVerifyError),
    /// The revoked links could not be read or written.
    #[error(transparent)]
    Denylist(#[from] DenylistError),
    /// The revoked device keys could not be read or written.
    #[error(transparent)]
    RevokedKeys(#[from] RevokedKeysError),
    /// The update could not be written.
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    /// A file the fold reads or writes failed.
    #[error("{}: {source}", .path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// The address book could not be read or written.
    #[error(transparent)]
    Contacts(#[from] crate::contacts::StoreError),
    /// This machine's standing could not be written.
    #[error(transparent)]
    Write(#[from] eyre::Report),
}

/// Fold `bytes`, an update, into this home.
///
/// Folds run only on a device of a root, one that holds it or not. Below the update held here is not
/// newer; the same bytes change nothing; another update at the same number is a fork, whose revocations
/// are added and which is kept as evidence. A newer update adds its revocations, rebuilds `me`, gives this
/// machine a newer standing it carries, and becomes the update held here; `roster.fork` goes only once an
/// update carries everything the fork revoked.
pub async fn fold(home: &Home, bytes: &[u8]) -> Result<Folded, FoldError> {
    let _lock = RosterLock::take(&home.roster_lock()).await?;
    let (pin, badge_until) = match Standing::read(home).await?.standing {
        Standing::Device { pin, until } | Standing::HoldsRoot { pin, until } => (pin, until),
        Standing::Unpinned | Standing::PinOnly { .. } | Standing::InterruptedMint { .. } => {
            return Err(FoldError::NotADevice);
        }
    };
    let pin = crate::standing::pin_key(home, pin)?;
    if bytes.len() as u64 > MAX_ROSTER_BLOB {
        return Err(FoldError::TooLarge);
    }
    let doc = super::verify(bytes, pin)?;
    let held = read_held(&home.roster(), pin);
    seam().await;
    let floor = held
        .as_ref()
        .map_or(Epoch::UNVERSIONED, |(held, _)| held.epoch());
    match doc.epoch().cmp(&floor) {
        core::cmp::Ordering::Less => Ok(Folded::NotNewer),
        core::cmp::Ordering::Equal => match &held {
            None => Ok(Folded::NotNewer),
            Some((_, held)) if held.as_slice() == bytes => Ok(Folded::Same),
            Some(_) => {
                revoke(home, &doc).await?;
                keep_fork(home, bytes, pin).await?;
                Ok(Folded::Fork { floor })
            }
        },
        core::cmp::Ordering::Greater => {
            revoke(home, &doc).await?;
            let mut contacts = ContactsStore::open(home.contacts()).await?;
            let _ = contacts.contacts_mut().rebuild_me(&doc);
            contacts.save().await?;
            pick_up(home, &doc, pin, badge_until).await?;
            super::write(&home.roster(), bytes).await?;
            clear_fork(home, &doc, pin)?;
            Ok(Folded::Newer)
        }
    }
}

/// The update at `path` and its bytes, if it verifies under `root`; else `None`.
pub(crate) fn read_held(path: &Path, root: VerifyKey) -> Option<(RosterDoc, Vec<u8>)> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_ROSTER_BLOB + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_ROSTER_BLOB {
        return None;
    }
    let doc = super::verify(&bytes, root).ok()?;
    Some((doc, bytes))
}

/// Add the update's revoked ids that have not ended to `<home>/revoked`, and its revoked keys to
/// `<home>/revoked_keys`.
async fn revoke(home: &Home, doc: &RosterDoc) -> Result<(), FoldError> {
    let now = unix_now();
    let mut denylist = FileDenylist::load(home.revoked()).await?;
    for id in doc.revoked().iter().filter(|id| id.expires > now) {
        if !denylist.is_revoked_any([&id.id]) {
            denylist.revoke_id(id.id.clone()).await?;
        }
    }
    crate::gate::add_revoked_keys(home, doc.revoked_keys())?;
    Ok(())
}

/// Take this machine's standing from the update when it is bound to this machine's key, rooted at the
/// pin, ends after the one held, and neither its id nor this key is revoked in the update.
async fn pick_up(
    home: &Home,
    doc: &RosterDoc,
    pin: VerifyKey,
    badge_until: SystemTime,
) -> Result<(), FoldError> {
    let own = keystore::KeyFile::device(home.key())
        .load()
        .map_err(|error| eyre::eyre!(error))?
        .map(|stored| stored.node_id().verify_key());
    let Some(Ok(own)) = own else {
        return Ok(());
    };
    let Some(member) = doc.members().iter().find(|member| member.node == own) else {
        return Ok(());
    };
    let now = SystemTime::now();
    let cap = member.standing.cap();
    let ends = SystemTime::UNIX_EPOCH + Duration::from_secs(member.until);
    let bound = cap
        .verify_member_at_root_without_revocation(now, own, pin)
        .is_ok();
    let revoked = doc.revoked_keys().contains(&own)
        || cap
            .root_revocation_id()
            .is_some_and(|id| doc.revoked().iter().any(|revoked| revoked.id == id));
    if bound && ends > badge_until && !revoked {
        crate::config::write_badge(home, &member.standing).await?;
    }
    Ok(())
}

/// Keep `bytes` as `roster.fork`, unless a fork of this root is kept already.
async fn keep_fork(home: &Home, bytes: &[u8], pin: VerifyKey) -> Result<(), FoldError> {
    if read_held(&home.roster_fork(), pin).is_none() {
        super::write(&home.roster_fork(), bytes).await?;
    }
    Ok(())
}

/// Remove `roster.fork` once `doc` carries every revoked id that has not ended and every revoked key of
/// the fork kept.
fn clear_fork(home: &Home, doc: &RosterDoc, pin: VerifyKey) -> Result<(), FoldError> {
    let path = home.roster_fork();
    let Some((fork, _)) = read_held(&path, pin) else {
        return Ok(());
    };
    let now = unix_now();
    let ids = fork
        .revoked()
        .iter()
        .filter(|id| id.expires > now)
        .all(|id| doc.revoked().iter().any(|carried| carried.id == id.id));
    let keys = fork
        .revoked_keys()
        .iter()
        .all(|key| doc.revoked_keys().contains(key));
    if ids && keys {
        match std::fs::remove_file(&path) {
            Err(source) if source.kind() != io::ErrorKind::NotFound => {
                return Err(FoldError::Io { path, source });
            }
            _ => {}
        }
    }
    Ok(())
}

/// The fold's exclusive flock on `<home>/roster.lock`, held while this value lives.
struct RosterLock {
    /// Held, never read: the lock lives exactly as long as this open file does.
    _held: std::fs::File,
}

impl RosterLock {
    /// How long to wait between two tries while another fold holds the lock.
    const RETRY: Duration = Duration::from_millis(10);

    /// Take the lock at `path`, creating the file, and wait for any other fold to finish. It waits
    /// without blocking the thread, so a fold in another task of this process can finish meanwhile.
    async fn take(path: &Path) -> Result<Self, FoldError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| FoldError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        loop {
            // SAFETY: `file` owns a valid fd for the whole call, and `flock` only attaches an advisory
            // lock to it. `LOCK_NB` makes a held lock an error, and the loop waits.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { _held: file });
            }
            let source = io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(FoldError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            tokio::time::sleep(Self::RETRY).await;
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
pub(crate) static SLOW: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Between the read of the held update and the writes: a test widens it, to make two folds overlap.
async fn seam() {
    #[cfg(test)]
    if SLOW.load(core::sync::atomic::Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
