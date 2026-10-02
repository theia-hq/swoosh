//! The fold: how an update reaches this machine's files, whoever carried it.
//!
//! A root act's own cut, an update taken in an exchange, and one given to this machine in an exchange all
//! fold here, and nowhere else writes `devices`. The fold verifies the update under the pin, compares it with
//! the one held, and only ever adds: a revoked id or key it learns is written to the files the gate reads,
//! and none is ever removed. A fork another device passes on in an exchange folds here too
//! ([`fold_fork`]), and never becomes the update held.
//!
//! Every fold runs under `home.lock`, taken by its caller and passed in, from the read of the held update to
//! its last write, so two folds never both read one floor and both write. A root act's commit folds its own
//! cut under the lock it already holds.

use core::time::Duration;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use nauthy::{Revocation, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;

use super::{ArtifactError, Epoch, MAX_ROSTER_BLOB, RosterDoc, RosterVerifyError};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::revoked::RevokedError;
use crate::standing::{Standing, StandingError};

/// What a fold did with an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Folded {
    /// Below the update held here: nothing written.
    NotNewer,
    /// The update held here, byte for byte: nothing written.
    Same,
    /// Another update at the number of the one held here: two copies of the root both signed. Its
    /// revocations were added, it was kept as `devices.conflict`, and `devices` was left as it was.
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
    /// The revocations could not be read or written.
    #[error(transparent)]
    Revoked(#[from] RevokedError),
    /// The update could not be written.
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    /// A file the fold reads or writes failed.
    #[error("{}: {source}", EscapedPath(.path))]
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
    /// `home.lock` could not be taken.
    #[error(transparent)]
    Lock(#[from] crate::home::LockError),
}

/// Fold `bytes`, an update, into this home.
///
/// Folds run only on a device of a root, one that holds it or not. Below the update held here is not
/// newer; the same bytes change nothing; another update at the same number is a fork, whose revocations
/// are added and which is kept as evidence. A newer update adds its revocations, gives this machine a
/// newer standing it carries, and becomes the update held here, from which `me` is read; `invited-by` goes
/// with it, and `devices.conflict` goes only once an update carries everything the fork revoked. Under
/// `home.lock`, which the caller holds.
pub async fn fold(home_lock: &HomeWrite, home: &Home, bytes: &[u8]) -> Result<Folded, FoldError> {
    let (pin, badge_until) = match Standing::read(home).await? {
        Standing::Device { pin, until } | Standing::HoldsRoot { pin, until } => (pin, until),
        Standing::Unpinned | Standing::InterruptedMint { .. } => {
            return Err(FoldError::NotADevice);
        }
    };
    let pin = crate::standing::pin_key(home, pin)?;
    if bytes.len() as u64 > MAX_ROSTER_BLOB {
        return Err(FoldError::TooLarge);
    }
    let doc = super::verify(bytes, pin)?;
    let held = read_held(&home.devices(), pin);
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
                revoke(home_lock, home, &doc)?;
                keep_fork(home_lock, home, bytes, pin)?;
                Ok(Folded::Fork { floor })
            }
        },
        core::cmp::Ordering::Greater => {
            revoke(home_lock, home, &doc)?;
            pick_up(home_lock, home, &doc, pin, badge_until)?;
            super::write(home_lock, &home.devices(), bytes)?;
            forget_invited_by(home);
            clear_fork(home, &doc, pin)?;
            Ok(Folded::Newer)
        }
    }
}

/// Remove `invited-by` once a list is held: the list names every device a sync asks, so the one device the
/// invite named is no longer needed. Only a fold that writes `devices` calls this, under `home.lock`.
/// Best-effort: one left behind is only one more device a sync asks.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn forget_invited_by(home: &Home) {
    match std::fs::remove_file(home.invited_by()) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            tracing::debug!(%error, "could not remove invited-by");
        }
        _ => {}
    }
}

/// Fold `bytes`, the fork another device keeps and passed on in an exchange, into this home.
///
/// Folds run only on a device of a root, one that holds it or not. A fork that is the update held here, or
/// whose revocations the update held here all carries, changes nothing. Any other adds its revocations,
/// whatever its number, and is kept as `devices.conflict` unless a fork is kept already, so the next exchange
/// here passes it on. It never becomes the update held here. Under `home.lock`, which the caller holds.
pub async fn fold_fork(home_lock: &HomeWrite, home: &Home, bytes: &[u8]) -> Result<(), FoldError> {
    let pin = match Standing::read(home).await? {
        Standing::Device { pin, .. } | Standing::HoldsRoot { pin, .. } => pin,
        Standing::Unpinned | Standing::InterruptedMint { .. } => {
            return Err(FoldError::NotADevice);
        }
    };
    let pin = crate::standing::pin_key(home, pin)?;
    if bytes.len() as u64 > MAX_ROSTER_BLOB {
        return Err(FoldError::TooLarge);
    }
    let fork = super::verify(bytes, pin)?;
    if let Some((held, held_bytes)) = read_held(&home.devices(), pin)
        && (held_bytes.as_slice() == bytes || carries(&held, &fork))
    {
        return Ok(());
    }
    revoke(home_lock, home, &fork)?;
    keep_fork(home_lock, home, bytes, pin)
}

/// The update at `path` and its bytes, if it verifies under `root`; else `None`.
pub(crate) fn read_held(path: &Path, root: VerifyKey) -> Option<(RosterDoc, Vec<u8>)> {
    read_held_or_error(path, root).ok().flatten()
}

/// The update at `path` and its bytes, if it verifies under `root`; `None` when there is none, or it does
/// not verify.
///
/// # Errors
///
/// The file is there and could not be read.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub(crate) fn read_held_or_error(
    path: &Path,
    root: VerifyKey,
) -> std::io::Result<Option<(RosterDoc, Vec<u8>)>> {
    use std::io::Read as _;

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_ROSTER_BLOB + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ROSTER_BLOB {
        return Ok(None);
    }
    Ok(super::verify(&bytes, root).ok().map(|doc| (doc, bytes)))
}

/// Add the update's revoked ids that have not ended, and its revoked keys, to `<home>/revoked`, in one
/// write. The writer leaves out this machine's own key (see [`crate::revoked::add`]); the pick-up still
/// refuses a standing whose key the update revokes.
fn revoke(home_lock: &HomeWrite, home: &Home, doc: &RosterDoc) -> Result<(), FoldError> {
    let now = unix_now();
    let ids = doc
        .revoked()
        .iter()
        .filter(|id| id.expires > now)
        .map(|id| Revocation::Id(id.id.clone()));
    let keys = doc.revoked_keys().map(Revocation::Key);
    crate::revoked::add(home_lock, home, ids.chain(keys))?;
    Ok(())
}

/// This machine's key, from its key file's header; `None` when it has none, or the header is not a usable
/// key.
fn own_key(home: &Home) -> Result<Option<VerifyKey>, FoldError> {
    Ok(keystore::KeyFile::device(home.key())
        .load()
        .map_err(|error| eyre::eyre!(error))?
        .and_then(|stored| stored.node_id().verify_key().ok()))
}

/// Take this machine's standing from the update when it is bound to this machine's key, rooted at the
/// pin, ends after the one held, and neither its id nor this key is revoked in the update.
fn pick_up(
    home_lock: &HomeWrite,
    home: &Home,
    doc: &RosterDoc,
    pin: VerifyKey,
    badge_until: SystemTime,
) -> Result<(), FoldError> {
    let Some(own) = own_key(home)? else {
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
    let revoked = doc.is_revoked_key(&own)
        || cap
            .root_revocation_id()
            .is_some_and(|id| doc.revoked().iter().any(|revoked| revoked.id == id));
    if bound && ends > badge_until && !revoked {
        crate::config::write_badge(home_lock, home, &member.standing).map_err(|source| {
            FoldError::Io {
                path: home.key_cert(),
                source,
            }
        })?;
    }
    Ok(())
}

/// Keep `bytes` as `devices.conflict`, unless a fork of this root is kept already.
fn keep_fork(
    home_lock: &HomeWrite,
    home: &Home,
    bytes: &[u8],
    pin: VerifyKey,
) -> Result<(), FoldError> {
    if read_held(&home.devices_conflict(), pin).is_none() {
        super::write(home_lock, &home.devices_conflict(), bytes)?;
    }
    Ok(())
}

/// Remove `devices.conflict` once `doc` carries every revoked id that has not ended and every revoked key of
/// the fork kept.
fn clear_fork(home: &Home, doc: &RosterDoc, pin: VerifyKey) -> Result<(), FoldError> {
    let path = home.devices_conflict();
    let Some((fork, _)) = read_held(&path, pin) else {
        return Ok(());
    };
    if carries(doc, &fork) {
        match std::fs::remove_file(&path) {
            Err(source) if source.kind() != io::ErrorKind::NotFound => {
                return Err(FoldError::Io { path, source });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Whether `doc` carries every revoked id of `fork` that has not ended and every revoked key of `fork`.
fn carries(doc: &RosterDoc, fork: &RosterDoc) -> bool {
    let now = unix_now();
    let ids = fork
        .revoked()
        .iter()
        .filter(|id| id.expires > now)
        .all(|id| doc.revoked().iter().any(|carried| carried.id == id.id));
    let keys = fork.revoked_keys().all(|key| doc.is_revoked_key(&key));
    ids && keys
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
