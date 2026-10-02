//! `root restore <dir>`: put your root on this machine from a copy.
//!
//! Restore is for a machine where no root is kept any more: one that keeps no root, or a device of this
//! root. A machine that was never one of your devices restores with a key of its own, made if it has none;
//! a lost machine is replaced, not restored, so a copy never carries a machine's key.
//!
//! In two steps, so nothing is dialed before the prompt and a refusal binds no transport:
//!
//! 1. [`restore`]: every check, the copy's passphrase, then under `home.lock` the root's files in the order
//!    a mint writes them, `root.key`, `devices`, `key.cert`, `root.pub`, the pin last. This machine's row
//!    needs nothing signed when it is live; a lapsed row is renewed and an absent one added under the
//!    suggested name for 90 days, as a mint signs its own, and that cut is kept here, offered to nobody. A
//!    crash before the pin leaves a root with no pin, which running this again (or the next `invite`)
//!    finishes.
//! 2. [`Restored::sync`]: an exchange with the devices the copy lists, then `invited-by`, for 10 s, which
//!    brings the list here up to date and gives a device that is behind this one. If that shows this
//!    machine's key revoked, the root's files go again, the pin last, and the restore refuses.

use core::time::Duration;
use std::io;
use std::path::{Path, PathBuf};

use bifrost::NodeId;
use keystore::{KeyFile, Protection, Unlock};
use nauthy::VerifyKey;
use rand::seq::SliceRandom as _;
use tightbeam::identity::AsVerifyKey as _;

use super::{
    Act, KEY_FILE, LIST_FILE, Root, RootError, header_key, not_admitting, read_header, read_list,
    remove_file, still, take_standing, unix_now,
};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::passphrase::{Asked, Prompt};
use crate::standing::Standing;
use crate::sync::{Dial, Until};

/// How long the exchange after a restore asks your devices.
const SYNC_BOUND: Duration = Duration::from_secs(10);

/// Why a root was not restored on this machine.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// `<dir>` holds no root key.
    #[error(
        "{} holds no copy of your root; make one first: swoosh root backup {}",
        EscapedPath(.dir),
        EscapedPath(.dir)
    )]
    NoCopy {
        /// The directory named.
        dir: PathBuf,
    },
    /// This root is already kept here.
    #[error("your root is already on this machine.")]
    AlreadyHere,
    /// Another root is kept here.
    #[error(
        "your root is on this machine: swoosh root backup <dir>, then swoosh root forget <dir>"
    )]
    KeepsAnother,
    /// This machine is a device of another root.
    #[error(
        "this machine is a device of root:{}, not of this copy's root:{}; to start over: swoosh leave",
        crate::credential::short(.pin),
        crate::credential::short(.root)
    )]
    DeviceOfAnother {
        /// The root this machine trusts.
        pin: NodeId,
        /// The copy's root.
        root: NodeId,
    },
    /// This machine's key is revoked by this root.
    #[error("this machine's key was revoked: swoosh leave --new-key first")]
    RevokedOwnKey,
    /// The passphrase could not be asked for, or did not open the copy.
    #[error("{0}")]
    Prompt(String),
    /// The root, its records, or a file failed.
    #[error(transparent)]
    Root(#[from] RootError),
}

/// A root restored here, before the exchange that brings it up to date.
#[derive(Debug)]
#[must_use = "a restore is checked against your devices"]
pub struct Restored {
    /// The root.
    pub root: NodeId,
    /// Whether this machine was a device of the root before: else the copy came from elsewhere, and a
    /// copy of the root is wherever the lost one is.
    pub was_device: bool,
    own: VerifyKey,
    /// The live devices the copy lists, but this machine, in random order.
    peers: Vec<(VerifyKey, String)>,
}

/// What the exchange after a restore found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Synced {
    /// `me/<name>` of the first device that answered, if one did.
    pub from: Option<String>,
}

/// Restore the root in the copy at `dir` on this machine: every check, the passphrase, then the root's files.
///
/// # Errors
///
/// A check refused, the passphrase did not open the copy, or a read or a write failed.
pub async fn restore(
    home: &Home,
    dir: &Path,
    prompt: &mut impl Prompt,
) -> Result<Restored, RestoreError> {
    let key_file = dir.join(KEY_FILE);
    if !key_file.is_file() {
        return Err(RestoreError::NoCopy {
            dir: dir.to_path_buf(),
        });
    }
    let locked = read_header(&key_file)?;
    let root = header_key(&key_file, &locked)?;
    let pin = root.verify_key().map_err(RootError::from)?;
    let revoked = crate::revoked::open(home)
        .map_err(crate::standing::StandingError::Revoked)
        .map_err(RootError::from)?;
    if revoked.is_revoked_key(&pin) {
        return Err(RootError::Revoked { root }.into());
    }
    let standing = Standing::read(home).await.map_err(RootError::from)?;
    let was_device = match standing {
        Standing::HoldsRoot { pin: held, .. } if held == root => {
            return Err(RestoreError::AlreadyHere);
        }
        Standing::HoldsRoot { .. } => return Err(RestoreError::KeepsAnother),
        Standing::InterruptedMint { root_key } if root_key != root => {
            return Err(RestoreError::KeepsAnother);
        }
        // A restore that stopped before its pin: this run finishes it.
        Standing::InterruptedMint { .. } | Standing::Unpinned => false,
        Standing::Device { pin: trusted, .. } if trusted != root => {
            return Err(RestoreError::DeviceOfAnother { pin: trusted, root });
        }
        Standing::Device { .. } => true,
    };
    // A machine with no key makes its own: a copy never carries one.
    let own = crate::identity::inspect(home)
        .map_err(RootError::from)?
        .key()
        .verify_key()
        .map_err(RootError::from)?;
    let copied = read_list(home, Some(dir), pin)?;
    let held = crate::roster::read_held(&home.devices(), pin);
    let revokes_own = |list: Option<&crate::roster::RosterDoc>| {
        list.is_some_and(|list| list.is_revoked_key(&own))
    };
    if revoked.is_revoked_key(&own)
        || revokes_own(copied.as_ref())
        || revokes_own(held.as_ref().map(|(held, _)| held))
    {
        return Err(RestoreError::RevokedOwnKey);
    }
    if !prompt.terminal() {
        return Err(RootError::NoTerminalToUnlock.into());
    }
    let (secret, passphrase) = crate::passphrase::unlock(prompt, Asked::Copy(dir), |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase))
    })
    .map_err(|report| RestoreError::Prompt(format!("{report:#}")))?;

    let home_lock = HomeWrite::take(home).await.map_err(RootError::from)?;
    still(&home_lock, home, standing).await?;
    not_admitting(&home_lock, home)?;
    // `root.key`, unless a restore that stopped left it: an unpinned home keeps no root but a revoked one,
    // which is no root, so it goes first.
    if !matches!(standing, Standing::InterruptedMint { .. }) {
        remove_file(&home.root_key())?;
        KeyFile::root(home.root_key())
            .write(&secret, Protection::Passphrase(&passphrase))
            .map_err(RootError::from)?;
    }
    drop(passphrase);
    // `devices`: the copy's list, when it is newer than the one held here.
    let held_number = held.as_ref().map(|(held, _)| held.epoch());
    if let Some(copied) = &copied
        && held_number.is_none_or(|number| number < copied.epoch())
    {
        let path = dir.join(LIST_FILE);
        let bytes = std::fs::read(&path).map_err(super::io_at(&path))?;
        crate::roster::write(&home_lock, &home.devices(), &bytes).map_err(RootError::from)?;
    }
    let newest = crate::roster::read_held(&home.devices(), pin).map(|(list, _)| list);
    let mut act = Act::new(home, root, None, newest.as_ref(), Some(own));
    act.bring_forward(&mut io::sink())?;
    let now = unix_now();
    let row = act.book.rows.iter().find(|row| row.node == own).cloned();
    let peers = peers(&act, own);
    let mut root_here = Root { secret, act };
    match row {
        // Live: nothing to sign. A device's own standing is kept when it already runs as long.
        Some(row) if row.until > now => {
            let kept = matches!(standing, Standing::Device { until, .. }
                if until >= super::at(row.until));
            if !kept {
                take_standing(&home_lock, home, root, &row.standing)?;
            }
        }
        // Lapsed or absent: signed as a mint signs its own, into a list kept here.
        _ => root_here.take_own(&home_lock, own)?,
    }
    drop(home_lock);
    Ok(Restored {
        root,
        was_device,
        own,
        peers,
    })
}

/// The live devices `act` lists, but `own`, in random order.
fn peers(act: &Act, own: VerifyKey) -> Vec<(VerifyKey, String)> {
    let mut peers: Vec<(VerifyKey, String)> = act
        .book
        .rows
        .iter()
        .filter(|row| row.node != own)
        .map(|row| (row.node, format!("me/{}", row.label)))
        .collect();
    peers.shuffle(&mut rand::thread_rng());
    peers
}

impl Restored {
    /// Exchange with your devices through `dial`: the ones the copy lists, then `invited-by`, for 10 s. When
    /// that shows this machine's key revoked, take the root off again, the pin last, and refuse.
    ///
    /// # Errors
    ///
    /// This machine's key is revoked, or a write failed.
    pub async fn sync(self, home: &Home, dial: &impl Dial) -> Result<Synced, RestoreError> {
        let devices = crate::sync::devices(home, self.peers)
            .await
            .map_err(RootError::from)?;
        let replies = crate::sync::round(dial, &devices, Until::Newer, SYNC_BOUND).await;
        let from = replies
            .into_iter()
            .find(|(_, reply)| reply.answer().is_some())
            .map(|(device, _)| device.name);
        let pin = self.root.verify_key().map_err(RootError::from)?;
        let revoked = crate::revoked::open(home)
            .map_err(crate::standing::StandingError::Revoked)
            .map_err(RootError::from)?;
        let held = crate::roster::read_held(&home.devices(), pin);
        if revoked.is_revoked_key(&self.own)
            || held.is_some_and(|(held, _)| held.is_revoked_key(&self.own))
        {
            let _home_lock = HomeWrite::take(home).await.map_err(RootError::from)?;
            for path in [home.root_key(), home.key_cert(), home.root_pub()] {
                remove_file(&path)?;
            }
            return Err(RestoreError::RevokedOwnKey);
        }
        Ok(Synced { from })
    }
}
