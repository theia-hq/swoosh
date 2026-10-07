//! `root restore <dir>`: put your root on this machine from a copy.
//!
//! Restore is for a machine where no root is kept any more: one that keeps no root, or a device of this
//! root. A machine that was never one of your devices restores with a key of its own, made if it has none;
//! a lost machine is replaced, not restored, so a copy never carries a machine's key.
//!
//! In two steps, so nothing is dialed before the prompt and a refusal binds no transport:
//!
//! 1. [`restore`]: every check, the copy's passphrase, then under `home.lock` the root's files. A copy is its
//!    key and the last list it signed, so a copy without its list, or with one its root did not sign, is
//!    refused before the prompt, and the bytes that verified then are the ones written. The order is
//!    `devices`, then `root.key`, then this machine's row, `key.cert` and the pin. On a device of this root
//!    `root.key` is the commit point (the home keeps the root from then on), so everything the copy brings
//!    lands before it: on a device the list goes through the fold, the one path that writes `devices`, and
//!    elsewhere it is written only over an older list or none, decided under the lock. This machine's row
//!    needs nothing signed when it is live; a lapsed row is renewed and an absent one added under the
//!    suggested name for 90 days, as a mint signs its own, and that cut is kept here, offered to nobody. On a
//!    machine that kept no root, a crash before the pin leaves a root with no pin, which running this again
//!    (or the next `invite`) finishes; on a device, the next act that cuts carries the row.
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
    Act, KEY_FILE, LIST_FILE, Renamed, Root, RootError, header_key, not_admitting, read_header,
    read_list_at, remove_file, still, take_standing, unix_now,
};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::passphrase::{Asked, Prompt};
use crate::roster::Epoch;
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
    /// `<dir>` holds a root key but not the list of your devices beside it.
    #[error(
        "the copy in {} has no list of your devices beside its key, so it is not a whole copy of your root; use \
         another copy.",
        EscapedPath(.dir)
    )]
    NoList {
        /// The directory named.
        dir: PathBuf,
    },
    /// This root is already kept here.
    #[error("your root is already on this machine.")]
    AlreadyHere,
    /// Another root is kept here.
    #[error(
        "this machine keeps root:{}, and the copy in {} is root:{}; to restore the copy here, first remove \
         root:{} from this machine: swoosh root forget --help",
        crate::credential::short(.held),
        EscapedPath(.dir),
        crate::credential::short(.root),
        crate::credential::short(.held)
    )]
    KeepsAnother {
        /// The root kept here.
        held: NodeId,
        /// The directory named.
        dir: PathBuf,
        /// The copy's root.
        root: NodeId,
    },
    /// This machine is a device of another root.
    #[error(
        "the copy in {} is root:{}, and this machine is a device of root:{}; to restore the copy here, first \
         leave root:{}: swoosh leave",
        EscapedPath(.dir),
        crate::credential::short(.root),
        crate::credential::short(.pin),
        crate::credential::short(.pin)
    )]
    DeviceOfAnother {
        /// The directory named.
        dir: PathBuf,
        /// The root this machine trusts.
        pin: NodeId,
        /// The copy's root.
        root: NodeId,
    },
    /// This machine's key is revoked by this root.
    #[error(
        "this machine's key was revoked; to restore here, first give this machine a new key: swoosh leave \
         --new-key"
    )]
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
    /// The number of the list the restore left as `devices`: its own cut, or the copy's list.
    written: Epoch,
    /// The root, unlocked at the prompt and held through the exchange, so an answer above `written` is
    /// carried with no second prompt.
    unlocked: Root,
    /// This machine's row, renamed in the list the restore cut, when a fork kept here gave its name to
    /// another device.
    renamed: Option<Renamed>,
}

/// What the exchange after a restore found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Synced {
    /// `me/<name>` of the first device that answered, if one did.
    pub from: Option<String>,
    /// Whether this machine's row waits for the next act that cuts: a list moved under the re-cut, which
    /// then offered nothing.
    pub waiting: bool,
    /// This machine's row, renamed in the list that stands: the restore's own cut, or the re-cut's when
    /// an answer replaced it.
    pub renamed: Option<Renamed>,
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
        Standing::HoldsRoot { pin: held, .. } => {
            return Err(RestoreError::KeepsAnother {
                held,
                dir: dir.to_path_buf(),
                root,
            });
        }
        Standing::InterruptedMint { root_key } if root_key != root => {
            return Err(RestoreError::KeepsAnother {
                held: root_key,
                dir: dir.to_path_buf(),
                root,
            });
        }
        // A restore that stopped before its pin: this run finishes it.
        Standing::InterruptedMint { .. } | Standing::Unpinned => false,
        Standing::Device { pin: trusted, .. } if trusted != root => {
            return Err(RestoreError::DeviceOfAnother {
                dir: dir.to_path_buf(),
                pin: trusted,
                root,
            });
        }
        Standing::Device { .. } => true,
    };
    // A machine with no key makes its own: a copy never carries one.
    let own = crate::identity::inspect(home)
        .map_err(RootError::from)?
        .key()
        .verify_key()
        .map_err(RootError::from)?;
    // The copy's list, required and verified now, before the prompt: these bytes are the ones written.
    let Some((copied, copied_bytes)) = read_list_at(&dir.join(LIST_FILE), pin)? else {
        return Err(RestoreError::NoList {
            dir: dir.to_path_buf(),
        });
    };
    let held = crate::roster::read_held(&home.devices(), pin);
    let revokes_own = |list: Option<&crate::roster::RosterDoc>| {
        list.is_some_and(|list| list.is_revoked_key(&own))
    };
    if revoked.is_revoked_key(&own)
        || revokes_own(Some(&copied))
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
    // 1. `devices`, never over a newer list: decided here, under the lock. A device folds the copy's list, the
    // one path that writes `devices` (newer taken, the same number with other bytes kept as the conflict,
    // older nothing); elsewhere the bytes are written only over an older list or none.
    match standing {
        Standing::Device { .. } => {
            crate::roster::fold(&home_lock, home, &copied_bytes)
                .await
                .map_err(RootError::from)?;
        }
        // `HoldsRoot` returned before the prompt, and `still` refuses a standing that moved since.
        Standing::Unpinned | Standing::InterruptedMint { .. } | Standing::HoldsRoot { .. } => {
            let held_here = crate::roster::read_held(&home.devices(), pin);
            if held_here.is_none_or(|(held, _)| held.epoch() < copied.epoch()) {
                crate::roster::write(&home_lock, &home.devices(), &copied_bytes)
                    .map_err(RootError::from)?;
            }
        }
    }
    drop(copied_bytes);
    // A list that revokes this machine can land while the prompt waits, so the refusal before the prompt is
    // made again here, before the commit point. What step 1 folded stays: revocations only grow.
    if super::own_key_revoked(home, pin)? {
        return Err(RestoreError::RevokedOwnKey);
    }
    // 2. `root.key`, unless a restore that stopped left it: an unpinned home keeps no root but a revoked one,
    // which is no root, so it goes first. On a device this is the commit point.
    if !matches!(standing, Standing::InterruptedMint { .. }) {
        remove_file(&home.root_key())?;
        KeyFile::root(home.root_key())
            .write(&secret, Protection::Passphrase(&passphrase))
            .map_err(RootError::from)?;
    }
    drop(passphrase);
    super::seam(super::Seam::Keyed)?;
    // 3. This machine's row, `key.cert` and the pin.
    let newest = crate::roster::read_held(&home.devices(), pin).map(|(list, _)| list);
    let mut act = Act::new(home, root, None, newest.as_ref(), Some(own));
    let renamed = act.bring_forward(&mut io::sink())?;
    let now = unix_now();
    let row = act.book.rows.iter().find(|row| row.node == own).cloned();
    let peers = peers(&act, own);
    let mut root_here = Root { secret, act };
    let renamed = match row {
        // Live: nothing to sign, so nothing is cut, and records renamed on the way are dropped. A device's
        // own standing is kept when it already runs as long.
        Some(row) if row.until > now => {
            let kept = matches!(standing, Standing::Device { until, .. }
                if until >= super::at(row.until));
            if !kept {
                take_standing(&home_lock, home, root, &row.standing)?;
            }
            None
        }
        // Lapsed or absent: signed as a mint signs its own, into a list kept here, which carries the rename.
        _ => {
            root_here.take_own(&home_lock, own)?;
            renamed
        }
    };
    // Read under the lock: a fold that lands once it is let go is an answer above this number, and is
    // carried after the sync.
    let written = crate::roster::read_held(&home.devices(), pin)
        .map_or(Epoch::UNVERSIONED, |(list, _)| list.epoch());
    drop(home_lock);
    Ok(Restored {
        root,
        was_device,
        own,
        peers,
        written,
        unlocked: root_here,
        renamed,
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
            || held
                .as_ref()
                .is_some_and(|(held, _)| held.is_revoked_key(&self.own))
        {
            let _home_lock = HomeWrite::take(home).await.map_err(RootError::from)?;
            for path in [home.root_key(), home.key_cert(), home.root_pub()] {
                remove_file(&path)?;
            }
            return Err(RestoreError::RevokedOwnKey);
        }
        // An answer above the restore's own number replaced `devices` with a list that may not carry this
        // machine's row. The row step runs again on that list's records, never a union with the replaced cut
        // (a union would take a name the newer list gave another key, and revoke this machine), and the cut
        // goes to your devices. At or below, the list here is the restore's own, and nothing is cut.
        // The restore's own cut, and a rename in it, stand only while no answer replaced it.
        let Some((newer, _)) = held.filter(|(held, _)| held.epoch() > self.written) else {
            return Ok(Synced {
                from,
                waiting: false,
                renamed: self.renamed,
            });
        };
        let mut root = self.unlocked;
        root.act = Act::new(home, self.root, None, Some(&newer), Some(self.own));
        let renamed = root.act.bring_forward(&mut io::sink())?;
        root.carry_own()?;
        // A list that moved under the re-cut is not an error here: the root, the pin and this machine's
        // standing are in place, and the next act that cuts carries the row. Once `carry_own` leaves this
        // machine's row out of what the act added and renewed, nothing a fold can land stops the re-cut, so
        // this arm is defence.
        let committed = match root.commit_to(&mut io::sink()).await {
            Ok(committed) => committed,
            Err(RootError::ListChanged) => {
                return Ok(Synced {
                    from,
                    waiting: true,
                    renamed: None,
                });
            }
            Err(error) => return Err(error.into()),
        };
        if committed.number > newer.epoch() {
            let _reach = committed.offer(dial).await;
        }
        Ok(Synced {
            from,
            waiting: false,
            renamed,
        })
    }
}
