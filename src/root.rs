//! The root: the one thing that signs as your root, presented for one command and dropped.
//!
//! A [`Root`] is built only by [`Root::present`] (a root kept on this machine, or a copy given with
//! `--root <dir>`) and [`Root::mint`] (this machine's first root). Both run every check before they ask for
//! the passphrase, so a refusal never costs a prompt.
//!
//! A root is its key and the last list of your devices it signed, kept beside it: `<home>/root.key` beside
//! the home's own `devices`, or a copy, a directory holding `root.key` and `devices` and nothing else. That
//! list is also its counter: an act reads its records forward from the newest of the list beside the key,
//! the home's `devices`, `devices.conflict` and `revoked`, and writes its cut beside the key before the
//! home's `devices` and before anything is offered. [`Root::inspect`] reads the same records with no lock,
//! no prompt and no write, for a command that only reports.
//!
//! Every signature the root makes is made here: a device's standing and the update. Nothing outside this
//! module holds an unlocked root, and `serve` never reaches it.
//!
//! The key is unlocked in the process that runs the command. It wipes itself on drop, and every root act
//! sets the core-dump limit to zero first, so a crash leaves no copy of it on disk.

use core::fmt;
use core::time::Duration;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Protection, Stored, Unlock};
use nauthy::{Link, RevocationId, VerifyKey};
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};
use zeroize::Zeroizing;

use crate::codec::{
    FormatError, Id, MAX_IDS, MAX_MEMBERS, MAX_REVOKED, MAX_REVOKED_KEYS, RevokedDevice,
};
use crate::contacts::DeviceLabel;
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite, ServeLock};
use crate::passphrase::{Asked, Prompt};
use crate::reach_report::{Missed, Reach, Why};
use crate::roster::{
    ArtifactError, Epoch, FoldError, Folded, MAX_ROSTER_BLOB, Member, RosterDoc, read_held,
};
use crate::standing::{Standing, StandingError};
use crate::sync::{Answer, Device, Dial, EACH, Until};

mod backup;
mod forget;
mod lock;
mod restore;

pub use backup::{BackupError, backup};
pub use forget::{Disk, ForgetError, Forgot, Place, RealDisk, forget};
pub use lock::{Relocked, RootLockError, lock};
pub use restore::{RestoreError, Restored, Synced, restore};

/// The root's key file in its directory: always sealed, and of the root kind.
pub const KEY_FILE: &str = "root.key";

/// The last list of your devices the root signed, beside its key in a copy.
pub const LIST_FILE: &str = "devices";

/// How long a device's standing runs when nothing else says: 90 days.
pub const DEFAULT_DURATION: Duration = Duration::from_secs(90 * DAY);

/// A device renews on its own only when its standing runs at least this long.
const SHORTEST_RENEWING: u64 = 30 * DAY;

const DAY: u64 = 24 * 60 * 60;

/// The number of the list a mint cuts: the root's first, listing only the machine that made it.
const MINTED: Epoch = Epoch(1);

/// How long an act that cuts spends asking your devices for a newer update before it signs.
const SYNC_BOUND: Duration = Duration::from_secs(10);

/// How long a root act's offer of its cut may take in all.
const OFFER_BOUND: Duration = Duration::from_secs(20);

/// The refusal when a root is to be made with nobody at a terminal to choose its passphrase.
pub(crate) const MINT_NEEDS_TERMINAL: &str = "making your root asks you to choose its passphrase, which needs a terminal once: run this at one.";

/// The refusal when a root is to be used with nobody at a terminal to type its passphrase.
pub(crate) const UNLOCK_NEEDS_TERMINAL: &str =
    "using your root asks for its passphrase, which needs a terminal: run this at one.";

/// The refusal of an act that only a machine keeping no root may run (`join`, `leave`), where a root is kept:
/// the two commands that take it off this machine, one per line.
pub const KEPT_HERE: &str = "your root is on this machine, and this runs only where no root is kept. Back it up: swoosh root backup <dir>\nthen remove it from this machine: swoosh root forget <dir>";

/// The warning before the prompt of an act that cuts on the root kept here, when this machine's key is revoked:
/// the act goes on, since the root's authority does not depend on this machine being one of your devices, and
/// it signs no row for this machine.
pub const OWN_KEY_REVOKED: &str = "warning: this machine's key was revoked, so your devices no longer admit it. Your root still works here.";

/// Whether this machine's key is revoked, by this home's `revoked` or by the list of the root `root` held here.
///
/// # Errors
///
/// This machine's key or the revocations could not be read.
pub fn own_key_revoked(home: &Home, root: VerifyKey) -> Result<bool, RootError> {
    let Some(own) = own_key(home)? else {
        return Ok(false);
    };
    let revoked = crate::revoked::open(home).map_err(StandingError::Revoked)?;
    Ok(revoked.is_revoked_key(&own)
        || read_held(&home.devices(), root).is_some_and(|(held, _)| held.is_revoked_key(&own)))
}

/// Where the root for one command is: kept in this home, or a copy in a directory given with `--root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootPlace {
    /// `<home>/root.key`, beside the home's own `devices`.
    Home,
    /// A copy, from `--root <dir>`.
    Dir(PathBuf),
}

/// The command a root is presented to. Each decides whether a machine that is not a device of the root
/// may present it, whether the copy is written, and whether the act cuts an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootVerb {
    /// Adds or renews a device; ends in a cut.
    Invite,
    /// Revokes a device or a link; ends in a cut.
    Revoke,
    /// Makes this machine a device of the root; syncs and cuts in its own steps.
    Restore,
    /// Copies the root; signs nothing and never writes its source.
    Backup,
    /// Changes the root's passphrase; rewrites `root.key` only.
    Lock,
    /// Retires the root; only where the root is kept, and never folds or cuts.
    RevokeRoot,
}

impl RootVerb {
    /// Whether the act cuts an update. Only a device of the root may present it to one, because an
    /// update cut elsewhere reaches none of its devices; and it brings the root forward first.
    fn cuts(self) -> bool {
        matches!(self, Self::Invite | Self::Revoke)
    }

    /// Whether the act writes beside the root's key, so a copy that cannot be written is refused.
    fn writes_source(self) -> bool {
        !matches!(self, Self::Backup | Self::Restore)
    }
}

/// Why a root could not be presented, made, or used.
#[derive(Debug, thiserror::Error)]
pub enum RootError {
    /// This home's standing could not be read.
    #[error(transparent)]
    Standing(#[from] StandingError),
    /// An act that cuts, on a machine that is not a device of the root.
    #[error(
        "this machine is not a device of your root, so nothing it signs reaches your devices. Run this on \
        one of your devices, or make this one a device: swoosh root restore <dir>"
    )]
    NotADevice,
    /// A copy presented where a root is already kept.
    #[error("your root is on this machine, so drop --root.")]
    HeldHere,
    /// A root to be made or finished here while a `serve --admit` admits another root's devices.
    #[error("swoosh serve is running; stop it first: swoosh stop")]
    Admitting,
    /// This machine's standing moved between the check before the prompt and the write under `home.lock`:
    /// a `join`, `leave` or another mint ran meanwhile. Nothing was written.
    #[error("{}", crate::standing::CHANGED)]
    StandingChanged,
    /// No root is kept here, and this machine is no root's device.
    #[error("this machine holds no root. Your first `swoosh invite <name> <key>` makes one.")]
    NoRootHere,
    /// No root is kept on this device of one.
    #[error("your root is not on this machine: run this where it is, or add --root <dir>.")]
    NotOnThisMachine,
    /// A root is here, and making it did not finish.
    #[error("{}", crate::standing::UNFINISHED_MINT)]
    Unfinished {
        /// The root being made.
        root: NodeId,
    },
    /// The root's key file could not be read or unlocked.
    #[error(transparent)]
    KeyFile(#[from] keystore::Error),
    /// A key file's header names a key nobody can hold.
    #[error(transparent)]
    UnusableKey(#[from] crate::identity::UnusableKey),
    /// A key stored on this machine is not a usable key.
    #[error("a key stored on this machine is not a usable key ({0}): refusing to use it")]
    Key(#[from] nauthy::KeyError),
    /// The root's key file is plain.
    #[error(
        "this root key is not sealed, and swoosh never writes one that way: it was changed outside swoosh. \
        Use another copy."
    )]
    Plain,
    /// The root's key file opens with a method this build does not know.
    #[error("this root opens with method {found}, which this build does not support.")]
    Method {
        /// The method byte.
        found: u8,
    },
    /// The root is not the one this machine trusts.
    #[error("this root is root:{}, and this machine trusts root:{}", crate::credential::short(.root), crate::credential::short(.pin))]
    Mismatch {
        /// The root presented.
        root: NodeId,
        /// The root this machine trusts.
        pin: NodeId,
    },
    /// The root was revoked on this machine.
    #[error("root root:{} was revoked on this machine; recovery is a new root", crate::credential::short(.root))]
    Revoked {
        /// The revoked root.
        root: NodeId,
    },
    /// The copy cannot be written, and the act records what it signs there.
    #[error(
        "this copy of your root cannot be written ({}); using your root must record what it signs.",
        EscapedPath(.dir)
    )]
    ReadOnly {
        /// The copy's directory.
        dir: PathBuf,
    },
    /// The list beside the root's key is not one this root signed. Names the list's own file, never the
    /// directory: for the root kept here that is the whole home.
    #[error(
        "this root's devices list was changed outside swoosh ({}): refusing to sign from it. Use another copy.",
        EscapedPath(.path)
    )]
    Damaged {
        /// The list's file, `devices` beside the root's key.
        path: PathBuf,
    },
    /// The root lists as many devices as one update can carry.
    #[error(
        "your root lists {count} devices, the most one root can publish. Revoke some first: swoosh revoke \
        me/<name>"
    )]
    TooManyDevices {
        /// The live devices.
        count: usize,
    },
    /// The root has revoked as many unexpired ids as one update can carry.
    #[error(
        "your root has revoked {count} links and devices that have not ended yet, the most it can publish at \
        once. The oldest end on {oldest}; or replace your root (swoosh revoke --help)."
    )]
    TooManyRevoked {
        /// The unexpired revoked ids.
        count: usize,
        /// When the first of them ends.
        oldest: Date,
    },
    /// The root has revoked as many device keys as one update can carry.
    #[error(
        "your root has revoked {count} device keys, the most it can publish at once, and a revoked key never \
        ends. Replace your root (swoosh revoke --help)."
    )]
    TooManyKeys {
        /// The revoked keys.
        count: usize,
    },
    /// The update's number cannot move past the last one.
    #[error("this root can sign no more lists of your devices: replace it (swoosh revoke --help).")]
    Exhausted,
    /// Making a root needs a terminal to choose its passphrase at.
    #[error("{}", MINT_NEEDS_TERMINAL)]
    NoTerminal,
    /// Using a root needs a terminal to type its passphrase at.
    #[error("{}", UNLOCK_NEEDS_TERMINAL)]
    NoTerminalToUnlock,
    /// A root is made only on a machine that trusts none, or finishes one made here.
    #[error("this machine already trusts a root")]
    NotMintable,
    /// A renewal named a device the root does not have.
    #[error(
        "you have no device {name}. For a machine with no console: swoosh invite {name} --new-key. \
        Otherwise: swoosh invite {name} <its key>."
    )]
    NoDeviceToRenew {
        /// The name asked for.
        name: DeviceLabel,
    },
    /// A new key was asked for a device that made its own.
    #[error(
        "me/{name} keeps its own key; renew it without --new-key. For a new key: on it, swoosh leave \
        --new-key; then here, swoosh revoke me/{name} and invite the new key."
    )]
    KeepsOwnKey {
        /// The device.
        name: DeviceLabel,
    },
    /// A new key was asked for a device that holds the most renewals in force.
    #[error(
        "me/{name} has {MAX_IDS} renewals in force until {earliest}. To hand it a new key now: swoosh \
        revoke me/{name}, then swoosh invite {name} --new-key."
    )]
    RenewalsInForce {
        /// The device.
        name: DeviceLabel,
        /// When the first of them ends.
        earliest: Date,
    },
    /// A revoke named a device the root does not have.
    #[error("me/{name} is not one of your devices (`swoosh status`)")]
    NotYourDevice {
        /// The name asked for.
        name: DeviceLabel,
    },
    /// A live device already has this name, under another key.
    #[error(
        "me/{name} is {}. To replace it: swoosh revoke me/{name}, then invite the new key.",
        crate::credential::short(.key)
    )]
    NameTaken {
        /// The name.
        name: DeviceLabel,
        /// The key it names.
        key: VerifyKey,
    },
    /// The key is this machine's, already a live device.
    #[error("that is this machine's key; it is already your device me/{name}")]
    OwnKey {
        /// This machine's name.
        name: DeviceLabel,
    },
    /// The key is already a live device.
    #[error(
        "{} is already your device me/{name} (until {until}). To renew it: swoosh invite {name}. A \
        machine has one name.",
        crate::credential::short(.key)
    )]
    AlreadyDevice {
        /// The key.
        key: VerifyKey,
        /// Its name.
        name: DeviceLabel,
        /// When its standing ends.
        until: Date,
    },
    /// The key is revoked, and a revoked key is never admitted again.
    #[error(
        "{} was me/{name}'s key and is revoked; a revoked key is not re-admitted. Give that machine a new \
        key and invite that one. On that machine: swoosh leave --new-key",
        crate::credential::short(.key)
    )]
    RevokedKey {
        /// The key.
        key: VerifyKey,
        /// The name the revoked device had. The short key stays beside it: the name may now be a live
        /// device's, and the key says which `me/{name}` is meant.
        name: DeviceLabel,
    },
    /// The passphrase could not be asked for.
    #[error("{0}")]
    Prompt(String),
    /// A standing could not be signed.
    #[error("signing a standing")]
    Sign(#[source] nauthy::CapError),
    /// The records would not form a valid update.
    #[error("the root's records are malformed")]
    Format(#[source] FormatError),
    /// The update could not be written here.
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    /// The update cut could not be folded here.
    #[error(transparent)]
    Fold(#[from] FoldError),
    /// The list moved while the act ran so that the act no longer holds: the list folded meanwhile
    /// revoked a device the act added, renewed or handed a new key, gave a device it added's name away, or
    /// already listed a key it added; or its own cut did not fold here as the newest update. Nothing was
    /// offered.
    #[error("your devices' list changed while this ran: run it again.")]
    ListChanged,
    /// A device the act revokes is listed, since its caller resolved it, under a key the caller never saw:
    /// the device got a new key, or its name passed to another device. Revoking the key the caller found
    /// would leave the device live, and running the revoke again would take whatever the name holds now,
    /// so the refusal names no command. Nothing was cut or offered.
    #[error(
        "me/{name} is now listed under a key this revoke did not see, so your root did not revoke it"
    )]
    NameMoved {
        /// The device's name.
        name: DeviceLabel,
    },
    /// A file the act reads or writes failed.
    #[error("{}: {source}", EscapedPath(.path))]
    Io {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// A write this home shares with other commands failed.
    #[error(transparent)]
    Write(Box<dyn core::error::Error + Send + Sync + 'static>),
    /// `home.lock` could not be taken.
    #[error(transparent)]
    Lock(#[from] crate::home::LockError),
}

impl From<eyre::Report> for RootError {
    fn from(report: eyre::Report) -> Self {
        Self::Write(report.into())
    }
}

/// A date, printed as `YYYY-MM-DD` (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date(pub u64);

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Howard Hinnant's days-to-civil, over days since 0000-03-01.
        let days = self.0 / DAY + 719_468;
        let era = days / 146_097;
        let day_of_era = days - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };
        let year = year_of_era + era * 400 + u64::from(month <= 2);
        write!(f, "{year:04}-{month:02}-{day:02}")
    }
}

/// The day a device standing renews from, when it renews on its own: halfway through its last standing.
/// `None` for a standing too short to renew on its own, or one whose key came in its invite.
pub fn renew_by(until: u64, duration: u64, seeded: bool) -> Option<u64> {
    (duration >= SHORTEST_RENEWING && !seeded).then(|| until.saturating_sub(duration / 2))
}

/// The root, unlocked for one command.
///
/// Not `Clone`, and its `Debug` names only its directory: the key wipes itself when this drops.
pub struct Root {
    secret: keystore::Secret,
    act: Act,
}

/// Everything a root act holds but the key: where the root is, its records as the act changes them, and
/// what the act has done so far.
struct Act {
    key: NodeId,
    /// The copy's directory, for a root given with `--root`; `None` for the root kept in this home, whose
    /// list is the home's own `devices`.
    copy: Option<PathBuf>,
    /// The number of the list beside the key as the act read it: a copy's list is only ever replaced by a
    /// higher one.
    beside: Epoch,
    home: Home,
    book: Book,
    /// The update this machine holds from this root, and its bytes: the floor the next cut must pass.
    held: Option<(RosterDoc, Vec<u8>)>,
    /// The bytes of the fork this machine kept when the act read it, if any: the commit reads it again.
    fork: Option<Vec<u8>>,
    /// Rows due to renew at this act, found before the prompt.
    due: Vec<VerifyKey>,
    now: u64,
    /// This machine's key.
    own: Option<VerifyKey>,
    /// Devices this act added.
    added: Vec<VerifyKey>,
    /// The old keys of the devices this act handed a new key.
    replaced: Vec<VerifyKey>,
    /// The keys of the devices this act renewed.
    renewed: Vec<VerifyKey>,
    /// The latest `until` among the rows this act revoked.
    revoked_until: Option<u64>,
    /// The devices this act revoked, by name, each with the keys its name held live when it did. The commit
    /// stops when a name holds another key by then: the revoke would leave the device live under it.
    revoked: Vec<(DeviceLabel, Vec<VerifyKey>)>,
    /// Whether this act made the root.
    minted: bool,
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Root")
            .field("key_file", &self.act.key_file())
            .finish_non_exhaustive()
    }
}

/// What [`Root::inspect`] read: the root's key and records, with no secret.
#[derive(Debug)]
pub struct Inspected {
    /// The root's key, from its key file's header.
    pub root: NodeId,
    /// The list beside the key, as signed.
    list: Book,
    /// The records as the next act that cuts would find them before its prompt, read-only: brought forward
    /// from the update held here and any fork of it, with this machine's own revocations, and every row
    /// whose key is revoked marked.
    forward: Book,
}

impl Inspected {
    /// The live devices as the next act that cuts would sign from them: the records brought forward,
    /// read-only.
    pub fn rows(&self) -> &[Member] {
        &self.forward.rows
    }

    /// The devices the records brought forward mark revoked: listed beside the key, and revoked since.
    pub fn marked(&self) -> &[Member] {
        &self.forward.marked
    }

    /// The devices the records brought forward revoke, each by its key and the name it had.
    pub fn revoked_devices(&self) -> impl Iterator<Item = &RevokedDevice> {
        self.forward.revoked_keys.values()
    }

    /// The ids the list beside the key revokes, as signed.
    pub fn listed_revoked(&self) -> impl Iterator<Item = &Id> {
        self.list.revoked.values()
    }

    /// The device keys the list beside the key revokes, as signed.
    pub fn listed_revoked_keys(&self) -> impl Iterator<Item = &VerifyKey> {
        self.list.revoked_keys.values().map(|device| &device.node)
    }

    /// The rows due to renew at `now`: what the next act that cuts renews on its own.
    pub fn due(&self, now: u64) -> impl Iterator<Item = &Member> {
        self.forward.rows.iter().filter(move |row| due(row, now))
    }
}

/// The records of a root whose making or restore was interrupted, as [`Root::mint`] finds them before it
/// finishes: read with no lock, no prompt and no write, for a check that must refuse before either.
#[derive(Debug)]
pub struct HalfMade {
    book: Book,
    own: Option<VerifyKey>,
    now: u64,
}

impl HalfMade {
    /// The records, for a check before the prompt.
    pub fn records(&self) -> Records<'_> {
        Records {
            book: &self.book,
            own: self.own,
            now: self.now,
        }
    }
}

/// What [`Root::mint`] did.
#[derive(Debug)]
pub enum Minted {
    /// Made a root on this machine, or finished one under the passphrase: unlocked for the rest of the
    /// command, which asks for it no more.
    Made(Box<Root>),
    /// Finished a root whose making was interrupted, with no prompt. The command presents it as usual
    /// to go on.
    Finished,
}

/// What a commit published: the update, and where to offer it.
#[derive(Debug)]
#[must_use = "a cut is offered to your devices"]
pub struct Committed {
    /// The signed update: the one this act cut, or the one held here when there was nothing new to cut.
    pub bytes: Vec<u8>,
    /// Its number.
    pub number: Epoch,
    /// The devices to offer it to: every live device (never a revoked key) but this machine and the ones
    /// this act added.
    pub targets: Vec<Device>,
    /// The latest date a row this act revoked would have lasted to, if it revoked one.
    pub until: Option<u64>,
    /// The home the cut was folded into, which offers it.
    home: Home,
}

impl Committed {
    /// Offer the cut to every target at once, each within [`EACH`] and all within [`OFFER_BOUND`], and say
    /// which of them have it. Runs after the command has printed what it made. Each exchange names and
    /// sends this cut, never a later list this machine folded since it was made.
    ///
    /// A device that answers that it holds this cut, or that it folded it, has it. One that holds a newer
    /// list, or another list at this number, makes the whole act [`Reach::Behind`]. One that refused it,
    /// or did not answer in time, did not take it.
    pub async fn offer(self, dial: &impl Dial) -> Reach {
        let started = tokio::time::Instant::now();
        let each = EACH.min(OFFER_BOUND);
        let (number, bytes) = (self.number, self.bytes.as_slice());
        let answers = futures::future::join_all(self.targets.iter().map(|device| async move {
            let offered = dial.offer(device.key, number, bytes);
            (
                device,
                tokio::time::timeout_at(started + each, offered).await,
            )
        }))
        .await;
        let mut took = Vec::new();
        let mut missed = Vec::new();
        let mut behind = false;
        for (device, answer) in answers {
            match answer {
                Ok(Ok(Answer::Same | Answer::Gave)) => took.push(device.name.clone()),
                Ok(Ok(Answer::Took | Answer::Forked)) => {
                    tracing::debug!(device = %device.name, cut = self.number.0, "a device holds a newer or another list");
                    behind = true;
                }
                Ok(Ok(Answer::ForkRecorded { floor })) => {
                    tracing::debug!(device = %device.name, cut = self.number.0, floor = floor.0, "a device recorded a fork");
                    behind = true;
                }
                Ok(Ok(Answer::Refused)) => missed.push(Missed {
                    name: device.name.clone(),
                    why: Why::Refused,
                }),
                Ok(Err(error)) => {
                    tracing::debug!(device = %device.name, %error, "an offer failed");
                    missed.push(Missed {
                        name: device.name.clone(),
                        why: Why::Silent,
                    });
                }
                Err(_) => {
                    tracing::debug!(device = %device.name, "an offer timed out");
                    missed.push(Missed {
                        name: device.name.clone(),
                        why: Why::Silent,
                    });
                }
            }
        }
        if behind {
            Reach::Behind
        } else if !took.is_empty() || crate::home::serve_running(&self.home).await {
            Reach::Published {
                took,
                missed,
                until: self.until,
            }
        } else {
            Reach::Held {
                missed,
                until: self.until,
            }
        }
    }
}

/// One device a renewal gave a new standing.
#[derive(Debug)]
pub struct Renewed {
    /// Its name.
    pub name: DeviceLabel,
    /// Its key.
    pub key: VerifyKey,
    /// When the new standing ends, in unix seconds.
    pub until: u64,
    /// The new standing.
    pub standing: Link,
}

/// What a renewal signed, and what it left as it was.
#[derive(Debug, Default)]
pub struct RenewalList {
    /// Each device given a new standing.
    pub renewed: Vec<Renewed>,
    /// Each named device that needed no new standing: its name, its end, and the standing it holds.
    pub unchanged: Vec<(DeviceLabel, u64, Link)>,
}

impl Root {
    /// Present the root at `place` to `verb`: every check, then one prompt, then unlock. An act that cuts
    /// first exchanges with your devices through `dial`, so it signs from the newest update they hold.
    pub async fn present(
        home: &Home,
        place: RootPlace,
        verb: RootVerb,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
    ) -> Result<Self, RootError> {
        Self::present_to(home, place, verb, prompt, dial, &mut io::stderr()).await
    }

    /// [`present`](Self::present), printing to `out`.
    pub async fn present_to<W: Write>(
        home: &Home,
        place: RootPlace,
        verb: RootVerb,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
        out: &mut W,
    ) -> Result<Self, RootError> {
        Self::present_with(home, place, verb, prompt, dial, out, |_, _| Ok(()))
            .await
            .map(|(root, ())| root)
    }

    /// [`present_to`](Self::present_to), with `check` run on the records as the act will sign from them,
    /// after every other check and before the prompt: a refusal it returns costs no prompt, and what it
    /// prints comes before one. What it returns comes back with the root.
    pub async fn present_with<W: Write, T>(
        home: &Home,
        place: RootPlace,
        verb: RootVerb,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
        out: &mut W,
        check: impl FnOnce(&Records<'_>, &mut W) -> Result<T, RootError>,
    ) -> Result<(Self, T), RootError> {
        no_core_dumps()?;
        let found = find(home, &place, Some(verb)).await?;
        if verb.writes_source()
            && let Some(dir) = &found.copy
        {
            writable(dir)?;
        }
        let list = read_list(home, found.copy.as_deref(), found.header.verify_key()?)?;
        let act = Act::new(
            home,
            found.header,
            found.copy,
            list.as_ref(),
            own_key(home)?,
        );
        // The prompt comes before the sync and before any line that states an effect, so a wrong passphrase
        // asked again never runs the sync again, and nothing is said of an act that a passphrase then stops.
        if !prompt.terminal() {
            return Err(RootError::NoTerminalToUnlock);
        }
        // An act that cuts on the root kept here, with this machine's key revoked, goes on and says so first.
        if verb.cuts() && act.copy.is_none() && own_key_revoked(home, act.key.verify_key()?)? {
            let _ = writeln!(out, "{OWN_KEY_REVOKED}");
        }
        let asked = act.asked();
        let (secret, _) = crate::passphrase::unlock(prompt, asked, |passphrase| {
            found.locked.unlock(Unlock::Passphrase(passphrase))
        })
        .map_err(prompt_error)?;
        let mut root = Self { secret, act };
        if verb.cuts() {
            root.act.sync(dial, out).await;
            root.act.bring_forward(out)?;
            root.act.book.check_bounds(root.act.now)?;
            if root.act.copy.is_none() {
                root.carry_own()?;
            }
            root.act.list_renewals(out);
        }
        let checked = check(&root.act.records(), out)?;
        Ok((root, checked))
    }

    /// The named device's key, end and stored standing when renewing it would sign nothing and nothing
    /// else is to be signed: it needs no renewal, no device is due, and the update held here and the
    /// records carry the same thing. Read with no lock, no prompt and no write, as
    /// [`inspect`](Self::inspect) reads: the held update, any fork of it, and this machine's own
    /// revocations are applied to a copy of the records, and anything they would change there (a device, a
    /// revocation, a row marked revoked) means the act has something to sign. `None` then, and for a name
    /// the root has no live device under.
    pub async fn unchanged(
        home: &Home,
        place: RootPlace,
        name: &DeviceLabel,
        duration: Option<Duration>,
    ) -> Result<Option<(VerifyKey, u64, Link)>, RootError> {
        let found = find(home, &place, None).await?;
        let pin = found.header.verify_key()?;
        let own = own_key(home)?;
        let book = Book::of(read_list(home, found.copy.as_deref(), pin)?.as_ref(), own);
        let now = unix_now();
        let (forward, held) = book.read_forward(home, pin, now)?;
        let Some(held) = held else {
            return Ok(None);
        };
        if forward != book || book.lacks(&held, now) || forward.rows.iter().any(|row| due(row, now))
        {
            return Ok(None);
        }
        // An act on the root kept here signs this machine a live row when it has none, so it signs.
        if found.copy.is_none() && forward.lacks_own(now) && !own_key_revoked(home, pin)? {
            return Ok(None);
        }
        let Some(row) = book.rows.iter().find(|row| &row.label == name) else {
            return Ok(None);
        };
        let duration = duration.map_or_else(|| own_duration(row), |duration| duration.as_secs());
        Ok(book
            .renewal_skips(row, duration, now)
            .then(|| (row.node, row.until, row.standing.clone())))
    }

    /// Read the root at `place` with no lock, no prompt and no write: its key and verified records.
    pub async fn inspect(home: &Home, place: RootPlace) -> Result<Inspected, RootError> {
        let found = find(home, &place, None).await?;
        let pin = found.header.verify_key()?;
        let list = Book::of(
            read_list(home, found.copy.as_deref(), pin)?.as_ref(),
            own_key(home)?,
        );
        let (forward, _) = list.read_forward(home, pin, unix_now())?;
        Ok(Inspected {
            root: found.header,
            list,
            forward,
        })
    }

    /// The records of the root whose making or restore was interrupted here, the one `root_key` names: the
    /// list it left beside its key, if it got that far.
    pub fn half_made(home: &Home, root_key: NodeId) -> Result<HalfMade, RootError> {
        let list = read_list(home, None, root_key.verify_key()?)?;
        let own = own_key(home)?;
        Ok(HalfMade {
            book: Book::of(list.as_ref(), own),
            own,
            now: unix_now(),
        })
    }

    /// Make this machine's first root, or finish one whose making was interrupted.
    pub async fn mint(home: &Home, prompt: &mut impl Prompt) -> Result<Minted, RootError> {
        Self::mint_to(home, prompt, &mut io::stderr()).await
    }

    /// [`mint`](Self::mint), printing to `out`.
    pub async fn mint_to(
        home: &Home,
        prompt: &mut impl Prompt,
        out: &mut impl Write,
    ) -> Result<Minted, RootError> {
        no_core_dumps()?;
        let standing = Standing::read(home).await?;
        // A machine that pins a root admits no other root's devices, so no root is made or finished here
        // while a `serve --admit` runs: asked here, before any prompt, and again under `home.lock` before
        // the pin is written.
        if matches!(
            standing,
            Standing::Unpinned | Standing::InterruptedMint { .. }
        ) {
            not_admitting(&HomeWrite::take(home).await?, home)?;
        }
        match standing {
            Standing::Unpinned => make(home, prompt, out)
                .await
                .map(|root| Minted::Made(Box::new(root))),
            Standing::InterruptedMint { root_key } => {
                Ok(match finish(home, root_key, prompt, out).await? {
                    Some(root) => Minted::Made(Box::new(root)),
                    None => Minted::Finished,
                })
            }
            Standing::Device { .. } | Standing::HoldsRoot { .. } => Err(RootError::NotMintable),
        }
    }

    /// The root's key.
    pub fn key(&self) -> NodeId {
        self.act.key
    }

    /// The live devices of the root's records as this act has them so far.
    pub fn rows(&self) -> &[Member] {
        &self.act.book.rows
    }

    /// The records as this act has them so far, for the checks an act runs before it signs.
    pub fn records(&self) -> Records<'_> {
        self.act.records()
    }

    /// Sign a standing for a new device `key` named `name`, running `duration` from now, and add its row.
    ///
    /// While the root's list holds only the one its mint cut, `name` may be the one the mint gave this
    /// machine: no other device has seen that name yet, so this machine moves to the next free `-2`, `-3`
    /// and the new device keeps the name it was asked for.
    pub fn sign_standing(
        &mut self,
        key: VerifyKey,
        name: DeviceLabel,
        duration: Duration,
    ) -> Result<Link, RootError> {
        self.act.records().check_add(key, &name)?;
        let book = &self.act.book;
        if let Some(index) = book.rows.iter().position(|row| row.label == name) {
            // `check_add` let the name through only as the one this machine's mint gave it.
            let moved = fresh_name(name.as_str(), |label| {
                book.rows.iter().any(|row| &row.label == label)
            });
            self.act.book.rows[index].label = moved;
        }
        let until = self.act.now.saturating_add(duration.as_secs());
        let (standing, id) = self.sign_member(key, until)?;
        self.act.book.rows.push(Member {
            node: key,
            label: name,
            until,
            duration: duration.as_secs(),
            invite_until: 0,
            ids: vec![id],
            standing: standing.clone(),
        });
        self.act.added.push(key);
        Ok(standing)
    }

    /// Add a device named `name` whose key the root makes here, running `duration` from now: its standing,
    /// and the key's seed for the invite that carries it. The root keeps no copy of the seed; the row is
    /// marked as having come with its key, and its invite's end is recorded.
    pub fn sign_keyed(
        &mut self,
        name: DeviceLabel,
        duration: Duration,
    ) -> Result<(Link, Zeroizing<[u8; 32]>), RootError> {
        let (seed, key) = fresh_key()?;
        let standing = self.sign_standing(key, name, duration)?;
        if let Some(row) = self.act.book.rows.iter_mut().find(|row| row.node == key) {
            row.invite_until = row.until;
        }
        Ok((standing, seed))
    }

    /// Hand the live device named `name`, whose key came in its invite, a new key made here, running
    /// `duration` from now. The old key leaves the row and is not revoked: its ids stay in the row, so its
    /// invite works to its own date and a revoke of the device still ends it.
    pub fn rekey(&mut self, name: &DeviceLabel, duration: Duration) -> Result<Rekeyed, RootError> {
        self.act.records().check_rekey(name)?;
        let Some(index) = self.act.book.rows.iter().position(|row| &row.label == name) else {
            return Err(RootError::NoDeviceToRenew { name: name.clone() });
        };
        let (seed, key) = fresh_key()?;
        let now = self.act.now;
        let until = now.saturating_add(duration.as_secs());
        let (standing, id) = self.sign_member(key, until)?;
        let row = &mut self.act.book.rows[index];
        let old_invite_until = row.invite_until;
        self.act.replaced.push(row.node);
        row.node = key;
        row.ids.retain(|id| id.expires > now);
        row.ids.push(id);
        row.until = until;
        row.duration = duration.as_secs();
        row.invite_until = until;
        row.standing = standing.clone();
        self.act.due.retain(|due| *due != key);
        self.act.added.push(key);
        Ok(Rekeyed {
            standing,
            seed,
            until,
            old_invite_until,
        })
    }

    /// Revoke the device `name` names, found by its key: its row, its key and every id it holds. The key
    /// finds the row, never the name, since a name can pass to a new device once the old one is revoked.
    /// A row the records brought forward mark revoked, by this machine's own block, is revoked again as it
    /// stands, so running a revoke again with the root publishes it.
    ///
    /// `listed` is every key `name` held live when the caller resolved it, before this act brought its
    /// records forward. When the records now list the device under a key outside `listed` and `key`, the
    /// device got a new key the caller never saw, and revoking `key` would leave it live under that one, so
    /// the act stops with [`RootError::NameMoved`].
    pub fn revoke_device(
        &mut self,
        name: &DeviceLabel,
        key: VerifyKey,
        listed: &[VerifyKey],
    ) -> Result<(), RootError> {
        let act = &mut self.act;
        let now = act.now;
        let seen: Vec<VerifyKey> = listed.iter().copied().chain([key]).collect();
        if act
            .book
            .rows
            .iter()
            .any(|row| &row.label == name && !seen.contains(&row.node))
        {
            return Err(RootError::NameMoved { name: name.clone() });
        }
        let Some(row) = act.book.rows.iter().find(|row| row.node == key) else {
            let Some(row) = act.book.marked.iter().find(|row| row.node == key) else {
                return Err(RootError::NotYourDevice { name: name.clone() });
            };
            let until = row.until;
            act.revoked_until = Some(act.revoked_until.map_or(until, |latest| latest.max(until)));
            act.revoked.push((name.clone(), seen));
            return Ok(());
        };
        let (key, until, label) = (row.node, row.until, row.label.clone());
        let adds = row
            .ids
            .iter()
            .filter(|id| id.expires > now && !act.book.revoked.contains_key(id.id.as_bytes()))
            .map(|id| id.expires);
        let mut unexpired: Vec<u64> = act
            .book
            .revoked
            .values()
            .map(|id| id.expires)
            .filter(|expires| *expires > now)
            .chain(adds)
            .collect();
        if unexpired.len() > MAX_REVOKED {
            unexpired.sort_unstable();
            return Err(RootError::TooManyRevoked {
                count: unexpired.len(),
                oldest: Date(unexpired[0]),
            });
        }
        if !act.book.revoked_keys.contains_key(key.bytes()) {
            let count = act.book.revoked_keys.len();
            if count >= MAX_REVOKED_KEYS {
                return Err(RootError::TooManyKeys { count });
            }
            act.book.revoke_key(RevokedDevice { node: key, label });
        }
        act.book.follow_keys(act.now);
        act.revoked_until = Some(act.revoked_until.map_or(until, |latest| latest.max(until)));
        act.revoked.push((name.clone(), seen));
        Ok(())
    }

    /// Renew every device found due before the prompt: each gets a standing from now for its duration.
    pub fn renew_due(&mut self) -> Result<RenewalList, RootError> {
        let mut list = RenewalList::default();
        for key in core::mem::take(&mut self.act.due) {
            let Some(index) = self.act.book.rows.iter().position(|row| row.node == key) else {
                continue;
            };
            let duration = self.act.book.rows[index].duration;
            list.renewed.push(self.renew_row(index, duration)?);
        }
        Ok(list)
    }

    /// Renew the devices named, whatever their window, a lapsed one included. `duration` becomes each
    /// one's duration (else its own, or 90 days if it has none). A device holding the most renewals in
    /// force, or one still in force that was renewed under a day ago or whose date a renewal would not
    /// move, is left as it is.
    pub fn renew(
        &mut self,
        names: &[DeviceLabel],
        duration: Option<Duration>,
    ) -> Result<RenewalList, RootError> {
        let mut list = RenewalList::default();
        let now = self.act.now;
        for name in names {
            let Some(index) = self.act.book.rows.iter().position(|row| &row.label == name) else {
                return Err(RootError::NoDeviceToRenew { name: name.clone() });
            };
            let row = &self.act.book.rows[index];
            let duration =
                duration.map_or_else(|| own_duration(row), |duration| duration.as_secs());
            if self.act.book.renewal_skips(row, duration, now) {
                list.unchanged
                    .push((row.label.clone(), row.until, row.standing.clone()));
                continue;
            }
            let key = row.node;
            // Renewed by name here, so the renewal of what is due does not sign it a second time.
            self.act.due.retain(|due| *due != key);
            list.renewed.push(self.renew_row(index, duration)?);
        }
        Ok(list)
    }

    /// Cut the update whenever the records hold anything the held one lacks, write it beside the key, and
    /// keep it here as this machine's update.
    ///
    /// Only the root signs an update, and only here: any device may serve one, but none may cut one, so
    /// two updates share a number only when two copies of one root both cut.
    pub async fn commit(mut self) -> Result<Committed, RootError> {
        self.commit_to(&mut io::stderr()).await
    }

    /// [`commit`](Self::commit), printing to `out`.
    ///
    /// The cut is made under `home.lock`, taken here after the prompt: the act reads `devices` and
    /// `devices.conflict` again, brings its records forward from them when either moved since it read
    /// them, and checks its changes again against what they brought, so a list folded while the act waited
    /// at its prompt is carried by the cut and never forked or undone by it.
    ///
    /// It writes, in order: the list beside a copy's key, then the home's `devices`, through the fold. At
    /// home the two are one file. A copy's list is also brought up to an update held here that is newer
    /// than it, when there was nothing new to cut.
    pub async fn commit_to(&mut self, out: &mut impl Write) -> Result<Committed, RootError> {
        let home_lock = HomeWrite::take(&self.act.home).await?;
        meanwhile(&home_lock, &self.act.home).await?;
        self.act.again(out)?;
        let now = self.act.now;
        self.act.book.prune(now);
        self.act.book.check_bounds(now)?;
        let (bytes, number, cut) = match self.act.held.take() {
            Some((held, bytes)) if !self.act.book.lacks(&held, now) => (bytes, held.epoch(), false),
            _ => {
                let number = self
                    .act
                    .book
                    .last_update
                    .0
                    .checked_add(1)
                    .map(Epoch)
                    .ok_or(RootError::Exhausted)?;
                let doc = self.act.book.update(number, now)?;
                self.act.book.last_update = number;
                (self.sign(&doc.canonical_bytes())?, number, true)
            }
        };
        if let Some(dir) = &self.act.copy
            && number > self.act.beside
        {
            crate::roster::write(&home_lock, &dir.join(LIST_FILE), &bytes)?;
        }
        // The act's own cut must be the newest update here. Anything else (a fork, or a list another copy
        // cut past it) means the list moved while this ran, and the cut is not offered.
        if cut
            && !matches!(
                crate::roster::fold(&home_lock, &self.act.home, &bytes).await?,
                Folded::Newer
            )
        {
            return Err(RootError::ListChanged);
        }
        if self.act.minted {
            self.act.announce_made(out);
        }
        let act = &self.act;
        let targets = act
            .book
            .rows
            .iter()
            // A row whose key is revoked is marked, never live, so the rows already leave every revoked
            // key out.
            .filter(|row| Some(row.node) != act.own && !act.added.contains(&row.node))
            // A key nobody can hold cannot be dialed, so it is left out.
            .filter_map(|row| {
                Some(Device {
                    key: row.node.node_id().ok()?,
                    name: format!("me/{}", row.label),
                })
            })
            .collect();
        Ok(Committed {
            bytes,
            number,
            targets,
            until: act.revoked_until,
            home: act.home.clone(),
        })
    }

    /// `bytes`, signed as a document of this root.
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, RootError> {
        self.secret
            .with_bytes(nauthy::Identity::from_secret)
            .map(|root| root.sign_document(bytes).encode())
            .map_err(RootError::Sign)
    }

    /// A sealed device standing for `key` until `until`, and its id.
    fn sign_member(&self, key: VerifyKey, until: u64) -> Result<(Link, Id), RootError> {
        let cap = self
            .secret
            .with_bytes(nauthy::Identity::from_secret)
            .and_then(|root| root.mint_member(key, at(until)))
            .and_then(|cap| cap.seal())
            .map_err(RootError::Sign)?;
        let id = cap
            .root_revocation_id()
            .ok_or(RootError::Format(FormatError::Truncated))?;
        Ok((
            cap.link().map_err(RootError::Sign)?,
            Id { expires: until, id },
        ))
    }

    /// A new standing for the row at `index`, running `duration` from now.
    fn renew_row(&mut self, index: usize, duration: u64) -> Result<Renewed, RootError> {
        let now = self.act.now;
        let key = self.act.book.rows[index].node;
        let until = now.saturating_add(duration);
        let (standing, id) = self.sign_member(key, until)?;
        self.act.renewed.push(key);
        let row = &mut self.act.book.rows[index];
        row.ids.retain(|id| id.expires > now);
        row.ids.push(id);
        row.until = until;
        row.duration = duration;
        row.standing = standing.clone();
        Ok(Renewed {
            name: row.label.clone(),
            key,
            until,
            standing,
        })
    }
}

impl Act {
    /// An act on the root `key`, kept in `home` or the copy at `copy`, whose records start from `list`, the
    /// list beside its key; `own` is this machine's key.
    fn new(
        home: &Home,
        key: NodeId,
        copy: Option<PathBuf>,
        list: Option<&RosterDoc>,
        own: Option<VerifyKey>,
    ) -> Self {
        Self {
            key,
            copy,
            beside: list.map_or(Epoch::UNVERSIONED, RosterDoc::epoch),
            home: home.clone(),
            book: Book::of(list, own),
            held: None,
            fork: None,
            due: Vec::new(),
            now: unix_now(),
            own,
            added: Vec::new(),
            replaced: Vec::new(),
            renewed: Vec::new(),
            revoked_until: None,
            revoked: Vec::new(),
            minted: false,
        }
    }

    /// What the prompt asks for: your root, or the copy in its directory.
    fn asked(&self) -> Asked<'_> {
        self.copy.as_deref().map_or(Asked::Root, Asked::Copy)
    }

    /// The root's key file.
    fn key_file(&self) -> PathBuf {
        self.copy
            .as_ref()
            .map_or_else(|| self.home.root_key(), |dir| dir.join(KEY_FILE))
    }

    /// The records as this act has them, for a check before the prompt.
    fn records(&self) -> Records<'_> {
        Records {
            book: &self.book,
            own: self.own,
            now: self.now,
        }
    }

    /// Present step 9's exchange: ask your devices for a newer update than the one held here, `me` in
    /// random order, then the root's own live devices, then `invited-by`, stopping at the first that
    /// gives one, within 10 s. When devices were asked and none answered, or they could not be listed, say
    /// so; a list read and found empty has nothing to ask and says nothing.
    async fn sync(&self, dial: &impl Dial, out: &mut impl Write) {
        let also: Vec<(VerifyKey, String)> = self
            .book
            .rows
            .iter()
            .map(|row| (row.node, format!("me/{}", row.label)))
            .collect();
        let checked = match crate::sync::devices(&self.home, also).await {
            Ok(devices) if devices.is_empty() => return,
            Ok(devices) => crate::sync::round(dial, &devices, Until::Newer, SYNC_BOUND)
                .await
                .iter()
                .any(|(_, reply)| reply.answer().is_some()),
            Err(error) => {
                tracing::debug!(%error, "could not list the devices to sync with");
                false
            }
        };
        if !checked {
            let _ = writeln!(
                out,
                "could not check this root against your devices (last synced {}). If another copy of it \
                has been used since, a device will report two copies.",
                crate::sync::ago(&self.home)
            );
        }
    }

    /// Bring the records forward from the update this machine holds and any fork of it, carry this
    /// machine's own revocations of the root's devices, then mark every row whose key is revoked. This
    /// machine's row renamed on the way, if it was.
    fn bring_forward(&mut self, out: &mut impl Write) -> Result<Option<Renamed>, RootError> {
        let pin = self.key.verify_key()?;
        self.held = read_held(&self.home.devices(), pin);
        let fork = read_held(&self.home.devices_conflict(), pin);
        self.fork = fork.as_ref().map(|(_, bytes)| bytes.clone());
        let held = self.held.as_ref().map(|(held, _)| held);
        let fork_doc = fork.as_ref().map(|(fork, _)| fork);
        let (brought, behind) = self.book.forward(&self.home, held, fork_doc, self.now)?;
        // A fork that adds nothing is no news; a copy behind the held update always says so.
        if behind || (fork.is_some() && brought.any()) {
            brought.print(out);
        }
        Ok(brought.renamed)
    }

    /// Under `home.lock`, before the cut: read `devices` and `devices.conflict` again, and when either moved
    /// since this act read them, bring the records forward from them again and check again what the act
    /// checked before its prompt, against the records brought forward. The act stops, having written and
    /// printed nothing, when the list folded meanwhile:
    ///
    /// - revoked a device it added or renewed, or gave a device it added's name to another key (which
    ///   revokes the act's);
    /// - lists a key it added, under any name: that key was already a device;
    /// - revoked the old key of a device it handed a new key;
    /// - handed a device it revoked a key it did not see: revoking the keys it saw would leave the device
    ///   live under that one.
    fn again(&mut self, out: &mut impl Write) -> Result<(), RootError> {
        let pin = self.key.verify_key()?;
        let held = read_held(&self.home.devices(), pin);
        let fork = read_held(&self.home.devices_conflict(), pin);
        let had = self.held.as_ref().map(|(_, bytes)| bytes);
        let held_moved = held.as_ref().map(|(_, bytes)| bytes) != had;
        let fork_moved = fork.as_ref().map(|(_, bytes)| bytes) != self.fork.as_ref();
        if !held_moved && !fork_moved {
            return Ok(());
        }
        let listed = [(held_moved, &held), (fork_moved, &fork)]
            .into_iter()
            .filter_map(|(moved, doc)| doc.as_ref().filter(|_| moved))
            .flat_map(|(doc, _)| doc.members())
            .any(|member| self.added.contains(&member.node));
        let before = self.book.revoked_keys.clone();
        let mut brought = Vec::new();
        self.bring_forward(&mut brought)?;
        // A key revoked by the bring-forward, never by the act itself: an act may revoke a device it renewed.
        let revoked = |key: &VerifyKey| {
            !before.contains_key(key.bytes()) && self.book.revoked_keys.contains_key(key.bytes())
        };
        let mut touched = self.added.iter().chain(&self.replaced).chain(&self.renewed);
        if let Some((name, _)) = self.revoked.iter().find(|(name, seen)| {
            self.book
                .rows
                .iter()
                .any(|row| &row.label == name && !seen.contains(&row.node))
        }) {
            return Err(RootError::NameMoved { name: name.clone() });
        }
        if listed || touched.any(revoked) {
            return Err(RootError::ListChanged);
        }
        let _ = out.write_all(&brought);
        Ok(())
    }

    /// Find the rows due to renew, and print the list before the prompt.
    fn list_renewals(&mut self, out: &mut impl Write) {
        let mut skipped = Vec::new();
        for row in &self.book.rows {
            if due(row, self.now) {
                self.due.push(row.node);
            } else if Book::renews_on_its_own(row, self.now) {
                let live = row.ids.iter().filter(|id| id.expires > self.now);
                let newest = live.map(|id| id.expires).max().unwrap_or(row.until);
                skipped.push((row.label.clone(), newest));
            }
        }
        let names: Vec<String> = self
            .book
            .rows
            .iter()
            .filter(|row| self.due.contains(&row.node))
            .map(|row| format!("me/{} ({})", row.label, crate::credential::short(&row.node)))
            .collect();
        if !names.is_empty() {
            let count = names.len();
            let noun = if count == 1 { "device" } else { "devices" };
            let _ = writeln!(
                out,
                "renewing {count} {noun}: {}. Revoke any you no longer have.",
                names.join(", ")
            );
        }
        for (name, newest) in skipped {
            let _ = writeln!(
                out,
                "me/{name}: not renewed, it already has {MAX_IDS} renewals in force (the newest until {})",
                Date(newest)
            );
        }
    }

    /// The lines after the first root is made and its first update cut.
    fn announce_made(&self, out: &mut impl Write) {
        let mut dates = Vec::new();
        let own = self
            .own
            .and_then(|own| self.book.rows.iter().find(|row| row.node == own));
        if let Some(own) = own {
            dates.push(format!(
                "This machine is me/{} until {}.",
                own.label,
                Date(own.until)
            ));
        }
        for row in self
            .book
            .rows
            .iter()
            .filter(|row| self.added.contains(&row.node))
        {
            dates.push(format!(
                "me/{} can join until {}.",
                row.label,
                Date(row.until)
            ));
        }
        let _ = writeln!(
            out,
            "made your root root:{}, kept on this machine, locked with a passphrase.",
            crate::credential::short(&self.key)
        );
        let _ = writeln!(out, "{}", dates.join(" "));
        let _ = writeln!(
            out,
            "Back up your root now, off this disk: swoosh root backup <dir>"
        );
        let _ = writeln!(
            out,
            "To keep it off this machine, back it up, then: swoosh root forget <dir>"
        );
    }
}

/// What [`find`] found: where the root is, its key, and its locked key file.
struct Found {
    /// The copy's directory; `None` for the root kept in this home.
    copy: Option<PathBuf>,
    header: NodeId,
    locked: keystore::Locked,
}

/// Present steps 1 to 5, for `verb`, or for a read that cuts nothing when `verb` is `None`: whether this
/// machine may present the root at `place`, and the root's key file read to its header.
async fn find(home: &Home, place: &RootPlace, verb: Option<RootVerb>) -> Result<Found, RootError> {
    let (copy, pin, device) = match (place, Standing::read(home).await?) {
        (RootPlace::Home, Standing::HoldsRoot { pin, .. }) => (None, Some(pin), true),
        (RootPlace::Home, Standing::InterruptedMint { root_key }) => {
            return Err(RootError::Unfinished { root: root_key });
        }
        (RootPlace::Home, Standing::Device { .. }) => return Err(RootError::NotOnThisMachine),
        (RootPlace::Home, Standing::Unpinned) => {
            return Err(RootError::NoRootHere);
        }
        (RootPlace::Dir(_), Standing::HoldsRoot { .. } | Standing::InterruptedMint { .. }) => {
            return Err(RootError::HeldHere);
        }
        (RootPlace::Dir(dir), Standing::Device { pin, .. }) => (Some(dir.clone()), Some(pin), true),
        (RootPlace::Dir(dir), Standing::Unpinned) => (Some(dir.clone()), None, false),
    };
    if verb.is_some_and(RootVerb::cuts) && !device {
        return Err(RootError::NotADevice);
    }
    let key_file = copy
        .as_ref()
        .map_or_else(|| home.root_key(), |dir| dir.join(KEY_FILE));
    let locked = read_header(&key_file)?;
    let header = header_key(&key_file, &locked)?;
    if let Some(pin) = pin
        && pin != header
    {
        return Err(RootError::Mismatch { root: header, pin });
    }
    let revoked = crate::revoked::open(home).map_err(StandingError::Revoked)?;
    if revoked.is_revoked_key(&header.verify_key()?) {
        return Err(RootError::Revoked { root: header });
    }
    Ok(Found {
        copy,
        header,
        locked,
    })
}

/// The root's key file at `path`: sealed, and of the root kind.
fn read_header(path: &Path) -> Result<keystore::Locked, RootError> {
    let file = KeyFile::root(path);
    match file.load() {
        // A sealed root key always keeps its passphrase lock (the key store refuses one without), so any
        // sealed file of the root kind opens at a prompt here.
        Ok(Some(Stored::Locked(locked))) => Ok(locked),
        Ok(Some(Stored::Plain(_))) => Err(RootError::Plain),
        Ok(None) => Err(RootError::KeyFile(keystore::Error::Absent {
            path: file.path().to_path_buf(),
        })),
        Err(keystore::Error::Format {
            source: keystore::FormatError::Method { found },
            ..
        }) => Err(RootError::Method { found }),
        Err(error) => Err(error.into()),
    }
}

/// The key a root key file's header claims, checked as a key at tightbeam's bridge.
fn header_key(path: &Path, locked: &keystore::Locked) -> Result<NodeId, RootError> {
    locked.public_key().node_id().map_err(|_| {
        RootError::UnusableKey(crate::identity::UnusableKey {
            path: path.to_path_buf(),
            whose: crate::identity::Whose::Root,
        })
    })
}

/// The list beside the root's key, `devices`, verified under `root`: in the copy at `copy`, or in this home
/// for the root kept here. `None` when there is none yet; one that is not a list this root signed is
/// refused, so an act never signs from records changed outside swoosh.
fn read_list(
    home: &Home,
    copy: Option<&Path>,
    root: VerifyKey,
) -> Result<Option<RosterDoc>, RootError> {
    let path = match copy {
        Some(dir) => dir.join(LIST_FILE),
        None => home.devices(),
    };
    Ok(read_list_at(&path, root)?.map(|(list, _)| list))
}

/// The list at `path`, verified under `root`, and the bytes that verified: `None` when nothing is there. Read
/// once, capped at the largest list there can be, and only from a regular file, so a planted pipe or device
/// can neither block the read nor grow it. A caller that writes the list writes these bytes, never the file
/// read again.
fn read_list_at(path: &Path, root: VerifyKey) -> Result<Option<(RosterDoc, Vec<u8>)>, RootError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = path.to_path_buf();
    // Non-blocking, so opening a pipe returns at once; the type is then checked on the handle.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(RootError::Io { path, source }),
    };
    if !file.metadata().map_err(io_at(&path))?.is_file() {
        return Err(RootError::Damaged { path });
    }
    let mut bytes = Vec::new();
    file.take(MAX_ROSTER_BLOB + 1)
        .read_to_end(&mut bytes)
        .map_err(io_at(&path))?;
    if bytes.len() as u64 > MAX_ROSTER_BLOB {
        return Err(RootError::Damaged { path });
    }
    match crate::roster::verify(&bytes, root) {
        Ok(list) => Ok(Some((list, bytes))),
        Err(_) => Err(RootError::Damaged { path }),
    }
}

/// Present step 6: refuse a copy this act cannot write, before anything is signed, since it writes what it
/// signs beside the key. Asked of the filesystem, so nothing is created in the copy to learn it.
fn writable(dir: &Path) -> Result<(), RootError> {
    use std::os::unix::ffi::OsStrExt as _;

    let read_only = || RootError::ReadOnly {
        dir: dir.to_path_buf(),
    };
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|_| read_only())?;
    // SAFETY: `path` is a NUL-terminated string that outlives the call, which only reads it.
    if unsafe { libc::access(path.as_ptr(), libc::W_OK) } != 0 {
        return Err(read_only());
    }
    Ok(())
}

/// Make a root on an `Unpinned` home: choose its passphrase, then under `home.lock` write `root.key`, sign
/// this machine's standing into the root's first list and write it as `devices`, then take the standing
/// as this machine's and pin the root. The pin is the commit point: a crash before it leaves an
/// interrupted mint the next one finishes.
async fn make(
    home: &Home,
    prompt: &mut impl Prompt,
    out: &mut impl Write,
) -> Result<Root, RootError> {
    if !prompt.terminal() {
        return Err(RootError::NoTerminal);
    }
    let own = crate::identity::inspect(home)?.key().verify_key()?;
    let _ = writeln!(
        out,
        "This makes your root on this machine: a second key, not a machine, that vouches for all your \
        devices."
    );
    let _ = writeln!(
        out,
        "It is locked with a passphrase, which you type whenever you add, renew or revoke a device."
    );
    let key_file = home.root_key();
    let passphrase = crate::passphrase::choose(prompt, Asked::Root).map_err(prompt_error)?;
    let secret =
        keystore::Secret::generate().map_err(|source| RootError::Write(Box::new(source)))?;

    let home_lock = HomeWrite::take(home).await?;
    still(&home_lock, home, Standing::Unpinned).await?;
    not_admitting(&home_lock, home)?;
    // An unpinned home keeps no root but a revoked one, which is no root: the new one takes its place.
    remove_file(&key_file)?;
    KeyFile::root(&key_file).write(&secret, Protection::Passphrase(&passphrase))?;
    seam(Seam::Keyed)?;
    let mut root = Root {
        act: Act::new(
            home,
            secret.with_bytes(NodeId::from_ed25519_secret),
            None,
            None,
            Some(own),
        ),
        secret,
    };
    root.act.minted = true;
    root.take_own(&home_lock, own)?;
    Ok(root)
}

/// Finish a root whose making or restore stopped after `root.key` was written and before the pin. When
/// the list beside the key carries a standing of this root for this machine's key, take it and pin the
/// root, with no prompt. Else sign one under one prompt, as a mint does.
///
/// When it prompts, it returns the root unlocked, brought forward and checked as `present` leaves it for
/// an act that cuts, so the command goes on without asking again; else `None`, and the command presents.
async fn finish(
    home: &Home,
    root_key: NodeId,
    prompt: &mut impl Prompt,
    out: &mut impl Write,
) -> Result<Option<Root>, RootError> {
    let locked = read_header(&home.root_key())?;
    let pin = root_key.verify_key()?;
    let list = read_list(home, None, pin)?;
    let own = crate::identity::inspect(home)?.key().verify_key()?;
    let listed = list.as_ref().and_then(|list| {
        list.members()
            .iter()
            .find(|member| member.node == own)
            .map(|member| member.standing.clone())
    });
    if let Some(standing) = listed
        && standing
            .cap()
            .verify_member_at_root_without_revocation(at(unix_now()), own, pin)
            .is_ok()
    {
        let home_lock = HomeWrite::take(home).await?;
        still(&home_lock, home, Standing::InterruptedMint { root_key }).await?;
        not_admitting(&home_lock, home)?;
        take_standing(&home_lock, home, root_key, &standing)?;
        return Ok(None);
    }

    let act = Act::new(home, root_key, None, list.as_ref(), Some(own));
    if !prompt.terminal() {
        return Err(RootError::NoTerminalToUnlock);
    }
    // Asked before any line that states an effect, as `present` asks.
    let (secret, _) = crate::passphrase::unlock(prompt, Asked::Root, |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase))
    })
    .map_err(prompt_error)?;
    let mut root = Root { secret, act };
    root.act.bring_forward(out)?;
    root.act.book.check_bounds(root.act.now)?;
    root.act.list_renewals(out);
    let home_lock = HomeWrite::take(home).await?;
    still(&home_lock, home, Standing::InterruptedMint { root_key }).await?;
    not_admitting(&home_lock, home)?;
    root.take_own(&home_lock, own)?;
    Ok(Some(root))
}

impl Root {
    /// Sign this machine's standing, cut it into a list and write that list as `devices`, then take the
    /// standing as this machine's and pin the root, under `home.lock`: the steps a mint and its finish
    /// share, in the order a crash is finished from.
    fn take_own(&mut self, home_lock: &HomeWrite, own: VerifyKey) -> Result<(), RootError> {
        let standing = self.sign_own(own)?;
        let act = &mut self.act;
        let number = act
            .book
            .last_update
            .0
            .checked_add(1)
            .map(Epoch)
            .ok_or(RootError::Exhausted)?;
        let doc = act.book.update(number, act.now)?;
        let bytes = self.sign(&doc.canonical_bytes())?;
        let act = &mut self.act;
        crate::roster::write(home_lock, &act.home.devices(), &bytes)?;
        act.book.last_update = number;
        act.held = Some((doc, bytes));
        // This machine's row is in the list now: not a device this act invites or renews.
        act.added.clear();
        act.renewed.clear();
        act.due.retain(|due| *due != own);
        seam(Seam::Listed)?;
        take_standing(home_lock, &act.home, act.key, &standing)
    }

    /// Carry a live row for this machine, on the root kept here: when the records hold none (a list cut past
    /// this machine's last cut was folded here since, or its row lapsed), sign one as a restore does, renewing
    /// a lapsed row or adding one under a name fresh against the records for 90 days. The commit's own fold
    /// takes its standing as this machine's. A revoked key is never signed.
    fn carry_own(&mut self) -> Result<(), RootError> {
        let Some(own) = self.act.own else {
            return Ok(());
        };
        if !self.act.book.lacks_own(self.act.now)
            || own_key_revoked(&self.act.home, self.act.key.verify_key()?)?
        {
            return Ok(());
        }
        self.sign_own(own)?;
        // This machine's row is not a device the act adds or renews: a list folded meanwhile that already
        // carries it is brought forward, never a reason to stop, as `take_own` leaves its row.
        self.act.added.retain(|key| *key != own);
        self.act.renewed.retain(|key| *key != own);
        Ok(())
    }

    /// Sign this machine's standing: from its live row for its duration, or on a new row under the
    /// suggested name for 90 days when it has none.
    fn sign_own(&mut self, own: VerifyKey) -> Result<Link, RootError> {
        let row = self.act.book.rows.iter().position(|row| row.node == own);
        match row {
            Some(index) => {
                let duration = own_duration(&self.act.book.rows[index]);
                Ok(self.renew_row(index, duration)?.standing)
            }
            None => {
                let book = &self.act.book;
                let name = fresh_name(crate::names::suggest().as_str(), |name| {
                    book.rows.iter().any(|row| &row.label == name)
                });
                self.sign_standing(own, name, DEFAULT_DURATION)
            }
        }
    }
}

/// Refuse, under `home.lock`, when this home's standing is no longer `was`, the standing the mint or its
/// finish checked before its prompt: a `join`, `leave` or another mint ran while it waited.
async fn still(_home_lock: &HomeWrite, home: &Home, was: Standing) -> Result<(), RootError> {
    if Standing::read(home).await?.same(&was) {
        Ok(())
    } else {
        Err(RootError::StandingChanged)
    }
}

/// Refuse, under `home.lock`, to make or finish a root here while a `serve --admit` admits another root's
/// devices: a machine that pins a root admits no other root's.
fn not_admitting(home_lock: &HomeWrite, home: &Home) -> Result<(), RootError> {
    match ServeLock::admitting(home_lock, home)? {
        Some(_) => Err(RootError::Admitting),
        None => Ok(()),
    }
}

/// Take `standing` as this machine's device standing, then pin `root`, under `home.lock`. The pin is
/// written last: it is what makes the rest this machine's standing.
fn take_standing(
    home_lock: &HomeWrite,
    home: &Home,
    root: NodeId,
    standing: &Link,
) -> Result<(), RootError> {
    crate::config::write_badge(home_lock, home, standing).map_err(io_at(&home.key_cert()))?;
    seam(Seam::Badged)?;
    crate::config::write_signet(home_lock, home, root).map_err(io_at(&home.root_pub()))
}

/// Remove the file at `path`. Already gone is done.
fn remove_file(path: &Path) -> Result<(), RootError> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(RootError::Io {
            path: path.to_path_buf(),
            source: error,
        }),
        _ => Ok(()),
    }
}

/// `base`, then `base-2`, `base-3` and on while `taken` says the name is held.
fn fresh_name(base: &str, taken: impl Fn(&DeviceLabel) -> bool) -> DeviceLabel {
    let mut suffix = 1_u32;
    loop {
        let text = match suffix {
            1 => base.to_owned(),
            n => {
                let tail = format!("-{n}");
                let keep = DeviceLabel::MAX_LEN
                    .saturating_sub(tail.len())
                    .min(base.len());
                format!("{}{tail}", base[..keep].trim_end_matches('-'))
            }
        };
        if let Ok(name) = text.parse::<DeviceLabel>()
            && !taken(&name)
        {
            return name;
        }
        suffix += 1;
    }
}

/// The root's working records: the list beside its key as this act changes it. A plain structure, so a
/// bound can be crossed here and refused with its count, rather than being unrepresentable in a
/// [`RosterDoc`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Book {
    /// The number of the last update this root signed that these records have seen.
    last_update: Epoch,
    /// The live devices, at most one per name.
    rows: Vec<Member>,
    /// The devices revoked since the list was read, by key: kept for this act only, so a revoke of one
    /// still finds it. An update never lists them.
    marked: Vec<Member>,
    revoked: BTreeMap<Vec<u8>, Id>,
    /// The revoked devices by key, each with the name its row had, so an update says which device a key
    /// was.
    revoked_keys: BTreeMap<[u8; 32], RevokedDevice>,
    /// This machine's key, when it has one: a name clash never revokes it ([`Book::take_member`]).
    own: Option<VerifyKey>,
}

impl Book {
    /// The records `list` holds, or none when there is no list, read on the machine whose key is `own`.
    fn of(list: Option<&RosterDoc>, own: Option<VerifyKey>) -> Self {
        let Some(list) = list else {
            return Self {
                own,
                ..Self::default()
            };
        };
        Self {
            own,
            last_update: list.epoch(),
            rows: list.members().to_vec(),
            marked: Vec::new(),
            revoked: list
                .revoked()
                .iter()
                .map(|id| (id.id.as_bytes().to_vec(), id.clone()))
                .collect(),
            revoked_keys: list
                .revoked_devices()
                .iter()
                .map(|device| (*device.node.bytes(), device.clone()))
                .collect(),
        }
    }
}

/// What a bring-forward changed, for its line.
#[derive(Debug, Default)]
struct Brought {
    devices: usize,
    revocations: usize,
    marked: usize,
    /// Each row whose oldest ids beyond the cap were revoked: its name, how many, and the date its oldest
    /// kept standing was signed.
    capped: Vec<(DeviceLabel, usize, u64)>,
    /// Each row revoked because the update gave its name to another key.
    clashed: Vec<(DeviceLabel, VerifyKey)>,
    /// This machine's row, renamed because the update gave its name to another device.
    renamed: Option<Renamed>,
}

/// This machine's row, renamed by a bring-forward because a list gave its name to another device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renamed {
    /// The name it had.
    pub was: DeviceLabel,
    /// The name it has now.
    pub now: DeviceLabel,
}

impl fmt::Display for Renamed {
    /// The clause every line that reports the rename carries.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Another device took the name me/{}; this machine is me/{} now.",
            self.was, self.now
        )
    }
}

impl Brought {
    /// Whether the bring-forward added anything.
    fn any(&self) -> bool {
        self.devices + self.revocations + self.marked > 0 || self.renamed.is_some()
    }

    /// The one bring-forward line, with the capped and clashed rows appended.
    fn print(&self, out: &mut impl Write) {
        let mut line = format!(
            "this copy of your root was behind your devices; brought forward: +{} devices, +{} revocations, \
            +{} devices marked revoked.",
            self.devices, self.revocations, self.marked
        );
        for (name, count, since) in &self.capped {
            line.push_str(&format!(
                " +{count} older renewals of me/{name} revoked (two copies of your root renewed it); if \
                me/{name} was offline since {}: swoosh invite {name}; it picks it up the next time it \
                reaches one of your devices.",
                Date(*since)
            ));
        }
        for (name, key) in &self.clashed {
            line.push_str(&format!(
                " me/{name} ({}) was also added on another copy of your root; it is revoked here. To keep \
                that machine: on it, swoosh leave --new-key, then invite the new key under another name.",
                crate::credential::short(key)
            ));
        }
        if let Some(renamed) = &self.renamed {
            line.push_str(&format!(" {renamed}"));
        }
        let _ = writeln!(out, "{line}");
    }
}

impl Book {
    /// Add a revoked id, keeping the later expiry of two copies.
    fn revoke_id(&mut self, id: Id) -> bool {
        match self.revoked.get_mut(id.id.as_bytes()) {
            Some(held) => {
                held.expires = held.expires.max(id.expires);
                false
            }
            None => {
                self.revoked.insert(id.id.as_bytes().to_vec(), id);
                true
            }
        }
    }

    /// Revoke a device's key, keeping the name already held for it: a name is a suggestion, and the key
    /// decides. Whether the key is newly revoked.
    fn revoke_key(&mut self, device: RevokedDevice) -> bool {
        match self.revoked_keys.entry(*device.node.bytes()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(device);
                true
            }
        }
    }

    /// Bring these records forward from `update`: its number, its revocations, the devices it lists that
    /// these lack, and for a device in both, its ids and its newer standing.
    fn bring_forward(&mut self, update: &RosterDoc, now: u64, brought: &mut Brought) {
        self.last_update = self.last_update.max(update.epoch());
        self.bring_revocations(update, now, brought);
        for member in update.members() {
            self.take_member(member, now, brought);
        }
    }

    /// Bring only `update`'s revoked ids that have not ended and its revoked keys into these records.
    fn bring_revocations(&mut self, update: &RosterDoc, now: u64, brought: &mut Brought) {
        for id in update.revoked() {
            if id.expires > now && self.revoke_id(id.clone()) {
                brought.revocations += 1;
            }
        }
        for device in update.revoked_devices() {
            if self.revoke_key(device.clone()) {
                brought.revocations += 1;
            }
        }
    }

    /// Bring one device from an update into these records.
    fn take_member(&mut self, member: &Member, now: u64, brought: &mut Brought) {
        // The update's device wins its name: a different live row under it is revoked here, and leaves the
        // rows at once, so the name is held once. This machine's own row is never revoked by a clash: the
        // machine that keeps the root would revoke itself, and a cut would publish it. It yields the name and
        // takes one fresh against these records and the update's device.
        if let Some(index) = self
            .rows
            .iter()
            .position(|row| row.label == member.label && row.node != member.node)
            && Some(self.rows[index].node) == self.own
        {
            let rows = &self.rows;
            let fresh = fresh_name(member.label.as_str(), |name| {
                name == &member.label || rows.iter().any(|row| &row.label == name)
            });
            let was = core::mem::replace(&mut self.rows[index].label, fresh.clone());
            // A second clash in one update renames it again; the line names where it started.
            let was = brought.renamed.take().map_or(was, |first| first.was);
            brought.renamed = Some(Renamed { was, now: fresh });
        } else if let Some(index) = self
            .rows
            .iter()
            .position(|row| row.label == member.label && row.node != member.node)
        {
            let key = self.rows[index].node;
            self.revoke_key(RevokedDevice {
                node: key,
                label: self.rows[index].label.clone(),
            });
            brought.clashed.push((member.label.clone(), key));
            brought.marked += self.follow_keys(now);
        }
        // A revoked key's device stays revoked, whatever an update lists.
        if self.revoked_keys.contains_key(member.node.bytes()) {
            return;
        }
        let Some(index) = self.rows.iter().position(|row| row.node == member.node) else {
            let mut row = member.clone();
            row.ids.retain(|id| id.expires > now);
            self.rows.push(row);
            brought.devices += 1;
            return;
        };
        let row = &mut self.rows[index];
        // A key that came in an invite stays one that came in an invite, from whichever list says so.
        row.invite_until = row.invite_until.max(member.invite_until);
        for id in &member.ids {
            if id.expires > now && !row.ids.iter().any(|held| held.id == id.id) {
                row.ids.push(id.clone());
            }
        }
        row.ids.retain(|id| id.expires > now);
        let mut capped = Vec::new();
        if row.ids.len() > MAX_IDS {
            row.ids.sort_by_key(|id| id.expires);
            capped = row.ids.drain(..row.ids.len() - MAX_IDS).collect();
        }
        if member.until > row.until {
            row.until = member.until;
            row.standing = member.standing.clone();
        }
        if !capped.is_empty() {
            let oldest_kept = row.ids.first().map_or(row.until, |id| id.expires);
            let since = oldest_kept.saturating_sub(row.duration);
            brought
                .capped
                .push((row.label.clone(), capped.len(), since));
            for id in capped {
                if self.revoke_id(id) {
                    brought.revocations += 1;
                }
            }
        }
    }

    /// Bring these records forward as an act that cuts does before its prompt: from `held` and `fork` when
    /// they are behind `held` or a fork is held, then this machine's own revocations, then every row whose
    /// key is revoked marked, and every device `held` or `fork` lists whose key is revoked. A fork below
    /// the number of `held` or of these records, and `held` below these records, bring only their
    /// revocations: their devices and names are older than the ones held. What it brought, and whether the
    /// records were behind `held`.
    fn forward(
        &mut self,
        home: &Home,
        held: Option<&RosterDoc>,
        fork: Option<&RosterDoc>,
        now: u64,
    ) -> Result<(Brought, bool), RootError> {
        let behind = held.is_some_and(|held| held.epoch() > self.last_update);
        let floor = held.map_or(self.last_update, |held| held.epoch().max(self.last_update));
        let mut brought = Brought::default();
        if behind || fork.is_some() {
            match held {
                Some(held) if held.epoch() < self.last_update => {
                    self.bring_revocations(held, now, &mut brought);
                }
                Some(held) => self.bring_forward(held, now, &mut brought),
                None => {}
            }
            match fork {
                Some(fork) if fork.epoch() < floor => {
                    self.bring_revocations(fork, now, &mut brought);
                }
                Some(fork) => self.bring_forward(fork, now, &mut brought),
                None => {}
            }
        }
        self.carry_forward(home, held)?;
        brought.marked += self.follow_keys(now);
        for update in held.into_iter().chain(fork) {
            brought.marked += self.mark_listed(update);
        }
        Ok((brought, behind))
    }

    /// Mark each device `update` lists whose key these records revoke and that is not yet marked, so an
    /// update that still lists a device these records revoked (one cut before the revocation, say) shows it
    /// revoked, and a revoke of it finds it. Returns how many it marked.
    fn mark_listed(&mut self, update: &RosterDoc) -> usize {
        let mut marked = 0;
        for member in update.members() {
            if self.revoked_keys.contains_key(member.node.bytes())
                && !self.marked.iter().any(|row| row.node == member.node)
            {
                self.marked.push(member.clone());
                marked += 1;
            }
        }
        marked
    }

    /// A copy of these records brought [`forward`](Self::forward) from what `home` holds of the root
    /// `pin`, read with no lock and no write; and the update held, if any.
    fn read_forward(
        &self,
        home: &Home,
        pin: VerifyKey,
        now: u64,
    ) -> Result<(Self, Option<RosterDoc>), RootError> {
        let held = read_held(&home.devices(), pin).map(|(held, _)| held);
        let fork = read_held(&home.devices_conflict(), pin).map(|(fork, _)| fork);
        let mut forward = self.clone();
        forward.forward(home, held.as_ref(), fork.as_ref(), now)?;
        Ok((forward, held))
    }

    /// Add to these records' revocations the ids `home`'s `revoked` holds that are the root's own (a row's,
    /// or in `held`) and the keys it holds that are rows' keys. A machine's revocations of its own links
    /// never go further.
    fn carry_forward(&mut self, home: &Home, held: Option<&RosterDoc>) -> Result<(), RootError> {
        let revoked = crate::revoked::open(home).map_err(StandingError::Revoked)?;
        let mut known: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
        for id in self.rows.iter().flat_map(|row| row.ids.iter()) {
            known.insert(id.id.as_bytes().to_vec(), id.expires);
        }
        if let Some(held) = held {
            let members = held.members().iter().flat_map(|member| member.ids.iter());
            for id in held.revoked().iter().chain(members) {
                known.insert(id.id.as_bytes().to_vec(), id.expires);
            }
        }
        for (bytes, expires) in known {
            let id = RevocationId::from_bytes(bytes);
            if revoked.is_revoked_any([&id]) {
                self.revoke_id(Id { expires, id });
            }
        }
        let devices: Vec<RevokedDevice> = self
            .rows
            .iter()
            .filter(|row| revoked.is_revoked_key(&row.node))
            .map(|row| RevokedDevice {
                node: row.node,
                label: row.label.clone(),
            })
            .collect();
        for device in devices {
            self.revoke_key(device);
        }
        Ok(())
    }

    /// Move every row whose key is revoked to the marked rows, and revoke its live ids. A revoked id alone
    /// never marks a row. Returns how many rows it marked.
    fn follow_keys(&mut self, now: u64) -> usize {
        let (revoked, live): (Vec<Member>, Vec<Member>) = core::mem::take(&mut self.rows)
            .into_iter()
            .partition(|row| self.revoked_keys.contains_key(row.node.bytes()));
        self.rows = live;
        let marked = revoked.len();
        for row in revoked {
            for id in row.ids.iter().filter(|id| id.expires > now) {
                self.revoke_id(id.clone());
            }
            self.marked.retain(|held| held.node != row.node);
            self.marked.push(row);
        }
        marked
    }

    /// Whether `row` renews on its own at `now`: it runs at least 30 days, did not come with its key, has
    /// not lapsed, and is in the last half of its duration. Read after rows follow keys, so a row whose key
    /// is revoked is marked, never a row here.
    fn renews_on_its_own(row: &Member, now: u64) -> bool {
        row.duration >= SHORTEST_RENEWING
            && !row.seeded()
            && now < row.until
            && row.until - now < row.duration / 2
    }

    /// Whether a renewal of `row` by name, for `duration`, would leave it as it is: it holds the most
    /// renewals in force, or its standing still stands and it was renewed under a day ago or the renewal
    /// would not move its date later. A standing whose id is revoked here always takes a new one, and so
    /// does one that has ended: the day after its signing holds back only a standing still in force, so a
    /// short one that ended within that day is renewed.
    fn renewal_skips(&self, row: &Member, duration: u64, now: u64) -> bool {
        let newest = row.ids.iter().max_by_key(|id| id.expires);
        let newest_signed = newest.map_or(0, |id| id.expires.saturating_sub(row.duration));
        let standing_revoked = newest.is_some_and(|id| self.revoked.contains_key(id.id.as_bytes()));
        live_ids(row, now) >= MAX_IDS
            || (!standing_revoked
                && now < row.until
                && (newest_signed.saturating_add(DAY) > now
                    || now.saturating_add(duration) <= row.until))
    }

    /// Whether these records hold no live row for this machine's key, and that key is not revoked: the case
    /// in which an act on the root kept here signs one ([`Root::carry_own`]).
    fn lacks_own(&self, now: u64) -> bool {
        self.own.is_some_and(|own| {
            !self.revoked_keys.contains_key(own.bytes())
                && !self
                    .rows
                    .iter()
                    .any(|row| row.node == own && row.until > now)
        })
    }

    /// Drop every id whose standing has ended: a revocation of an ended standing blocks nothing.
    fn prune(&mut self, now: u64) {
        self.revoked.retain(|_, id| id.expires > now);
        for row in &mut self.rows {
            row.ids.retain(|id| id.expires > now);
        }
    }

    /// Refuse, before the prompt, records one update cannot carry.
    fn check_bounds(&self, now: u64) -> Result<(), RootError> {
        let devices = self.rows.len();
        if devices > MAX_MEMBERS {
            return Err(RootError::TooManyDevices { count: devices });
        }
        let unexpired: Vec<u64> = self
            .revoked
            .values()
            .map(|id| id.expires)
            .filter(|expires| *expires > now)
            .collect();
        if unexpired.len() > MAX_REVOKED {
            let oldest = unexpired.iter().copied().min().unwrap_or(now);
            return Err(RootError::TooManyRevoked {
                count: unexpired.len(),
                oldest: Date(oldest),
            });
        }
        if self.revoked_keys.len() > MAX_REVOKED_KEYS {
            return Err(RootError::TooManyKeys {
                count: self.revoked_keys.len(),
            });
        }
        if self.last_update.0.checked_add(1).is_none() {
            return Err(RootError::Exhausted);
        }
        Ok(())
    }

    /// Whether these records hold a live device, a revoked id or a revoked key that `held` lacks.
    fn lacks(&self, held: &RosterDoc, now: u64) -> bool {
        let rows = self.rows.iter().any(|row| {
            !held.members().iter().any(|member| {
                member.node == row.node
                    && member.label == row.label
                    && member.until == row.until
                    && member.duration == row.duration
                    && member.invite_until == row.invite_until
                    && member.standing.as_str() == row.standing.as_str()
                    && row
                        .ids
                        .iter()
                        .filter(|id| id.expires > now)
                        .all(|id| member.ids.contains(id))
            })
        });
        let ids = self
            .revoked
            .values()
            .filter(|id| id.expires > now)
            .any(|id| !held.revoked().iter().any(|held| held.id == id.id));
        // Keys only: two copies that name one revoked key differently never force a cut.
        let keys = self
            .revoked_keys
            .values()
            .any(|device| !held.is_revoked_key(&device.node));
        rows || ids || keys
    }

    /// The update at `number`: every live device with the ids it holds that have not ended, every
    /// revoked id that has not ended, and every revoked key for good.
    fn update(&self, number: Epoch, now: u64) -> Result<RosterDoc, RootError> {
        let members = self
            .rows
            .iter()
            .cloned()
            .map(|mut row| {
                row.ids.retain(|id| id.expires > now);
                row
            })
            .collect();
        let revoked = self
            .revoked
            .values()
            .filter(|id| id.expires > now)
            .cloned()
            .collect();
        RosterDoc::with_revocations(
            number,
            members,
            revoked,
            self.revoked_keys.values().cloned().collect(),
        )
        .map_err(RootError::Format)
    }
}

/// The root's records as an act will sign from them, brought forward, for a check before the prompt.
#[derive(Debug)]
pub struct Records<'a> {
    book: &'a Book,
    own: Option<VerifyKey>,
    now: u64,
}

impl Records<'_> {
    /// The device named `name` that is not revoked, lapsed or live.
    pub fn device(&self, name: &DeviceLabel) -> Option<&Member> {
        self.book.rows.iter().find(|row| &row.label == name)
    }

    /// When the act runs, in unix seconds.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Refuse adding the device `key` as `name`: a revoked key, a key that is already a device, a name a
    /// device already has, or one device more than an update can carry. While the root's list is the one
    /// its mint cut, the name the mint gave this machine is free: this machine moves off it.
    pub fn check_add(&self, key: VerifyKey, name: &DeviceLabel) -> Result<(), RootError> {
        let book = self.book;
        if let Some(revoked) = book.revoked_keys.get(key.bytes()) {
            return Err(RootError::RevokedKey {
                key,
                name: revoked.label.clone(),
            });
        }
        if let Some(row) = book.rows.iter().find(|row| row.node == key) {
            if Some(key) == self.own {
                return Err(RootError::OwnKey {
                    name: row.label.clone(),
                });
            }
            return Err(RootError::AlreadyDevice {
                key,
                name: row.label.clone(),
                until: Date(row.until),
            });
        }
        // The mint's list is the root's first, and lists only this machine: no other device has seen it.
        if let Some(row) = self.device(name)
            && (Some(row.node) != self.own || book.last_update > MINTED)
        {
            return Err(RootError::NameTaken {
                name: name.clone(),
                key: row.node,
            });
        }
        let count = book.rows.len();
        if count >= MAX_MEMBERS {
            return Err(RootError::TooManyDevices { count });
        }
        Ok(())
    }

    /// Refuse handing the device named `name` a new key: it has none, it made its own key, or it holds the
    /// most renewals in force.
    pub fn check_rekey(&self, name: &DeviceLabel) -> Result<(), RootError> {
        let Some(row) = self.device(name) else {
            return Err(RootError::NoDeviceToRenew { name: name.clone() });
        };
        if !row.seeded() {
            return Err(RootError::KeepsOwnKey { name: name.clone() });
        }
        if live_ids(row, self.now) >= MAX_IDS {
            let earliest = row
                .ids
                .iter()
                .map(|id| id.expires)
                .filter(|expires| *expires > self.now)
                .min()
                .unwrap_or(row.until);
            return Err(RootError::RenewalsInForce {
                name: name.clone(),
                earliest: Date(earliest),
            });
        }
        Ok(())
    }
}

/// What handing a device a new key signed.
#[derive(Debug)]
pub struct Rekeyed {
    /// The standing for the new key.
    pub standing: Link,
    /// The new key's seed, for the invite that carries it.
    pub seed: Zeroizing<[u8; 32]>,
    /// When the new standing ends, in unix seconds.
    pub until: u64,
    /// When the invite that carried the old key ended, in unix seconds; 0 if none did.
    pub old_invite_until: u64,
}

/// A fresh random device key: its seed, and the key.
fn fresh_key() -> Result<(Zeroizing<[u8; 32]>, VerifyKey), RootError> {
    let secret =
        keystore::Secret::generate().map_err(|source| RootError::Write(Box::new(source)))?;
    let seed = secret.with_bytes(|bytes| Zeroizing::new(*bytes));
    Ok((
        seed,
        secret
            .with_bytes(NodeId::from_ed25519_secret)
            .verify_key()?,
    ))
}

/// Whether `row` is due to renew at this act: it renews on its own, and it holds fewer than the most
/// renewals in force. The one test the renewal list, bare `invite`'s list and [`Root::unchanged`] share.
fn due(row: &Member, now: u64) -> bool {
    Book::renews_on_its_own(row, now) && live_ids(row, now) < MAX_IDS
}

/// How many of `row`'s standings have not ended at `now`.
fn live_ids(row: &Member, now: u64) -> usize {
    row.ids.iter().filter(|id| id.expires > now).count()
}

/// This machine's key, from its key file's header, when it has one.
fn own_key(home: &Home) -> Result<Option<VerifyKey>, RootError> {
    let file = KeyFile::device(home.key());
    match file.load()? {
        Some(stored) => Ok(Some(crate::identity::key_of(&file, &stored)?.verify_key()?)),
        None => Ok(None),
    }
}

/// Set the core-dump limit to zero, soft and hard, so a crash with the root unlocked writes no copy of it.
fn no_core_dumps() -> Result<(), RootError> {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `none` is a valid `rlimit` that outlives the call, which only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        return Err(RootError::Io {
            path: PathBuf::from("RLIMIT_CORE"),
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn io_at(path: &Path) -> impl Fn(io::Error) -> RootError + use<> {
    let path = path.to_path_buf();
    move |source| RootError::Io {
        path: path.clone(),
        source,
    }
}

/// A prompt's failure, as the one line it reads as.
fn prompt_error(report: eyre::Report) -> RootError {
    RootError::Prompt(format!("{report:#}"))
}

/// A row's own renewal length, or 90 days when it has none.
fn own_duration(row: &Member) -> u64 {
    match row.duration {
        0 => DEFAULT_DURATION.as_secs(),
        own => own,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn at(unix: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(unix)
}

/// A point in a mint where a test stops it, as a crash would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seam {
    /// `root.key` is written, and no list beside it yet.
    Keyed,
    /// The list beside `root.key` is written, and this machine has no standing from it yet.
    Listed,
    /// This machine's standing is written, and the pin is not.
    Badged,
}

#[cfg(test)]
thread_local! {
    /// The seam a test stops the mint at, on the thread the mint runs on.
    static STOP: core::cell::Cell<Option<Seam>> = const { core::cell::Cell::new(None) };
}

/// Stop here when a test asked to. Nothing outside tests.
fn seam(at: Seam) -> Result<(), RootError> {
    #[cfg(test)]
    if STOP.get() == Some(at) {
        return Err(RootError::Io {
            path: PathBuf::from("stopped by the test"),
            source: io::ErrorKind::Interrupted.into(),
        });
    }
    #[cfg(not(test))]
    let _ = at;
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// A list a test folds inside [`Root::commit_to`] on the thread the act runs on, once the lock is taken
    /// and before `again`: the list a fold landed while the act waited for the lock.
    static MEANWHILE: core::cell::RefCell<Option<Vec<u8>>> = const { core::cell::RefCell::new(None) };
}

/// Fold the list a test left in [`MEANWHILE`], under the act's own lock. Nothing outside tests.
async fn meanwhile(home_lock: &HomeWrite, home: &Home) -> Result<(), RootError> {
    #[cfg(test)]
    if let Some(bytes) = MEANWHILE.take() {
        crate::roster::fold(home_lock, home, &bytes).await?;
    }
    #[cfg(not(test))]
    let _ = (home_lock, home);
    Ok(())
}

#[cfg(test)]
#[path = "root_tests.rs"]
mod root_tests;
