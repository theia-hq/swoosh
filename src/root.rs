//! The root: the one thing that signs as your root, presented for one command and dropped.
//!
//! A [`Root`] is built only by [`Root::present`] (a root kept on this machine, or a copy given with
//! `--root <dir>`) and [`Root::mint`] (this machine's first root). Both run every check before they ask for
//! the passphrase, so a refusal never costs a prompt. The root's records ([`State`]) travel with its key and
//! are written back before anything prints. [`Root::inspect`] reads the same records with no lock, no
//! prompt and no write, for a command that only reports.
//!
//! Every signature the root makes is made here: a device's standing, the update, and `state`. Nothing
//! outside this module holds an unlocked root, and `serve` never reaches it.
//!
//! The key is unlocked in the process that runs the command. It wipes itself on drop, and every root act
//! sets the core-dump limit to zero first, so a crash leaves no copy of it on disk.

use core::fmt;
use core::time::Duration;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Method, Protection, Stored};
use nauthy::{DisabledRoots, Link, RevocationId, VerifyKey};
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};

use crate::codec::{FormatError, Id, MAX_IDS, MAX_MEMBERS, MAX_REVOKED, MAX_REVOKED_KEYS};
use crate::contacts::DeviceLabel;
use crate::home::Home;
use crate::passphrase::Prompt;
use crate::roster::{ArtifactError, Epoch, FoldError, Member, RosterDoc, read_held};
use crate::standing::{DirLock, Finished, LockError, Standing, StandingError};
use crate::state::{self, Row, State, StateError};
use crate::sync::{Dial, Until};

/// The root's key file in its directory: always sealed, and of the root kind.
pub const KEY_FILE: &str = "root.key";

/// This machine's standing, left in a root being made until the pin is written.
const STANDING_FILE: &str = "standing";

/// The file a write probe creates and removes, to learn whether a copy can be written.
const PROBE_FILE: &str = "lock.probe";

/// How long a device's standing runs when nothing else says: 90 days.
pub const DEFAULT_DURATION: Duration = Duration::from_secs(90 * DAY);

/// A device renews on its own only when its standing runs at least this long.
const SHORTEST_RENEWING: u64 = 30 * DAY;

const DAY: u64 = 24 * 60 * 60;

/// How long an act that cuts spends asking your devices for a newer update before it signs.
const SYNC_BOUND: Duration = Duration::from_secs(10);

/// The refusal when a root is to be made with nobody at a terminal to choose its passphrase.
pub(crate) const MINT_NEEDS_TERMINAL: &str = "making your root asks you to choose its passphrase, which needs a terminal once: run this at one.";

/// The refusal when a root is to be used with nobody at a terminal to type its passphrase.
pub(crate) const UNLOCK_NEEDS_TERMINAL: &str =
    "using your root asks for its passphrase, which needs a terminal: run this at one.";

/// Where the root for one command is: kept in this home, or a copy in a directory given with `--root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootPlace {
    /// `<home>/root/`.
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
    /// Moves the root kept here elsewhere; only where the root is kept.
    MoveRoot,
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

    /// Whether the act works only on the root kept on this machine.
    fn holder_only(self) -> bool {
        matches!(self, Self::MoveRoot | Self::RevokeRoot)
    }

    /// Whether the act writes the root's directory, so a copy that cannot be written is refused.
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
        one of your devices, or make this one a device: `swoosh restore <dir>`."
    )]
    NotADevice,
    /// A copy presented where a root is already kept.
    #[error("drop `--root`, or move yours off first")]
    HeldHere,
    /// No root is kept here, and this machine is no root's device.
    #[error("this machine holds no root. Your first `swoosh invite <name> <key>` makes one.")]
    NoRootHere,
    /// No root is kept on this device of one.
    #[error("your root is not on this machine: run this where it is, or add --root <dir>.")]
    NotOnThisMachine,
    /// A root is here, and making it did not finish.
    #[error("{}", crate::standing::unfinished_line(*.root))]
    Unfinished {
        /// The root being made.
        root: NodeId,
    },
    /// An act on the root kept here, given a copy.
    #[error("this works only on the root kept on this machine: drop --root")]
    HolderOnly,
    /// The root's key file could not be read or unlocked.
    #[error(transparent)]
    KeyFile(#[from] keystore::Error),
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
    #[error("this root is root:{}…, and this machine trusts root:{}…", .root.short(), .pin.short())]
    Mismatch {
        /// The root presented.
        root: NodeId,
        /// The root this machine trusts.
        pin: NodeId,
    },
    /// The root was revoked on this machine.
    #[error("root root:{}… was revoked on this machine; recovery is a new root", .root.short())]
    Revoked {
        /// The revoked root.
        root: NodeId,
    },
    /// The copy cannot be written, and the act records what it signs there.
    #[error(
        "this copy of your root cannot be written ({}); using your root must record what it signs.",
        .dir.display()
    )]
    ReadOnly {
        /// The copy's directory.
        dir: PathBuf,
    },
    /// Another command holds the root's lock.
    #[error("another swoosh command is using your root: wait for it.")]
    InUse,
    /// The root's records could not be read, or were changed outside swoosh.
    #[error(transparent)]
    State(#[from] StateError),
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
        once. The oldest end on {oldest}; or replace your root (swoosh revoke-root --help)."
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
        ends. Replace your root (swoosh revoke-root --help)."
    )]
    TooManyKeys {
        /// The revoked keys.
        count: usize,
    },
    /// The update's number cannot move past the last one.
    #[error(
        "this root can sign no more lists of your devices: replace it (swoosh revoke-root --help)."
    )]
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
    /// A revoke named a device the root does not have.
    #[error("me/{name} is not one of your devices (`swoosh status`)")]
    NotYourDevice {
        /// The name asked for.
        name: DeviceLabel,
    },
    /// A live device already has this name, under another key.
    #[error(
        "me/{name} is {}…. To replace it: swoosh revoke me/{name}, then invite the new key.",
        .key.node_id().short()
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
        "{}… is already your device me/{name} (until {until}). To renew it: swoosh invite {name}. A \
        machine has one name.",
        .key.node_id().short()
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
        "{}… was revoked{}; a revoked key is not re-admitted. On that machine: swoosh leave --new-key, then \
        invite the new key.",
        .key.node_id().short(),
        .on.map(|on| format!(" on {on}")).unwrap_or_default()
    )]
    RevokedKey {
        /// The key.
        key: VerifyKey,
        /// The day its row was marked revoked, when a row carries it.
        on: Option<Date>,
    },
    /// The passphrase could not be asked for.
    #[error("{0}")]
    Prompt(String),
    /// A standing could not be signed.
    #[error("signing a standing")]
    Sign(#[source] nauthy::CapError),
    /// The records would not form a valid `state` or update.
    #[error("the root's records are malformed")]
    Format(#[source] FormatError),
    /// The update could not be written here.
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    /// The update cut could not be folded here.
    #[error(transparent)]
    Fold(#[from] FoldError),
    /// A file the act reads or writes failed.
    #[error("{}: {source}", .path.display())]
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
    dir: PathBuf,
    home: Home,
    /// Held, never read: the copy's `lock`, for as long as the act lives. `None` only for a copy this act
    /// never writes and whose lock could be neither opened nor created.
    _lock: Option<DirLock>,
    book: Book,
    /// The update this machine holds from this root, and its bytes: the floor the next cut must pass.
    held: Option<(RosterDoc, Vec<u8>)>,
    /// Rows due to renew at this act, found before the prompt.
    due: Vec<VerifyKey>,
    now: u64,
    /// This machine's key.
    own: Option<VerifyKey>,
    /// Devices this act added.
    added: Vec<VerifyKey>,
    /// The latest `until` among the rows this act revoked.
    revoked_until: Option<u64>,
    /// Whether this act made the root.
    minted: bool,
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Root")
            .field("dir", &self.act.dir)
            .finish_non_exhaustive()
    }
}

/// What [`Root::inspect`] read: the root's records and its key, with no secret.
#[derive(Debug)]
pub struct Inspected {
    /// The root's key, from its key file's header.
    pub root: NodeId,
    /// Its verified records.
    pub state: State,
    /// The crash states the standing read finished on the way, for the command to print.
    pub finished: Vec<Finished>,
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
    /// The devices to offer it to: every live device but this machine and the ones this act added.
    pub targets: Vec<VerifyKey>,
    /// The latest date a row this act revoked would have lasted to, if it revoked one.
    pub until: Option<u64>,
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
    pub(crate) async fn present_to(
        home: &Home,
        place: RootPlace,
        verb: RootVerb,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
        out: &mut impl Write,
    ) -> Result<Self, RootError> {
        no_core_dumps()?;
        let found = find(home, &place, Some(verb)).await?;
        report(out, &found.finished);
        if verb.writes_source() {
            probe(&found.dir)?;
        }
        let lock = take_lock(&found.dir, verb.writes_source() || place == RootPlace::Home)?;
        // Only an act that writes the copy, and so holds its lock, may promote a staged `state.new`.
        let state = if verb.writes_source() {
            state::recover(&found.dir, found.header.verify_key())?
        } else {
            state::load(&found.dir, found.header.verify_key())?
        };
        let book = Book::from(state);
        let mut act = Act {
            key: found.header,
            dir: found.dir,
            home: home.clone(),
            _lock: lock,
            book,
            held: None,
            due: Vec::new(),
            now: unix_now(),
            own: own_key(home)?,
            added: Vec::new(),
            revoked_until: None,
            minted: false,
        };
        if verb.cuts() {
            act.sync(dial, out).await;
            act.bring_forward(out)?;
            act.book.check_bounds(act.now)?;
            act.list_renewals(out);
        }
        if !prompt.terminal() {
            return Err(RootError::NoTerminalToUnlock);
        }
        let passphrase = prompt
            .unlock(&act.dir.join(KEY_FILE))
            .map_err(prompt_error)?;
        Ok(Self {
            secret: found.locked.unlock(&passphrase)?,
            act,
        })
    }

    /// Read the root at `place` with no lock, no prompt and no write: its key and verified records. A
    /// staged `state.new` is read, never promoted.
    pub async fn inspect(home: &Home, place: RootPlace) -> Result<Inspected, RootError> {
        let found = find(home, &place, None).await?;
        Ok(Inspected {
            root: found.header,
            state: state::load(&found.dir, found.header.verify_key())?,
            finished: found.finished,
        })
    }

    /// Make this machine's first root, or finish one whose making was interrupted.
    pub async fn mint(home: &Home, prompt: &mut impl Prompt) -> Result<Minted, RootError> {
        Self::mint_to(home, prompt, &mut io::stderr()).await
    }

    /// [`mint`](Self::mint), printing to `out`.
    pub(crate) async fn mint_to(
        home: &Home,
        prompt: &mut impl Prompt,
        out: &mut impl Write,
    ) -> Result<Minted, RootError> {
        no_core_dumps()?;
        let read = Standing::read(home).await?;
        report(out, &read.finished);
        match read.standing {
            Standing::Unpinned => make(home, prompt, out)
                .await
                .map(|root| Minted::Made(Box::new(root))),
            Standing::InterruptedMint { root_key } => {
                Ok(match finish(home, root_key, prompt, out).await? {
                    Some(root) => Minted::Made(Box::new(root)),
                    None => Minted::Finished,
                })
            }
            Standing::PinOnly { .. } | Standing::Device { .. } | Standing::HoldsRoot { .. } => {
                Err(RootError::NotMintable)
            }
        }
    }

    /// The root's key.
    pub fn key(&self) -> NodeId {
        self.act.key
    }

    /// Every row of the root's records as this act has them so far.
    pub fn rows(&self) -> &[Row] {
        &self.act.book.rows
    }

    /// Sign a standing for a new device `key` named `name`, running `duration` from now, and add its row.
    ///
    /// Before the root's first update, `name` may be the one its mint gave this machine: no device has
    /// seen that name yet, so this machine moves to the next free `-2`, `-3` and the new device keeps the
    /// name it was asked for.
    pub fn sign_standing(
        &mut self,
        key: VerifyKey,
        name: DeviceLabel,
        duration: Duration,
    ) -> Result<Link, RootError> {
        let book = &self.act.book;
        if book.revoked_keys.contains_key(key.bytes()) {
            let on = book
                .rows
                .iter()
                .find(|row| row.key == key && row.revoked_on != 0)
                .map(|row| Date(row.revoked_on));
            return Err(RootError::RevokedKey { key, on });
        }
        if let Some(row) = book.live().find(|row| row.key == key) {
            if Some(key) == self.act.own {
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
        if let Some(index) = book
            .rows
            .iter()
            .position(|row| !row.is_revoked() && row.label == name)
        {
            let row = &book.rows[index];
            if Some(row.key) != self.act.own || book.last_update != Epoch(0) {
                return Err(RootError::NameTaken { name, key: row.key });
            }
            let moved = fresh_name(name.as_str(), |label| {
                book.live().any(|row| &row.label == label)
            });
            self.act.book.rows[index].label = moved;
        }
        let book = &self.act.book;
        let count = book.live().count();
        if count >= MAX_MEMBERS {
            return Err(RootError::TooManyDevices { count });
        }
        let until = self.act.now.saturating_add(duration.as_secs());
        let (standing, id) = self.sign_member(key, until)?;
        self.act.book.rows.push(Row {
            key,
            label: name,
            until,
            duration: duration.as_secs(),
            seeded: false,
            invite_until: 0,
            revoked_on: 0,
            ids: vec![id],
            standing: standing.clone(),
        });
        self.act.added.push(key);
        Ok(standing)
    }

    /// Revoke the live device named `name`: its row, its key and every id it holds.
    pub fn revoke_device(&mut self, name: &DeviceLabel) -> Result<(), RootError> {
        let act = &mut self.act;
        let now = act.now;
        let Some(row) = act.book.live().find(|row| &row.label == name) else {
            return Err(RootError::NotYourDevice { name: name.clone() });
        };
        let (key, until) = (row.key, row.until);
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
            act.book.revoked_keys.insert(*key.bytes(), key);
        }
        act.book.follow_keys(act.now);
        act.revoked_until = Some(act.revoked_until.map_or(until, |latest| latest.max(until)));
        Ok(())
    }

    /// Renew every device found due before the prompt: each gets a standing from now for its duration.
    pub fn renew_due(&mut self) -> Result<RenewalList, RootError> {
        let mut list = RenewalList::default();
        for key in core::mem::take(&mut self.act.due) {
            let Some(index) = self.act.book.rows.iter().position(|row| row.key == key) else {
                continue;
            };
            let duration = self.act.book.rows[index].duration;
            list.renewed.push(self.renew_row(index, duration)?);
        }
        Ok(list)
    }

    /// Renew the devices named, whatever their window, a lapsed one included. `duration` becomes each
    /// one's duration (else its own, or 90 days if it has none). A device renewed under a day ago, holding
    /// the most renewals in force, or whose date a renewal would not move is left as it is.
    pub fn renew(
        &mut self,
        names: &[DeviceLabel],
        duration: Option<Duration>,
    ) -> Result<RenewalList, RootError> {
        let mut list = RenewalList::default();
        let now = self.act.now;
        for name in names {
            let Some(index) = self
                .act
                .book
                .rows
                .iter()
                .position(|row| !row.is_revoked() && &row.label == name)
            else {
                return Err(RootError::NoDeviceToRenew { name: name.clone() });
            };
            let row = &self.act.book.rows[index];
            let duration =
                duration.map_or_else(|| own_duration(row), |duration| duration.as_secs());
            let newest_signed = row
                .ids
                .iter()
                .map(|id| id.expires.saturating_sub(row.duration))
                .max()
                .unwrap_or(0);
            let live = row.ids.iter().filter(|id| id.expires > now).count();
            if newest_signed.saturating_add(DAY) > now
                || live >= MAX_IDS
                || now.saturating_add(duration) <= row.until
            {
                list.unchanged
                    .push((row.label.clone(), row.until, row.standing.clone()));
                continue;
            }
            list.renewed.push(self.renew_row(index, duration)?);
        }
        Ok(list)
    }

    /// Write `state`, cut the update whenever `state` holds anything the held one lacks, and keep the cut
    /// here as this machine's update.
    ///
    /// Only the root signs an update, and only here: any device may serve one, but none may cut one, so
    /// two updates share a number only when two copies of one root both cut.
    pub async fn commit(mut self) -> Result<Committed, RootError> {
        self.commit_to(&mut io::stderr()).await
    }

    /// [`commit`](Self::commit), printing to `out`.
    pub(crate) async fn commit_to(&mut self, out: &mut impl Write) -> Result<Committed, RootError> {
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
        self.write_state()?;
        if cut {
            let _ = crate::roster::fold(&self.act.home, &bytes).await?;
        }
        if self.act.minted {
            self.act.announce_made(out);
        }
        let act = &self.act;
        let targets = act
            .book
            .live()
            .map(|row| row.key)
            .filter(|key| Some(*key) != act.own && !act.added.contains(key))
            .collect();
        Ok(Committed {
            bytes,
            number,
            targets,
            until: act.revoked_until,
        })
    }

    /// Write `state` only, and cut nothing.
    pub fn commit_state(mut self) -> Result<(), RootError> {
        self.act.book.prune(self.act.now);
        self.write_state()
    }

    /// Sign and write the records as `state`: `state.new`, then over `state`.
    fn write_state(&self) -> Result<(), RootError> {
        let state = self.act.book.state(self.act.now)?;
        let signed = self.sign(&state.canonical_bytes())?;
        state::write(&self.act.dir, &signed).map_err(io_at(&self.act.dir.join(state::FILE)))
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
        let key = self.act.book.rows[index].key;
        let until = now.saturating_add(duration);
        let (standing, id) = self.sign_member(key, until)?;
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
    /// Present step 9's exchange: ask your devices for a newer update than the one held here, `me` in
    /// random order, then the root's own live devices, then `roster.seed`, stopping at the first that
    /// gives one, within 10 s. When devices were asked and none answered, say so.
    async fn sync(&self, dial: &impl Dial, out: &mut impl Write) {
        let also: Vec<(VerifyKey, String)> = self
            .book
            .live()
            .map(|row| (row.key, format!("me/{}", row.label)))
            .collect();
        let devices = match crate::sync::devices(&self.home, also).await {
            Ok(devices) => devices,
            Err(error) => {
                tracing::debug!(%error, "could not list the devices to sync with");
                Vec::new()
            }
        };
        if devices.is_empty() {
            return;
        }
        let answers = crate::sync::round(dial, &devices, Until::Newer, SYNC_BOUND).await;
        if answers.iter().all(|(_, answer)| answer.is_none()) {
            let _ = writeln!(
                out,
                "could not check this root against your devices (last synced {}). If another copy of it \
                has been used since, a device will report two copies.",
                crate::sync::ago(&self.home)
            );
        }
    }

    /// Bring the records forward from the update this machine holds and any fork of it, carry this
    /// machine's own revocations of the root's devices, then mark every row whose key is revoked.
    fn bring_forward(&mut self, out: &mut impl Write) -> Result<(), RootError> {
        let pin = self.key.verify_key();
        self.held = read_held(&self.home.roster(), pin);
        let fork = read_held(&self.home.roster_fork(), pin);
        let behind = self
            .held
            .as_ref()
            .is_some_and(|(held, _)| held.epoch() > self.book.last_update);
        let applies = behind || fork.is_some();
        let mut brought = Brought::default();
        if applies {
            let updates = self
                .held
                .iter()
                .chain(fork.iter())
                .map(|(update, _)| update);
            for update in updates {
                self.book.bring_forward(update, self.now, &mut brought);
            }
        }
        self.carry_forward()?;
        brought.marked += self.book.follow_keys(self.now);
        // A fork that adds nothing is no news; a copy behind the held update always says so.
        if behind || (fork.is_some() && brought.any()) {
            brought.print(out);
        }
        Ok(())
    }

    /// Add to the root's revocations the ids in this machine's `revoked` that are the root's own (a row's,
    /// or in the held update) and the keys in its `revoked_keys` that are rows' keys. A machine's
    /// revocations of its own links never go further.
    fn carry_forward(&mut self) -> Result<(), RootError> {
        let mut known: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
        for id in self.book.rows.iter().flat_map(|row| row.ids.iter()) {
            known.insert(id.id.as_bytes().to_vec(), id.expires);
        }
        if let Some((held, _)) = &self.held {
            let members = held.members().iter().flat_map(|member| member.ids.iter());
            for id in held.revoked().iter().chain(members) {
                known.insert(id.id.as_bytes().to_vec(), id.expires);
            }
        }
        for line in read_lines(&self.home.revoked())? {
            let Ok(id) = RevocationId::from_hex(&line) else {
                continue;
            };
            if let Some(expires) = known.get(id.as_bytes()) {
                self.book.revoke_id(Id {
                    expires: *expires,
                    id,
                });
            }
        }
        for line in read_lines(&self.home.revoked_keys())? {
            let Ok(key) = line.parse::<NodeId>() else {
                continue;
            };
            let key = key.verify_key();
            if self.book.rows.iter().any(|row| row.key == key) {
                self.book.revoked_keys.insert(*key.bytes(), key);
            }
        }
        Ok(())
    }

    /// Find the rows due to renew, and print the list before the prompt.
    fn list_renewals(&mut self, out: &mut impl Write) {
        let mut skipped = Vec::new();
        for row in &self.book.rows {
            if !Book::renews_on_its_own(row, self.now) {
                continue;
            }
            let live = row.ids.iter().filter(|id| id.expires > self.now);
            if live.clone().count() >= MAX_IDS {
                let newest = live.map(|id| id.expires).max().unwrap_or(row.until);
                skipped.push((row.label.clone(), newest));
                continue;
            }
            self.due.push(row.key);
        }
        let names: Vec<String> = self
            .book
            .rows
            .iter()
            .filter(|row| self.due.contains(&row.key))
            .map(|row| format!("me/{} ({}…)", row.label, row.key.node_id().short()))
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
            .and_then(|own| self.book.live().find(|row| row.key == own));
        if let Some(own) = own {
            dates.push(format!(
                "This machine is me/{} until {}.",
                own.label,
                Date(own.until)
            ));
        }
        for row in self.book.live().filter(|row| self.added.contains(&row.key)) {
            dates.push(format!(
                "me/{} can join until {}.",
                row.label,
                Date(row.until)
            ));
        }
        let _ = writeln!(
            out,
            "made your root root:{}…, kept on this machine, locked with a passphrase.",
            self.key.short()
        );
        let _ = writeln!(out, "{}", dates.join(" "));
        let _ = writeln!(
            out,
            "Back up your root now, off this disk: swoosh backup <dir>"
        );
        let _ = writeln!(out, "To keep it off this machine: swoosh move-root <dir>");
    }
}

/// What [`find`] found: the root's directory, its key, its locked key file, and the crash states the
/// standing read finished.
struct Found {
    dir: PathBuf,
    header: NodeId,
    locked: keystore::Locked,
    finished: Vec<Finished>,
}

/// Present steps 1 to 5, for `verb`, or for a read that cuts nothing when `verb` is `None`: whether this
/// machine may present the root at `place`, and the root's key file read to its header.
async fn find(home: &Home, place: &RootPlace, verb: Option<RootVerb>) -> Result<Found, RootError> {
    let read = Standing::read(home).await?;
    let (dir, pin, device) = match (place, read.standing) {
        (RootPlace::Home, Standing::HoldsRoot { pin, .. }) => (home.root(), Some(pin), true),
        (RootPlace::Home, Standing::InterruptedMint { root_key }) => {
            return Err(RootError::Unfinished { root: root_key });
        }
        (RootPlace::Home, Standing::Device { .. }) => return Err(RootError::NotOnThisMachine),
        (RootPlace::Home, Standing::Unpinned | Standing::PinOnly { .. }) => {
            return Err(RootError::NoRootHere);
        }
        (RootPlace::Dir(_), Standing::HoldsRoot { .. } | Standing::InterruptedMint { .. }) => {
            return Err(RootError::HeldHere);
        }
        (RootPlace::Dir(_), _) if verb.is_some_and(RootVerb::holder_only) => {
            return Err(RootError::HolderOnly);
        }
        (RootPlace::Dir(dir), Standing::Device { pin, .. }) => (dir.clone(), Some(pin), true),
        (RootPlace::Dir(dir), Standing::PinOnly { pin }) => (dir.clone(), Some(pin), false),
        (RootPlace::Dir(dir), Standing::Unpinned) => (dir.clone(), None, false),
    };
    if verb.is_some_and(RootVerb::cuts) && !device {
        return Err(RootError::NotADevice);
    }
    let locked = read_header(&dir)?;
    let header = locked.node_id();
    if let Some(pin) = pin
        && pin != header
    {
        return Err(RootError::Mismatch { root: header, pin });
    }
    let revoked = DisabledRoots::load(home.disabled_roots())
        .await
        .map_err(StandingError::Revoked)?;
    if revoked.is_disabled(header.verify_key()) {
        return Err(RootError::Revoked { root: header });
    }
    Ok(Found {
        dir,
        header,
        locked,
        finished: read.finished,
    })
}

/// The root's key file at `dir`: sealed, and of the root kind.
fn read_header(dir: &Path) -> Result<keystore::Locked, RootError> {
    let file = KeyFile::root(dir.join(KEY_FILE));
    match file.load() {
        Ok(Some(Stored::Locked(locked))) => match locked.method() {
            Method::Passphrase => Ok(locked),
            Method::Plain => Err(RootError::Plain),
        },
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

/// Present step 6: create and remove a file in `dir`, so a copy that cannot be written is refused before
/// anything is signed. Whatever is at the name first is removed, never opened: a link planted there by
/// someone who can write the copy is not followed.
fn probe(dir: &Path) -> Result<(), RootError> {
    let path = dir.join(PROBE_FILE);
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
    .and_then(|()| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
    })
    .and_then(|_| std::fs::remove_file(&path))
    .map_err(|_| RootError::ReadOnly {
        dir: dir.to_path_buf(),
    })
}

/// Present step 7: take `<dir>/lock` without waiting. A copy the act never writes proceeds with no lock
/// when the lock can be neither opened nor created (`required` is false).
fn take_lock(dir: &Path, required: bool) -> Result<Option<DirLock>, RootError> {
    match DirLock::take(dir) {
        Ok(lock) => Ok(Some(lock)),
        Err(LockError::Held) => Err(RootError::InUse),
        Err(LockError::Io(_)) if !required => Ok(None),
        Err(LockError::Io(source)) => Err(RootError::Io {
            path: dir.join("lock"),
            source,
        }),
    }
}

/// Make a root on an `Unpinned` home: choose its passphrase, write it with its records and this machine's
/// standing to `root.new/`, rename that to `root/`, then take the standing as this machine's and pin the
/// root. The pin is the commit point: a crash before it leaves an interrupted mint the next one finishes.
async fn make(
    home: &Home,
    prompt: &mut impl Prompt,
    out: &mut impl Write,
) -> Result<Root, RootError> {
    if !prompt.terminal() {
        return Err(RootError::NoTerminal);
    }
    let own = crate::identity::inspect(home)?.node_id().verify_key();
    let _ = writeln!(
        out,
        "This makes your root on this machine: a second key, not a machine, that vouches for all your \
        devices."
    );
    let _ = writeln!(
        out,
        "It is locked with a passphrase, which you type whenever you add, renew or revoke a device."
    );
    let staging = home.root_new();
    let passphrase = prompt
        .choose(&staging.join(KEY_FILE))
        .map_err(prompt_error)?;
    let secret =
        keystore::Secret::generate().map_err(|source| RootError::Write(Box::new(source)))?;

    remove_staging(&staging)?;
    crate::config::create_store_dir(&staging).map_err(io_at(&staging))?;
    let lock = take_lock(&staging, true)?;
    KeyFile::root(staging.join(KEY_FILE)).write(&secret, Protection::Passphrase(&passphrase))?;
    let mut root = Root {
        act: Act {
            key: secret.node_id(),
            dir: staging.clone(),
            home: home.clone(),
            _lock: lock,
            book: Book::default(),
            held: None,
            due: Vec::new(),
            now: unix_now(),
            own: Some(own),
            added: Vec::new(),
            revoked_until: None,
            minted: true,
        },
        secret,
    };
    let standing = root.sign_own(own)?;
    root.write_state()?;
    crate::config::write_private_atomic(
        &staging.join(STANDING_FILE),
        format!("{standing}\n").as_bytes(),
    )
    .await?;
    sync_dir(&staging)?;
    std::fs::rename(&staging, home.root()).map_err(io_at(&staging))?;
    sync_dir(home.dir())?;
    root.act.dir = home.root();
    // The own row is this machine's, not a device this act invites.
    root.act.added.clear();
    seam(Seam::Renamed)?;

    take_standing(home, root.act.key, &standing).await?;
    Ok(root)
}

/// Finish a root whose making stopped after `root/` was renamed into place and before the pin: take this
/// machine's standing as the stopped mint left it, or keep a live one, or sign one from its row under one
/// prompt; then pin the root. A standing is taken only if it is this root's, for this machine's key.
///
/// When it prompts, it returns the root unlocked, brought forward and checked as `present` leaves it for
/// an act that cuts, so the command goes on without asking again; else `None`, and the command presents.
async fn finish(
    home: &Home,
    root_key: NodeId,
    prompt: &mut impl Prompt,
    out: &mut impl Write,
) -> Result<Option<Root>, RootError> {
    let dir = home.root();
    let locked = read_header(&dir)?;
    let lock = take_lock(&dir, true)?;
    let book = Book::from(state::recover(&dir, root_key.verify_key())?);
    let own = crate::identity::inspect(home)?.node_id().verify_key();
    let now = unix_now();
    let ours = |standing: &Link| {
        standing
            .cap()
            .verify_member_at_root_without_revocation(at(now), own, root_key.verify_key())
            .is_ok()
    };

    if let Some(standing) = read_standing(&dir.join(STANDING_FILE))?
        && ours(&standing)
    {
        take_standing(home, root_key, &standing).await?;
        return Ok(None);
    }
    if let Some(badge) = crate::config::load_badge(home).await.ok().flatten()
        && ours(&badge)
    {
        take_standing(home, root_key, &badge).await?;
        return Ok(None);
    }

    let mut act = Act {
        key: root_key,
        dir,
        home: home.clone(),
        _lock: lock,
        book,
        held: None,
        due: Vec::new(),
        now,
        own: Some(own),
        added: Vec::new(),
        revoked_until: None,
        minted: false,
    };
    act.bring_forward(out)?;
    act.book.check_bounds(now)?;
    act.list_renewals(out);
    if !prompt.terminal() {
        return Err(RootError::NoTerminalToUnlock);
    }
    let passphrase = prompt
        .unlock(&act.dir.join(KEY_FILE))
        .map_err(prompt_error)?;
    let mut root = Root {
        secret: locked.unlock(&passphrase)?,
        act,
    };
    let standing = root.sign_own(own)?;
    root.write_state()?;
    take_standing(home, root_key, &standing).await?;
    Ok(Some(root))
}

impl Root {
    /// Sign this machine's standing: from its live row for its duration, or on a new row under the
    /// suggested name for 90 days when it has none.
    fn sign_own(&mut self, own: VerifyKey) -> Result<Link, RootError> {
        let row = self
            .act
            .book
            .rows
            .iter()
            .position(|row| !row.is_revoked() && row.key == own);
        match row {
            Some(index) => {
                let duration = own_duration(&self.act.book.rows[index]);
                Ok(self.renew_row(index, duration)?.standing)
            }
            None => {
                let book = &self.act.book;
                let name = fresh_name(crate::names::suggest().as_str(), |name| {
                    book.live().any(|row| &row.label == name)
                });
                self.sign_standing(own, name, DEFAULT_DURATION)
            }
        }
    }
}

/// Take `standing` as this machine's device standing, pin `root`, and drop the staged copy. The pin is
/// written last: it is what makes the rest this machine's standing.
async fn take_standing(home: &Home, root: NodeId, standing: &Link) -> Result<(), RootError> {
    crate::config::write_badge(home, standing).await?;
    seam(Seam::Badged)?;
    crate::config::write_signet(home, root).await?;
    let staged = home.root().join(STANDING_FILE);
    match std::fs::remove_file(&staged) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(RootError::Io {
            path: staged,
            source: error,
        }),
        _ => Ok(()),
    }
}

/// Remove a `root.new/` a mint left with no `root/`, unless a command holds it.
fn remove_staging(staging: &Path) -> Result<(), RootError> {
    if !staging.exists() {
        return Ok(());
    }
    let _lock = take_lock(staging, true)?;
    std::fs::remove_dir_all(staging).map_err(io_at(staging))
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

/// The root's working records: `state` as this act changes it. A plain structure, so a bound can be
/// crossed here and refused with its count, rather than being unrepresentable in [`State`].
#[derive(Debug, Default)]
struct Book {
    last_update: Epoch,
    rows: Vec<Row>,
    revoked: BTreeMap<Vec<u8>, Id>,
    revoked_keys: BTreeMap<[u8; 32], VerifyKey>,
}

impl From<State> for Book {
    fn from(state: State) -> Self {
        Self {
            last_update: state.last_update(),
            rows: state.rows().to_vec(),
            revoked: state
                .revoked()
                .iter()
                .map(|id| (id.id.as_bytes().to_vec(), id.clone()))
                .collect(),
            revoked_keys: state
                .revoked_keys()
                .iter()
                .map(|key| (*key.bytes(), *key))
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
}

impl Brought {
    /// Whether the bring-forward added anything.
    fn any(&self) -> bool {
        self.devices + self.revocations + self.marked > 0
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
                " me/{name} ({}…) was also added on another copy of your root; it is revoked here. To keep \
                that machine: on it, swoosh leave --new-key, then invite the new key under another name.",
                key.node_id().short()
            ));
        }
        let _ = writeln!(out, "{line}");
    }
}

impl Book {
    /// The rows that are not revoked.
    fn live(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter().filter(|row| !row.is_revoked())
    }

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

    /// Bring these records forward from `update`: its number, its revocations, the devices it lists that
    /// these lack, and for a device in both, its ids and its newer standing.
    fn bring_forward(&mut self, update: &RosterDoc, now: u64, brought: &mut Brought) {
        self.last_update = self.last_update.max(update.epoch());
        for id in update.revoked() {
            if id.expires > now && self.revoke_id(id.clone()) {
                brought.revocations += 1;
            }
        }
        for key in update.revoked_keys() {
            if self.revoked_keys.insert(*key.bytes(), *key).is_none() {
                brought.revocations += 1;
            }
        }
        for member in update.members() {
            self.take_member(member, now, brought);
        }
    }

    /// Bring one device from an update into these records.
    fn take_member(&mut self, member: &Member, now: u64, brought: &mut Brought) {
        // The update's device wins its name: a different live row under it is revoked here.
        if let Some(index) = self.rows.iter().position(|row| {
            !row.is_revoked() && row.label == member.label && row.key != member.node
        }) {
            let key = self.rows[index].key;
            self.revoked_keys.insert(*key.bytes(), key);
            brought.clashed.push((member.label.clone(), key));
        }
        let Some(index) = self.rows.iter().position(|row| row.key == member.node) else {
            self.rows.push(Row {
                key: member.node,
                label: member.label.clone(),
                until: member.until,
                duration: member.duration,
                seeded: false,
                invite_until: 0,
                revoked_on: 0,
                ids: member
                    .ids
                    .iter()
                    .filter(|id| id.expires > now)
                    .cloned()
                    .collect(),
                standing: member.standing.clone(),
            });
            brought.devices += 1;
            return;
        };
        let row = &mut self.rows[index];
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

    /// Mark revoked every row whose key is revoked, and revoke its live ids. A revoked id alone never
    /// marks a row. Returns how many rows it marked.
    fn follow_keys(&mut self, now: u64) -> usize {
        let mut marked = 0;
        let mut ids = Vec::new();
        for row in &mut self.rows {
            if !self.revoked_keys.contains_key(row.key.bytes()) {
                continue;
            }
            if row.revoked_on == 0 {
                row.revoked_on = now.max(1);
                marked += 1;
            }
            ids.extend(row.ids.iter().filter(|id| id.expires > now).cloned());
        }
        for id in ids {
            self.revoke_id(id);
        }
        marked
    }

    /// Whether `row` renews on its own at `now`: it runs at least 30 days, is not revoked, did not come
    /// with its key, has not lapsed, and is in the last half of its duration. Read after rows follow keys,
    /// so a row whose key is revoked is a revoked row here.
    fn renews_on_its_own(row: &Row, now: u64) -> bool {
        row.duration >= SHORTEST_RENEWING
            && !row.is_revoked()
            && !row.seeded
            && now < row.until
            && row.until - now < row.duration / 2
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
        let devices = self.live().count();
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
        let rows = self.live().any(|row| {
            !held.members().iter().any(|member| {
                member.node == row.key
                    && member.label == row.label
                    && member.until == row.until
                    && member.duration == row.duration
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
        let keys = self
            .revoked_keys
            .values()
            .any(|key| !held.revoked_keys().contains(key));
        rows || ids || keys
    }

    /// The update at `number`: every live device with the ids it holds that have not ended, every
    /// revoked id that has not ended, and every revoked key for good.
    fn update(&self, number: Epoch, now: u64) -> Result<RosterDoc, RootError> {
        let members = self
            .live()
            .map(|row| Member {
                node: row.key,
                label: row.label.clone(),
                until: row.until,
                duration: row.duration,
                ids: row
                    .ids
                    .iter()
                    .filter(|id| id.expires > now)
                    .cloned()
                    .collect(),
                standing: row.standing.clone(),
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
            self.revoked_keys.values().copied().collect(),
        )
        .map_err(RootError::Format)
    }

    /// These records as `state`.
    fn state(&self, now: u64) -> Result<State, RootError> {
        let rows = self
            .rows
            .iter()
            .cloned()
            .map(|mut row| {
                row.ids.retain(|id| id.expires > now);
                row
            })
            .collect();
        State::new(
            self.last_update,
            rows,
            self.revoked
                .values()
                .filter(|id| id.expires > now)
                .cloned()
                .collect(),
            self.revoked_keys.values().copied().collect(),
        )
        .map_err(RootError::Format)
    }
}

/// A standing left at `path`, or `None` when there is none or it is not one.
fn read_standing(path: &Path) -> Result<Option<Link>, RootError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.trim().parse::<Link>().ok()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(RootError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The non-empty lines of a small text file, none when it is absent.
fn read_lines(path: &Path) -> Result<Vec<String>, RootError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(RootError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// This machine's key, from its key file's header, when it has one.
fn own_key(home: &Home) -> Result<Option<VerifyKey>, RootError> {
    Ok(KeyFile::device(home.identity_key())
        .load()?
        .map(|stored| stored.node_id().verify_key()))
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

/// Make the entries in `dir` durable.
fn sync_dir(dir: &Path) -> Result<(), RootError> {
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(io_at(dir))
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
fn own_duration(row: &Row) -> u64 {
    match row.duration {
        0 => DEFAULT_DURATION.as_secs(),
        own => own,
    }
}

/// Print each crash state the standing read finished.
fn report(out: &mut impl Write, finished: &[Finished]) {
    for line in finished {
        let _ = writeln!(out, "{line}");
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
    /// `root/` is in place, and this machine has no standing from it yet.
    Renamed,
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
#[path = "root_tests.rs"]
mod root_tests;
