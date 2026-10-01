//! A machine's standing: which root it trusts, whether it is that root's device, and whether it holds the
//! root itself.
//!
//! Every verb that depends on the answer asks [`Standing::read`] once and matches on the result, so no two
//! verbs can read one home two ways. The read never prompts: it looks only at public files and at the
//! header of a root key, never inside a sealed one.
//!
//! A root kept here is `root.key`, read by its header alone. One this machine has revoked is no root: it
//! reads as absent. A pin to a revoked root is removed by the read, after the standing under it, and the
//! read says so through [`Read::finished`].
//!
//! **Any other disagreement is refused** as [`StandingError::Damaged`], naming what disagrees. Among them
//! is a home made before a root had its own key: its badge was signed by this machine's own key, with no
//! pin or with a pin naming that same key, and either shape reads as damaged rather than as a standing.

use core::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::KeyFile;
use nauthy::{Denylist, Link, VerifyKey};
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};

use crate::escape::EscapedPath;
use crate::home::Home;

/// What this machine is to a root. Built only by [`Standing::read`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// This machine trusts no root. A pin to a root revoked here counts as none.
    Unpinned,
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
    /// finishes it. A revoked root is never one of these: it reads as no root.
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
    /// This machine trusted `root`, which is revoked here. The read removed this machine's device
    /// standing, the update files and the pin, the pin last.
    Retired {
        /// The retired root, when its key file or the pin still named it.
        root: Option<NodeId>,
    },
}

impl fmt::Display for Finished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
    #[error("could not read the revocations on this machine")]
    Revoked(#[source] crate::revoked::RevokedError),
    /// A file the standing is read from could not be read.
    #[error("could not read {}", EscapedPath(path))]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// A crash state could not be finished. What was removed before the failure stays removed, and the
    /// next read goes on from there.
    #[error("could not finish an interrupted change at {}", EscapedPath(path))]
    Finish {
        /// The path that could not be removed.
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
    /// A pin is here with no device standing and no root: only a crash while leaving leaves one.
    PinWithoutStanding {
        /// The root the pin names.
        pin: NodeId,
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
    /// The root's key file has no header that can be read.
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
            Self::PinWithoutStanding { pin } => write!(
                formatter,
                "this machine trusts root {}… and has no device record from it",
                pin.short()
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
                write!(formatter, "{} is not one root key", EscapedPath(path))
            }
            Self::UnreadableStanding { path } => write!(
                formatter,
                "{} is not a device record with an end date",
                EscapedPath(path)
            ),
            Self::StandingForAnotherKey { path } => write!(
                formatter,
                "{} is a device record for a key other than this machine's",
                EscapedPath(path)
            ),
            Self::UnreadableRoot { path } => {
                write!(
                    formatter,
                    "{} is not a readable root key",
                    EscapedPath(path)
                )
            }
        }
    }
}

/// The line for a root made here whose making did not finish: `status`'s, and the refusal of every verb
/// that needs the root finished first.
pub fn unfinished_line(root: NodeId) -> String {
    format!(
        "root: root:{}… made here, not finished: the next swoosh invite finishes it.",
        root.short()
    )
}

/// The line for a home whose records disagree: `status`'s, and the refusal of every verb that needs to
/// know which root this machine trusts.
pub fn damaged_line(what: &Disagreement) -> String {
    format!(
        "root: this machine's records disagree ({what}): swoosh cannot tell which root it trusts. Run swoosh \
        leave to start over; a root kept here stays."
    )
}

/// The line a command prints when this machine's standing moved between its check and its write: a `join`,
/// `leave` or mint ran meanwhile, and nothing was written.
pub const CHANGED: &str = "this machine's records changed while this ran: run it again.";

impl Standing {
    /// Whether `other` is this standing to the same root, whatever either's end: what a command checked
    /// before a prompt still holds under the lock it writes under.
    #[must_use]
    pub fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unpinned, Self::Unpinned) => true,
            (Self::Device { pin: a, .. }, Self::Device { pin: b, .. })
            | (Self::HoldsRoot { pin: a, .. }, Self::HoldsRoot { pin: b, .. })
            | (Self::InterruptedMint { root_key: a }, Self::InterruptedMint { root_key: b }) => {
                a == b
            }
            _ => false,
        }
    }

    /// Read this home's standing. Never prompts. A pin whose key is revoked here is removed first, after
    /// the device standing and the update files.
    pub async fn read(home: &Home) -> Result<Read, StandingError> {
        let own = own_key(home)?;
        let revoked = crate::revoked::open(home).map_err(StandingError::Revoked)?;
        let mut finished = Vec::new();

        let mut pin = read_pin(home).await?;
        if let Some(key) = pin {
            if own == Some(key) {
                return Err(StandingError::Damaged(Disagreement::OwnKeyPinned { key }));
            }
            if is_revoked(&revoked, key) {
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
            Some(badge) => match badge.root().node_id() {
                Ok(standing_root) => damaged(Disagreement::StandingWithoutPin { standing_root }),
                Err(_) => Err(unreadable_badge(home)),
            },
        },
        (None, Some(pin)) => match read_badge(home, own, pin).await? {
            None => damaged(Disagreement::PinWithoutStanding { pin }),
            Some(until) => Ok(Standing::Device { pin, until }),
        },
    }
}

/// The pin as the key a standing roots at. A pin that is not a usable key reads as damaged.
pub fn pin_key(home: &Home, pin: NodeId) -> Result<VerifyKey, StandingError> {
    pin.verify_key().map_err(|_| {
        StandingError::Damaged(Disagreement::UnreadablePin {
            path: home.root_pub(),
        })
    })
}

/// Whether `revoked` holds `key`. A key that is not a usable key is no root's, so it is not revoked here;
/// every use of it refuses on its own.
fn is_revoked(revoked: &Denylist, key: NodeId) -> bool {
    key.verify_key()
        .is_ok_and(|key| revoked.is_revoked_key(&key))
}

/// This machine's own key, from its key file's header. `None` when the home has no key yet.
fn own_key(home: &Home) -> Result<Option<NodeId>, StandingError> {
    KeyFile::device(home.key())
        .load()
        .map(|stored| stored.map(|stored| stored.node_id()))
        .map_err(StandingError::OwnKey)
}

/// The key the root kept here names, or `None` when no root is kept here or the one kept here is
/// revoked: a revoked root is no root.
async fn held_root(home: &Home, revoked: &Denylist) -> Result<Option<NodeId>, StandingError> {
    let path = home.root_key();
    if !exists(&path).await? {
        return Ok(None);
    }
    let root = root_key(path).map_err(StandingError::Damaged)?;
    Ok((!is_revoked(revoked, root)).then_some(root))
}

/// The key `root.key`'s header names, read without unlocking it.
fn root_key(path: PathBuf) -> Result<NodeId, Disagreement> {
    match KeyFile::root(&path).load() {
        Ok(Some(stored)) => Ok(stored.node_id()),
        Ok(None) | Err(_) => Err(Disagreement::UnreadableRoot { path }),
    }
}

/// Remove this machine's standing under its root: the device standing, the update files, then the pin.
///
/// The pin goes last. It is what makes the rest mean anything, so a crash part way leaves a pin with
/// less beneath it, which the next read finishes, never a device standing with no pin, which reads as
/// damaged.
pub(crate) async fn strip(home: &Home) -> Result<(), StandingError> {
    for path in [
        home.key_cert(),
        home.devices(),
        home.synced(),
        home.invited_by(),
        home.devices_conflict(),
        home.root_pub(),
    ] {
        remove_file(path).await?;
    }
    Ok(())
}

/// The pin, or `None` when there is none. A file that is not exactly one key is damaged.
async fn read_pin(home: &Home) -> Result<Option<NodeId>, StandingError> {
    let path = home.root_pub();
    let Some(text) = text_of(crate::home::read_trust_file_async(&path).await, &path)? else {
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
    let Ok(standing_root) = badge.root().node_id() else {
        return Err(unreadable_badge(home));
    };
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
    let ours = match (own.map(|own| own.verify_key()), pin.verify_key()) {
        (Some(Ok(own)), Ok(pin)) => badge
            .cap()
            .verify_member_at_root_without_revocation(until, own, pin)
            .is_ok(),
        _ => false,
    };
    if !ours {
        return Err(StandingError::Damaged(
            Disagreement::StandingForAnotherKey {
                path: home.key_cert(),
            },
        ));
    }
    Ok(Some(until))
}

/// The device standing as a verified link, or `None` when there is none. A file that is not one is
/// damaged: a torn write reads this way.
async fn load_badge(home: &Home) -> Result<Option<Link>, StandingError> {
    let Some(text) = read_text(&home.key_cert()).await? else {
        return Ok(None);
    };
    text.and_then(|text| text.trim().parse::<Link>().ok())
        .map(Some)
        .ok_or_else(|| unreadable_badge(home))
}

fn unreadable_badge(home: &Home) -> StandingError {
    StandingError::Damaged(Disagreement::UnreadableStanding {
        path: home.key_cert(),
    })
}

/// A small text file: `None` when it is absent, `Some(None)` when its bytes are not text.
async fn read_text(path: &Path) -> Result<Option<Option<String>>, StandingError> {
    text_of(tokio::fs::read_to_string(path).await, path)
}

/// What [`read_text`] makes of one read of the file at `path`.
// `core::io::ErrorKind` is still unstable, so the kinds read from `std`.
#[allow(clippy::std_instead_of_core)]
fn text_of(read: io::Result<String>, path: &Path) -> Result<Option<Option<String>>, StandingError> {
    match read {
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

#[cfg(test)]
#[path = "standing_tests.rs"]
mod standing_tests;
