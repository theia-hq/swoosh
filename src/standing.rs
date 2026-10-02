//! A machine's standing: which root it trusts, whether it is that root's device, and whether it holds the
//! root itself.
//!
//! Every verb that depends on the answer asks [`Standing::read`] once and matches on the result, so no two
//! verbs can read one home two ways. The read never prompts: it looks only at public files and at the
//! header of a root key, never inside a sealed one.
//!
//! A root kept here is `root.key`, read by its header alone. The read writes nothing: a file rooted at a key
//! this machine has revoked reads as absent, so a revoked `root.key` is no root and a revoked pin, with the
//! standing it signed, is no pin. Each crash state is finished by running again the verb that left it: a
//! mint by `invite`, a first join or a switch by `join`, a leave by `leave`.
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
    /// This machine's key file names, in its header, a key nobody can hold.
    #[error(transparent)]
    UnusableKey(#[from] crate::identity::UnusableKey),
    /// The roots revoked here could not be read. Fails closed: a revoked root is never read as live.
    #[error("could not read the revocations on this machine")]
    Revoked(#[source] crate::revoked::RevokedError),
    /// A key file the standing is read from has loose modes or another owner.
    #[error(transparent)]
    Loose(crate::home::LooseFile),
    /// A key file the standing is read from is not a regular file.
    #[error("{} is not a regular file", EscapedPath(path))]
    NotAFile {
        /// The path.
        path: PathBuf,
    },
    /// A file the standing is read from could not be read.
    #[error("could not read {}", EscapedPath(path))]
    Read {
        /// The file.
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
    /// The device standing was signed by a root other than the one pinned: a `join --switch` writes the
    /// standing before the pin, so only a switch that stopped between them leaves one.
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
    /// The root's key file has no header that can be read: its bytes are not a root key. A file the key
    /// store will not open, or could not read, is a [`StandingError::Read`] instead.
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
                "this machine trusts its own key {} as a root",
                crate::credential::short(key)
            ),
            Self::RootNotPinned { root, pin } => write!(
                formatter,
                "this machine keeps {}, and trusts {}",
                root_short(root),
                root_short(pin)
            ),
            Self::RootWithoutStanding { root } => write!(
                formatter,
                "this machine keeps {} and has no device record from it",
                root_short(root)
            ),
            Self::PinWithoutStanding { pin } => write!(
                formatter,
                "this machine trusts {} and has no device record from it",
                root_short(pin)
            ),
            Self::StandingWithoutPin { standing_root } => write!(
                formatter,
                "this machine's device record is from {}, and this machine trusts no root",
                root_short(standing_root)
            ),
            Self::StandingFromAnotherRoot { standing_root, pin } => write!(
                formatter,
                "this machine's device record is from {}, and this machine trusts {}",
                root_short(standing_root),
                root_short(pin)
            ),
            Self::UnreadablePin { path } => {
                write!(formatter, "{} is not one root key", file_name(path))
            }
            Self::UnreadableStanding { path } => write!(
                formatter,
                "{} is not a device record with an end date",
                file_name(path)
            ),
            Self::StandingForAnotherKey { path } => write!(
                formatter,
                "{} is a device record for a key other than this machine's",
                file_name(path)
            ),
            Self::UnreadableRoot { path } => {
                write!(formatter, "{} is not a root key", file_name(path))
            }
        }
    }
}

/// A root key in prose: `root:` and the short key.
fn root_short(key: &NodeId) -> String {
    format!("root:{}", crate::credential::short(key))
}

/// A home file by its name alone: `status` prints the home on `home:`, and no other line names a path in it.
fn file_name(path: &Path) -> EscapedPath<'_> {
    EscapedPath(Path::new(path.file_name().unwrap_or(path.as_os_str())))
}

/// The line for a root made on this machine whose making did not finish: `status`'s, and the refusal of
/// every verb that needs the root finished first. The next `invite` finishes it.
pub const UNFINISHED_MINT: &str =
    "making your root did not finish; to finish it: swoosh invite <name> <key>";

/// The line for a join that stopped after its standing and before its pin: a first join, or a switch to
/// another root. Running `join` again finishes it.
pub const UNFINISHED_JOIN: &str = "joining did not finish; to finish it: swoosh join";

/// The line for a leave that stopped after its standing went and before its pin did. Running `leave` again
/// finishes it.
pub const UNFINISHED_LEAVE: &str = "leaving did not finish; to finish it: swoosh leave";

/// The line for a home whose records disagree: `status`'s, and the refusal of every verb that needs to
/// know which root this machine trusts. The shapes a stopped `join` (a first join or a switch) or a stopped
/// `leave` leaves name the verb that finishes them. A `root.key` whose bytes are not a root key names no
/// command: `leave` keeps a root kept here, so it would leave the same line behind, and no verb can tell a
/// torn root key from one to throw away. Every other names `leave`, which starts over.
pub fn damaged_line(what: &Disagreement) -> String {
    match what {
        Disagreement::StandingWithoutPin { .. } | Disagreement::StandingFromAnotherRoot { .. } => {
            UNFINISHED_JOIN.to_owned()
        }
        Disagreement::PinWithoutStanding { .. } => UNFINISHED_LEAVE.to_owned(),
        what @ Disagreement::UnreadableRoot { .. } => format!(
            "this machine's records disagree ({what}); swoosh cannot tell which root it trusts"
        ),
        what => format!(
            "this machine's records disagree ({what}): swoosh cannot tell which root it trusts. A root \
             kept on this machine stays. To start over: swoosh leave"
        ),
    }
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

    /// Read this home's standing. Never prompts and never writes: a pin whose key is revoked here reads
    /// as no pin, and a standing that key signed as no standing.
    pub async fn read(home: &Home) -> Result<Self, StandingError> {
        let own = own_key(home)?;
        let revoked = crate::revoked::open(home).map_err(StandingError::Revoked)?;
        let pin = match read_pin(home).await? {
            Some(key) if own == Some(key) => {
                return Err(StandingError::Damaged(Disagreement::OwnKeyPinned { key }));
            }
            Some(key) if is_revoked(&revoked, key) => None,
            pin => pin,
        };
        classify(home, own, pin, held_root(home, &revoked).await?, &revoked).await
    }

    /// The root kept on this machine that this machine has revoked: its `root.key` stays until a `revoke`
    /// of that root deletes it, and every read takes it for no root. `None` when no root is kept here, the
    /// one kept here is live, or its key file has no header to read: [`read`](Self::read) reports that home
    /// as damaged. Never prompts and never writes.
    ///
    /// # Errors
    ///
    /// The revocations could not be read, or whether a key file is there could not be told.
    pub async fn revoked_root(home: &Home) -> Result<Option<NodeId>, StandingError> {
        let path = home.root_key();
        if !exists(&path).await? {
            return Ok(None);
        }
        let revoked = crate::revoked::open(home).map_err(StandingError::Revoked)?;
        Ok(root_key(path)
            .ok()
            .filter(|root| is_revoked(&revoked, *root)))
    }
}

/// Classify a home from its pin and the root held here, each already read as absent when revoked.
///
/// A root with no pin is an interrupted mint whatever the badge holds, so the badge is read only where
/// it decides something: a torn badge beside an interrupted mint is the mint's to replace. With no pin and
/// no root, a badge a revoked root signed is what that root's pin left, and reads as absent with it.
async fn classify(
    home: &Home,
    own: Option<NodeId>,
    pin: Option<NodeId>,
    root: Option<NodeId>,
    revoked: &Denylist,
) -> Result<Standing, StandingError> {
    let damaged = |disagreement| Err(StandingError::Damaged(disagreement));
    match (root, pin) {
        (Some(root_key), None) => Ok(Standing::InterruptedMint { root_key }),
        (Some(root), Some(pin)) if root != pin => {
            damaged(Disagreement::RootNotPinned { root, pin })
        }
        // A standing from another root beside a root kept here is no stopped switch: `join` never runs
        // where a root is kept.
        (Some(root), Some(pin)) => match read_badge(home, own, pin).await {
            Ok(None)
            | Err(StandingError::Damaged(Disagreement::StandingFromAnotherRoot { .. })) => {
                damaged(Disagreement::RootWithoutStanding { root })
            }
            Ok(Some(until)) => Ok(Standing::HoldsRoot { pin, until }),
            Err(other) => Err(other),
        },
        (None, None) => match load_badge(home).await? {
            None => Ok(Standing::Unpinned),
            Some(badge) => match badge.root().node_id() {
                Ok(standing_root) if is_revoked(revoked, standing_root) => Ok(Standing::Unpinned),
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
    let file = KeyFile::device(home.key());
    let stored = file.load().map_err(StandingError::OwnKey)?;
    Ok(stored
        .map(|stored| crate::identity::key_of(&file, &stored))
        .transpose()?)
}

/// The key the root kept here names, or `None` when no root is kept here or the one kept here is
/// revoked: a revoked root is no root.
async fn held_root(home: &Home, revoked: &Denylist) -> Result<Option<NodeId>, StandingError> {
    let path = home.root_key();
    if !exists(&path).await? {
        return Ok(None);
    }
    let root = root_key(path)?;
    Ok((!is_revoked(revoked, root)).then_some(root))
}

/// The key `root.key`'s header names, read without unlocking it. Only a file whose bytes are not a root
/// key is damaged. One the key store will not open is refused in swoosh's words, never the key store's:
/// loose modes or another owner as [`Home::check_key_file`](crate::home::Home::check_key_file) names them,
/// and a path that is not a regular file as that. One that could not be read is a read error. So a sound
/// key with loose modes never reads as a torn one.
fn root_key(path: PathBuf) -> Result<NodeId, StandingError> {
    let file = KeyFile::root(&path);
    match file.load() {
        // A header no key could be is a file whose bytes are not a root key.
        Ok(Some(stored)) => crate::identity::key_of(&file, &stored).map_err(|_| {
            StandingError::Damaged(Disagreement::UnreadableRoot { path: path.clone() })
        }),
        Err(keystore::Error::Io { source, .. }) => Err(StandingError::Read { path, source }),
        Err(keystore::Error::Permissive { .. } | keystore::Error::Owner { .. }) => {
            Err(StandingError::Loose(crate::home::loose_key_file(path)))
        }
        Err(keystore::Error::NotAFile { .. }) => Err(StandingError::NotAFile { path }),
        Ok(None) | Err(_) => Err(StandingError::Damaged(Disagreement::UnreadableRoot {
            path,
        })),
    }
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

#[cfg(test)]
#[path = "standing_tests.rs"]
mod standing_tests;
