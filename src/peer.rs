//! A peer to dial, as typed: a saved name, a raw key, or a self-addressing `swoosh:` link, typed as itself
//! or as a path to a file holding it, and the one [`Machine`] it resolves to.
//!
//! A "peer to dial" is a higher-level concept than the address book, so it composes the contacts domain
//! (`ContactRef`, `Contacts`) rather than squatting in it. Every verb that reaches a machine holds a
//! [`Peer`] and resolves it once, through [`Peer::machine`], to exactly one machine or a typed refusal:
//! `alice`, `alice/desk`, a raw key and a `swoosh:` link all parse in one place and resolve in one place.

use core::str::FromStr;
use std::path::{Path, PathBuf};

use bifrost::{KeyError, NodeId, NodeIdParseError};
use nauthy::Link;

use crate::contacts::{ContactRef, Contacts, DeviceLabel, ME, Petname, ResolveError};
use crate::credential::LinkExt as _;
use crate::link::LinkError;
use crate::names::NameError;

/// A peer a dialing verb reaches, before resolution: three arms, tried in a fixed order at the clap
/// boundary.
///
/// A path (`./`, `/`, `~/`) is read first, as a file holding a link, so the link never enters argv. A
/// `swoosh:` link supersedes the identity path (it self-addresses: it names the node to dial AND carries
/// the credential); else a raw base32 node id is dialed verbatim; else the text is a saved name, resolved
/// against the contact store once it opens (deferred because the store loads at startup, not at the clap
/// boundary). Every dialing verb holds this in its peer slot, so `alice`, `alice/desk`, a raw key, and
/// a `swoosh:` link all parse in one place, uniform across `ping`/`speed`/`status`/`proxy`/`forward`/
/// `send`/`service`/`ssh`.
#[derive(Debug, Clone)]
pub enum Peer {
    /// A saved name (`alice`, `me/ci`), resolved against the store before the key is read. A bare person
    /// is one machine only when exactly one of theirs is saved.
    Named(ContactRef),
    /// A literal node id, dialed verbatim with no store lookup.
    Raw(NodeId),
    /// A `swoosh:` capability link. Self-addressing: it supplies the dial target (the cap's root node) AND
    /// the slot-1 credential (see the fold in [`self_present`](Self::self_present)), so a link is given
    /// where the machine goes and never beside it.
    Capability {
        /// The link.
        link: Link,
        /// The file it was read from, when the peer was typed as a path: a surface that hands the peer on
        /// to another process hands on this path, so the link never enters that process's argv.
        file: Option<PathBuf>,
    },
}

/// What a peer typed as a path starts with. No name starts with `.`, `/` or `~`, so a path never shadows a
/// name.
const PATH_STARTS: [&str; 3] = ["./", "/", "~/"];

impl FromStr for Peer {
    type Err = PeerParseError;

    /// A `swoosh:` link first (the self-addressing capability form, parse-validated here so a malformed link
    /// fails fast at the boundary), then a raw base32 node id (always valid, never a petname, since petnames
    /// are additive), else a saved petname address (validated here, resolved against the store at dial time).
    /// A bare link (`ed01….x`) is none of these: no name holds a dot, so it refuses naming the prefix.
    /// Before all of them, text starting `./`, `/` or `~/` is a file holding a link (see [`read_file`]).
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if is_path(text) {
            read_file(text)
        } else if crate::link::is_prefixed(text) {
            Ok(Self::Capability {
                link: crate::link::parse(text)?,
                file: None,
            })
        } else {
            if let Some(node) = raw_key(text)? {
                return Ok(Self::Raw(node));
            }
            if crate::link::looks_bare(text) {
                Err(PeerParseError::Capability(LinkError::Prefix))
            } else {
                Ok(Self::Named(text.parse::<ContactRef>()?))
            }
        }
    }
}

/// Whether `text` is a peer typed as a path: it starts with `./`, `/` or `~/`.
pub fn is_path(text: &str) -> bool {
    PATH_STARTS.iter().any(|start| text.starts_with(start))
}

/// One of your own devices, typed `me/<name>`: the one shape a verb that acts only on your own machines
/// takes. It holds a name and never a key, a link or a contact, so such a verb cannot be pointed at a
/// machine that is not yours; whether the name is one of yours is read from the list of your devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDevice(DeviceLabel);

impl OwnDevice {
    /// The device `reference` names when it is `me/<name>`; `None` for every other address, `me` alone
    /// included.
    pub fn of(reference: &ContactRef) -> Option<Self> {
        match reference.device() {
            Some(device) if reference.petname().as_str() == ME => Some(Self(device.clone())),
            _ => None,
        }
    }

    /// The name the list of your devices gives it.
    pub fn label(&self) -> &DeviceLabel {
        let Self(label) = self;
        label
    }

    /// Its key in the list of your devices this machine holds, or `None` when no device of yours has the
    /// name.
    pub fn key(&self, contacts: &Contacts) -> Option<NodeId> {
        contacts
            .mine()
            .find(|(label, _)| *label == self.label())
            .map(|(_, node)| *node)
    }
}

impl From<DeviceLabel> for OwnDevice {
    /// The device of yours a label in the list of your devices names.
    fn from(label: DeviceLabel) -> Self {
        Self(label)
    }
}

impl core::fmt::Display for OwnDevice {
    /// `me/<name>`, as typed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{ME}/{}", self.label())
    }
}

/// The most a peer file is read for. A link is well under a kilobyte, so a file past this holds something
/// else, and reading it whole would only spend memory finding that out.
const MAX_PEER_FILE: u64 = 64 * 1024;

/// A peer typed as a path: the file it names holds one link, so the link never enters argv. A `~/` that
/// reached swoosh quoted is expanded here (an empty `HOME` counts as unset), and one trailing newline is
/// trimmed. The file's mode is not checked. Only a regular file is read, so a device or a FIFO refuses
/// instead of filling memory or waiting on a writer, and only its first [`MAX_PEER_FILE`] bytes.
fn read_file(text: &str) -> Result<Peer, PeerParseError> {
    let (link, path) = read_link_file(text)?;
    Ok(Peer::Capability {
        link,
        file: Some(path),
    })
}

/// The one link in the file `text` names, and the file it was read from: what a peer typed as a path
/// reads, on the same rules ([`read_file`]). Anything else in the file refuses, a root key included.
pub fn read_link_file(text: &str) -> Result<(Link, PathBuf), PeerParseError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = expand(text, std::env::var_os("HOME"))?;
    let unreadable = |error: std::io::Error| PeerParseError::Unreadable {
        path: text.to_owned(),
        reason: io_reason(&error),
    };
    // Opened without blocking, then checked on the handle: a FIFO opens at once instead of waiting on a
    // writer, and a file swapped for one after a check by name is still the file refused.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .map_err(unreadable)?;
    if !file.metadata().map_err(unreadable)?.is_file() {
        return Err(PeerParseError::NotAFile {
            path: text.to_owned(),
        });
    }
    let mut held = String::new();
    file.take(MAX_PEER_FILE + 1)
        .read_to_string(&mut held)
        .map_err(unreadable)?;
    if held.len() as u64 > MAX_PEER_FILE {
        return Err(PeerParseError::TooLarge {
            path: text.to_owned(),
        });
    }
    let held = held.strip_suffix('\n').unwrap_or(&held);
    if !crate::link::is_prefixed(held) {
        return Err(PeerParseError::NoLink {
            path: text.to_owned(),
        });
    }
    let link = crate::link::parse(held).map_err(|error| PeerParseError::BadLink {
        path: text.to_owned(),
        error,
    })?;
    Ok((link, path))
}

/// The file a peer path names: a leading `~/` joined onto `home`, which an empty value leaves unset (an
/// empty `HOME` would otherwise read `~/x` as `x` in the working directory).
fn expand(text: &str, home: Option<std::ffi::OsString>) -> Result<PathBuf, PeerParseError> {
    match text.strip_prefix("~/") {
        Some(rest) => match home.filter(|home| !home.is_empty()) {
            Some(home) => Ok(Path::new(&home).join(rest)),
            None => Err(PeerParseError::NoHome),
        },
        None => Ok(PathBuf::from(text)),
    }
}

/// Why a file could not be read, as a person reads it: the system's own words, without the `(os error N)`
/// tail and starting lower-case, so it reads as the second half of a line.
fn io_reason(error: &std::io::Error) -> String {
    let text = error.to_string();
    let reason = text.split(" (os error").next().unwrap_or(&text);
    let mut chars = reason.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(chars).collect()
    })
}

/// A typed key that spells a key, but not one anyone can hold: the one line every typed key refuses with,
/// naming the check it failed.
#[derive(Debug, thiserror::Error)]
#[error("{text} is not a usable key: {error}")]
pub struct UnusableKey {
    /// The text as typed.
    pub text: String,
    /// Which check the key failed.
    pub error: KeyError,
}

/// Why typed text is not a key.
#[derive(Debug, thiserror::Error)]
pub enum KeyTextError {
    /// It spells a key nobody can hold.
    #[error(transparent)]
    Unusable(#[from] UnusableKey),
    /// It does not spell a key at all.
    #[error(transparent)]
    NotAKey(NodeIdParseError),
}

/// Typed text as a key: the parser every typed key goes through, so a key nobody can hold refuses with
/// the same line wherever it is typed.
pub fn parse_key(text: &str) -> Result<NodeId, KeyTextError> {
    match text.parse::<NodeId>() {
        Ok(node) => Ok(node),
        Err(NodeIdParseError::Key(error)) => Err(UnusableKey {
            text: text.to_owned(),
            error,
        }
        .into()),
        Err(other) => Err(KeyTextError::NotAKey(other)),
    }
}

/// Typed text as a key where a name may stand instead: `None` when it does not spell a key, the refusal
/// when it spells one nobody can hold (that text is a key, never a name).
pub fn raw_key(text: &str) -> Result<Option<NodeId>, UnusableKey> {
    match parse_key(text) {
        Ok(node) => Ok(Some(node)),
        Err(KeyTextError::Unusable(unusable)) => Err(unusable),
        Err(KeyTextError::NotAKey(_)) => Ok(None),
    }
}

/// Why a string was not a valid [`Peer`].
#[derive(Debug, thiserror::Error)]
pub enum PeerParseError {
    /// The text was a link without its `swoosh:` prefix, or a `swoosh:` link that did not parse.
    #[error(transparent)]
    Capability(#[from] LinkError),
    /// The text was neither a link nor a raw key, and a part of it was not a name: the name rule's own line.
    #[error(transparent)]
    Contact(#[from] NameError),
    /// The text spells a key, but not one anyone can hold.
    #[error(transparent)]
    Key(#[from] UnusableKey),
    /// The text is a path, and the file it names holds no link.
    #[error("{path} holds no swoosh: link.")]
    NoLink {
        /// The path as typed.
        path: String,
    },
    /// The text is a path, and the file it names could not be read.
    #[error("could not read {path}: {reason}")]
    Unreadable {
        /// The path as typed.
        path: String,
        /// Why, in the system's words.
        reason: String,
    },
    /// The text is a path, and it names something other than a regular file.
    #[error("{path} is not a file; name the file that holds the swoosh: link")]
    NotAFile {
        /// The path as typed.
        path: String,
    },
    /// The text is a path, and the file it names is far larger than any link.
    #[error("{path} is too large to hold one swoosh: link")]
    TooLarge {
        /// The path as typed.
        path: String,
    },
    /// The text is a path, and the file it names holds a `swoosh:` link that does not parse.
    #[error("{path}: {error}")]
    BadLink {
        /// The path as typed.
        path: String,
        /// Why the link did not parse.
        error: LinkError,
    },
    /// The text is a `~/` path, and `HOME` is not set (or empty) to expand it against.
    #[error("HOME is not set, so ~/ has nowhere to point; type the file's full path")]
    NoHome,
}

impl Peer {
    /// The one machine this peer names, resolved against `contacts` once, before the key is read or
    /// anything binds: a usage error never touches a secret or the network, and the book cannot change
    /// between the parse and the dial.
    ///
    /// A bare person is never guessed at: one machine saved is that machine, several or none refuse, and
    /// so do `me` alone and a bare word that is one of your device names (a bare word is a person; `me/` is
    /// the only prefix for yours). The kind is read from where this book saves the resolved key, never
    /// from the form typed, so a key typed bare and the name it is saved under resolve alike; a link
    /// typed as the machine is always [`Kind::Link`], since a refusal could be the link's.
    pub fn machine(&self, contacts: &Contacts) -> Result<Machine, MachineError> {
        match self {
            Self::Raw(key) => Ok(Machine::saved(contacts, *key)),
            Self::Capability { link, .. } => {
                let key = link.dial_node().map_err(MachineError::Link)?;
                Ok(Machine {
                    key,
                    name: contacts.saved_at(&key),
                    kind: Kind::Link,
                    picked: None,
                })
            }
            Self::Named(reference) => named(contacts, reference),
        }
    }

    /// The credential this peer self-supplies when it is a self-addressing link, else `None`. A `swoosh:`
    /// link passed AS the peer flows through the one [`resolve`](crate::reaching::resolve) path, so a
    /// signet-bound link-as-peer computes its slot-2 member badge there.
    pub fn self_present(&self) -> Option<Link> {
        match self {
            Self::Capability { link, .. } => Some(link.clone()),
            _ => None,
        }
    }

    /// The file this peer's link was read from, when it was typed as a path.
    pub fn file(&self) -> Option<&Path> {
        match self {
            Self::Capability { file, .. } => file.as_deref(),
            _ => None,
        }
    }
}

/// A typed name as one machine: a machine of theirs, one of your devices, or a bare person, refused
/// unless exactly one of their machines is saved.
fn named(contacts: &Contacts, reference: &ContactRef) -> Result<Machine, MachineError> {
    let person = reference.petname();
    if let Some(device) = reference.device() {
        let Some(mut machines) = contacts.devices(person) else {
            // `me/<name>` with no list of your devices names no person to save; its own line stays.
            return Err(if person.as_str() == ME {
                MachineError::Unknown(ResolveError::UnknownPetname(person.clone()))
            } else {
                MachineError::NotSaved {
                    person: person.clone(),
                }
            });
        };
        return match machines.find(|(label, _)| *label == device) {
            Some((_, key)) => Ok(Machine::saved(contacts, *key)),
            None => Err(MachineError::Unknown(ResolveError::UnknownDevice {
                petname: person.clone(),
                device: device.clone(),
            })),
        };
    }
    if person.as_str() == ME {
        return Err(MachineError::WhichOfYours {
            yours: yours(contacts),
        });
    }
    let Some(devices) = contacts.devices(person) else {
        // No person by that name. One of your devices typed without `me/` is named for what it is.
        return Err(
            match yours(contacts)
                .into_iter()
                .find(|device| device.label().as_str() == person.as_str())
            {
                Some(device) => MachineError::YourDevice { device },
                None => MachineError::NotSaved {
                    person: person.clone(),
                },
            },
        );
    };
    let machines: Vec<(&DeviceLabel, &NodeId)> = devices.collect();
    match machines.as_slice() {
        [] => Err(MachineError::NoneSaved {
            person: person.clone(),
        }),
        [(_, key)] => Ok(Machine {
            picked: Some(person.clone()),
            ..Machine::saved(contacts, **key)
        }),
        several => Err(MachineError::Several {
            person: person.clone(),
            machines: several.iter().map(|(label, _)| (*label).clone()).collect(),
        }),
    }
}

/// Your devices, in name order, as `me/<name>`.
fn yours(contacts: &Contacts) -> Vec<OwnDevice> {
    contacts
        .mine()
        .map(|(label, _)| OwnDevice::from(label.clone()))
        .collect()
}

/// The one machine a verb's argument names, resolved before the key is read: its key, the name this home
/// gives it, and what kind of machine it is, which picks the line a refusal from it prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    key: NodeId,
    name: Option<ContactRef>,
    kind: Kind,
    picked: Option<Petname>,
}

impl Machine {
    /// `key` as this book saves it: its name, and the kind that name makes it.
    fn saved(contacts: &Contacts, key: NodeId) -> Self {
        let name = contacts.saved_at(&key);
        let kind = match &name {
            Some(name) if name.petname().as_str() == ME => Kind::Yours,
            Some(_) => Kind::Contact,
            None => Kind::Key,
        };
        Self {
            key,
            name,
            kind,
            picked: None,
        }
    }

    /// The key to dial.
    pub fn key(&self) -> NodeId {
        self.key
    }

    /// The name this home gives the key (`me/nas`, `alice/laptop`), or `None` when no name holds it.
    pub fn name(&self) -> Option<&ContactRef> {
        self.name.as_ref()
    }

    /// How a line of output labels it: its name here, else its key's short form.
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) => name.to_string(),
            None => crate::credential::short(&self.key),
        }
    }

    /// What kind of machine it is.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The person typed bare, when they have exactly one machine saved and this is it: the verb says which
    /// machine it dialed, since the person typed none.
    pub fn picked(&self) -> Option<&Petname> {
        self.picked.as_ref()
    }
}

/// What kind of machine a verb dials: the fact a refusal's line is picked by. Read from this home's book
/// for the key dialed, so two forms of one machine are one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One of your devices (`me/<name>`): it answers you `control.services`, which tells a refusal's cause.
    Yours,
    /// Typed as a link: the refusal may be the link's.
    Link,
    /// A machine this book saves under a contact's name.
    Contact,
    /// A key no name here holds.
    Key,
}

/// Why a verb's argument is not one machine. Each is a usage error, found before the key is read; the bin
/// renders the words.
#[derive(Debug, thiserror::Error)]
pub enum MachineError {
    /// A bare person with more than one machine saved.
    #[error("which machine?")]
    Several {
        /// The person typed.
        person: Petname,
        /// Their machines' names, in name order.
        machines: Vec<DeviceLabel>,
    },
    /// A person saved with no machine.
    #[error("none of {person}'s machines is saved here")]
    NoneSaved {
        /// The person typed.
        person: Petname,
    },
    /// A word that names no person here and none of your devices.
    #[error("{person} is not saved here")]
    NotSaved {
        /// The word typed.
        person: Petname,
    },
    /// `me` alone, which names none of your devices in particular.
    #[error("which machine?")]
    WhichOfYours {
        /// Your devices, in name order.
        yours: Vec<OwnDevice>,
    },
    /// A bare word that is no person here but is one of your device names.
    #[error("name the machine: {device}")]
    YourDevice {
        /// The device it names.
        device: OwnDevice,
    },
    /// A machine of a known person that this book does not hold, in the book's own words.
    #[error(transparent)]
    Unknown(ResolveError),
    /// A link whose machine is no usable key.
    #[error(transparent)]
    Link(KeyError),
}

impl core::fmt::Display for Peer {
    /// The peer as the user would recognize it: the name for a petname, the short key for a raw id, the
    /// link's short form (the cap root's short id) for a capability link.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Named(reference) => reference.fmt(f),
            Self::Raw(node) => f.write_str(&crate::credential::short(node)),
            Self::Capability { link, .. } => f.write_str(&link.short()),
        }
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
