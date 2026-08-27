//! The local, self-sovereign contact store: petnames mapped to peer identities.
//!
//! A petname is a name YOU chose for a peer, meaningful only on this box. `swoosh contact add alice
//! <key>` saves it; then `swoosh ping alice` reaches that key without pasting base32. Nothing here is
//! synced, published, or globally unique: it is your address book, Alice keeps hers. Zooko's triangle
//! resolved by dropping GLOBAL uniqueness, so a name can be human-meaningful AND secure with no registry.
//!
//! A petname groups one or more device identities (WEAK grouping: manual, no cryptographic claim the
//! devices are truly one person, that is HD-identity work sequenced for later). Address a specific device
//! (`alice/macbook`) for that exact key, or the person (`alice`) for the ordered set of their devices, so
//! a reach verb can try each until one connects. Adding under a person with no device label uses the
//! reserved [`DeviceLabel::DEFAULT`] slot, so `contact add alice <key>` and `contact add alice/macbook
//! <key>` coexist under one petname.
//!
//! The store persists beside the identity key as `~/.config/swoosh/contacts.toml` (honoring the same
//! `SWOOSH_KEY`-adjacent config dir the identity module uses), a plain TOML table of `petname -> { device
//! -> node id }`. It is LOCAL STATE, not a wire or registry format, so a human-editable TOML file is the
//! right representation.

use core::str::FromStr;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::path::{Path, PathBuf};

use bifrost::NodeId;

mod store;

pub use store::{ContactsStore, StoreError};

/// A local alias for a peer: a human-meaningful name for one or more of their device identities.
///
/// Validated once at the boundary so the rest of the code holds a name already known to be a single
/// non-empty path segment: no slash (that separates a petname from a device label), no whitespace, non
/// empty. Parsing rejects garbage here rather than letting it reach a lookup and miss silently.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Petname(String);

impl Petname {
    /// The underlying name, for display and lookup.
    pub fn as_str(&self) -> &str {
        let Self(name) = self;
        name
    }
}

impl FromStr for Petname {
    type Err = PetnameParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() {
            return Err(PetnameParseError::Empty);
        }
        if text.contains('/') {
            return Err(PetnameParseError::Slash);
        }
        if text.chars().any(char::is_whitespace) {
            return Err(PetnameParseError::Whitespace);
        }
        Ok(Self(text.to_owned()))
    }
}

impl core::fmt::Display for Petname {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a string was not a valid [`Petname`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PetnameParseError {
    /// The name was empty.
    #[error("petname is empty")]
    Empty,
    /// The name held a `/`, which separates a petname from a device label and cannot appear inside one.
    #[error("petname cannot contain '/' (that separates the device label)")]
    Slash,
    /// The name held whitespace.
    #[error("petname cannot contain whitespace")]
    Whitespace,
}

/// A label for one device under a petname (`macbook`, `iphone`).
///
/// Same single-segment discipline as a [`Petname`]. A bare `contact add alice <key>` (no `/device`) uses
/// the reserved [`DEFAULT`](Self::DEFAULT) slot, so a person addressed without a device still resolves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceLabel(String);

impl DeviceLabel {
    /// The slot a device-less `contact add alice <key>` occupies. Sorts before named devices, so an
    /// unqualified person resolves to their default device first.
    pub const DEFAULT: &'static str = "default";

    /// The underlying label, for display and lookup.
    pub fn as_str(&self) -> &str {
        let Self(label) = self;
        label
    }
}

impl FromStr for DeviceLabel {
    type Err = DeviceLabelParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() {
            return Err(DeviceLabelParseError::Empty);
        }
        if text.contains('/') {
            return Err(DeviceLabelParseError::Slash);
        }
        if text.chars().any(char::is_whitespace) {
            return Err(DeviceLabelParseError::Whitespace);
        }
        Ok(Self(text.to_owned()))
    }
}

impl core::fmt::Display for DeviceLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a string was not a valid [`DeviceLabel`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeviceLabelParseError {
    /// The label was empty (a trailing `alice/` with nothing after the slash).
    #[error("device label is empty")]
    Empty,
    /// The label held a further `/`; a device address is exactly `<petname>/<device>`, one level deep.
    #[error("device label cannot contain '/'")]
    Slash,
    /// The label held whitespace.
    #[error("device label cannot contain whitespace")]
    Whitespace,
}

/// A `<petname>` or `<petname>/<device>` address, as typed on the command line.
///
/// Parsed once at the clap boundary from the `<positional>` a `contact` verb takes, so a handler holds a
/// validated petname and an optional device rather than re-splitting a string. `alice` targets the whole
/// person; `alice/macbook` targets exactly that device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRef {
    petname: Petname,
    device: Option<DeviceLabel>,
}

impl ContactRef {
    /// The person this address names.
    pub fn petname(&self) -> &Petname {
        &self.petname
    }

    /// The specific device, if one was named (`alice/macbook`), else `None` (`alice`).
    pub fn device(&self) -> Option<&DeviceLabel> {
        self.device.as_ref()
    }
}

impl FromStr for ContactRef {
    type Err = ContactRefParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.split_once('/') {
            None => Ok(Self {
                petname: text.parse()?,
                device: None,
            }),
            Some((petname, device)) => Ok(Self {
                petname: petname.parse()?,
                device: Some(device.parse()?),
            }),
        }
    }
}

/// Why a string was not a valid [`ContactRef`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContactRefParseError {
    /// The petname part was invalid.
    #[error("invalid petname")]
    Petname(#[from] PetnameParseError),
    /// The device part was invalid.
    #[error("invalid device label")]
    Device(#[from] DeviceLabelParseError),
}

/// The in-memory address book: every petname mapped to its ordered group of device identities.
///
/// This is the pure domain view the store loads into and saves back from. It owns the add / list /
/// remove / resolve behaviour; persistence is the [`ContactsStore`]'s job, layered around it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Contacts {
    people: BTreeMap<Petname, BTreeMap<DeviceLabel, NodeId>>,
}

impl Contacts {
    /// Add or update the identity for a petname's device, returning whether an existing binding was
    /// replaced. Idempotent: re-adding the same name and device just overwrites, so the caller can warn
    /// on a clobber rather than the store silently losing the old key. A device-less add targets the
    /// [`DEFAULT`](DeviceLabel::DEFAULT) slot.
    pub fn add(&mut self, petname: Petname, device: Option<DeviceLabel>, node: NodeId) -> Added {
        let device = device.unwrap_or(DeviceLabel(DeviceLabel::DEFAULT.to_owned()));
        let group = self.people.entry(petname).or_default();
        match group.insert(device, node) {
            Some(previous) if previous == node => Added::Unchanged,
            Some(previous) => Added::Replaced(previous),
            None => Added::Created,
        }
    }

    /// Every petname, in name order, for `contact ls` with no argument.
    pub fn petnames(&self) -> impl Iterator<Item = &Petname> {
        self.people.keys()
    }

    /// One person's devices, label to identity, in label order, for `contact ls <petname>`. `None` if
    /// the petname is unknown.
    pub fn devices(
        &self,
        petname: &Petname,
    ) -> Option<impl Iterator<Item = (&DeviceLabel, &NodeId)>> {
        self.people.get(petname).map(|group| group.iter())
    }

    /// Resolve an address to the ordered identities a reach verb should try.
    ///
    /// A specific device (`alice/macbook`) resolves to exactly that one key. A bare person (`alice`)
    /// resolves to ALL their devices in label order, so the verb can dial each until one connects
    /// (v1 first-reachable-wins). An unknown name or device yields the error, never an empty success,
    /// so a reach verb never silently dials nothing.
    pub fn resolve(&self, target: &ContactRef) -> Result<Vec<NodeId>, ResolveError> {
        let group = self
            .people
            .get(&target.petname)
            .ok_or_else(|| ResolveError::UnknownPetname(target.petname.clone()))?;
        match &target.device {
            None => Ok(group.values().copied().collect()),
            Some(device) => group
                .get(device)
                .copied()
                .map(|node| vec![node])
                .ok_or_else(|| ResolveError::UnknownDevice {
                    petname: target.petname.clone(),
                    device: device.clone(),
                }),
        }
    }

    /// Remove a whole petname (all its devices) or, with a device, just that one device. Returns whether
    /// anything was removed. Removing a person's last device removes the now-empty person too, so an
    /// empty group never lingers.
    pub fn remove(&mut self, petname: &Petname, device: Option<&DeviceLabel>) -> Removed {
        let Entry::Occupied(mut entry) = self.people.entry(petname.clone()) else {
            return Removed::Absent;
        };
        match device {
            None => {
                entry.remove();
                Removed::Removed
            }
            Some(device) => {
                let group = entry.get_mut();
                if group.remove(device).is_none() {
                    return Removed::Absent;
                }
                if group.is_empty() {
                    entry.remove();
                }
                Removed::Removed
            }
        }
    }
}

/// The outcome of an [`add`](Contacts::add): whether it created, replaced, or was a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    /// A new device binding was created.
    Created,
    /// An existing binding held the same identity already; nothing changed.
    Unchanged,
    /// An existing binding was overwritten; carries the identity that was replaced, so the caller can
    /// warn instead of silently clobbering.
    Replaced(NodeId),
}

/// The outcome of a [`remove`](Contacts::remove): whether it removed anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removed {
    /// The target existed and was removed.
    Removed,
    /// The target did not exist; nothing changed.
    Absent,
}

impl core::fmt::Display for ContactRef {
    /// `alice` or `alice/macbook`, as typed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.petname.fmt(f)?;
        if let Some(device) = &self.device {
            write!(f, "/{device}")?;
        }
        Ok(())
    }
}

/// Why an address did not resolve to any identity.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    /// No such petname in this store.
    #[error("unknown contact '{0}'; add it with `swoosh contact add {0} <key>`")]
    UnknownPetname(Petname),
    /// The petname exists but has no device by that label.
    #[error(
        "contact '{petname}' has no device '{device}'; see its devices with `swoosh contact ls {petname}`"
    )]
    UnknownDevice {
        /// The known petname.
        petname: Petname,
        /// The device label that was not found under it.
        device: DeviceLabel,
    },
}

/// A reach verb's peer slot: a raw [`NodeId`] or a petname, before resolution.
///
/// This replaces the bare `NodeId` a reach verb used to take, so `swoosh ping alice` and `swoosh ping
/// bf01...` both parse in the same slot. Parsing is petname-free: a raw base32 key is recognized as a
/// [`Raw`](Self::Raw) here (it always works, petnames are additive and never mandatory), and anything
/// else is kept as a [`Named`](Self::Named) address to resolve against the store just before dialing.
/// Resolution is deferred because the store is loaded once at startup, not at the clap boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A literal node id, dialed verbatim with no store lookup.
    Raw(NodeId),
    /// A petname (optionally a specific device), resolved against the store at dial time.
    Named(ContactRef),
}

impl Target {
    /// The identities to try dialing, in order, resolving a petname against `contacts`.
    ///
    /// A [`Raw`](Self::Raw) target is a single literal key. A [`Named`](Self::Named) target resolves to
    /// one device (exact) or the ordered set of a person's devices (first-reachable-wins). An unknown
    /// name is a clean [`ResolveError`], never a silent empty dial.
    pub fn resolve(&self, contacts: &Contacts) -> Result<Vec<NodeId>, ResolveError> {
        match self {
            Self::Raw(node) => Ok(vec![*node]),
            Self::Named(reference) => contacts.resolve(reference),
        }
    }
}

impl core::fmt::Display for Target {
    /// The target as the user would recognize it: the short key for a raw id, the name for a petname.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Raw(node) => f.write_str(&node.short()),
            Self::Named(reference) => reference.fmt(f),
        }
    }
}

impl FromStr for Target {
    type Err = ContactRefParseError;

    /// Try a raw node id first (the always-valid literal form); on failure treat it as a petname
    /// address. A syntactically invalid petname (embedded whitespace, a bare trailing slash) still
    /// errors here at the boundary rather than deferring to a lookup that would miss.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.parse::<NodeId>() {
            Ok(node) => Ok(Self::Raw(node)),
            Err(_) => Ok(Self::Named(text.parse()?)),
        }
    }
}

/// The default contacts file, `~/.config/swoosh/contacts.toml`, beside the identity key.
///
/// Honors the same config-dir convention as the identity module: the store lives next to the one
/// identity it belongs to, one box, one address book.
pub fn default_path() -> Result<PathBuf, StoreError> {
    let home = std::env::var_os("HOME").ok_or(StoreError::NoHome)?;
    Ok(Path::new(&home)
        .join(".config")
        .join("swoosh")
        .join("contacts.toml"))
}

#[cfg(test)]
#[path = "contacts_tests.rs"]
mod contacts_tests;
