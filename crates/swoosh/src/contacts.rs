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

use bifrost::{CryptoKind, NodeId};

use crate::roster::RosterDoc;

/// The reserved petname for the operator's own devices: the signet is person-zero, each device it derives
/// lives under `me/<label>`. A signet-verified roster hydrates into exactly this partition.
const ME: &str = "me";

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
/// Same single-segment discipline as a [`Petname`], plus a length bound and a control-byte reject the
/// signed-roster encoding requires: this is the ONE label type, used both for local contacts and for a
/// member in a [`RosterDoc`](crate::roster::RosterDoc), so the codec's `u16` length prefix stays total and
/// no smuggled control byte can reframe the signed bytes at a puller. A bare `contact add alice <key>` (no
/// `/device`) uses the reserved [`DEFAULT`](Self::DEFAULT) slot, so a person addressed without a device
/// still resolves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceLabel(String);

impl DeviceLabel {
    /// The slot a device-less `contact add alice <key>` occupies. Sorts before named devices, so an
    /// unqualified person resolves to their default device first.
    pub const DEFAULT: &'static str = "default";

    /// The maximum label length in bytes. Small: a device label (`desk`, `macbook`) is never long, and a
    /// bound keeps the `u16` length prefix in the roster's canonical encoding total.
    pub const MAX_LEN: usize = 255;

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
        if text.len() > Self::MAX_LEN {
            return Err(DeviceLabelParseError::TooLong);
        }
        if text.contains('/') {
            return Err(DeviceLabelParseError::Slash);
        }
        // Reject whitespace AND other control bytes: whitespace keeps a label a single word, and a control
        // byte (a smuggled newline) must never enter the roster's signed bytes where it could reframe a
        // later field.
        if text
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(DeviceLabelParseError::BadByte);
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
    /// The label exceeded [`DeviceLabel::MAX_LEN`].
    #[error("device label is too long")]
    TooLong,
    /// The label held a further `/`; a device address is exactly `<petname>/<device>`, one level deep.
    #[error("device label cannot contain '/'")]
    Slash,
    /// The label held whitespace or another control byte.
    #[error("device label cannot contain whitespace or control bytes")]
    BadByte,
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

/// Where a contact binding came from: a name YOU typed, or a member the signet vouched for in a signed
/// roster. This distinction is the moat: a roster-hydrated member stays distinguishable from a hand-typed
/// peer at read time, so flattening the two can never silently launder a stranger into a signed member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A binding the operator added by hand (`contact add`, `mint`), or loaded from the legacy bare-string
    /// wire form. It carries no signature; it is trust the operator asserted locally.
    HandTyped,
    /// A binding hydrated from a signet-signed roster at the given epoch. Only [`Contacts::hydrate`] writes
    /// this, and only from an already-verified [`RosterDoc`], so the signet-only membership fence is a
    /// type-path property: no hand-typed op can forge a `Roster` provenance.
    Roster { epoch: u64 },
}

/// One device binding: its node identity and where that binding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// The device's node identity.
    pub node: NodeId,
    /// Whether the operator typed this binding or the signet vouched for it in a roster.
    pub source: Source,
}

/// The in-memory address book: every petname mapped to its ordered group of device bindings, plus the
/// persisted roster epoch floor.
///
/// This is the pure domain view the store loads into and saves back from. It owns the add / list /
/// remove / resolve / hydrate behaviour; persistence is the [`ContactsStore`]'s job, layered around it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Contacts {
    people: BTreeMap<Petname, BTreeMap<DeviceLabel, Binding>>,
    /// The highest roster epoch this book has applied: the anti-rollback FLOOR. `None` before any roster is
    /// hydrated. A snapshot at or below it is refused as stale, so a replayed old-but-genuine roster can
    /// never roll the fleet back (delib-28 F1). For B1 there is one signet, so one floor; a device in two
    /// fleets is out of scope until the floor is keyed per-signet.
    roster_epoch: Option<u64>,
}

impl Contacts {
    /// Add or update the identity for a petname's device, returning whether an existing binding was
    /// replaced. Idempotent: re-adding the same name and device just overwrites, so the caller can warn
    /// on a clobber rather than the store silently losing the old key. A device-less add targets the
    /// [`DEFAULT`](DeviceLabel::DEFAULT) slot.
    pub fn add(&mut self, petname: Petname, device: Option<DeviceLabel>, node: NodeId) -> Added {
        let device = device.unwrap_or(DeviceLabel(DeviceLabel::DEFAULT.to_owned()));
        let group = self.people.entry(petname).or_default();
        let binding = Binding {
            node,
            source: Source::HandTyped,
        };
        match group.insert(device, binding) {
            Some(previous) if previous.node == node => Added::Unchanged,
            Some(previous) => Added::Replaced(previous.node),
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
        self.people
            .get(petname)
            .map(|group| group.iter().map(|(label, binding)| (label, &binding.node)))
    }

    /// Every device binding under a petname WITH its provenance, in label order, for the store's codec and
    /// for a `contact ls` that wants to show which entries the signet vouched for. `None` for an unknown
    /// petname. Unlike [`devices`](Self::devices) (which projects to the node for reach), this carries the
    /// [`Source`] so a roster-hydrated member round-trips through persistence.
    pub fn bindings(
        &self,
        petname: &Petname,
    ) -> Option<impl Iterator<Item = (&DeviceLabel, &Binding)>> {
        self.people.get(petname).map(|group| group.iter())
    }

    /// Resolve an address to its ordered [`Candidate`]s, each carrying the `<petname>/<device>` label it
    /// resolved from.
    ///
    /// A specific device (`alice/macbook`) resolves to exactly that one key. A bare person (`alice`)
    /// resolves to ALL their devices in label order, so a verb can dial each until one connects (v1
    /// first-reachable-wins) or fan out over all of them. An unknown name or device yields the error,
    /// never an empty success, so a reach verb never silently dials nothing. The labels let a fan-out
    /// verb (`ping`, `status`) report per device by name, not by an opaque key.
    pub fn resolve_candidates(&self, target: &ContactRef) -> Result<Vec<Candidate>, ResolveError> {
        let group = self
            .people
            .get(&target.petname)
            .ok_or_else(|| ResolveError::UnknownPetname(target.petname.clone()))?;
        let candidate = |device: &DeviceLabel, node: NodeId| Candidate {
            label: format!("{}/{device}", target.petname),
            node,
        };
        match &target.device {
            None => Ok(group
                .iter()
                .map(|(device, binding)| candidate(device, binding.node))
                .collect()),
            Some(device) => group
                .get(device)
                .map(|binding| binding.node)
                .map(|node| vec![candidate(device, node)])
                .ok_or_else(|| ResolveError::UnknownDevice {
                    petname: target.petname.clone(),
                    device: device.clone(),
                }),
        }
    }

    /// This book's roster epoch floor: the highest roster epoch it has applied, or `None` before any roster
    /// is hydrated. The store persists and reloads it so the anti-rollback floor survives a restart.
    pub fn roster_epoch(&self) -> Option<u64> {
        self.roster_epoch
    }

    /// Fold a signet-verified roster into the `me` partition (the operator's own fleet) as a FLOORED
    /// SNAPSHOT-REPLACE, tagging each member [`Source::Roster`]. THIS is the moat's write path, and it is
    /// safe by construction: the only way to obtain a [`RosterDoc`] is [`crate::roster::verify`], so a
    /// `Roster` provenance can only ever come from the signet, never from a hand-typed op.
    ///
    /// A roster is a whole SNAPSHOT, not an op-log, so the correct fold is a REPLACE under a persisted floor
    /// (delib-28 F1). Returns whether the doc was applied:
    ///
    /// - `doc.epoch <= floor` (a stale or same-epoch replay from a lagging/hostile courier) is REFUSED
    ///   wholesale, a no-op, so a genuinely-signed OLD roster can never roll the fleet back or re-add a
    ///   removed member. The first hydrate (floor `None`) always applies.
    /// - `doc.epoch > floor`: the roster-sourced `me/*` set is REPLACED by the doc's members (add new,
    ///   refresh changed, and DROP any prior `Roster`-sourced device NOT in the new doc so a removed member
    ///   disappears), then the floor advances to `doc.epoch`.
    ///
    /// A `HandTyped` binding under `me` is NEVER touched (the operator's local choice is sovereign, and a
    /// member is only a suggestion); only `Roster`-sourced entries are in the replace-set. Only the `me`
    /// partition is touched: other petnames (people you know) are never rewritten by your own fleet roster.
    pub fn hydrate(&mut self, roster: &RosterDoc) -> bool {
        let epoch = roster.epoch().0;
        // Refuse a stale or same-epoch snapshot before touching anything: the whole-doc floor is what kills
        // F1's removed-member re-add (the old blob never applies at all) and the same-epoch overwrite.
        if self.roster_epoch.is_some_and(|floor| epoch <= floor) {
            return false;
        }
        let group = self.people.entry(Petname(ME.to_owned())).or_default();
        // Snapshot-REPLACE: drop the prior roster-sourced set, keep every HandTyped binding, then lay the
        // new doc's members down. Dropping first is what makes a removed member disappear; a hand-typed
        // entry never enters the drop-set, so the operator's local choice survives.
        group.retain(|_, binding| binding.source == Source::HandTyped);
        for member in roster.members() {
            // The label is already a `DeviceLabel` (one label type across the seam), so there is no lossy
            // re-parse here. A HandTyped binding is sovereign and was kept by `retain`; never clobber it.
            if let Entry::Occupied(entry) = group.entry(member.label.clone()) {
                if entry.get().source == Source::HandTyped {
                    continue;
                }
            }
            group.insert(
                member.label.clone(),
                Binding {
                    node: NodeId::new(CryptoKind::Ed25519, *member.node.bytes()),
                    source: Source::Roster { epoch },
                },
            );
        }
        // An empty `me` group (a roster of only skipped members over no hand-typed entries) should not
        // linger as an empty person; mirror `remove`'s tidy-up.
        if self
            .people
            .get(&Petname(ME.to_owned()))
            .is_some_and(BTreeMap::is_empty)
        {
            self.people.remove(&Petname(ME.to_owned()));
        }
        self.roster_epoch = Some(epoch);
        true
    }

    /// Set the persisted roster epoch floor when the store reconstructs a book from disk. For the store's
    /// codec ONLY: the floor was established by a prior [`hydrate`], and reload just round-trips it, so a
    /// restart does not reset the anti-rollback high-water mark to zero.
    pub(crate) fn set_roster_epoch(&mut self, floor: Option<u64>) {
        self.roster_epoch = floor;
    }

    /// Insert a fully-formed binding (node + provenance) under a petname's device. For the store's codec,
    /// which reconstructs persisted state INCLUDING a `Roster` provenance; the trust for that provenance was
    /// established when it was first hydrated from a verified roster, and persistence just round-trips it.
    pub(crate) fn insert_binding(
        &mut self,
        petname: Petname,
        device: DeviceLabel,
        binding: Binding,
    ) {
        self.people
            .entry(petname)
            .or_default()
            .insert(device, binding);
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

/// One resolved peer to try: the identity to dial and the label to print for it.
///
/// A reach verb dials the [`node`](Self::node) and reports the [`label`](Self::label) (`alice/macbook`,
/// or a raw key's short form), so a fan-out over a person's devices names each device rather than a bare
/// key. Carried through resolution because the label is lost once a `ContactRef` becomes a `NodeId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The peer's identity, dialed verbatim.
    pub node: NodeId,
    /// How to name this candidate in output: `alice/macbook`, or a raw key's short form.
    pub label: String,
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

/// The contacts file for a given `--key`: beside the key's dir when one is set (so one `--key` moves the
/// whole config), else [`default_path`]. Lets a command open its own store from the key alone.
pub fn path(key: Option<&Path>) -> Result<PathBuf, StoreError> {
    match key.and_then(Path::parent) {
        Some(dir) => Ok(dir.join("contacts.toml")),
        None => default_path(),
    }
}

#[cfg(test)]
#[path = "contacts_tests.rs"]
mod contacts_tests;
