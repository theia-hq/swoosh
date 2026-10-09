//! The local, self-sovereign contact store: petnames mapped to peer identities.
//!
//! A petname is a name YOU chose for a peer, meaningful only on this box. `swoosh contact add alice/laptop
//! <key>` saves one machine of theirs; then `swoosh ping alice/laptop` reaches that key without pasting
//! base32, and `swoosh ping alice` tries each machine saved under her. Nothing here is
//! synced, published, or globally unique: it is your address book, Alice keeps hers. Zooko's triangle
//! resolved by dropping GLOBAL uniqueness, so a name can be human-meaningful AND secure with no registry.
//!
//! A petname groups one or more device identities (WEAK grouping: manual, no cryptographic claim the
//! devices are truly one person, that is HD-identity work sequenced for later). Address a specific device
//! (`alice/macbook`) for that exact key, or the person (`alice`) for the ordered set of their devices, so
//! a reach verb can try each until one connects. A person's root is kept beside their devices, never
//! among them: `contact add alice root:<key>` saves it, `contact add alice/macbook <key>` saves a device.
//! A root can also be learned from one of a person's saved devices, and is then marked with the device it
//! came from ([`Source::Learned`]).
//!
//! The store persists in the node home as `<home>/contacts.toml` (the same directory the identity key
//! and the trust files live in, [`Home::contacts`](crate::home::Home::contacts)), a plain TOML table of
//! `petname -> { device -> node id }`. It is LOCAL STATE, not a wire or registry format, so a
//! human-editable TOML file is the right representation.

use core::str::FromStr;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use bifrost::NodeId;
use tightbeam::identity::AsNodeId as _;

use crate::names::{Name, NameError};
use crate::roster::RosterDoc;

/// The reserved petname for the operator's own devices: the signet is person-zero, each device it derives
/// lives under `me/<label>`, derived from the home's list of your devices, never saved.
pub const ME: &str = "me";

mod store;

pub use store::{ContactsStore, StoreError};

/// A local alias for a peer: a human-meaningful name for one or more of their device identities.
///
/// A [`Name`] under the one name rule, so it is a single segment that never holds the `/` separating a
/// petname from a device label. It may be reserved: `me` addresses this person's own devices. Naming a new
/// person refuses a reserved name through [`Name::unreserved`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Petname(String);

impl Petname {
    /// The underlying name, for display and lookup.
    pub fn as_str(&self) -> &str {
        let Self(name) = self;
        name
    }

    /// This petname, refused when it is reserved: the check for a petname about to name a person.
    pub fn unreserved(self) -> Result<Self, NameError> {
        let Self(name) = self;
        Ok(Self(Name::from_str(&name)?.unreserved()?.into()))
    }

    /// A petname read back from the contacts file, taken as stored: a capital there refuses rather than
    /// folds ([`Name::stored`]), so one person has one spelling on disk.
    pub fn stored(text: &str) -> Result<Self, NameError> {
        Ok(Self(Name::stored(text)?.into()))
    }
}

impl FromStr for Petname {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(Self(text.parse::<Name>()?.into()))
    }
}

impl core::fmt::Display for Petname {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A label for one device under a petname (`macbook`, `iphone`).
///
/// A [`Name`] under the one name rule, never reserved: no device is `me`, `root` or `anyone`. This is the ONE
/// label type, used both for local contacts and for a member in a [`RosterDoc`](crate::roster::RosterDoc),
/// so the codec's `u16` length prefix stays total. A test's `Contacts::add` with no label uses the
/// [`DEFAULT`](Self::DEFAULT) slot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceLabel(String);

impl DeviceLabel {
    /// The slot a test's `Contacts::add` fills when it is given no label. `contact add` always names the
    /// machine (`alice` alone saves her root), so only a book written by hand or by a test holds it. Sorts
    /// before named devices, so an unqualified person resolves to their default device first.
    pub const DEFAULT: &'static str = "default";

    /// The maximum label length in bytes, the name rule's bound.
    pub const MAX_LEN: usize = Name::MAX_LEN;

    /// The underlying label, for display and lookup.
    pub fn as_str(&self) -> &str {
        let Self(label) = self;
        label
    }

    /// A label read back from disk or a signed roster, taken as stored: a capital there refuses rather than
    /// folds ([`Name::stored`]), so one label has one byte-string and a signed roster stays non-malleable.
    pub fn stored(text: &str) -> Result<Self, NameError> {
        Ok(Self(Name::stored(text)?.unreserved()?.into()))
    }
}

impl FromStr for DeviceLabel {
    type Err = NameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(Self(text.parse::<Name>()?.unreserved()?.into()))
    }
}

impl core::fmt::Display for DeviceLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
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

    /// The whole person `petname`, naming no device.
    pub fn person(petname: Petname) -> Self {
        Self {
            petname,
            device: None,
        }
    }
}

impl FromStr for ContactRef {
    type Err = NameError;

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

/// One device binding: its node identity, and the root this machine last saw vouch for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// The device's node identity.
    pub node: NodeId,
    /// The root the device last presented when this machine asked who vouches for it: kept on this machine
    /// only, never served or synced, so a root it keeps presenting is said once, and a new one again.
    pub seen_root: Option<NodeId>,
}

impl Binding {
    /// A device just saved: its key, with no root seen yet.
    fn new(node: NodeId) -> Self {
        Self {
            node,
            seen_root: None,
        }
    }
}

/// A person's saved root: its key, and how it came to be saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedRoot {
    /// The root's key.
    pub node: NodeId,
    /// Typed by the person, or learned from one of the person's devices.
    pub source: Source,
}

/// How a person's root came to be saved here: the mark a learned root carries until an explicit save
/// replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Saved by an explicit act: a root key typed into `contact add`.
    Explicit,
    /// Learned from the person's device under this label, when it presented a standing the root signed
    /// and the person here said yes. Only as trustworthy as whoever holds that device's key, so it is kept
    /// and shown.
    Learned(DeviceLabel),
}

/// One person in the address book: their device bindings plus, optionally, their SIGNET root.
///
/// A signet is the key a person's fleet roots at (the root that vouches for their devices); it is NOT a
/// device, so it lives in its own at-most-one slot, never in `devices`. Keeping it out of `devices` keeps
/// it out of resolution ([`resolve_candidates`](Contacts::resolve_candidates)) and out of `status`'s
/// device columns: you never dial a signet, you BIND a link to it (`share <service> <petname>`).
/// Modeling it as a distinct `Option` makes "a person has zero-or-one signet" the only representable shape.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Person {
    /// This person's device identities, label -> binding, in label order (unchanged from the old value type).
    devices: BTreeMap<DeviceLabel, Binding>,
    /// This person's signet root, if recorded. `None` until saved.
    signet: Option<SavedRoot>,
}

impl Person {
    /// A person with no devices AND no signet: nothing left to keep. Used by `remove`'s tidy-up so a
    /// signet-only person (you recorded alice's signet before any device) is NOT swept away, but a truly
    /// empty person still is.
    fn is_empty(&self) -> bool {
        self.devices.is_empty() && self.signet.is_none()
    }
}

/// The in-memory address book: every petname mapped to its ordered group of device bindings.
///
/// This is the pure domain view the store loads into and saves back from. It owns the add / list /
/// remove / resolve behaviour; persistence is the [`ContactsStore`]'s job, layered around it. Your own
/// devices, under `me`, are never saved: the store derives them from the home's list of your devices each
/// time it opens the book ([`derive_me`](Self::derive_me)).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Contacts {
    people: BTreeMap<Petname, Person>,
    /// The root this machine trusts, when it trusts one: your own root, which no person here is saved
    /// under, read beside `me` so a root key typed where a machine goes can be named yours.
    yours: Option<NodeId>,
}

impl Contacts {
    /// Add or update the identity for a petname's device, returning whether an existing binding was
    /// replaced. Idempotent: re-adding the same name and device just overwrites, so the caller can warn
    /// on a clobber rather than the store silently losing the old key. A device-less add targets the
    /// [`DEFAULT`](DeviceLabel::DEFAULT) slot. Tests only: it replaces a key, and every product write goes
    /// through [`save`](Self::save), which never does.
    #[cfg(any(test, feature = "test-support"))]
    pub fn add(&mut self, petname: Petname, device: Option<DeviceLabel>, node: NodeId) -> Added {
        let device = device.unwrap_or(DeviceLabel(DeviceLabel::DEFAULT.to_owned()));
        let person = self.people.entry(petname).or_default();
        match person.devices.insert(device, Binding::new(node)) {
            Some(previous) if previous.node == node => Added::Unchanged,
            Some(previous) => Added::Replaced(previous.node),
            None => Added::Created,
        }
    }

    /// Every petname, in name order, for `status`'s contacts.
    pub fn petnames(&self) -> impl Iterator<Item = &Petname> {
        self.people.keys()
    }

    /// One person's devices, label to identity, in label order, for `status`'s contacts. `None` if
    /// the petname is unknown.
    pub fn devices(
        &self,
        petname: &Petname,
    ) -> Option<impl Iterator<Item = (&DeviceLabel, &NodeId)>> {
        self.people.get(petname).map(|person| {
            person
                .devices
                .iter()
                .map(|(label, binding)| (label, &binding.node))
        })
    }

    /// Your own devices, the ones under `me`, label to identity, in label order; none when this machine
    /// holds no list of them. `me` is always a name, so this needs no fallible lookup.
    pub fn mine(&self) -> impl Iterator<Item = (&DeviceLabel, &NodeId)> {
        self.people
            .get(&Petname(ME.to_owned()))
            .into_iter()
            .flat_map(|person| person.devices.iter())
            .map(|(label, binding)| (label, &binding.node))
    }

    /// Resolve an address to its ordered [`Candidate`]s, each carrying the `<petname>/<device>` label it
    /// resolved from.
    ///
    /// A specific device (`alice/macbook`) resolves to exactly that one key. A bare person (`alice`)
    /// resolves to ALL their devices in label order, for a caller that acts on every one of them (a
    /// verb that dials resolves one machine through [`Peer::machine`](crate::peer::Peer::machine)
    /// instead). An unknown name or device yields the error, never an empty success. The labels name
    /// each device rather than an opaque key.
    pub fn resolve_candidates(&self, target: &ContactRef) -> Result<Vec<Candidate>, ResolveError> {
        let person = self
            .people
            .get(&target.petname)
            .ok_or_else(|| ResolveError::UnknownPetname(target.petname.clone()))?;
        let candidate = |device: &DeviceLabel, node: NodeId| Candidate {
            label: format!("{}/{device}", target.petname),
            node,
        };
        // Only DEVICES are candidates; the signet is never dialed (it vouches, it is not a reachable peer).
        match &target.device {
            None => Ok(person
                .devices
                .iter()
                .map(|(device, binding)| candidate(device, binding.node))
                .collect()),
            Some(device) => person
                .devices
                .get(device)
                .map(|binding| binding.node)
                .map(|node| vec![candidate(device, node)])
                .ok_or_else(|| ResolveError::UnknownDevice {
                    petname: target.petname.clone(),
                    device: device.clone(),
                }),
        }
    }

    /// Lay `me` down as the devices of `devices`, the list of your devices this machine holds, verified
    /// under `root`, the root this machine trusts, replacing whatever `me` held; with no list, `me` names
    /// nothing. The one writer of `me` and of [`your_root`](Self::your_root): no hand-typed binding lives
    /// there, and the book never saves either.
    pub(crate) fn derive_me(&mut self, devices: Option<&RosterDoc>, root: Option<NodeId>) {
        let me = Petname(ME.to_owned());
        self.people.remove(&me);
        self.yours = root;
        let Some(devices) = devices else {
            return;
        };
        let mut person = Person::default();
        for member in devices.members() {
            // The list's decode refused any key that is not a usable key, and bifrost runs the same
            // check, so this conversion does not fail; a key that did would not be dialable anyway.
            let Ok(node) = member.node.node_id() else {
                continue;
            };
            person
                .devices
                .insert(member.label.clone(), Binding::new(node));
        }
        if !person.is_empty() {
            self.people.insert(me, person);
        }
    }

    /// Insert a binding under a petname's device. For the store's codec, which reconstructs what was saved.
    pub(crate) fn insert_binding(
        &mut self,
        petname: Petname,
        device: DeviceLabel,
        binding: Binding,
    ) {
        self.people
            .entry(petname)
            .or_default()
            .devices
            .insert(device, binding);
    }

    /// Record (or overwrite) a person's SIGNET root, hand-typed. Idempotent, mirroring [`add`](Self::add):
    /// re-setting the same key is a no-op the caller can report; a different key is a [`Replaced`](Added::Replaced)
    /// the caller can warn on rather than silently clobbering a signet the operator may not mean to lose.
    /// Tests only, as [`add`](Self::add) is.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_signet(&mut self, petname: Petname, node: NodeId) -> Added {
        let person = self.people.entry(petname).or_default();
        let saved = SavedRoot {
            node,
            source: Source::Explicit,
        };
        match person.signet.replace(saved) {
            Some(prev) if prev.node == node => Added::Unchanged,
            Some(prev) => Added::Replaced(prev.node),
            None => Added::Created,
        }
    }

    /// A person's saved root, or `None` if none is on file.
    pub fn signet(&self, petname: &Petname) -> Option<&SavedRoot> {
        self.people
            .get(petname)
            .and_then(|person| person.signet.as_ref())
    }

    /// The root this machine trusts, your own: never a person's here, read with `me`.
    pub fn your_root(&self) -> Option<NodeId> {
        self.yours
    }

    /// The person `root` is saved for, when one is.
    pub fn saved_root(&self, root: NodeId) -> Option<&Petname> {
        self.people
            .iter()
            .find(|(_, person)| {
                person
                    .signet
                    .as_ref()
                    .is_some_and(|saved| saved.node == root)
            })
            .map(|(petname, _)| petname)
    }

    /// The root the machine `<person>/<device>` last presented here, if it was asked.
    pub fn seen_root(&self, person: &Petname, device: &DeviceLabel) -> Option<NodeId> {
        self.people
            .get(person)
            .and_then(|saved| saved.devices.get(device))
            .and_then(|binding| binding.seen_root)
    }

    /// Remember `root` as the one `<person>/<device>` presented, so it is said once: a no-op for a machine
    /// no longer saved.
    pub fn see_root(&mut self, person: &Petname, device: &DeviceLabel, root: NodeId) {
        if let Some(binding) = self
            .people
            .get_mut(person)
            .and_then(|saved| saved.devices.get_mut(device))
        {
            binding.seen_root = Some(root);
        }
    }

    /// Save `root` as `person`'s, learned from their machine `from`: only into an empty slot, and only for a
    /// key no name here holds, so a learned root never replaces a saved one and one key keeps one name.
    pub fn learn(
        &mut self,
        person: &Petname,
        root: NodeId,
        from: DeviceLabel,
    ) -> Result<(), Taken> {
        if let Some(held) = self.signet(person) {
            return Err(Taken::Name { held: held.node });
        }
        if let Some(at) = self.saved_at(&root) {
            return Err(Taken::Key { at });
        }
        self.people.entry(person.clone()).or_default().signet = Some(SavedRoot {
            node: root,
            source: Source::Learned(from),
        });
        Ok(())
    }

    /// Replace `person`'s saved root with `root`, saved explicitly; the root it held is returned. Refuses a
    /// key any name here holds, the person's own old root aside, so one key keeps one name. `None` when the
    /// person has no root saved: there is nothing to replace.
    pub fn replace_root(
        &mut self,
        person: &Petname,
        root: NodeId,
    ) -> Result<Option<NodeId>, Taken> {
        match self.saved_at(&root) {
            Some(at) if at.device.is_some() || at.petname != *person => {
                return Err(Taken::Key { at });
            }
            _ => {}
        }
        let Some(saved) = self
            .people
            .get_mut(person)
            .and_then(|saved| saved.signet.as_mut())
        else {
            return Ok(None);
        };
        let old = saved.node;
        *saved = SavedRoot {
            node: root,
            source: Source::Explicit,
        };
        Ok(Some(old))
    }

    /// Save `node` at `at`, `contact add`'s one write: a person's root when `at` names no machine
    /// (`alice`), else that one machine (`alice/laptop`). It never moves a name or a key: a name that holds
    /// another key refuses ([`Taken::Name`]), since a pasted key must not quietly repoint it and the links
    /// given to the key it holds would drop out of every by-name tool; and a key saved under any other name,
    /// as a root or a machine, refuses ([`Taken::Key`]), so one key has one name on this machine and a
    /// revoke by one name never ends links given by another. Nothing is written on a refusal.
    pub fn save(&mut self, at: &ContactRef, node: NodeId) -> Result<Saved, Taken> {
        let person = self.people.get_mut(&at.petname);
        match (person, &at.device) {
            (Some(person), None) => match &mut person.signet {
                // The same root saved explicitly replaces the learned mark: the person said it is theirs.
                Some(saved) if saved.node == node => {
                    return Ok(
                        match core::mem::replace(&mut saved.source, Source::Explicit) {
                            Source::Explicit => Saved::Unchanged,
                            Source::Learned(_) => Saved::Unlearned,
                        },
                    );
                }
                Some(saved) => return Err(Taken::Name { held: saved.node }),
                None => {}
            },
            (Some(person), Some(device)) => match person.devices.get(device) {
                Some(held) if held.node == node => return Ok(Saved::Unchanged),
                Some(held) => return Err(Taken::Name { held: held.node }),
                None => {}
            },
            (None, _) => {}
        }
        if let Some(at) = self.saved_at(&node) {
            return Err(Taken::Key { at });
        }
        let person = self.people.entry(at.petname.clone()).or_default();
        match &at.device {
            None => {
                person.signet = Some(SavedRoot {
                    node,
                    source: Source::Explicit,
                });
            }
            Some(device) => {
                person.devices.insert(device.clone(), Binding::new(node));
            }
        }
        Ok(Saved::Created)
    }

    /// Where `node` is saved in this book, as a person's root (`alice`) or as one machine (`alice/laptop`),
    /// your own devices under `me` included; `None` when no name holds it.
    pub fn saved_at(&self, node: &NodeId) -> Option<ContactRef> {
        self.people.iter().find_map(|(petname, person)| {
            let device = if person
                .signet
                .as_ref()
                .is_some_and(|root| root.node == *node)
            {
                None
            } else {
                let (label, _) = person
                    .devices
                    .iter()
                    .find(|(_, binding)| binding.node == *node)?;
                Some(label.clone())
            };
            Some(ContactRef {
                petname: petname.clone(),
                device,
            })
        })
    }

    /// Insert a saved root under a petname. For the store codec ONLY, reconstructing a saved signet, as
    /// [`insert_binding`](Self::insert_binding) does for devices.
    pub(crate) fn set_signet_binding(&mut self, petname: Petname, root: SavedRoot) {
        self.people.entry(petname).or_default().signet = Some(root);
    }

    /// Remove a whole petname (all its devices and signet) or, with a device, just that one device. Returns
    /// whether anything was removed. Removing a person's last device removes the now-empty person too, UNLESS
    /// a signet keeps them (a signet-only person is kept), so an empty person never lingers.
    pub fn remove(&mut self, petname: &Petname, device: Option<&DeviceLabel>) -> Removed {
        let Entry::Occupied(mut entry) = self.people.entry(petname.clone()) else {
            return Removed::Absent;
        };
        match device {
            None => {
                entry.remove();
            }
            Some(device) => {
                let person = entry.get_mut();
                if person.devices.remove(device).is_none() {
                    return Removed::Absent;
                }
                // Tidy only a TRULY empty person: removing a person's last DEVICE keeps a signet-only person
                // alive (you may have recorded their signet before any device).
                if person.is_empty() {
                    entry.remove();
                }
            }
        }
        Removed::Removed
    }
}

/// The outcome of an [`add`](Contacts::add): whether it created, replaced, or was a no-op.
#[cfg(any(test, feature = "test-support"))]
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

/// What a [`save`](Contacts::save) did: it never replaces, so a key is either new here or already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Saved {
    /// The key was saved under the name.
    Created,
    /// The name held this key already; nothing changed.
    Unchanged,
    /// The name held this root already, learned from a device; it is now saved explicitly, and the mark
    /// is gone.
    Unlearned,
}

/// Why a [`save`](Contacts::save) refused: the name or the key is taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Taken {
    /// The name holds another key.
    #[error("the name holds another key, {held}")]
    Name {
        /// The key the name holds.
        held: NodeId,
    },
    /// The key is saved under another name.
    #[error("the key is saved as {at}")]
    Key {
        /// Where it is saved: a person for their root, `<person>/<name>` for a machine.
        at: ContactRef,
    },
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
    #[error("{0} is not saved here: swoosh contact add {0}/<name> <key>")]
    UnknownPetname(Petname),
    /// The petname exists but has no device by that label.
    #[error("contact '{petname}' has no device '{device}'; `swoosh status` lists your contacts")]
    UnknownDevice {
        /// The known petname.
        petname: Petname,
        /// The device label that was not found under it.
        device: DeviceLabel,
    },
}

/// One resolved peer to try: the identity to dial and the label to print for it.
///
/// A caller acts on the [`node`](Self::node) and reports the [`label`](Self::label) (`alice/macbook`),
/// so a person's devices are named each rather than by a bare key. Carried through resolution because the label is lost once a `ContactRef` becomes a `NodeId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The peer's identity, dialed verbatim.
    pub node: NodeId,
    /// How to name this candidate in output: `alice/macbook`, or a raw key's short form.
    pub label: String,
}

#[cfg(test)]
#[path = "contacts_tests.rs"]
mod contacts_tests;
