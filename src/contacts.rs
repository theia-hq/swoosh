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
//! The store persists in the node home as `<home>/contacts.toml` (the same directory the identity key
//! and the trust files live in, [`Home::contacts`](crate::home::Home::contacts)), a plain TOML table of
//! `petname -> { device -> node id }`. It is LOCAL STATE, not a wire or registry format, so a
//! human-editable TOML file is the right representation.

use core::num::NonZeroU64;
use core::str::FromStr;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use bifrost::NodeId;
use tightbeam::identity::AsNodeId as _;

use crate::names::{Name, NameError};
use crate::roster::{Epoch, RosterDoc};

/// The reserved petname for the operator's own devices: the signet is person-zero, each device it derives
/// lives under `me/<label>`. A signet-verified roster hydrates into exactly this partition.
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
/// so the codec's `u16` length prefix stays total. A bare `contact add alice <key>` (no `/device`) uses the
/// [`DEFAULT`](Self::DEFAULT) slot, so a person addressed without a device still resolves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceLabel(String);

impl DeviceLabel {
    /// The slot a device-less `contact add alice <key>` occupies. Sorts before named devices, so an
    /// unqualified person resolves to their default device first.
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

/// Where a contact binding came from: a name YOU typed, or a member the signet vouched for in a signed
/// roster. This distinction is the moat: a roster-hydrated member stays distinguishable from a hand-typed
/// peer at read time, so flattening the two can never silently launder a stranger into a signed member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A binding the operator added by hand (`contact add`, `invite add`), or loaded from the legacy bare-string
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

/// One person in the address book: their device bindings plus, optionally, their SIGNET root.
///
/// A signet is the key a person's fleet roots at (the root that vouches for their devices); it is NOT a
/// device, so it lives in its own at-most-one slot, never in `devices`. Keeping it out of `devices` keeps
/// it out of reach fan-out ([`resolve_candidates`](Contacts::resolve_candidates)) and out of `contact ls`'s
/// device columns: you never dial a signet, you BIND a fleet grant to it (`grant issue --for fleet:<petname>`).
/// Modeling it as a distinct `Option` makes "a person has zero-or-one signet" the only representable shape.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Person {
    /// This person's device identities, label -> binding, in label order (unchanged from the old value type).
    devices: BTreeMap<DeviceLabel, Binding>,
    /// This person's signet root, if recorded. `None` until hand-added (v1) or federation-hydrated (later).
    /// Reuses [`Binding`] so the signet carries the SAME [`Source`] provenance the moat depends on: a
    /// hand-typed signet is [`Source::HandTyped`]; a future synced roster could vouch one as
    /// [`Source::Roster`].
    signet: Option<Binding>,
}

impl Person {
    /// A person with no devices AND no signet: nothing left to keep. Used by `remove`/`hydrate` tidy-up so a
    /// signet-only person (you recorded alice's signet before any device) is NOT swept away, but a truly
    /// empty person still is.
    fn is_empty(&self) -> bool {
        self.devices.is_empty() && self.signet.is_none()
    }
}

/// The version of the operator's OWN `me/*` membership set: the CUTTER's number, bumped by this book
/// every time that set actually changes.
///
/// It is NOT the anti-rollback floor. Those are two different numbers with two different owners (a
/// cutter's "how many times my fleet has changed" and a puller's "highest epoch I have applied"), and
/// collapsing them into one field is what made a signet holder cut epoch 0 forever: the floor only ever
/// advanced by PULLING, and a signet holder never pulls. Separate types, separate fields, so the
/// confusion is unrepresentable rather than merely fixed.
///
/// [`Unversioned`](Self::Unversioned) is the reserved zero: a book that has made no membership edit since
/// versioning existed. It has nothing a puller may accept, so [`epoch`](Self::epoch) yields `None` and
/// there is nothing to cut. A [`NonZeroU64`] inside [`Versioned`](Self::Versioned) is what makes
/// "version 0" unrepresentable rather than merely avoided.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RosterVersion {
    /// No membership edit has been recorded under this book yet. Persists as the absent key (and loads
    /// from the reserved on-disk `0`), so every fleet already in the field reads as unversioned and the
    /// operator's next edit lifts it to 1, which is newer than every floor out there.
    #[default]
    Unversioned,
    /// The nth change to the `me/*` member set, counting from 1.
    Versioned(NonZeroU64),
}

impl RosterVersion {
    /// The version after one change to the member set. Total by construction: unversioned becomes 1 (the
    /// migration rule, so a pre-upgrade fleet unsticks itself on the owner's next edit), and a versioned
    /// book counts on. Saturating because u64 membership edits cannot be performed in any lifetime, and a
    /// wrap would silently hand a puller a version below its floor.
    pub fn bumped(self) -> Self {
        match self {
            Self::Unversioned => Self::Versioned(NonZeroU64::MIN),
            Self::Versioned(count) => Self::Versioned(count.saturating_add(1)),
        }
    }

    /// The epoch a cut doc carries at this version, or `None` when there is nothing to cut. This is the
    /// ONLY way an [`Epoch`] is derived from a local version, so a cutter cannot reach for the floor by
    /// mistake, and an unversioned book cannot emit the reserved 0 that [`hydrate`](Contacts::hydrate)
    /// refuses.
    pub fn epoch(self) -> Option<Epoch> {
        match self {
            Self::Unversioned => None,
            Self::Versioned(count) => Some(Epoch(count.get())),
        }
    }

    /// Reconstruct from the persisted integer. `0` is the reserved unversioned slot, so an old file (and
    /// an absent key) both load as [`Unversioned`](Self::Unversioned) with no migration step.
    pub(crate) fn from_stored(value: u64) -> Self {
        match NonZeroU64::new(value) {
            None => Self::Unversioned,
            Some(count) => Self::Versioned(count),
        }
    }

    /// The integer to persist, or `None` when there is nothing to write (an unversioned book writes no
    /// key at all, exactly as a book with no floor writes no floor).
    pub(crate) fn stored(self) -> Option<u64> {
        match self {
            Self::Unversioned => None,
            Self::Versioned(count) => Some(count.get()),
        }
    }
}

/// The in-memory address book: every petname mapped to its ordered group of device bindings, plus the two
/// roster counters (this book's own membership version, and the epoch floor it has accepted from its
/// signet).
///
/// This is the pure domain view the store loads into and saves back from. It owns the add / list /
/// remove / resolve / cut / hydrate behaviour; persistence is the [`ContactsStore`]'s job, layered around
/// it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Contacts {
    people: BTreeMap<Petname, Person>,
    /// This book's OWN membership version: the number a roster cut here is stamped with. Bumped by
    /// [`add`](Self::add) and [`remove`](Self::remove) when, and only when, the `me/*` device SET changes,
    /// so re-recording a device at the same key (a badge renewal) leaves it alone.
    roster_version: RosterVersion,
    /// The highest roster epoch this book has applied: the anti-rollback FLOOR. `None` before any roster is
    /// hydrated. A snapshot at or below it is refused as stale, so a replayed old-but-genuine roster can
    /// never roll the fleet back. There is one signet today, so one floor; a device in two fleets is out of
    /// scope until the floor is keyed per-signet.
    ///
    /// Written ONLY by [`hydrate`](Self::hydrate) (and the store, reloading it). Never read by the cut
    /// path: it is `pub(crate)`, so nothing outside this crate can mistake the floor for the version.
    roster_floor: Option<Epoch>,
}

impl Contacts {
    /// Add or update the identity for a petname's device, returning whether an existing binding was
    /// replaced. Idempotent: re-adding the same name and device just overwrites, so the caller can warn
    /// on a clobber rather than the store silently losing the old key. A device-less add targets the
    /// [`DEFAULT`](DeviceLabel::DEFAULT) slot.
    ///
    /// An add under `me` that CHANGES the member set bumps [`roster_version`](Self::roster_version); an
    /// [`Unchanged`](Added::Unchanged) one does not. A badge RENEWAL re-runs `invite add` with the same
    /// label and the same key, leaving the member set byte-identical, so bumping there would weld
    /// quarterly credential churn to the rare membership version and drive every device through a
    /// full-snapshot re-pull for no delta.
    pub fn add(&mut self, petname: Petname, device: Option<DeviceLabel>, node: NodeId) -> Added {
        let device = device.unwrap_or(DeviceLabel(DeviceLabel::DEFAULT.to_owned()));
        let mine = petname.as_str() == ME;
        let person = self.people.entry(petname).or_default();
        let binding = Binding {
            node,
            source: Source::HandTyped,
        };
        let added = match person.devices.insert(device, binding) {
            Some(previous) if previous.node == node => Added::Unchanged,
            Some(previous) => Added::Replaced(previous.node),
            None => Added::Created,
        };
        // Anchored to this book's OWN answer about whether the set changed, never to the verb that ran:
        // `invite add` enrolling and `invite add` renewing differ by the data, not by the call site.
        if mine && added != Added::Unchanged {
            self.roster_version = self.roster_version.bumped();
        }
        added
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
        self.people.get(petname).map(|person| {
            person
                .devices
                .iter()
                .map(|(label, binding)| (label, &binding.node))
        })
    }

    /// Every device binding under a petname WITH its provenance, in label order, for the store's codec and
    /// for a `contact ls` that wants to show which entries the signet vouched for. `None` for an unknown
    /// petname. Unlike [`devices`](Self::devices) (which projects to the node for reach), this carries the
    /// [`Source`] so a roster-hydrated member round-trips through persistence.
    pub fn bindings(
        &self,
        petname: &Petname,
    ) -> Option<impl Iterator<Item = (&DeviceLabel, &Binding)>> {
        self.people.get(petname).map(|person| person.devices.iter())
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

    /// This book's OWN membership version, the number a roster cut from it is stamped with. See
    /// [`RosterVersion`]: it is not the floor, and a caller that wants "how fresh is what I pulled"
    /// wants the floor instead.
    pub fn roster_version(&self) -> RosterVersion {
        self.roster_version
    }

    /// This book's roster epoch floor: the highest roster epoch it has applied, or `None` before any roster
    /// is hydrated. The store persists and reloads it so the anti-rollback floor survives a restart.
    ///
    /// `pub(crate)` deliberately. The floor is the PULLER's number; a cutter reading it was the whole
    /// defect, so no code outside this crate can obtain it and stamp a doc with it.
    pub(crate) fn roster_floor(&self) -> Option<Epoch> {
        self.roster_floor
    }

    /// Fold a signet-verified roster into the `me` partition (the operator's own fleet) as a FLOORED
    /// SNAPSHOT-REPLACE, tagging each member [`Source::Roster`]. THIS is the moat's write path, and it is
    /// safe by construction: the only way to obtain a [`RosterDoc`] is [`crate::roster::verify`], so a
    /// `Roster` provenance can only ever come from the signet, never from a hand-typed op.
    ///
    /// A roster is a whole SNAPSHOT, not an op-log, so the correct fold is a REPLACE under a persisted
    /// floor. The returned [`Hydrated`] says which happened, and it is the caller's only honest basis for
    /// claiming a pull:
    ///
    /// - [`Epoch`] `0` is REFUSED as [`Unversioned`](Hydrated::Unversioned). Zero is the reserved
    ///   pre-versioning stamp, so such a doc is not "not newer", it is "not versioned"; those are
    ///   different conditions and they owe different messages.
    /// - `doc.epoch <= floor` (a stale or same-epoch replay from a lagging/hostile courier) is REFUSED
    ///   wholesale as [`NotNewer`](Hydrated::NotNewer), a no-op, so a genuinely-signed OLD roster can never
    ///   roll the fleet back or re-add a removed member. The first hydrate (floor `None`) applies.
    /// - `doc.epoch > floor`: the roster-sourced `me/*` set is REPLACED by the doc's members (add new,
    ///   refresh changed, and DROP any prior `Roster`-sourced device NOT in the new doc so a removed member
    ///   disappears), then the floor advances to `doc.epoch`. The [`Applied`] report names what was bound,
    ///   what a sovereign local binding held back, and exactly which devices the replace REMOVED, because
    ///   a thinner snapshot silently deleting devices under the word "pulled" is a lie the caller cannot
    ///   otherwise avoid telling.
    ///
    /// A `HandTyped` binding under `me` is NEVER touched (the operator's local choice is sovereign, and a
    /// member is only a suggestion); only `Roster`-sourced entries are in the replace-set. Only the `me`
    /// partition is touched: other petnames (people you know) are never rewritten by your own fleet roster.
    ///
    /// This advances the FLOOR and never the [`RosterVersion`]: applying someone else's snapshot is not an
    /// edit to a membership set this book owns, and one node's fleet has exactly one cutter.
    pub fn hydrate(&mut self, roster: &RosterDoc) -> Hydrated {
        let epoch = roster.epoch();
        // Zero is reserved, so refuse it before the floor comparison even runs: a fresh book has NO floor,
        // and "the first hydrate always applies" would otherwise let a pre-versioning doc in and pin the
        // floor at 0, which is the state every device in the field is already stuck in.
        if epoch == Epoch::UNVERSIONED {
            return Hydrated::Unversioned;
        }
        // Refuse a stale or same-epoch snapshot before touching anything: the whole-doc floor is what kills
        // F1's removed-member re-add (the old blob never applies at all) and the same-epoch overwrite.
        if let Some(floor) = self.roster_floor
            && epoch <= floor
        {
            return Hydrated::NotNewer { floor };
        }
        let applied = self.rebuild_me(roster);
        self.roster_floor = Some(epoch);
        Hydrated::Applied(applied)
    }

    /// Replace the roster-sourced devices under `me` with the live devices of a verified update, keeping
    /// every hand-typed binding. The caller has already decided the update is newer: a fold holds the
    /// floor in the update it keeps, not here.
    pub fn rebuild_me(&mut self, roster: &RosterDoc) -> Applied {
        let epoch = roster.epoch();
        let person = self.people.entry(Petname(ME.to_owned())).or_default();
        // Snapshot-REPLACE the DEVICE set only; the fence: hydrate never touches `person.signet` (a roster
        // carries no signet in v1), so a hand-typed `me` signet survives every pull. Drop the prior
        // roster-sourced devices, keep every HandTyped binding, then lay the new doc's members down.
        // Dropping first is what makes a removed member disappear; a hand-typed entry never enters the
        // drop-set, so the operator's local choice survives. The dropped labels are COLLECTED, not just
        // discarded: they are the destructive half of the fold and the caller has to be able to name them.
        let mut dropped: Vec<DeviceLabel> = Vec::new();
        person.devices.retain(|label, binding| {
            let keep = binding.source == Source::HandTyped;
            if !keep {
                dropped.push(label.clone());
            }
            keep
        });
        let mut applied = Applied {
            bound: 0,
            skipped: 0,
            removed: Vec::new(),
        };
        for member in roster.members() {
            // The label is already a `DeviceLabel` (one label type across the seam), so there is no lossy
            // re-parse here. A HandTyped binding is sovereign and was kept by `retain`; never clobber it.
            if let Entry::Occupied(entry) = person.devices.entry(member.label.clone())
                && entry.get().source == Source::HandTyped
            {
                applied.skipped += 1;
                continue;
            }
            // The update's decode refused any key that is not a usable key, and bifrost runs the same
            // check, so this conversion does not fail; a key that did would not be dialable anyway.
            let Ok(node) = member.node.node_id() else {
                continue;
            };
            person.devices.insert(
                member.label.clone(),
                Binding {
                    node,
                    source: Source::Roster { epoch: epoch.0 },
                },
            );
            applied.bound += 1;
        }
        // A dropped label the new snapshot laid back down was refreshed, not removed; only the ones the
        // doc no longer carries are true removals.
        applied.removed = dropped
            .into_iter()
            .filter(|label| !person.devices.contains_key(label))
            .collect();
        // An empty `me` person (a roster of only skipped members over no hand-typed device AND no signet)
        // should not linger; mirror `remove`'s tidy-up. A `me` that kept a hand-typed signet is NOT empty,
        // so it survives a device-only pull.
        if self
            .people
            .get(&Petname(ME.to_owned()))
            .is_some_and(Person::is_empty)
        {
            self.people.remove(&Petname(ME.to_owned()));
        }
        applied
    }

    /// Set the persisted roster epoch floor when the store reconstructs a book from disk. For the store's
    /// codec ONLY: the floor was established by a prior [`hydrate`], and reload just round-trips it, so a
    /// restart does not reset the anti-rollback high-water mark to zero.
    pub(crate) fn set_roster_floor(&mut self, floor: Option<Epoch>) {
        self.roster_floor = floor;
    }

    /// Set this book's membership version when the store reconstructs it from disk. For the store's codec
    /// ONLY: the version was established by a prior membership edit, and reload just round-trips it, so a
    /// restart does not re-cut the fleet at a version pullers have already applied.
    pub(crate) fn set_roster_version(&mut self, version: RosterVersion) {
        self.roster_version = version;
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
            .devices
            .insert(device, binding);
    }

    /// Record (or overwrite) a person's SIGNET root, hand-typed. Idempotent, mirroring [`add`](Self::add):
    /// re-setting the same key is a no-op the caller can report; a different key is a [`Replaced`](Added::Replaced)
    /// the caller can warn on rather than silently clobbering a signet the operator may not mean to lose.
    /// Always [`Source::HandTyped`] in v1 (federation-synced signets arrive via a future `hydrate`, never
    /// this path).
    pub fn set_signet(&mut self, petname: Petname, node: NodeId) -> Added {
        let person = self.people.entry(petname).or_default();
        let binding = Binding {
            node,
            source: Source::HandTyped,
        };
        match person.signet.replace(binding) {
            Some(prev) if prev.node == node => Added::Unchanged,
            Some(prev) => Added::Replaced(prev.node),
            None => Added::Created,
        }
    }

    /// A person's recorded signet binding (node + provenance), or `None` if none is on file. The resolver
    /// reads `.node`; `contact ls` reads `.source` to mark a hand-typed vs vouched signet.
    pub fn signet(&self, petname: &Petname) -> Option<&Binding> {
        self.people
            .get(petname)
            .and_then(|person| person.signet.as_ref())
    }

    /// Insert a fully-formed signet binding (node + provenance) under a petname. For the store codec ONLY,
    /// reconstructing a persisted signet INCLUDING a future `Roster` provenance, exactly as
    /// [`insert_binding`](Self::insert_binding) does for devices.
    pub(crate) fn set_signet_binding(&mut self, petname: Petname, binding: Binding) {
        self.people.entry(petname).or_default().signet = Some(binding);
    }

    /// Remove a whole petname (all its devices and signet) or, with a device, just that one device. Returns
    /// whether anything was removed. Removing a person's last device removes the now-empty person too, UNLESS
    /// a signet keeps them (a signet-only person is kept), so an empty person never lingers.
    ///
    /// A removal that takes at least one DEVICE out of `me` bumps
    /// [`roster_version`](Self::roster_version), on the same rule [`add`](Self::add) follows: the member
    /// set changed. Dropping a signet-only `me` changes no member, so it does not bump.
    pub fn remove(&mut self, petname: &Petname, device: Option<&DeviceLabel>) -> Removed {
        let mine = petname.as_str() == ME;
        let Entry::Occupied(mut entry) = self.people.entry(petname.clone()) else {
            return Removed::Absent;
        };
        let (removed, lost_a_device) = match device {
            None => {
                let had_devices = !entry.get().devices.is_empty();
                entry.remove();
                (Removed::Removed, had_devices)
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
                (Removed::Removed, true)
            }
        };
        if mine && lost_a_device {
            self.roster_version = self.roster_version.bumped();
        }
        removed
    }
}

/// The outcome of a [`hydrate`](Contacts::hydrate): the snapshot was folded in, or refused and why.
///
/// A typed outcome rather than a bool because the two refusals mean different things to an operator (an
/// unversioned cutter needs an upgrade on the OTHER machine; a not-newer doc means there is simply nothing
/// new) and because an applied fold is not news until it says what it changed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Hydrated {
    /// The snapshot was applied and the floor advanced; the report names what changed.
    Applied(Applied),
    /// The doc was stamped the reserved [`Epoch::UNVERSIONED`], so it came from a cutter that predates
    /// membership versioning. Nothing can fix that from this side: the fleet's owner has to upgrade and
    /// make one membership edit.
    Unversioned,
    /// The doc was not newer than this book's floor, so it was refused wholesale as a replay.
    NotNewer {
        /// The highest epoch this book has already applied.
        floor: Epoch,
    },
}

/// What an applied [`hydrate`](Contacts::hydrate) actually did to the `me/*` partition.
///
/// The doc's member COUNT is not this, and reporting it as if it were is how a pull that bound nothing
/// (or deleted devices) still read as a success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    bound: usize,
    skipped: usize,
    removed: Vec<DeviceLabel>,
}

impl Applied {
    /// How many of the doc's members are now bound under `me/*`.
    pub fn bound(&self) -> usize {
        self.bound
    }

    /// How many of the doc's members were passed over because a sovereign `HandTyped` binding already
    /// held that label. They were NOT pulled in, and counting them as pulled is the lie.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// The devices this snapshot REMOVED: roster-sourced labels the new doc no longer carries. A
    /// snapshot-replace is destructive by design (it is what makes a removed member disappear), so the
    /// caller must be able to name what went.
    pub fn removed(&self) -> &[DeviceLabel] {
        &self.removed
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

#[cfg(test)]
#[path = "contacts_tests.rs"]
mod contacts_tests;
