//! Persistence for the [`Contacts`] address book: load from and save to a TOML file.
//!
//! The store is the boundary between the pure domain [`Contacts`] and the on-disk TOML. It maps between
//! the two explicitly: the wire form is a plain `petname -> { device -> key-string }` table (a [`NodeId`]
//! renders as its base32 string, which is exactly what a human sees and pastes), and the domain form is
//! the strictly-typed [`Contacts`]. Neither the domain types nor [`NodeId`] carry serde derives, so the
//! wire representation lives here and only here, converted at load and save.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use bifrost::NodeIdParseError;

use super::{Binding, Contacts, DeviceLabel, Petname, RosterVersion, Source};
use crate::home::Home;
use crate::names::NameError;
use crate::roster::{Epoch, FoldError, RosterLock};

/// A contacts file at a known path, loaded into a mutable [`Contacts`] and saved back atomically.
///
/// Own the path once, then [`save`](Self::save) after each mutation. The store creates the parent config
/// dir on first save, mirroring how the identity key is provisioned lazily beside it. A writer holds
/// `<home>/roster.lock` from the read to the save: [`open_to_edit`](Self::open_to_edit) takes it, and a
/// fold or a join already holds it when it opens the book.
#[derive(Debug)]
pub struct ContactsStore {
    path: PathBuf,
    contacts: Contacts,
    /// `<home>/roster.lock`, held until this store drops, when [`open_to_edit`](Self::open_to_edit) opened
    /// it.
    _lock: Option<RosterLock>,
}

impl ContactsStore {
    /// Open the store at `path`, loading existing contacts or starting empty if the file is absent.
    ///
    /// A missing file is the first-run case, not an error: an empty address book. A present-but-corrupt
    /// file IS an error, surfaced rather than silently discarding what the user saved.
    ///
    /// It takes no lock: a reader, or a writer that already holds `<home>/roster.lock`, opens this way.
    pub async fn open(path: PathBuf) -> Result<Self, StoreError> {
        let contacts = match tokio::fs::read_to_string(&path).await {
            Ok(text) => decode(&text)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Contacts::default(),
            Err(error) => return Err(StoreError::Read(error)),
        };
        Ok(Self {
            path,
            contacts,
            _lock: None,
        })
    }

    /// Open `home`'s book to change it: take `<home>/roster.lock`, then read the book under it.
    ///
    /// The lock is held until the store drops, so the read, the change and the [`save`](Self::save) are
    /// one write that no fold and no other editor interleaves with, and none of them loses an update.
    pub async fn open_to_edit(home: &Home) -> Result<Self, StoreError> {
        crate::config::create_store_dir(home.dir())
            .map_err(|error| StoreError::Write(error.into()))?;
        // Only the io error goes on: a lock that cannot be taken reads like any other failed write of the
        // book, and the lock's path inside the home stays out of the line.
        let lock = RosterLock::take(&home.roster_lock())
            .await
            .map_err(|error| match error {
                FoldError::Io { source, .. } => StoreError::Write(source.into()),
                other => StoreError::Write(other.into()),
            })?;
        let Self { path, contacts, .. } = Self::open(home.contacts()).await?;
        Ok(Self {
            path,
            contacts,
            _lock: Some(lock),
        })
    }

    /// The loaded address book, to read.
    pub fn contacts(&self) -> &Contacts {
        &self.contacts
    }

    /// The loaded address book, to mutate. Persist with [`save`](Self::save) afterward.
    pub fn contacts_mut(&mut self) -> &mut Contacts {
        &mut self.contacts
    }

    /// Write the current contacts back to disk, creating the config dir on first save.
    ///
    /// Writes through [`config::write_private_atomic`](crate::config::write_private_atomic): a temp unique
    /// to this write, owner-only (`0600`) and synced, renamed over the target. A crash mid-write never
    /// leaves a half-written book, and two writes never share a temp.
    pub async fn save(&self) -> Result<(), StoreError> {
        let text = encode(&self.contacts)?;
        crate::config::write_private_atomic(&self.path, text.as_bytes())
            .await
            .map_err(StoreError::Write)
    }
}

/// The reserved top-level key carrying the roster epoch FLOOR: an integer beside the petname tables. A
/// petname's value is a table and this is an integer, so decode dispatches on the key before parsing it as
/// a petname; the two never collide, and an old file with no such key loads a `None` floor (backward
/// compatible). It is a reserved slot for the operator's own fleet floor, the same way `me` is reserved for
/// the fleet itself.
const ROSTER_EPOCH_KEY: &str = "roster_epoch";

/// The reserved top-level key carrying this book's OWN membership version: the number a roster cut here
/// is stamped with, beside (and never confused with) the [`ROSTER_EPOCH_KEY`] floor. Two keys because
/// they are two numbers with two owners; one key doing both jobs is the defect that pinned every fleet
/// at epoch 0. Absent, or the reserved `0`, means unversioned, so a file written before this key existed
/// loads correctly and the operator's next membership edit writes `1`.
const ROSTER_VERSION_KEY: &str = "roster_version";

/// The per-person key carrying that person's SIGNET root. A person table's other keys are device labels;
/// [`decode`] dispatches on this key FIRST (like [`ROSTER_EPOCH_KEY`] at the top level) and [`encode`]
/// writes it FIRST. The value reuses the device wire form: a bare string is a hand-typed signet, an inline
/// `{ key, roster }` table is a (future) roster-vouched signet, so [`decode_binding`]/[`encode_binding`]
/// handle both. The `_` puts it outside the name rule, so no device label can ever collide with it.
const SIGNET_KEY: &str = "signet_root";

/// The on-disk shape: a top-level table whose keys are petnames (each mapping to a device table) plus the
/// one reserved [`ROSTER_EPOCH_KEY`] integer. A separate wire type so no serde derive touches the domain,
/// and the string keys/values are exactly what a human reads and edits. A device value is either the legacy
/// bare key string (a hand-typed binding) or an inline table `{ key = "...", roster = <epoch> }` for a
/// member the signet vouched for. Modeled as a generic [`toml::Value`] so every shape round-trips through
/// one document and files written before provenance or the floor existed still load.
type Wire = BTreeMap<String, toml::Value>;

/// Parse a contacts TOML document into the strictly-typed domain, validating every name, key, and entry.
fn decode(text: &str) -> Result<Contacts, StoreError> {
    let wire: Wire = toml::from_str(text).map_err(StoreError::Parse)?;
    let mut contacts = Contacts::default();
    for (key, value) in wire {
        // The two reserved counter keys are integers, not petname tables; dispatch on them first so
        // neither reaches the petname parser and no group table can masquerade as one.
        if key == ROSTER_EPOCH_KEY {
            let floor = value.as_integer().ok_or(StoreError::BadEntry)?;
            contacts.set_roster_floor(Some(Epoch(
                u64::try_from(floor).map_err(|_| StoreError::BadEntry)?,
            )));
            continue;
        }
        if key == ROSTER_VERSION_KEY {
            let version = value.as_integer().ok_or(StoreError::BadEntry)?;
            contacts.set_roster_version(RosterVersion::from_stored(
                u64::try_from(version).map_err(|_| StoreError::BadEntry)?,
            ));
            continue;
        }
        let petname = Petname::stored(&key)?;
        let group = value.as_table().ok_or(StoreError::BadEntry)?;
        for (label, value) in group {
            // The reserved signet key holds the person's signet root, not a device; dispatch on it first so
            // it never reaches the device parser (which would refuse it: `_` is outside the name rule).
            if label == SIGNET_KEY {
                contacts.set_signet_binding(petname.clone(), decode_binding(value)?);
                continue;
            }
            let device = DeviceLabel::stored(label)?;
            contacts.insert_binding(petname.clone(), device, decode_binding(value)?);
        }
    }
    Ok(contacts)
}

/// Parse one device's wire value into a [`Binding`]: a bare string is a hand-typed key, an inline table is
/// a roster-hydrated member.
fn decode_binding(value: &toml::Value) -> Result<Binding, StoreError> {
    match value {
        toml::Value::String(key) => Ok(Binding {
            node: key.parse()?,
            source: Source::HandTyped,
        }),
        toml::Value::Table(table) => {
            let key = table
                .get("key")
                .and_then(toml::Value::as_str)
                .ok_or(StoreError::BadEntry)?;
            let epoch = table
                .get("roster")
                .and_then(toml::Value::as_integer)
                .ok_or(StoreError::BadEntry)?;
            Ok(Binding {
                node: key.parse()?,
                source: Source::Roster {
                    epoch: u64::try_from(epoch).map_err(|_| StoreError::BadEntry)?,
                },
            })
        }
        _ => Err(StoreError::BadEntry),
    }
}

/// Render the domain address book as a contacts TOML document.
fn encode(contacts: &Contacts) -> Result<String, StoreError> {
    let mut wire = Wire::new();
    for petname in contacts.petnames() {
        // `petnames` yields only present names, so `bindings` is always `Some` here; skip defensively
        // rather than unwrap, since a future change to either method must not turn into a panic.
        let Some(bindings) = contacts.bindings(petname) else {
            continue;
        };
        let mut group: toml::value::Table = bindings
            .map(|(label, binding)| (label.as_str().to_owned(), encode_binding(binding)))
            .collect();
        // The signet persists under the reserved key inside the person's OWN table, so alice's whole record
        // (devices + signet) stays one `[alice]` block; a person with a signet but no devices still writes a
        // block, so a signet-only contact round-trips. The key can never collide with a device label (it is
        // not a name), so this insert never clobbers one.
        if let Some(binding) = contacts.signet(petname) {
            group.insert(SIGNET_KEY.to_owned(), encode_binding(binding));
        }
        // Skip a person with neither devices nor a signet: an empty table is nothing to persist. (`petnames`
        // yields only non-empty people today, but a future signet-only-then-cleared path must not write one.)
        if group.is_empty() {
            continue;
        }
        wire.insert(petname.as_str().to_owned(), toml::Value::Table(group));
    }
    // Persist the roster epoch floor so the anti-rollback high-water mark survives a restart; absent until
    // the first roster is hydrated, so a book with no fleet writes no such key.
    if let Some(floor) = contacts.roster_floor() {
        wire.insert(
            ROSTER_EPOCH_KEY.to_owned(),
            toml::Value::Integer(i64::try_from(floor.0).unwrap_or(i64::MAX)),
        );
    }
    // Persist this book's own membership version so a restart does not re-cut the fleet at a version
    // pullers have already applied. Absent until the first membership edit, exactly like the floor.
    if let Some(version) = contacts.roster_version().stored() {
        wire.insert(
            ROSTER_VERSION_KEY.to_owned(),
            toml::Value::Integer(i64::try_from(version).unwrap_or(i64::MAX)),
        );
    }
    toml::to_string_pretty(&wire).map_err(StoreError::Encode)
}

/// Render one binding to its wire value. A hand-typed binding stays a BARE key string (the legacy form, so
/// a file untouched by roster-sync reads and writes byte-for-byte as before); a roster-hydrated member
/// becomes `{ key = "...", roster = <epoch> }`, carrying the provenance the moat depends on.
fn encode_binding(binding: &Binding) -> toml::Value {
    match binding.source {
        Source::HandTyped => toml::Value::String(binding.node.to_string()),
        Source::Roster { epoch } => {
            let mut table = toml::value::Table::new();
            table.insert(
                "key".to_owned(),
                toml::Value::String(binding.node.to_string()),
            );
            table.insert(
                "roster".to_owned(),
                toml::Value::Integer(i64::try_from(epoch).unwrap_or(i64::MAX)),
            );
            toml::Value::Table(table)
        }
    }
}

/// Why the contacts store could not be loaded or saved.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// `HOME` was unset, so the default contacts path could not be built.
    #[error("HOME is not set; cannot locate the contacts file")]
    NoHome,
    /// The contacts file could not be read.
    #[error("reading the contacts file")]
    Read(#[source] io::Error),
    /// The contacts file could not be written.
    #[error("writing the contacts file")]
    Write(#[source] eyre::Report),
    /// The contacts file was not valid TOML.
    #[error("the contacts file is not valid TOML")]
    Parse(#[source] toml::de::Error),
    /// The contacts could not be serialized to TOML.
    #[error("encoding the contacts file")]
    Encode(#[source] toml::ser::Error),
    /// A stored petname or device label was not a name.
    #[error("the contacts file holds an invalid name")]
    Name(#[from] NameError),
    /// A stored identity string was not a valid node id. A plain `#[from]`: the bifrost umbrella
    /// re-exports the concrete [`NodeIdParseError`], so the source chain is preserved with no projection
    /// or manual `map_err`.
    #[error("the contacts file holds an invalid node id")]
    NodeId(#[from] NodeIdParseError),
    /// A device entry was neither a bare key string nor a well-formed `{ key, roster }` table.
    #[error("the contacts file holds a malformed contact entry")]
    BadEntry,
}
