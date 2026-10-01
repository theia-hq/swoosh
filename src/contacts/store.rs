//! Persistence for the [`Contacts`] address book: load from and save to a TOML file.
//!
//! The store is the boundary between the pure domain [`Contacts`] and the on-disk TOML. It maps between
//! the two explicitly: the wire form is a plain `petname -> { device -> key-string }` table (a [`NodeId`]
//! renders as its base32 string, which is exactly what a human sees and pastes), and the domain form is
//! the strictly-typed [`Contacts`]. Neither the domain types nor [`NodeId`] carry serde derives, so the
//! wire representation lives here and only here, converted at load and save.
//!
//! Your own devices, `me`, are not in the file: each open derives them from `<home>/devices`, verified
//! under `<home>/root.pub`, and a save writes everything but them.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use bifrost::NodeIdParseError;
use tightbeam::identity::AsVerifyKey as _;

use super::{Binding, Contacts, DeviceLabel, ME, Petname};
use crate::home::{Home, HomeWrite};
use crate::names::NameError;

/// A contacts file at a known path, loaded into a mutable [`Contacts`] and saved back atomically.
///
/// Own the path once, then [`save`](Self::save) after each mutation. The store creates the parent config
/// dir on first save, mirroring how the identity key is provisioned lazily beside it. A writer holds
/// `home.lock` from the read to the save, so the read, the change and the save are one write that no fold
/// and no other editor interleaves with, and none of them loses an update.
#[derive(Debug)]
pub struct ContactsStore {
    path: PathBuf,
    contacts: Contacts,
}

impl ContactsStore {
    /// Open `home`'s book, loading `<home>/contacts.toml` or starting empty if the file is absent, with `me`
    /// derived from the list of your devices the home holds.
    ///
    /// A missing file is the first-run case, not an error: an empty address book. A present-but-corrupt
    /// file IS an error, surfaced rather than silently discarding what the user saved. A list of devices
    /// that is missing, or that does not verify under the pin, leaves `me` empty.
    ///
    /// It takes no lock: a writer takes `home.lock` before it opens the book, and holds it to the save.
    pub async fn open(home: &Home) -> Result<Self, StoreError> {
        let path = home.contacts();
        let mut contacts = match crate::home::read_trust_file_async(&path).await {
            Ok(text) => decode(&text)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Contacts::default(),
            Err(error) => return Err(StoreError::Read(error)),
        };
        let devices = match crate::config::load_signet(home).await {
            Ok(Some(pin)) => pin
                .verify_key()
                .ok()
                .and_then(|pin| crate::roster::held(home, pin)),
            Ok(None) | Err(_) => None,
        };
        contacts.derive_me(devices.as_ref());
        Ok(Self { path, contacts })
    }

    /// The loaded address book, to read.
    pub fn contacts(&self) -> &Contacts {
        &self.contacts
    }

    /// The loaded address book, to mutate. Persist with [`save`](Self::save) afterward.
    pub fn contacts_mut(&mut self) -> &mut Contacts {
        &mut self.contacts
    }

    /// Write the current contacts back to disk under `home.lock`, which the caller took before it opened
    /// the book, creating the config dir on first save.
    ///
    /// Writes through [`config::write_private_atomic`](crate::config::write_private_atomic): a temp unique
    /// to this write, owner-only (`0600`) and synced, renamed over the target. A crash mid-write never
    /// leaves a half-written book, and two writes never share a temp.
    ///
    /// # Errors
    ///
    /// The book could not be encoded or written.
    pub fn save(&self, home_lock: &HomeWrite) -> Result<(), StoreError> {
        let text = encode(&self.contacts)?;
        crate::config::write_private_atomic(home_lock, &self.path, text.as_bytes())
            .map_err(|error| StoreError::Write(error.into()))
    }
}

/// The per-person key carrying that person's SIGNET root. A person table's other keys are device labels;
/// [`decode`] dispatches on this key FIRST and [`encode`] writes it FIRST. The value is a key string, as a
/// device's is. The `_` puts it outside the name rule, so no device label can ever collide with it.
const SIGNET_KEY: &str = "signet_root";

/// The on-disk shape: a top-level table whose keys are petnames, each mapping to a table of device label
/// to key string, plus the person's [`SIGNET_KEY`]. A separate wire type so no serde derive touches the
/// domain, and the string keys/values are exactly what a human reads and edits.
type Wire = BTreeMap<String, toml::Value>;

/// Parse a contacts TOML document into the strictly-typed domain, validating every name, key, and entry.
/// A `me` there is replaced: [`ContactsStore::open`] derives `me` from the list of your devices.
fn decode(text: &str) -> Result<Contacts, StoreError> {
    let wire: Wire = toml::from_str(text).map_err(StoreError::Parse)?;
    let mut contacts = Contacts::default();
    for (key, value) in wire {
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

/// Parse one wire value, a key string, into a [`Binding`].
fn decode_binding(value: &toml::Value) -> Result<Binding, StoreError> {
    let key = value.as_str().ok_or(StoreError::BadEntry)?;
    Ok(Binding { node: key.parse()? })
}

/// Render the domain address book as a contacts TOML document, every person but `me`.
fn encode(contacts: &Contacts) -> Result<String, StoreError> {
    let mut wire = Wire::new();
    for petname in contacts.petnames().filter(|petname| petname.as_str() != ME) {
        let mut group: toml::value::Table = contacts
            .devices(petname)
            .into_iter()
            .flatten()
            .map(|(label, node)| (label.as_str().to_owned(), key_value(node)))
            .collect();
        // The signet persists under the reserved key inside the person's OWN table, so alice's whole record
        // (devices + signet) stays one `[alice]` block; a person with a signet but no devices still writes a
        // block, so a signet-only contact round-trips. The key can never collide with a device label (it is
        // not a name), so this insert never clobbers one.
        if let Some(binding) = contacts.signet(petname) {
            group.insert(SIGNET_KEY.to_owned(), key_value(&binding.node));
        }
        // Skip a person with neither devices nor a signet: an empty table is nothing to persist.
        if group.is_empty() {
            continue;
        }
        wire.insert(petname.as_str().to_owned(), toml::Value::Table(group));
    }
    toml::to_string_pretty(&wire).map_err(StoreError::Encode)
}

/// A key's wire value: its string.
fn key_value(node: &bifrost::NodeId) -> toml::Value {
    toml::Value::String(node.to_string())
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
    /// A person was not a table of keys, or a device or signet entry was not a key string.
    #[error("the contacts file holds a malformed contact entry")]
    BadEntry,
}
