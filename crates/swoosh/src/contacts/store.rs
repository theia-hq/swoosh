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

use bifrost::{NodeId, NodeIdParseError};

use super::{Contacts, DeviceLabel, DeviceLabelParseError, Petname, PetnameParseError};

/// A contacts file at a known path, loaded into a mutable [`Contacts`] and saved back atomically.
///
/// Own the path once, then [`save`](Self::save) after each mutation. The store creates the parent config
/// dir on first save, mirroring how the identity key is provisioned lazily beside it.
#[derive(Debug)]
pub struct ContactsStore {
    path: PathBuf,
    contacts: Contacts,
}

impl ContactsStore {
    /// Open the store at `path`, loading existing contacts or starting empty if the file is absent.
    ///
    /// A missing file is the first-run case, not an error: an empty address book. A present-but-corrupt
    /// file IS an error, surfaced rather than silently discarding what the user saved.
    pub async fn open(path: PathBuf) -> Result<Self, StoreError> {
        let contacts = match tokio::fs::read_to_string(&path).await {
            Ok(text) => decode(&text)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Contacts::default(),
            Err(error) => return Err(StoreError::Read(error)),
        };
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

    /// Write the current contacts back to disk, creating the config dir on first save.
    ///
    /// Writes to a sibling temp file and renames it over the target, so a crash mid-write never leaves a
    /// half-written, unparseable address book: the rename is atomic, the reader sees the old file or the
    /// new one, never a torn one.
    pub async fn save(&self) -> Result<(), StoreError> {
        let text = encode(&self.contacts)?;
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(StoreError::Write)?;
        }
        let temp = self.path.with_extension("toml.tmp");
        tokio::fs::write(&temp, text)
            .await
            .map_err(StoreError::Write)?;
        tokio::fs::rename(&temp, &self.path)
            .await
            .map_err(StoreError::Write)?;
        Ok(())
    }
}

/// The on-disk shape: petname to device-label to base32 identity string. A separate wire type so no
/// serde derive touches the domain, and the string keys/values are exactly what a human reads and edits.
type Wire = BTreeMap<String, BTreeMap<String, String>>;

/// Parse a contacts TOML document into the strictly-typed domain, validating every name and key.
fn decode(text: &str) -> Result<Contacts, StoreError> {
    let wire: Wire = toml::from_str(text).map_err(StoreError::Parse)?;
    let mut contacts = Contacts::default();
    for (petname, group) in wire {
        let petname: Petname = petname.parse()?;
        for (device, key) in group {
            let device: DeviceLabel = device.parse()?;
            let node: NodeId = key.parse()?;
            contacts.add(petname.clone(), Some(device), node);
        }
    }
    Ok(contacts)
}

/// Render the domain address book as a contacts TOML document.
fn encode(contacts: &Contacts) -> Result<String, StoreError> {
    let mut wire = Wire::new();
    for petname in contacts.petnames() {
        // `petnames` yields only present names, so `devices` is always `Some` here; skip defensively
        // rather than unwrap, since a future change to either method must not turn into a panic.
        let Some(devices) = contacts.devices(petname) else {
            continue;
        };
        let group = devices
            .map(|(label, node)| (label.as_str().to_owned(), node.to_string()))
            .collect();
        wire.insert(petname.as_str().to_owned(), group);
    }
    toml::to_string_pretty(&wire).map_err(StoreError::Encode)
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
    Write(#[source] io::Error),
    /// The contacts file was not valid TOML.
    #[error("the contacts file is not valid TOML")]
    Parse(#[source] toml::de::Error),
    /// The contacts could not be serialized to TOML.
    #[error("encoding the contacts file")]
    Encode(#[source] toml::ser::Error),
    /// A stored petname was not a valid petname.
    #[error("the contacts file holds an invalid petname")]
    Petname(#[from] PetnameParseError),
    /// A stored device label was not valid.
    #[error("the contacts file holds an invalid device label")]
    Device(#[from] DeviceLabelParseError),
    /// A stored identity string was not a valid node id. A plain `#[from]`: the bifrost umbrella
    /// re-exports the concrete [`NodeIdParseError`], so the source chain is preserved with no projection
    /// or manual `map_err`.
    #[error("the contacts file holds an invalid node id")]
    NodeId(#[from] NodeIdParseError),
}
