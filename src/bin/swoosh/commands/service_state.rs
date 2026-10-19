//! The validated local service list and the running node's bound names, read without changing either.

use std::collections::BTreeSet;

use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _};
use swoosh::serve::control_codec::ControlError;
use swoosh::serve::{ServingError, Started};
use swoosh::serve_toml::{ServeToml, ServeTomlError};
use tightbeam::tunnel::ServiceCatalog;

/// Configured entries are the only source of printable names; the catalog proves only what is bound.
#[derive(Debug)]
pub(super) struct ServiceState {
    /// Retains the distinction between an absent list and an explicitly emptied one, and its targets.
    pub started: Started,
    /// The file's off marks, not the daemon's refused set, which also contains removed names.
    pub off: BTreeSet<String>,
    /// `None` only when no local resident answers; other socket errors remain errors.
    pub bound: Option<ServiceCatalog>,
}

impl ServiceState {
    /// Read through the trusted, bounded file opener and the same-UID socket client, never a transport.
    pub async fn read(home: &Home) -> Result<Self, ReadError> {
        let file = ServeToml::read(home)?;
        // TOML decoding alone accepts duplicate names and entries that a bare start refuses.
        let started = Started::bare(&file, &home.serve_toml())?;
        let bound = match ControlClient::resolve(home) {
            Ok(client) => match client.status().await {
                Ok(status) => Some(status.menu.catalog),
                Err(ControlError::NoResident) => None,
                Err(error) => return Err(ReadError::Daemon(error)),
            },
            Err(ControlError::NoResident) => None,
            Err(error) => return Err(ReadError::Daemon(error)),
        };
        Ok(Self {
            started,
            off: file.off,
            bound,
        })
    }
}

/// File refusal, semantic list refusal, and daemon failure must not become an absent resident.
#[derive(Debug, thiserror::Error)]
pub(super) enum ReadError {
    /// The local file could not be read or decoded.
    #[error(transparent)]
    File(#[from] ServeTomlError),
    /// Its entries are not one list a bare start can use.
    #[error(transparent)]
    List(#[from] ServingError),
    /// A resident path exists but could not be trusted or queried.
    #[error(transparent)]
    Daemon(ControlError),
}
