//! The saved next-start configuration and one local resident observation.

use std::collections::BTreeSet;

use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _};
use swoosh::serve::control_codec::{ControlError, LocalServiceSnapshot};
use swoosh::serve::{ServingError, Started};
use swoosh::serve_toml::{ServeToml, ServeTomlError};
use tightbeam::tunnel::ServiceCatalog;

/// Choose the resident read before acquisition; detail limits must not restrict membership.
#[derive(Debug, Clone, Copy)]
pub(super) enum ReadMode {
    Membership,
    Detail,
}

/// One answering resident, never independently acquired targets and membership.
#[derive(Debug)]
pub(super) enum ResidentObservation {
    Membership(Option<ServiceCatalog>),
    Detail(Option<LocalServiceSnapshot>),
}

/// Configured entries determine printable names and order. The selected resident observation supplies
/// membership or exact startup targets.
#[derive(Debug)]
pub(super) struct ServiceState {
    /// Retains the distinction between an absent list and an explicitly emptied one, and its targets.
    pub started: Started,
    /// The file's off marks, not the daemon's refused set, which also contains removed names.
    pub off: BTreeSet<String>,
    /// Only the selected mode's observation is retained.
    pub resident: ResidentObservation,
}

impl ServiceState {
    /// Read through the trusted, bounded file opener and the same-UID socket client, never a transport.
    pub async fn read(home: &Home, mode: ReadMode) -> Result<Self, ReadError> {
        let file = ServeToml::read(home)?;
        // TOML decoding alone accepts duplicate names and entries that a bare start refuses.
        let started = Started::bare(&file, &home.serve_toml())?;
        let client = match ControlClient::resolve(home) {
            Ok(client) => Some(client),
            Err(ControlError::NoResident) => None,
            Err(error) => return Err(ReadError::Daemon(error)),
        };
        let resident = match mode {
            ReadMode::Membership => ResidentObservation::Membership(match client {
                Some(client) => match client.status().await {
                    Ok(status) => Some(status.menu.catalog),
                    Err(ControlError::NoResident) => None,
                    Err(error) => return Err(ReadError::Daemon(error)),
                },
                None => None,
            }),
            ReadMode::Detail => ResidentObservation::Detail(match client {
                Some(client) => match client.local_service_detail().await {
                    Ok(snapshot) => Some(snapshot),
                    Err(ControlError::NoResident) => None,
                    Err(error) => return Err(ReadError::Daemon(error)),
                },
                None => None,
            }),
        };
        Ok(Self {
            started,
            off: file.off,
            resident,
        })
    }

    /// Only typed NoResident permits a down presentation.
    pub fn resident_present(&self) -> bool {
        match &self.resident {
            ResidentObservation::Membership(value) => value.is_some(),
            ResidentObservation::Detail(value) => value.is_some(),
        }
    }

    /// Membership comes solely from the selected exchange.
    pub fn contains_bound(&self, name: &str) -> bool {
        match &self.resident {
            ResidentObservation::Membership(value) => value
                .as_ref()
                .is_some_and(|catalog| catalog.entries().any(|entry| entry.name == name)),
            ResidentObservation::Detail(value) => value
                .as_ref()
                .is_some_and(|snapshot| snapshot.contains(name)),
        }
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
