//! The saved next-start configuration and one local resident observation.

use std::collections::BTreeSet;

use bifrost::NodeId;
use keystore::KeyFile;
use nauthy::Service;
use swoosh::home::{Home, HomeWrite, ProcessId, ResidentPresence, ServeLock};
use swoosh::identity;
use swoosh::node_client::{ControlClient, NodeClient as _};
use swoosh::serve::control_codec::{ControlError, LocalServiceSnapshot};
use swoosh::serve::{ServedTarget, ServingError, Started};
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

/// One parsed target retained through classification, signing and ledger construction.
pub(super) struct ShareTarget {
    /// Target retained through classification, signing and ledger construction.
    pub target: ServedTarget,
    /// Observations retained for issuer checks and availability output.
    pub basis: ShareBasis,
}

/// Checked acquisition basis, not a runtime-state reservation.
pub(super) enum ShareBasis {
    /// Complete attributed live detail supplied the target.
    Live {
        /// The selected home's local control client.
        client: ControlClient,
        /// Checked listener PID observed with the detail.
        pid: ProcessId,
        /// Whether detail reported this service refusing new admissions.
        refused: bool,
    },
    /// Checked absence and a free serve lock permitted saved/default selection.
    Next {
        /// Whether saved policy marked this service off.
        off: bool,
    },
}

impl ShareTarget {
    /// Resolve one target for service-form sharing. Complete live service details are authoritative, even
    /// when saved services differ or cannot be parsed. A missing live service or failed live-detail read
    /// never falls back to saved services.
    ///
    /// Use valid saved services only when initial acquisition reports no resident and the selected home's
    /// serve-lock probe reports free. An absent saved list uses the defaults; an explicitly empty list stays
    /// empty. An unknown saved name does not construct a service. A disabled service retains its target;
    /// sharing does not enable it.
    pub async fn read(home: &Home, service: &Service) -> eyre::Result<Self> {
        let initial = match ControlClient::resolve(home) {
            Ok(client) => client
                .local_service_detail_attributed()
                .await
                .map(|(snapshot, pid)| (client, snapshot, pid)),
            Err(error) => Err(error),
        };
        Self::from_initial(home, service, initial).await
    }

    /// Keep the initial exchange distinct: no later status or identity failure can select Next.
    pub(super) async fn from_initial(
        home: &Home,
        service: &Service,
        initial: Result<(ControlClient, LocalServiceSnapshot, ProcessId), ControlError>,
    ) -> eyre::Result<Self> {
        match initial {
            Ok((client, snapshot, pid)) => {
                let pair = snapshot
                    .get(service.as_str())
                    .ok_or_else(|| eyre::eyre!("the running node does not list that service"))?;
                Ok(Self {
                    target: pair.target().as_str().parse()?,
                    basis: ShareBasis::Live {
                        client,
                        pid,
                        refused: pair.refused(),
                    },
                })
            }
            Err(ControlError::NoResident) => {
                if home.resident_presence().await? != ResidentPresence::Free {
                    eyre::bail!("cannot confirm that no node is serving this home");
                }
                let file = ServeToml::read(home)?;
                let entries = Started::bare(&file, &home.serve_toml())?.entries();
                let target = entries
                    .iter()
                    .find_map(|entry| {
                        let (name, target) = entry.split_once('=')?;
                        (name == service.as_str()).then_some(target)
                    })
                    .ok_or_else(|| eyre::eyre!("saved services do not list that service"))?;
                Ok(Self {
                    target: target.parse()?,
                    basis: ShareBasis::Next {
                        off: file.off.contains(service.as_str()),
                    },
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Require live detail and status to report the same checked listener PID.
    ///
    /// Reading a plain stored identity may materialize secret bytes; this is not a secret-free check.
    pub async fn issuer(&self, home: &Home) -> eyre::Result<Option<NodeId>> {
        let ShareBasis::Live { client, pid, .. } = &self.basis else {
            return Ok(None);
        };
        let (status, observed) = client.status_attributed().await?;
        if observed != *pid {
            eyre::bail!("the running node's PID no longer matches this home");
        }
        let key = Self::stored_key(home)?.ok_or_else(|| {
            eyre::eyre!("this home has no stored identity; cannot share from the running node")
        })?;
        Self::same_identity(key, status.node_id)?;
        Ok(Some(key))
    }

    /// Load without provisioning on the live path; only a valid next-start share permits first use.
    pub async fn secret(
        &self,
        home: &Home,
        issuer: Option<NodeId>,
    ) -> eyre::Result<identity::Secret> {
        let secret = match &self.basis {
            ShareBasis::Live { .. } => identity::load(home).await?.ok_or_else(|| {
                eyre::eyre!("this home has no stored identity; cannot share from the running node")
            })?,
            ShareBasis::Next { .. } => {
                identity::resolve(identity::Identity::Persisted, home).await?
            }
        };
        if let Some(issuer) = issuer {
            Self::same_identity(secret.node_id(), issuer)?;
        }
        Ok(secret)
    }

    /// Recheck the disk identity and recorded live PID under the home write lock before appending the record.
    /// These rechecks do not create an atomic snapshot across files and sockets.
    pub fn recheck(&self, _guard: &HomeWrite, home: &Home, issuer: NodeId) -> eyre::Result<()> {
        if Self::stored_key(home)? != Some(issuer) {
            eyre::bail!(
                "the selected home's stored identity changed or is missing; cannot finish sharing"
            );
        }
        if let ShareBasis::Live { pid, .. } = &self.basis
            && ServeLock::checked_pid(home)? != *pid
        {
            eyre::bail!("the running node's PID no longer matches this home");
        }
        Ok(())
    }

    fn stored_key(home: &Home) -> eyre::Result<Option<NodeId>> {
        let file = KeyFile::new(home.key());
        file.load()?
            .as_ref()
            .map(|stored| identity::key_of(&file, stored))
            .transpose()
            .map_err(Into::into)
    }

    fn same_identity(actual: NodeId, expected: NodeId) -> eyre::Result<()> {
        if actual != expected {
            eyre::bail!("the running node's identity does not match this home");
        }
        Ok(())
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
