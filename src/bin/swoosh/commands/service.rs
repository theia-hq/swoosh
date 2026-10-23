//! `swoosh service`: show or change what this machine serves.
//!
//! The bare command reads the saved next-start list and one local resident snapshot.
//! It prints configured names in order, startup targets when bound, and next-start
//! targets when they differ. Off marks come from the fresh saved file, not the
//! resident's refusal bits. Neither observation is a health check.
//!
//! `add` and `rm` change the saved list under `home.lock`. Added services start
//! with the next serve; removed services are refused live. `on` and `off` change
//! whether a listed service answers, and off marks persist across restarts.
//!
//! A machine typed after `on` or `off` is refused with exit 2 until remote
//! toggles are supported.

use std::collections::BTreeSet;

use clap::Subcommand;
use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _};
use swoosh::serve::Mistyped;
use swoosh::serve::control_codec::DisabledList;

pub mod edit;
pub mod toggle;
pub mod view;

/// Show or change what this machine serves
#[derive(Debug, Subcommand)]
pub enum ServiceCmd {
    /// Add services to what this machine serves
    Add(edit::ServiceAddCmd),
    /// Remove services from what this machine serves
    Rm(edit::ServiceRmCmd),
    /// Turn a service on here
    On(toggle::ServiceToggleCmd),
    /// Turn a service off here
    #[command(after_long_help = "It stays off across restarts until you run swoosh service on.")]
    Off(toggle::ServiceToggleCmd),
}

/// A usage error a `service` leaf finds once the line is parsed: exit 2, as clap's own are, before the home
/// is read. A machine typed to `on` or `off`, a second service to either, an entry with no name, or a name
/// typed twice.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

impl From<Mistyped> for Usage {
    fn from(mistyped: Mistyped) -> Self {
        Self(mistyped.to_string())
    }
}

/// What the `serve` running for a home serves, as its control socket answers: the names it bound, internal
/// routes left out, and the ones it has off, when it could say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    /// The names it bound, in its catalog's order. A dotted name is the node's own route, which no typed
    /// name can be, so none is here.
    pub serves: Vec<String>,
    /// The names it has off; `None` when it could not read its own list, so no name can be called off.
    pub off: Option<BTreeSet<String>>,
}

impl Running {
    /// Ask the `serve` running for `home` over its control socket; `None` when none answers. A read only:
    /// what a line says about the running node, never what a write is allowed to do.
    pub async fn ask(home: &Home) -> Option<Self> {
        let client = ControlClient::resolve(home).ok()?;
        let menu = client.services().await.ok()?;
        Some(Self {
            serves: menu
                .catalog
                .entries()
                .filter(|entry| !entry.name.contains('.'))
                .map(|entry| entry.name.clone())
                .collect(),
            off: match menu.disabled {
                DisabledList::Known(names) => Some(names.into_iter().collect()),
                DisabledList::Unknown(_) => None,
            },
        })
    }

    /// Whether it bound `name`.
    pub fn serves(&self, name: &str) -> bool {
        self.serves.iter().any(|served| served == name)
    }

    /// Whether it has `name` off, as far as it could say.
    pub fn has_off(&self, name: &str) -> bool {
        self.off.as_ref().is_some_and(|off| off.contains(name))
    }
}
