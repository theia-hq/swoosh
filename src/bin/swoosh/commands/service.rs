//! `swoosh service`: change what this machine serves.
//!
//! Every leaf is a LOCAL FILE WRITE on `<home>/serve.toml` under `home.lock`, never a socket call and never
//! a remote op: each acts on this machine.
//!
//! - `service add <service>…` / `service rm <service>…` change this machine's list, which a bare `serve`
//!   serves. A running `serve` binds only at its start, so an add is served from its next start; a remove
//!   is refused live. See [`edit`].
//! - `service on <service>` / `service off <service>` change whether a listed service answers, live, with
//!   no restart, and `off` holds across restarts. See [`toggle`].
//!
//! A machine typed after `on` or `off` (`[me/<name>]`) is parsed, hidden from usage, and refused with exit 2
//! until those can act on another of your devices.

use std::collections::BTreeSet;

use clap::Subcommand;
use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _};
use swoosh::serve::control_codec::DisabledList;

pub mod edit;
pub mod toggle;

/// Change what this machine serves
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
