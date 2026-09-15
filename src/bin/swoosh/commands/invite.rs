//! `swoosh invite`: create, list, or cancel membership invites for devices.
//!
//! A local group: no leaf binds a transport. `add` signs a device-bound badge with this node's persisted
//! identity (the signet) and records the `me/<label>` contact plus a mint-log ledger row; `ls` reads that
//! ledger; `rm` revokes the badge it recorded at the root id, leaving the ledger row for audit. `--for`
//! is the shared [`GrantFor`](crate::commands::share::GrantFor) WHO grammar, so `invite add` and
//! `grant issue` parse and teach the same tokens. An invite admits ONE device at the whole gate; a
//! per-service grant is `grant issue`.

use clap::Subcommand;
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;

pub mod add;
pub mod ls;
pub mod rm;

/// Create, list, and cancel invites: one device per invite.
#[derive(Debug, Subcommand)]
pub enum InviteCmd {
    /// Create an invite: label names the row, --for binds the key it admits.
    Add(add::AddCmd),
    /// List the invites you have issued.
    Ls(ls::LsCmd),
    /// Cancel an invite by revoking its badge.
    Rm(rm::RmCmd),
}

impl InviteCmd {
    /// Run the selected invite verb: every leaf reads or writes the store and the ledger in the one home.
    pub async fn run(self, store: ContactsStore, home: &Home) -> eyre::Result<()> {
        match self {
            Self::Add(cmd) => cmd.run(store, home).await,
            Self::Ls(cmd) => cmd.run(store.contacts(), home).await,
            Self::Rm(cmd) => cmd.run(store.contacts(), home).await,
        }
    }
}
