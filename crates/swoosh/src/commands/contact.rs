//! `swoosh contact`: manage the local address book (petnames for peer identities).
//!
//! A local verb group: unlike the reach verbs it binds no transport and dials nobody, it just edits the
//! contacts file beside the identity. `main` dispatches this before composing any transport, since there
//! is nothing to reach. Each leaf owns an `async fn run(self, store)` that consumes it and persists.

use clap::Subcommand;

use crate::contacts::ContactsStore;

pub mod add;
pub mod ls;
pub mod rm;
pub mod signet;

use add::AddCmd;
use ls::LsCmd;
use rm::RmCmd;
use signet::SignetCmd;

/// Manage local petnames: save a peer's key under a name, list saved contacts, remove one.
#[derive(Debug, Subcommand)]
pub enum ContactCmd {
    /// Save a peer's key under a petname (`alice` or `alice/macbook` for a device).
    Add(AddCmd),
    /// Record a person's signet root, so `--for fleet:<petname>` binds their fleet.
    Signet(SignetCmd),
    /// List saved contacts, or one contact's devices.
    #[command(alias = "list")]
    Ls(LsCmd),
    /// Remove a contact, or one of its devices (`alice` or `alice/macbook`).
    #[command(alias = "remove")]
    Rm(RmCmd),
}

impl ContactCmd {
    /// Run the selected contact verb against the loaded store.
    pub async fn run(self, store: ContactsStore) -> eyre::Result<()> {
        match self {
            Self::Add(cmd) => cmd.run(store).await,
            Self::Signet(cmd) => cmd.run(store).await,
            Self::Ls(cmd) => cmd.run(store).await,
            Self::Rm(cmd) => cmd.run(store).await,
        }
    }
}
