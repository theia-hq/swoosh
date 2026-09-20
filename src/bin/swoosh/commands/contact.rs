//! `swoosh contact`: manage the local address book (petnames for peer identities).
//!
//! A local verb group: unlike the reach verbs it binds no transport and dials nobody, it just edits the
//! contacts file beside the identity. `main` dispatches this before composing any transport, since there
//! is nothing to reach. Each leaf owns an `async fn run(self, ..)` that consumes it and persists.
//!
//! `add` and `rm` also take the home, because an edit under `me/` changes the operator's FLEET, and the
//! signed roster the fleet pulls is re-cut from the same act. `ls` and `signet` do not: a read changes
//! nothing, and a signet is a person's root, not a member.

use clap::Subcommand;
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;

pub mod add;
pub mod ls;
pub mod rm;
pub mod signet;

/// Manage local petnames: save a peer's key under a name, list saved contacts, remove one.
#[derive(Debug, Subcommand)]
pub enum ContactCmd {
    /// Save a peer's key under a petname (`alice` or `alice/macbook` for a device).
    Add(add::AddCmd),
    /// Record a person's signet root, so `--for fleet:<petname>` binds their fleet.
    Signet(signet::SignetCmd),
    /// List saved contacts, or one contact's devices.
    Ls(ls::LsCmd),
    /// Remove a contact, or one of its devices (`alice` or `alice/macbook`).
    Rm(rm::RmCmd),
}

impl ContactCmd {
    /// Run the selected contact verb against the loaded store.
    pub async fn run(self, store: ContactsStore, home: &Home) -> eyre::Result<()> {
        match self {
            Self::Add(cmd) => cmd.run(store, home).await,
            Self::Signet(cmd) => cmd.run(store).await,
            Self::Ls(cmd) => cmd.run(store).await,
            Self::Rm(cmd) => cmd.run(store, home).await,
        }
    }
}
