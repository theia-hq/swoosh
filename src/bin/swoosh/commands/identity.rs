//! `swoosh identity`: the group that backs this machine's key up, puts it back, and chooses how it is
//! protected. `swoosh status` prints the key.
//!
//! The leaves (`export`, `restore`, `protect`) are local, and each is its own module.

use clap::{Args, Subcommand};
use swoosh::home::Home;

pub mod export;
pub mod protect;
pub mod restore;

/// Back up, restore, or protect this machine's key.
#[derive(Debug, Args)]
pub struct IdentityCmd {
    #[command(subcommand)]
    action: IdentityAction,
}

/// The identity group's leaves.
#[derive(Debug, Subcommand)]
enum IdentityAction {
    /// Write a sealed backup of this identity to <path>.
    Export(export::ExportCmd),
    /// Restore this home's key from a backup file (the key only, not revocations).
    Restore(restore::RestoreCmd),
    /// Set how this identity is protected.
    Protect(protect::ProtectCmd),
}

impl IdentityCmd {
    /// Run the selected leaf.
    pub fn run(self, home: &Home) -> eyre::Result<()> {
        match self.action {
            IdentityAction::Export(cmd) => cmd.run(home),
            IdentityAction::Restore(cmd) => cmd.run(home),
            IdentityAction::Protect(cmd) => cmd.run(home),
        }
    }
}
