//! `swoosh identity`: print this node's identity (its NodeId), minting a key if there is none; and the
//! group that backs the key up, puts it back, and chooses how it is protected.
//!
//! A local verb: it resolves the key in the home (`--home`/`SWOOSH_HOME`, else the default), creating a
//! fresh one if the home has no key yet, and prints the NodeId a node bound under it will present. It
//! stands up no transport. This is how you pre-provision an identity: mint a key here, save its NodeId as
//! a contact, then hand the key file to the machine that will adopt it (e.g. a CI runner, via a secret) so
//! you can reach it by a name you already know.
//!
//! It is also the answer to "what is this machine" when something is off, so it reports the whole local
//! trust state: the key, how the key file protects it, the signet this machine trusts, and how long the
//! badge it presents still stands. That badge line lives HERE and not on `status`, because `status`'s
//! local read crosses the resident control socket, whose reply is a wire format that deliberately carries
//! no credential fact at all, while this verb answers offline, with no transport and no resident to be
//! running. It never asks for a passphrase: a sealed key file names its node and its protection in its
//! header.
//!
//! The leaves (`export`, `restore`, `protect`) are local too, and each is its own module.

use std::path::Path;
use std::time::SystemTime;

use bifrost::NodeId;
use clap::{Args, Subcommand};
use keystore::Method;
use swoosh::home::Home;
use swoosh::{badge, config, identity};

pub mod export;
pub mod protect;
pub mod restore;

/// Print this node's identity (its NodeId), minting a key if there is none.
#[derive(Debug, Args)]
pub struct IdentityCmd {
    #[command(subcommand)]
    action: Option<IdentityAction>,
}

/// The identity group's leaves. Bare `swoosh identity` is the print.
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
    /// Run the selected leaf, or, bare, print the home's identity.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        match self.action {
            None => print(home).await,
            Some(IdentityAction::Export(cmd)) => cmd.run(home),
            Some(IdentityAction::Restore(cmd)) => cmd.run(home),
            Some(IdentityAction::Protect(cmd)) => cmd.run(home),
        }
    }
}

/// Read the home's key (creating one if the home has none) without unlocking it, and print it with the
/// key's path, its protection, the trusted signet, and the stored badge's remaining life.
async fn print(home: &Home) -> eyre::Result<()> {
    let stored = identity::inspect(home)?;
    let signet = config::load_signet(home).await?;
    // Read the badge's remaining life, never its bytes: this is a local look at a credential this
    // machine already holds, so it discloses nothing it did not already have.
    let expiry = match config::load_badge(home).await? {
        Some(stored) => Some(badge::Expiry::read(&stored, SystemTime::now())?),
        None => None,
    };
    print!(
        "{}",
        render(
            stored.node_id(),
            &home.identity_key(),
            stored.method(),
            signet,
            expiry
        )
    );
    Ok(())
}

/// Render the whole local answer as ONE string (pure, so it is unit-testable and printed once): the key,
/// the file it lives in, how that file protects it, the signet this machine trusts, and how long its badge
/// still stands.
///
/// Every line is present on every run, including the absent cases: a machine with no badge says so,
/// because "no line" and "no badge" read identically to an operator who is here precisely because they
/// do not know which of the two they have.
fn render(
    node: NodeId,
    key: &Path,
    protection: Method,
    signet: Option<NodeId>,
    badge: Option<badge::Expiry>,
) -> String {
    let mut out = format!("{node}\nkey: {}\nprotection: {protection}\n", key.display());
    match signet {
        Some(signet) => out.push_str(&format!("signet: {signet}\n")),
        // No signet file means this machine's own key IS its root (person zero self-trusts), which is a
        // real provisioning state and not a missing one.
        None => out.push_str("signet: none (this machine is its own root)\n"),
    }
    match badge {
        Some(expiry) => out.push_str(&format!("badge: {expiry}\n")),
        // No stored badge is the signet holder's normal state: it self-signs a fresh badge per dial, so
        // it has nothing to store and nothing to renew.
        None => out.push_str("badge: none (this machine self-signs when it dials)\n"),
    }
    out
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
