//! `swoosh identity`: print this node's identity (its NodeId), minting a key if there is none.
//!
//! A local verb: it resolves the key in the home (`--home`/`SWOOSH_HOME`, else the default), creating a
//! fresh one if the home has no key yet, and prints the NodeId a node bound under it will present. It
//! stands up no transport. This is how you pre-provision an identity: mint a key here, save its NodeId as
//! a contact, then hand the key file to the machine that will adopt it (e.g. a CI runner, via a secret) so
//! you can reach it by a name you already know.
//!
//! It is also the answer to "what is this machine" when something is off, so it reports the whole local
//! trust state: the key, the signet this machine trusts, and how long the badge it presents still stands.
//! That badge line lives HERE and not on `status`, because `status`'s local read crosses the resident
//! control socket, whose reply is a wire format that deliberately carries no credential fact at all,
//! while this verb answers offline, with no transport and no resident to be running.

use std::path::Path;
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use swoosh::home::Home;
use swoosh::identity::{self, Identity};
use swoosh::{badge, config};

/// Print this node's identity (its NodeId), minting a key if there is none.
#[derive(Debug, Args)]
pub struct IdentityCmd {}

impl IdentityCmd {
    /// Resolve the home's key (creating one if the home has none) and print it with the key's path, the
    /// trusted signet, and the stored badge's remaining life.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        let secret = identity::resolve(Identity::Persisted, home).await?;
        let signet = config::load_signet(home).await?;
        // Read the badge's remaining life, never its bytes: this is a local look at a credential this
        // machine already holds, so it discloses nothing it did not already have.
        let standing = match config::load_badge(home).await? {
            Some(stored) => Some(badge::Standing::read(&stored, SystemTime::now())?),
            None => None,
        };
        print!(
            "{}",
            render(secret.node_id(), &home.identity_key(), signet, standing)
        );
        Ok(())
    }
}

/// Render the whole local answer as ONE string (pure, so it is unit-testable and printed once): the key,
/// the file it lives in, the signet this machine trusts, and how long its badge still stands.
///
/// Every line is present on every run, including the absent cases: a machine with no badge says so,
/// because "no line" and "no badge" read identically to an operator who is here precisely because they
/// do not know which of the two they have.
fn render(
    node: NodeId,
    key: &Path,
    signet: Option<NodeId>,
    badge: Option<badge::Standing>,
) -> String {
    let mut out = format!("{node}\nkey: {}\n", key.display());
    match signet {
        Some(signet) => out.push_str(&format!("signet: {signet}\n")),
        // No signet file means this machine's own key IS its root (person zero self-trusts), which is a
        // real provisioning state and not a missing one.
        None => out.push_str("signet: none (this machine is its own root)\n"),
    }
    match badge {
        Some(standing) => out.push_str(&format!("badge: {standing}\n")),
        // No stored badge is the signet holder's normal state: it self-signs a fresh badge per dial, so
        // it has nothing to store and nothing to renew.
        None => out.push_str("badge: none (this machine self-signs when it dials)\n"),
    }
    out
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
