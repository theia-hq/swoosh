//! `swoosh identity`: print this node's identity (its NodeId), minting a key if there is none.
//!
//! A local verb: it resolves the key in the home (`--home`/`SWOOSH_HOME`, else the default), creating a
//! fresh one if the home has no key yet, and prints the NodeId a node bound under it will present. It
//! stands up no transport. This is how you pre-provision an identity: mint a key here, save its NodeId as
//! a contact, then hand the key file to the machine that will adopt it (e.g. a CI runner, via a secret) so
//! you can reach it by a name you already know.

use clap::Args;

use crate::home::Home;
use crate::identity::{self, Identity};

/// Print this node's identity (its NodeId), minting a key if there is none.
#[derive(Debug, Args)]
pub struct IdentityCmd {}

impl IdentityCmd {
    /// Resolve the home's key (creating one if the home has none) and print its NodeId and the key's path.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        let secret = identity::resolve(Identity::Persisted, home).await?;
        println!("{}", secret.node_id());
        println!("key: {}", home.identity_key().display());
        Ok(())
    }
}
