//! `swoosh identity`: print this node's identity (its NodeId), minting a key if there is none.
//!
//! A local verb: it resolves the key `--key`/`SWOOSH_KEY` points at (or the default), creating a fresh
//! one if that path is empty, and prints the NodeId a node bound under it will present. It stands up no
//! transport. This is how you pre-provision an identity: mint a key here, save its NodeId as a contact,
//! then hand the key file to the machine that will adopt it (e.g. a CI runner, via a secret) so you can
//! reach it by a name you already know.

use std::path::{Path, PathBuf};

use clap::Args;

use crate::identity::{self, Identity};

/// Print this node's identity (its NodeId), minting a key if there is none.
#[derive(Debug, Args)]
pub struct IdentityCmd {}

impl IdentityCmd {
    /// Resolve the key (creating one if the path is empty) and print its NodeId and the key's path.
    pub async fn run(self, key: Option<&Path>) -> eyre::Result<()> {
        let secret = identity::resolve(Identity::Persisted, key).await?;
        let path: PathBuf = match key {
            Some(path) => path.to_path_buf(),
            None => identity::default_path()?,
        };
        println!("{}", secret.node_id());
        println!("key: {}", path.display());
        Ok(())
    }
}
