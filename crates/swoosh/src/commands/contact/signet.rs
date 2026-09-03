//! `swoosh contact signet <petname> <key>`: record a person's SIGNET root under their petname.
//!
//! A signet is the key a person's fleet roots at (the root that vouches for their devices). Recording it is
//! what lets `swoosh grant issue --for fleet:<petname>` bind a fleet grant BY NAME instead of by a pasted
//! raw key. The positional is a bare petname, not a `petname/device` address: a signet is a person's root,
//! never a device, so a device address is refused at the parser boundary.

use bifrost::NodeId;
use clap::Args;

use crate::contacts::{Added, ContactsStore, Petname};

/// Record a person's signet root, so `--for fleet:<petname>` binds their fleet.
#[derive(Debug, Args)]
pub struct SignetCmd {
    /// The person whose signet this is (a bare petname; a device address `alice/x` is rejected).
    #[arg(value_name = "petname")]
    pub petname: Petname,
    /// The person's signet public key (from their `swoosh identity`).
    #[arg(value_name = "key")]
    pub key: NodeId,
}

impl SignetCmd {
    /// Record the signet and persist. Idempotent, mirroring `add`: re-setting the same key is a no-op that
    /// says so; a different key warns on the clobber rather than silently losing the previous signet.
    pub async fn run(self, mut store: ContactsStore) -> eyre::Result<()> {
        let outcome = store
            .contacts_mut()
            .set_signet(self.petname.clone(), self.key);
        match outcome {
            Added::Created => {
                println!("recorded {}'s signet -> {}", self.petname, self.key.short())
            }
            Added::Unchanged => println!(
                "{}'s signet already -> {} (unchanged)",
                self.petname,
                self.key.short()
            ),
            Added::Replaced(previous) => println!(
                "updated {}'s signet -> {} (was {})",
                self.petname,
                self.key.short(),
                previous.short()
            ),
        }
        store.save().await?;
        Ok(())
    }
}
