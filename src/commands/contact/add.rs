//! `swoosh contact add <petname>[/<device>] <key>`: save a peer's identity under a local name.

use bifrost::NodeId;
use clap::Args;

use crate::contacts::{Added, ContactRef, ContactsStore};

/// Save a peer's key under a petname, or add a device key under an existing person.
#[derive(Debug, Args)]
pub struct AddCmd {
    /// The name to save, `alice` for a person or `alice/macbook` to group a device under one.
    #[arg(value_name = "name")]
    pub name: ContactRef,
    /// The peer's identity, as a bifrost node id.
    #[arg(value_name = "key")]
    pub key: NodeId,
}

impl AddCmd {
    /// Add the binding and persist. Idempotent: re-adding the same name updates in place and warns on a
    /// clobber rather than silently replacing a key the user may not mean to lose.
    pub async fn run(self, mut store: ContactsStore) -> eyre::Result<()> {
        let (petname, device) = (self.name.petname().clone(), self.name.device().cloned());
        let outcome = store.contacts_mut().add(petname, device, self.key);

        match outcome {
            Added::Created => println!("added {} -> {}", self.name, self.key.short()),
            Added::Unchanged => {
                println!("{} already -> {} (unchanged)", self.name, self.key.short())
            }
            Added::Replaced(previous) => println!(
                "updated {} -> {} (was {})",
                self.name,
                self.key.short(),
                previous.short()
            ),
        }

        store.save().await?;
        Ok(())
    }
}
