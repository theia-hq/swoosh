//! `swoosh contact rm <petname>[/<device>]`: remove a contact, or one of its devices.

use clap::Args;

use crate::contacts::{ContactRef, ContactsStore, Removed};

/// Remove a whole contact, or just one device grouped under it.
#[derive(Debug, Args)]
pub struct RmCmd {
    /// The contact to remove, `alice` for the whole person or `alice/macbook` for one device.
    pub name: ContactRef,
}

impl RmCmd {
    /// Remove the target and persist. Idempotent: removing something absent is a no-op that says so,
    /// not an error, so a repeated `rm` is safe.
    pub async fn run(self, mut store: ContactsStore) -> eyre::Result<()> {
        let removed = store
            .contacts_mut()
            .remove(self.name.petname(), self.name.device());

        match removed {
            Removed::Removed => {
                println!("removed {}", self.name);
                store.save().await?;
            }
            Removed::Absent => println!("no such contact {}; nothing to remove", self.name),
        }
        Ok(())
    }
}
