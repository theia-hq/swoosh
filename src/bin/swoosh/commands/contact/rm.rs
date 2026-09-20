//! `swoosh contact rm <petname>[/<device>]`: remove a contact, or one of its devices.

use clap::Args;
use swoosh::contacts::{ContactRef, ContactsStore, Removed};
use swoosh::home::Home;

/// Remove a whole contact, or just one device grouped under it.
#[derive(Debug, Args)]
pub struct RmCmd {
    /// The contact to remove, `alice` for the whole person or `alice/macbook` for one device.
    #[arg(value_name = "name")]
    pub name: ContactRef,
}

impl RmCmd {
    /// Remove the target and persist. Idempotent: removing something absent is a no-op that says so,
    /// not an error, so a repeated `rm` is safe.
    ///
    /// Removing a device under `me/` is how a member LEAVES the fleet (`invite rm` cancels the badge and
    /// deliberately keeps the name), so it re-cuts the signed roster: the next pull drops the device
    /// everywhere, with no restart and no second verb.
    pub async fn run(self, mut store: ContactsStore, home: &Home) -> eyre::Result<()> {
        let before = store.contacts().roster_version();
        let removed = store
            .contacts_mut()
            .remove(self.name.petname(), self.name.device());

        match removed {
            Removed::Removed => {
                println!("removed {}", self.name);
                store.save().await?;
                if store.contacts().roster_version() != before {
                    crate::commands::recut::after_membership_change(home, store.contacts()).await?;
                }
            }
            Removed::Absent => println!("no such contact {}; nothing to remove", self.name),
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "rm_tests.rs"]
mod rm_tests;
