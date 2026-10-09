//! `swoosh contact rm <person>[/<name>]`: remove a contact, or one of its devices.
//!
//! A contact with live links refuses: the links outlive the name, and with the name gone `revoke <person>`
//! could no longer find them. Live is the ledger's view: a row given to the person's root or to one of
//! their machines' keys, not yet ended, and not in `revoked`.

use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use swoosh::contacts::{ContactRef, Contacts, ContactsStore, Removed, Source};
use swoosh::grants::Grants;
use swoosh::home::{Home, HomeWrite};

/// Remove a saved person, or one machine of theirs
#[derive(Debug, Args)]
pub struct RmCmd {
    /// A person, or one machine of theirs
    #[arg(value_name = "person | person/name")]
    pub name: ContactRef,
}

impl RmCmd {
    /// Remove the target and persist. Idempotent: removing something absent is a no-op that says so,
    /// not an error, so a repeated `rm` is safe. A name under `me/` is refused and nothing is written, and
    /// so is a contact this machine still has live links for.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        super::refuse_me(&self.name)?;
        let home_lock = HomeWrite::take(home).await?;
        let mut store = ContactsStore::open(home).await?;
        let live = live_links(home, &holders(store.contacts(), &self.name)).await?;
        if live > 0 {
            let name = &self.name;
            eyre::bail!(
                "links you shared with {name} are live ({live}): revoke them first: swoosh revoke {name}"
            );
        }
        // A root learned from this very machine stays saved once it goes, and is said to.
        let person = self.name.petname();
        let learned = self.name.device().is_some_and(|device| {
            store
                .contacts()
                .signet(person)
                .is_some_and(|root| root.source == Source::Learned(device.clone()))
        });
        let removed = store.contacts_mut().remove(person, self.name.device());

        match removed {
            Removed::Removed => {
                store.save(&home_lock)?;
                eprintln!("removed {}", self.name);
                if learned {
                    eprintln!("{person}'s root, learned from {}, stays saved.", self.name);
                }
            }
            Removed::Absent => eprintln!("no such contact {}; nothing to remove", self.name),
        }
        Ok(())
    }
}

/// The keys `name` stands for in the ledger: one machine's key for `<person>/<name>`; for a person, every
/// machine of theirs and their root. A name this book does not hold stands for none.
pub(super) fn holders(contacts: &Contacts, name: &ContactRef) -> Vec<NodeId> {
    let mut keys: Vec<NodeId> = contacts
        .resolve_candidates(name)
        .map(|candidates| {
            candidates
                .into_iter()
                .map(|candidate| candidate.node)
                .collect()
        })
        .unwrap_or_default();
    if name.device().is_none()
        && let Some(root) = contacts.signet(name.petname())
    {
        keys.push(root.node);
    }
    keys
}

/// How many links in the ledger were given to one of `keys` and still admit: not ended, not revoked.
pub(super) async fn live_links(home: &Home, keys: &[NodeId]) -> eyre::Result<usize> {
    if keys.is_empty() {
        return Ok(0);
    }
    let holders: Vec<String> = keys.iter().map(ToString::to_string).collect();
    let records = Grants::at(home.links()).load().await?;
    let now = SystemTime::now();
    let revoked = swoosh::revoked::open(home)?;
    Ok(records
        .iter()
        .filter(|record| holders.contains(&record.holder))
        .filter(|record| record.expiry > now)
        .filter(|record| !revoked.is_revoked_any([&record.root_id]))
        .count())
}

#[cfg(test)]
#[path = "rm_tests.rs"]
mod rm_tests;
