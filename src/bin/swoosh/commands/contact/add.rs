//! `swoosh contact add <person> <root key>` and `swoosh contact add <person>/<name> <key>`: save another
//! person's root, or one machine of theirs, under a local name.
//!
//! The name's shape decides which: a bare person is saved with their root's key, which `share <svc>
//! <person>` binds a link to, so every machine that root vouches for can use it; `<person>/<name>` is one
//! machine, which `share <svc> <person>/<name>` binds a link to alone, and which a dial can reach.

use bifrost::NodeId;
use clap::Args;
use swoosh::contacts::{Added, ContactRef, ContactsStore};
use swoosh::home::{Home, HomeWrite};

/// Save a person's root key (`alice`), or one machine of theirs (`alice/laptop`).
#[derive(Debug, Args)]
pub struct AddCmd {
    /// `alice` for a person, or `alice/laptop` for one machine of theirs
    #[arg(value_name = "name", value_parser = super::new_contact)]
    pub name: ContactRef,
    /// the person's root key, or that machine's key
    #[arg(value_name = "key", value_parser = swoosh::peer::parse_key)]
    pub key: NodeId,
}

impl AddCmd {
    /// Save the key and persist. Idempotent: re-adding the same key says so, and a different key warns on
    /// the clobber rather than silently replacing a key the user may not mean to lose. A reserved person
    /// (`me`, `root`, `anyone`) never reaches here: [`new_contact`](super::new_contact) refuses it at parse.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        let home_lock = HomeWrite::take(home).await?;
        let mut store = ContactsStore::open(home).await?;
        let person = self.name.petname().clone();
        let key = swoosh::credential::short(&self.key);
        match self.name.device().cloned() {
            None => {
                let line = match store.contacts_mut().set_signet(person.clone(), self.key) {
                    Added::Created => format!("saved root:{key} as {person}'s root."),
                    Added::Unchanged => format!("root:{key} is already {person}'s root."),
                    Added::Replaced(previous) => format!(
                        "saved root:{key} as {person}'s root, in place of root:{}.",
                        swoosh::credential::short(&previous)
                    ),
                };
                store.save(&home_lock)?;
                eprintln!("{line}");
            }
            Some(device) => {
                let line = match store.contacts_mut().add(person, Some(device), self.key) {
                    Added::Created => format!("added {} -> {key}", self.name),
                    Added::Unchanged => format!("{} already -> {key} (unchanged)", self.name),
                    Added::Replaced(previous) => format!(
                        "updated {} -> {key} (was {})",
                        self.name,
                        swoosh::credential::short(&previous)
                    ),
                };
                store.save(&home_lock)?;
                println!("{line}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "add_tests.rs"]
mod add_tests;
