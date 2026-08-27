//! `swoosh contact ls [<petname>]`: list saved contacts, or one contact's devices.

use clap::Args;

use crate::contacts::{ContactsStore, Petname};

/// List saved contacts, or the devices grouped under one contact.
#[derive(Debug, Args)]
pub struct LsCmd {
    /// A contact to expand into its devices. Omit to list every contact.
    pub petname: Option<Petname>,
}

impl LsCmd {
    /// Print the address book, or one person's devices when a petname is given.
    pub async fn run(self, store: ContactsStore) -> eyre::Result<()> {
        let contacts = store.contacts();
        match &self.petname {
            None => {
                let mut any = false;
                for petname in contacts.petnames() {
                    any = true;
                    // A device count reads better than dumping every key at the top level; expand a
                    // person with `contact ls <petname>`.
                    let devices = contacts.devices(petname).into_iter().flatten().count();
                    println!("{petname} ({devices} device{})", plural(devices));
                }
                if !any {
                    println!("no contacts yet; add one with `swoosh contact add <name> <key>`");
                }
            }
            Some(petname) => match contacts.devices(petname) {
                None => eyre::bail!("unknown contact '{petname}'"),
                Some(devices) => {
                    for (label, node) in devices {
                        println!("{petname}/{label} -> {node}");
                    }
                }
            },
        }
        Ok(())
    }
}

/// The plural suffix for a count: `""` for one, `"s"` otherwise.
fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}
