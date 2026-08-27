//! `swoosh contact ls [<petname>]`: list saved contacts, or one contact's devices.

use bifrost::NodeId;
use clap::Args;

use crate::contacts::{Contacts, ContactsStore, DeviceLabel, Petname};

/// List saved contacts, or the devices grouped under one contact.
#[derive(Debug, Args)]
pub struct LsCmd {
    /// A contact to expand into its devices. Omit to list every contact.
    pub petname: Option<Petname>,
    /// Print only the contact names, one per line.
    #[arg(short = 'q', long = "names-only")]
    pub names_only: bool,
}

impl LsCmd {
    /// Print the address book, or one person's devices when a petname is given.
    ///
    /// Two views on the same tree, split by what each is for. The overview (`contact ls`) is a scannable
    /// map: short keys, a device-less person collapsed to one line, a multi- or named-device person shown
    /// as an indented block. The detail (`contact ls <name>`) is copy-pasteable: full keys under one
    /// person. `-q` cuts the overview to bare names for a long list.
    pub async fn run(self, store: ContactsStore) -> eyre::Result<()> {
        let contacts = store.contacts();
        match &self.petname {
            None if self.names_only => print_names(contacts),
            None => print_overview(contacts),
            Some(petname) => print_detail(contacts, petname)?,
        }
        Ok(())
    }
}

/// The overview: every contact, short keys, a device-less person on one line and everyone else as an
/// indented person -> devices block. The two-space indent reads as a tree at a glance and stays
/// copy-pasteable (the `contact ls` decision in CLI-DESIGN); keys are short here since this is a map, not
/// a place to copy a key from (that is `contact ls <name>`).
fn print_overview(contacts: &Contacts) {
    let mut any = false;
    for petname in contacts.petnames() {
        any = true;
        let devices: Vec<_> = contacts.devices(petname).into_iter().flatten().collect();
        match devices.as_slice() {
            // A person with only the implicit default device is one line: name, then its key inline. No
            // `(default)` noise, since a device-less contact never named a device to begin with.
            [(label, node)] if label.as_str() == DeviceLabel::DEFAULT => {
                println!(
                    "{:<width$}{}",
                    petname.as_str(),
                    node.short(),
                    width = NAME_COL
                );
            }
            // A multi- or named-device person is a header with its devices indented beneath, columns
            // aligned so the keys line up down the block.
            _ => {
                println!("{petname}");
                print_devices(&devices, NodeId::short);
            }
        }
    }
    if !any {
        println!("no contacts yet; add one with `swoosh contact add <name> <key>`");
    }
}

/// The detail for one person: a header and their devices indented beneath with FULL keys, so a key can
/// be copied straight out of the block. An unknown name names the fix, matching the resolve error.
fn print_detail(contacts: &Contacts, petname: &Petname) -> eyre::Result<()> {
    let Some(devices) = contacts.devices(petname) else {
        eyre::bail!(
            "unknown contact '{petname}'; add it with `swoosh contact add {petname} <key>`"
        );
    };
    println!("{petname}");
    print_devices(&devices.collect::<Vec<_>>(), |node| node.to_string());
    Ok(())
}

/// Just the names, one per line, for a terse view of a long list.
fn print_names(contacts: &Contacts) {
    for petname in contacts.petnames() {
        println!("{petname}");
    }
}

/// Print a person's devices as an aligned `  label  key` block, rendering each key with `key` (short in
/// the overview, full in the detail). The label column is padded to the widest label so the keys align.
fn print_devices(devices: &[(&DeviceLabel, &NodeId)], key: impl Fn(&NodeId) -> String) {
    let width = devices
        .iter()
        .map(|(label, _)| label.as_str().len())
        .max()
        .unwrap_or(0);
    for (label, node) in devices {
        println!("  {:<width$}  {}", label.as_str(), key(node));
    }
}

/// The column a device-less contact's key starts at in the overview, so single-line and header rows read
/// as one table.
const NAME_COL: usize = 10;
