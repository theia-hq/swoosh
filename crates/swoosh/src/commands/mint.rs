//! `swoosh mint <label>`: derive a device identity from your signet and emit its authkey.
//!
//! Your persisted key is your SIGNET (person-zero, `me`). `mint ci-runner` derives a distinct child
//! identity for that device, records it as the contact `me/ci-runner` (so you can address the machine by
//! name), and prints an `authkey:` the machine adopts to become that identity and to trust your signet.
//! A local verb: it reads your key and edits the address book, binds no transport, reaches nobody. The
//! signet stays on this box; only the derived child seed leaves, inside the authkey.

use std::path::Path;

use bifrost::NodeId;
use clap::Args;
use zeroize::Zeroize as _;

use crate::authkey;
use crate::contacts::{ContactsStore, DeviceLabel, Petname};
use crate::identity::{self, Identity};

/// The reserved petname for your own devices: your signet is person-zero, and each device it derives
/// lives under `me/<label>`, addressed exactly like a saved contact (`swoosh ssh me/ci-runner`).
const ME: &str = "me";

/// Derive a device identity under your signet and print an authkey for the machine to adopt.
#[derive(Debug, Args)]
pub struct MintCmd {
    /// the device label, e.g. `ci-runner` or `desk` (recorded as `me/<label>`)
    #[arg(value_name = "label")]
    pub label: String,
}

impl MintCmd {
    /// Derive the child, record `me/<label>`, and print its authkey.
    pub async fn run(self, mut store: ContactsStore, key: Option<&Path>) -> eyre::Result<()> {
        // Validate the label as a device label before touching the key, so a bad name fails fast.
        let device: DeviceLabel = self.label.parse()?;
        // Deriving needs the signet present, so resolve it as a persisted identity (creating one on first
        // use, exactly as `swoosh identity` would).
        let signet = identity::resolve(Identity::Persisted, key).await?;

        let mut seed = signet.derive_child_seed(device.as_str());
        let node = NodeId::from_ed25519_secret(&seed);
        let token = authkey::encode(&seed, signet.node_id());
        seed.zeroize();

        // Record `me/<label> -> node` so the machine is addressable by name once it adopts the seed. The
        // reserved `me` petname is a constant and always parses; `?` satisfies the no-`expect` rule.
        let me: Petname = ME.parse()?;
        store.contacts_mut().add(me, Some(device.clone()), node);
        store.save().await?;

        // The authkey is the secret to hand off; the recorded line is what you keep. Blank-frame the token
        // so it is copy-obvious, like `serve` frames the node id.
        println!("{token}\n");
        println!("recorded me/{device} -> {}  [derived]", node.short());
        println!(
            "hand this authkey to the machine (a SECRET: adopting it becomes this identity and trusts your signet)."
        );
        Ok(())
    }
}
