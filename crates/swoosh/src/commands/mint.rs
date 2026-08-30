//! `swoosh mint <label>`: derive a device identity from your signet and emit its authkey.
//!
//! Your persisted key is your SIGNET (person-zero, `me`). `mint ci-runner` derives a distinct child
//! identity for that device, records it as the contact `me/ci-runner` (so you can address the machine by
//! name), and prints an `authkey:` the machine adopts to become that identity and to trust your signet.
//! A local verb: it reads your key and edits the address book, binds no transport, reaches nobody. The
//! signet stays on this box; only the derived child seed leaves, inside the authkey.

use std::path::Path;

use core::time::Duration;

use bifrost::NodeId;
use clap::Args;
use nauthy::expires_in;
use zeroize::Zeroize as _;

use crate::authkey;
use crate::contacts::{ContactsStore, DeviceLabel, Petname};
use crate::identity::{self, Identity};

/// The reserved petname for your own devices: your signet is person-zero, and each device it derives
/// lives under `me/<label>`, addressed exactly like a saved contact (`swoosh ssh me/ci-runner`).
const ME: &str = "me";

/// How long a minted device badge is valid. A provisioned device (a CI runner, a second laptop) is a
/// standing member, so the badge is effectively non-expiring; `expires_in` saturates a century out. A
/// shorter, rotatable TTL is a fast-follow, not v1 (the seed the badge rides with is the real secret).
const BADGE_TTL: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

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
        // Sign the device's membership badge: a `theia:member` cap rooted at the signet, BOUND to this
        // child's node id so it grants only when the proven dialer IS this device (a leaked badge is
        // useless without the matching seed). Sealed so the device cannot attenuate it into a slip and
        // hand it on. This is the "A vouches B once" step: thereafter the device carries its own proof.
        let badge = signet
            .cap_identity()?
            .mint_member(node, expires_in(BADGE_TTL))?
            .seal()?
            .link()?;
        let token = authkey::encode(&seed, signet.node_id(), Some(&badge));
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
