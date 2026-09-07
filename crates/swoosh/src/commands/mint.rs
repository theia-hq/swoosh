//! `swoosh mint <label>`: derive a device identity from your signet and emit its authkey.
//!
//! Your persisted key is your SIGNET (person-zero, `me`). `mint ci-runner` derives a distinct child
//! identity for that device, records it as the contact `me/ci-runner` (so you can address the machine by
//! name), and prints an `authkey:` the machine adopts to become that identity and to trust your signet.
//! A local verb: it reads your key and edits the address book, binds no transport, reaches nobody. The
//! signet stays on this box; only the derived child seed leaves, inside the authkey.

use bifrost::NodeId;
use clap::Args;
use nauthy::{Cap, Service};
use tightbeam::duration::Lifetime;
use zeroize::Zeroize as _;

use crate::authkey;
use crate::contacts::{ContactsStore, DeviceLabel, Petname};
use crate::grants::{Delegation, GrantKind, GrantRecord, Grants};
use crate::home::Home;
use crate::identity::{self, Identity};

/// The reserved petname for your own devices: your signet is person-zero, and each device it derives
/// lives under `me/<label>`, addressed exactly like a saved contact (`swoosh ssh me/ci-runner`).
const ME: &str = "me";

/// The service a device-membership badge records in the mint-log ledger. A `member(true)` badge is NOT
/// scoped to one service (it admits the device at the whole family gate), but a [`GrantRecord`] carries a
/// mandatory service, so a minted badge records under this reserved word. It is what `swoosh grant ls`
/// groups the badge under; the value (and whether `ls` should render membership distinctly from a real
/// service) is a display/vocabulary call flagged to the CLI-Architect + Product-Lead. The ledger record
/// exists to make the badge REVOCABLE by holder; revoke-by-holder keys on holder + root id, never this.
const MEMBER_BADGE_SERVICE: &str = "member";

/// Derive a device identity under your signet and print an authkey for the machine to adopt.
#[derive(Debug, Args)]
pub struct MintCmd {
    /// the device label, e.g. `ci-runner` or `desk` (recorded as `me/<label>`)
    #[arg(value_name = "label")]
    pub label: String,
    /// how long the device badge stays valid, e.g. `90d`, `365d`, `12h` (default 90d)
    #[arg(
        long,
        value_name = "duration",
        long_help = "How long the minted device badge stays valid before it must be re-minted, e.g. \
                     `90d`, `365d`, `12h`. Defaults to 90 days when omitted.\n\nThis is also your LEAK \
                     WINDOW: offline there is no way to split the authkey's exposure from the badge's \
                     lifetime, so a leaked authkey is adoptable for exactly this long. Mint short for a \
                     CI secret, longer for a provision-once device. The badge expiry is enforced at the \
                     gate (on dial), NOT re-checked at adopt time, so mint immediately before the machine \
                     adopts: `--expires 10m` means the badge is dead 10 minutes after MINT, adopted or not."
    )]
    pub expires: Option<Lifetime>,
}

impl MintCmd {
    /// Derive the child, record `me/<label>`, and print its authkey.
    pub async fn run(self, mut store: ContactsStore, home: &Home) -> eyre::Result<()> {
        // Validate the label as a device label before touching the key, so a bad name fails fast.
        let device: DeviceLabel = self.label.parse()?;
        // Deriving needs the signet present, so resolve it as a persisted identity (creating one on first
        // use, exactly as `swoosh identity` would).
        let signet = identity::resolve(Identity::Persisted, home).await?;

        let mut seed = signet.derive_child_seed(device.as_str());
        let node = NodeId::from_ed25519_secret(&seed);
        // The badge lifetime is the operator's `--expires`, or the ratified default when absent. This same
        // window bounds the badge (via `sign_device_badge`) and the ledger record's expiry below, so the
        // two agree on the one lifetime the token really has.
        let ttl = self
            .expires
            .map_or(identity::DEVICE_BADGE_TTL, Lifetime::duration);
        // The signet signs a membership badge FOR this device: rooted at the signet (so the family gate,
        // which trusts the signet, admits it) and bound to the device's own node id (so an intercepted
        // badge cannot be replayed from another key). The device could never mint this itself -- its own
        // self-sign roots at its child key and is refused -- which is exactly why the signet mints it here,
        // once, and the device carries it. The signet SECRET stays in `signet`; only the signed PUBLIC
        // badge (a `sheer:` link) leaves, alongside the child seed and the signet's public node id.
        let badge = signet.sign_device_badge(node, ttl)?;
        let token = authkey::encode(&seed, signet.node_id(), &badge);
        seed.zeroize();

        // Record `me/<label> -> node` so the machine is addressable by name once it adopts the seed. The
        // reserved `me` petname is a constant and always parses; `?` satisfies the no-`expect` rule.
        let me: Petname = ME.parse()?;
        store.contacts_mut().add(me, Some(device.clone()), node);
        store.save().await?;

        // Record the badge in the mint-log ledger so `swoosh grant revoke me/<label>` can later cut this
        // device: without this line the ledger has no record of the minted badge, revoke-by-holder finds
        // nothing, and the badge stands until its TTL, unrevocable. Same append `grant issue` runs, keyed
        // on the device's canonical node id (what `me/<label>` resolves to) and the badge's ROOT revocation
        // id (a pure function of the badge bytes, recovered by re-parsing the link; the ledger stores only
        // this opaque id, never the presentable badge). Non-delegable: a membership badge is device-bound.
        let root_id = Cap::parse(&badge)?.root_revocation_id().ok_or_else(|| {
            eyre::eyre!("minted device badge has no authority block to key revocation on")
        })?;
        let record = GrantRecord {
            service: MEMBER_BADGE_SERVICE.parse::<Service>()?,
            kind: GrantKind::Device,
            delegation: Delegation::Sealed,
            holder: node.to_string(),
            root_id,
            expiry: nauthy::Request::expires_in(ttl),
        };
        Grants::at(home.grants()).append(&record).await?;

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
