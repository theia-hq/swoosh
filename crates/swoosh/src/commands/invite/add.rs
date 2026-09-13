//! `swoosh invite add <label>`: create an invite for one device and print its `invite:` token.
//!
//! One create leaf, two cells:
//!
//! - `invite add <label> --for <key>` signs a membership badge for a key the DEVICE made and printed
//!   (`swoosh identity`). The token carries no secret, so it is safe over any channel; the device adopts
//!   it and keeps its own identity.
//! - `invite add <label>` derives a child identity from your signet and hands over its seed (today's
//!   `mint`, the CI case): adopting the token BECOMES that identity. The token is a device SECRET.
//!
//! Both record `me/<label> -> key` so the machine is addressable by name once it adopts, and both append
//! a ledger row keyed on the badge's root revocation id, so `invite rm <label>` cuts the badge at once.
//! A local verb: it reads your signet and edits the store, binds no transport, reaches nobody.

use bifrost::NodeId;
use clap::Args;
use nauthy::Cap;
use tightbeam::duration::Lifetime;
use zeroize::Zeroize as _;

use crate::commands::share::{GrantFor, resolve_one_device};
use crate::contacts::{ContactsStore, DeviceLabel, Petname};
use crate::grants::{Delegation, GrantKind, GrantRecord, GrantTarget, Grants};
use crate::home::Home;
use crate::identity::{self, Identity};
use crate::invite::Invite;

/// The reserved petname for your own devices: your signet is person-zero, and each device it vouches for
/// lives under `me/<label>`, addressed exactly like a saved contact (`swoosh ssh me/ci-runner`).
const ME: &str = "me";

/// Create an invite for one device and print it.
#[derive(Debug, Args)]
pub struct AddCmd {
    /// the device label, e.g. `ci-runner` or `desk` (recorded as `me/<label>`)
    #[arg(value_name = "label")]
    pub label: String,
    /// the key it admits; omit to derive a device identity
    #[arg(
        long = "for",
        value_name = "who",
        long_help = "The key this invite admits: a raw node id, or a `<person>/<device>` from your \
                     contacts. Omit `--for` to derive a child identity instead (the invite then carries a \
                     secret seed). An invite admits ONE device at your whole gate; to open one service to \
                     a device or a fleet, use `grant issue`."
    )]
    pub bind: Option<GrantFor>,
    /// how long the invite's badge stays valid, e.g. `90d`, `365d`, `12h` (default 90d)
    #[arg(
        long,
        value_name = "duration",
        long_help = "How long the invite's badge stays valid before the device must be invited again, \
                     e.g. `90d`, `365d`, `12h`. Defaults to 90 days when omitted.\n\nFor a derived invite \
                     (no `--for`) this is also the LEAK WINDOW: the token carries the device seed, and \
                     offline there is no way to split its exposure from the badge's lifetime, so a leaked \
                     derived invite is adoptable for exactly this long. A bound invite (`--for`) carries \
                     no secret; `swoosh invite rm <label>` cuts its badge early. The badge expiry is \
                     enforced at the gate (on dial), NOT re-checked at adopt time, so create the invite \
                     immediately before the machine adopts: `--expires 10m` means the badge is dead 10 \
                     minutes after add, adopted or not."
    )]
    pub expires: Option<Lifetime>,
}

impl AddCmd {
    /// Sign the invite, record `me/<label>` and the ledger row, and print the token.
    pub async fn run(self, mut store: ContactsStore, home: &Home) -> eyre::Result<()> {
        // Validate the label as a device label before touching the key, so a bad name fails fast. The
        // label also may not look like a `--for` widening token (DeviceLabel reserves `fleet:`/`cluster:`).
        let device: DeviceLabel = self.label.parse()?;
        // Signing needs the signet present, so resolve it as a persisted identity (creating one on first
        // use, exactly as `swoosh identity` would).
        let signet = identity::resolve(Identity::Persisted, home).await?;
        // The badge lifetime is the operator's `--expires`, or the ratified default when absent. This same
        // window bounds the badge (via `sign_device_badge`) and the ledger row's expiry below, so the two
        // agree on the one lifetime the token really has.
        let ttl = self
            .expires
            .map_or(identity::DEVICE_BADGE_TTL, Lifetime::duration);

        match self.bind {
            // A fleet row cannot be pre-signed (only the signet can mint an admitting badge and the keys
            // are unknown until each device dials), so the fleet arm rides the enrollment door, not built
            // yet. Refused at RUN time, never at parse: the grammar stays final so the arm is additive.
            Some(GrantFor::Fleet(_)) => Err(fleet_deferred()),
            Some(GrantFor::Device(target)) => {
                // Resolve the shared `--for` device grammar (one resolution home with `grant issue`) to
                // exactly one canonical node id. The device made this key; the signet only signs for it.
                let node = resolve_one_device(&target, store.contacts())?;
                // The signet signs a membership badge FOR this device: rooted at the signet (so a family
                // gate that trusts it admits) and bound to the device's own node id (so an intercepted
                // badge cannot be replayed from another key). The signet SECRET stays in `signet`; only
                // the signed PUBLIC badge leaves.
                let badge = signet.sign_device_badge(node, ttl)?;
                let token = Invite::bound(signet.node_id(), badge.clone());
                record(&mut store, home, &device, node, ttl, &badge).await?;
                // The token carries no secret, so it needs no private hand-off; the record line is what
                // the owner keeps. Blank-frame the token so it is copy-obvious, like `serve` frames the
                // node id.
                println!("{token}\n");
                println!("recorded me/{device} -> {}", node.short());
                println!(
                    "hand this invite back to that key: it admits {} only.",
                    node.short()
                );
                Ok(())
            }
            None => {
                // Derive the child identity and sign its badge, exactly as `mint` always has. The token
                // then carries the child seed, the signet's public id, and the public badge; the signet
                // secret never leaves this process.
                let mut seed = signet.derive_child_seed(device.as_str());
                let node = NodeId::from_ed25519_secret(&seed);
                let badge = signet.sign_device_badge(node, ttl)?;
                let token = Invite::derived(seed, signet.node_id(), badge.clone());
                seed.zeroize();
                record(&mut store, home, &device, node, ttl, &badge).await?;
                println!("{token}\n");
                println!("recorded me/{device} -> {}  [derived]", node.short());
                println!(
                    "hand this invite to the machine (a SECRET: adopting it becomes this identity and \
                     trusts your signet)."
                );
                Ok(())
            }
        }
    }
}

/// Record `me/<label> -> node` in the address book and the badge in the mint-log ledger.
///
/// The ledger row is what makes the invite cancellable: without it `invite rm <label>` finds no root id
/// to revoke and the badge stands until its TTL, unrevocable. It is keyed on the device's canonical node
/// id (what `me/<label>` resolves to) and the badge's ROOT revocation id (a pure function of the badge
/// bytes, recovered by re-parsing the link; the ledger stores only this opaque id, never the badge).
/// Non-delegable: a membership badge is device-bound.
async fn record(
    store: &mut ContactsStore,
    home: &Home,
    device: &DeviceLabel,
    node: NodeId,
    ttl: core::time::Duration,
    badge: &str,
) -> eyre::Result<()> {
    // The reserved `me` petname is a constant and always parses; `?` satisfies the no-`expect` rule.
    let me: Petname = ME.parse()?;
    store.contacts_mut().add(me, Some(device.clone()), node);
    store.save().await?;

    let root_id = Cap::parse(badge)?.root_revocation_id().ok_or_else(|| {
        eyre::eyre!("signed membership badge has no authority block to key revocation on")
    })?;
    let record = GrantRecord {
        // A `member(true)` badge is NOT scoped to one service (it admits the device at the whole family
        // gate), so it records as Membership: `grant ls` groups it under the bare `membership` heading
        // and `invite ls` selects it.
        target: GrantTarget::Membership,
        kind: GrantKind::Device,
        delegation: Delegation::Sealed,
        holder: node.to_string(),
        root_id,
        expiry: nauthy::Request::expires_in(ttl),
    };
    Grants::at(home.grants()).append(&record).await?;
    Ok(())
}

/// The named deferral for the fleet arm: it is reserved grammar (the shared `GrantFor` parser accepts
/// it), refused at run time until the enrollment door is built, so the later arm is additive.
pub(crate) fn fleet_deferred() -> eyre::Report {
    eyre::eyre!(
        "invite add failed: a fleet invite needs the enrollment door, not built yet; invite each device \
         with --for <key>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fleet arm is reserved grammar refused at RUN time with the named deferral (never a parse
    /// error), so the later enrollment arm is additive.
    #[test]
    fn the_fleet_deferral_names_the_door_and_the_fix() {
        let message = format!("{:#}", fleet_deferred());
        assert!(
            message.contains("enrollment door") && message.contains("--for <key>"),
            "the deferral names the missing door and the per-device fix: {message}"
        );
    }
}
