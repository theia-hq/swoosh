//! `swoosh grant issue <service>`: mint a `sheer:` capability link for one of this node's services.
//!
//! A local verb: it signs with this node's persisted identity (the key an exposed service roots at) and
//! binds no transport. Bare, the link is a BEARER slip, anyone holding it may present it, so short expiry is
//! its revocation story. `--for <device>` binds it to one device (theft-resistant, non-delegable, standing
//! access for that device alone); `--for-fleet <peer>` binds it to a whole fleet (every device that person
//! adopts). It calls tightbeam's cap leaves under swoosh's own key, so the link a peer presents to
//! `swoosh serve` roots at the same key swoosh serves under, with no allowlist to keep in sync. For a
//! device bind it reads the address book to resolve a `petname/device` to that device's key.

use std::path::Path;

use bifrost::NodeId;
use clap::Args;
use nauthy::{Cap, Service};
use tightbeam::duration::Lifetime;
use tightbeam::identity::AsVerifyKey as _;

use crate::contacts::{ContactRef, Contacts, ContactsStore};
use crate::grants::{self, Delegation, GrantKind, GrantRecord, Grants};
use crate::identity::{self, Identity};

/// Mint a `sheer:` capability link granting one service.
///
/// The link roots at this node's identity, so a connector needs no separate node id and the exposer needs
/// no allowlist to keep in sync. Bare it is a bearer slip (delegable with `--delegable`); `--for` /
/// `--for-fleet` bind it to a device or a fleet, which are theft-resistant and non-delegable by
/// construction, so `--delegable` conflicts with either bind.
#[derive(Debug, Args)]
pub struct ShareCmd {
    /// The service the link grants (as named in `serve`, e.g. `ssh`).
    #[arg(value_name = "service")]
    pub service: Service,
    /// How long the link is valid, e.g. `2h`, `30m`, `90s`. Short-expiry is the bearer revocation story.
    #[arg(long, value_name = "duration", default_value = "1h")]
    pub expires: Lifetime,
    /// Bind to ONE device (a node id or `petname/device`): theft-resistant, non-delegable, standing access.
    #[arg(long = "for", value_name = "peer", group = "binding")]
    pub bind_device: Option<String>,
    /// Bind to a whole FLEET (a person's signet): every device they adopt may use it, theft-resistant.
    #[arg(long = "for-fleet", value_name = "peer", group = "binding")]
    pub bind_fleet: Option<String>,
    /// Let the holder narrow and re-share the link (a delegable bearer slip); not valid with a bind.
    #[arg(long)]
    pub delegable: bool,
}

impl ShareCmd {
    /// Sign the link under swoosh's persisted identity, record it, frame the mint on stderr, and print the
    /// link on stdout. Reads the store only to resolve a `--for` device address to its key; the bearer and
    /// fleet paths never touch the address book.
    pub async fn run(self, store: ContactsStore, key: Option<&Path>) -> eyre::Result<()> {
        // A bound grant is theft-resistant, so it cannot be re-shared: `--delegable` is only meaningful for a
        // bearer link. Reject the combination with a message that says WHY (a bound slip cannot be delegated),
        // rather than clap's generic "cannot be used with" line.
        if self.delegable && (self.bind_device.is_some() || self.bind_fleet.is_some()) {
            eyre::bail!(
                "a bound grant (--for / --for-fleet) is theft-resistant and cannot be delegated; drop --delegable, or issue a bearer link (no bind) if you need to delegate"
            );
        }
        // The link roots at swoosh's stable key (the one an exposed service is reached at), so resolve the
        // persisted identity, creating one on first use exactly as `swoosh identity` would.
        let secret = identity::resolve(Identity::Persisted, key).await?;
        let cap_identity = secret.cap_identity()?;
        let lifetime = self.expires.duration();
        // The absolute expiry recorded in the ledger. `mint_*_link` recomputes its own from the same lifetime,
        // so the two agree to within the sub-millisecond between these calls, which is expiry enough for an
        // audit record.
        let expiry = nauthy::expires_in(lifetime);
        // `--for` and `--for-fleet` are a mutually-exclusive clap group, so at most one bind is set; the shape
        // of the grant (its link, kind, delegability, and recorded holder) follows from which.
        let (link, kind, delegation, holder) = match (&self.bind_device, &self.bind_fleet) {
            (Some(peer), None) => {
                let node = resolve_one_device(peer, store.contacts())?;
                let link = tightbeam::tunnel::mint_bound_link(
                    &cap_identity,
                    &self.service,
                    node.verify_key(),
                    lifetime,
                )?;
                // Record the RESOLVED device node id (canonical), so revoke-by-holder matches whether the
                // issuer named a petname or the raw key.
                (
                    link,
                    GrantKind::Device,
                    Delegation::Sealed,
                    node.to_string(),
                )
            }
            (None, Some(peer)) => {
                let fleet = resolve_signet_root(peer)?;
                let link = tightbeam::tunnel::mint_signet_link(
                    &cap_identity,
                    &self.service,
                    fleet,
                    lifetime,
                )?;
                // Record the RESOLVED signet key (canonical), so `grant revoke <holder>` matches a pasted
                // signet key. Revoking the slip cuts the WHOLE fleet's access at once.
                (
                    link,
                    GrantKind::Fleet,
                    Delegation::Sealed,
                    fleet.to_string(),
                )
            }
            (None, None) => {
                let link = tightbeam::tunnel::mint_link(
                    &cap_identity,
                    &self.service,
                    lifetime,
                    self.delegable,
                )?;
                let delegation = if self.delegable {
                    Delegation::Delegable
                } else {
                    Delegation::Sealed
                };
                // A bearer slip names no one, so it records the ANYONE placeholder as its holder.
                (
                    link,
                    GrantKind::Bearer,
                    delegation,
                    grants::ANYONE.to_owned(),
                )
            }
            (Some(_), Some(_)) => {
                // clap's arg group already fences these apart, so this is not reachable through the CLI; a
                // direct caller (a test, an embedder) that sets both gets a typed refusal, never a panic
                // (house rule: never panic on input).
                eyre::bail!(
                    "--for and --for-fleet cannot both be set; bind a device OR a fleet, not both"
                )
            }
        };
        // Record the grant in the mint-log ledger BEFORE printing, so the issuer's index of who can reach
        // what is durable the instant the link exists. The ROOT revocation id is a pure function of the
        // minted token's bytes, recovered by re-parsing the link we just produced (the ledger stores this
        // opaque id, never the presentable link), so revoke-by-holder can later cut this grant at its root.
        let root_id = Cap::parse(&link)?.root_revocation_id().ok_or_else(|| {
            eyre::eyre!("minted capability has no authority block to key revocation on")
        })?;
        let record = GrantRecord {
            service: Service::clone(&self.service),
            kind,
            delegation,
            holder,
            root_id,
            expiry,
        };
        Grants::at(crate::config::grants_path(key)?)
            .append(&record)
            .await?;
        // Frame the mint on STDERR (what was minted, its blast radius, and how to revoke it) so a person sees
        // the consequence; STDOUT gets ONLY the link, so `swoosh grant issue ... > link.txt` stays clean.
        eprint!("{}", frame(&record, self.service.as_str(), lifetime));
        println!("{link}");
        Ok(())
    }
}

/// The human-readable framing printed to stderr when a grant is issued: what was minted, who can use it, how
/// long it lasts, and the recipe to revoke it. A bound grant names its device and the `grant revoke <holder>`
/// recipe; a bearer link says anyone holding it may use it and points revocation at the link itself.
fn frame(record: &GrantRecord, service: &str, lifetime: core::time::Duration) -> String {
    let span = grants::humanize(lifetime);
    match record.kind {
        GrantKind::Device => format!(
            "issued a device-bound grant for `{service}` to {holder}\n  only that device can use it \
             (theft-resistant, non-delegable); expires in {span}\n  revoke: swoosh grant revoke {holder}\n",
            holder = record.holder,
        ),
        GrantKind::Fleet => format!(
            "issued a fleet-bound grant for `{service}` to fleet signet {holder}\n  every device that \
             signet vouches for can use it (theft-resistant); expires in {span}\n  revoke: swoosh grant \
             revoke {holder}\n",
            holder = record.holder,
        ),
        GrantKind::Bearer => {
            let reshare = match record.delegation {
                Delegation::Delegable => " the holder may narrow and re-share it.",
                Delegation::Sealed => "",
            };
            format!(
                "issued a bearer grant for `{service}`\n  anyone holding the link can use it; expires in \
                 {span}.{reshare}\n  revoke: paste the link to `swoosh grant revoke <link>`, or let it expire\n"
            )
        }
    }
}

/// Resolve a `--for-fleet <peer>` to the SIGNET root it binds. v1: a RAW signet key only (the hire hands
/// over their signet pubkey out of band). A petname cannot yet resolve to a foreign signet, because contacts
/// hold DEVICE keys, not a person's signet root, so a petname bails with a teaching message rather than
/// binding the wrong key. The petname -> foreign-signet path is a later slice (deliberation 42, section 6).
fn resolve_signet_root(peer: &str) -> eyre::Result<nauthy::VerifyKey> {
    // A raw node id already names one key; `--for-fleet` treats it as a SIGNET (a whole fleet), where `--for`
    // treats the same shape as one device.
    if let Ok(node) = peer.parse::<NodeId>() {
        return Ok(node.verify_key());
    }
    eyre::bail!(
        "--for-fleet needs the peer's SIGNET public key (a raw node id): a petname resolves to device keys, \
         not a signet. Ask `{peer}` for their signet key (`swoosh identity`) and paste it."
    )
}

/// Resolve a `--for` peer to exactly ONE device, returning its canonical node id. A raw node id already names
/// one device. A petname MUST name a specific device (`alice/laptop`): `--for` binds one device, so a bare
/// person is refused UNCONDITIONALLY (even a person with a single device today), because a bare-person bind
/// would silently re-target if they later add a device. Widening to a whole person is what `--for-fleet` is
/// for.
fn resolve_one_device(peer: &str, contacts: &Contacts) -> eyre::Result<NodeId> {
    // A raw node id is already a single, canonical device: bind straight to it, no address book needed.
    if let Ok(node) = peer.parse::<NodeId>() {
        return Ok(node);
    }
    // Otherwise it is a petname address. `--for` binds ONE device, so it must name a specific device.
    let contact: ContactRef = peer.parse()?;
    if contact.device().is_none() {
        eyre::bail!(
            "--for binds one device, but `{peer}` names a whole person. Name a device (e.g. `{peer}/laptop`), or use `--for-fleet {peer}` once fleet grants land."
        );
    }
    match contacts.resolve_candidates(&contact)?.as_slice() {
        [one] => Ok(one.node),
        [] => eyre::bail!(
            "no device `{peer}` in your contacts; add it with `swoosh contact add {peer} <node-id>`"
        ),
        _ => eyre::bail!("`{peer}` resolves to more than one device; name exactly one"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw signet key resolves to the [`VerifyKey`](nauthy::VerifyKey) it names: `--for-fleet` treats the
    /// node id as a whole fleet (a signet), so the resolved key is exactly the bound fleet root.
    #[test]
    fn resolve_signet_root_accepts_a_raw_key() {
        let signet = NodeId::from_ed25519_secret(&[5u8; 32]);
        let resolved = resolve_signet_root(&signet.to_string()).expect("a raw key resolves");
        assert_eq!(
            resolved,
            signet.verify_key(),
            "the resolved fleet root is the key the peer named"
        );
    }

    /// A petname cannot resolve to a foreign SIGNET (contacts hold device keys, not a person's signet root),
    /// so `--for-fleet <petname>` bails with a teaching message rather than binding the wrong key. The v1 gap
    /// (deliberation 42, section 6): the petname -> foreign-signet path is a later slice.
    #[test]
    fn resolve_signet_root_refuses_a_petname_with_a_teaching_message() {
        let error =
            resolve_signet_root("alice").expect_err("a petname must not resolve to a signet");
        let message = format!("{error:#}");
        assert!(
            message.contains("SIGNET") && message.contains("alice"),
            "the bail must teach that a petname is not a signet: {message}"
        );
    }

    /// The `--for-fleet` mint's stderr frame echoes the RESOLVED signet key (so the issuer can catch a wrong
    /// paste), names the fleet posture, and gives the `grant revoke <signet>` recipe keyed by that key.
    #[test]
    fn frame_for_a_fleet_grant_echoes_the_signet_key_and_the_revoke_recipe() {
        let work = nauthy::Identity::from_secret(&[1u8; 32]).expect("valid work secret");
        let fleet = nauthy::Identity::from_secret(&[2u8; 32])
            .expect("valid fleet secret")
            .node_id();
        let service: Service = "ssh".parse().expect("valid service");
        let cap = work
            .mint_signet_slip(
                &service,
                fleet,
                nauthy::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint signet slip");
        let record = GrantRecord {
            service: Service::clone(&service),
            kind: GrantKind::Fleet,
            delegation: Delegation::Sealed,
            holder: fleet.to_string(),
            root_id: cap.root_revocation_id().expect("root id"),
            expiry: nauthy::expires_in(core::time::Duration::from_secs(3600)),
        };
        let blurb = frame(&record, "ssh", core::time::Duration::from_secs(3600));
        assert!(
            blurb.contains(&fleet.to_string()),
            "the frame echoes the resolved signet key so a wrong paste is visible: {blurb}"
        );
        assert!(
            blurb.contains("fleet") && blurb.contains("swoosh grant revoke"),
            "the frame names the fleet posture and the revoke recipe: {blurb}"
        );
    }
}
