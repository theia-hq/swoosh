//! `swoosh grant issue <service>`: mint a `sheer:` capability link for one of this node's services.
//!
//! A local verb: it signs with this node's persisted identity (the key an exposed service roots at) and
//! binds no transport. Bare, the link is a BEARER slip, anyone holding it may present it, so short expiry is
//! its revocation story. `--for <who>` binds it, kind carried in a typed prefix: a raw key or `<person>/<device>`
//! binds ONE device (theft-resistant, non-delegable, standing access for that device alone); `fleet:<person>`
//! or `fleet:<signet-key>` binds a whole fleet (every device that person's signet vouches for). A BARE person
//! is refused: you must type `fleet:` to widen, so a device bind can never silently become a fleet bind. It
//! calls tightbeam's cap leaves under swoosh's own key, so the link a peer presents to `swoosh serve` roots at
//! the same key swoosh serves under, with no allowlist to keep in sync. For a device bind it reads the address
//! book to resolve a `petname/device` to that device's key; for a fleet bind by petname it reads the person's
//! stored signet (`swoosh contact signet`).

use core::str::FromStr;
use std::path::Path;

use bifrost::NodeId;
use clap::Args;
use nauthy::{Cap, Service};
use tightbeam::duration::Lifetime;
use tightbeam::identity::AsVerifyKey as _;

use crate::contacts::{ContactRef, ContactRefParseError, Contacts, ContactsStore, Petname};
use crate::grants::{self, Delegation, GrantKind, GrantRecord, Grants};
use crate::identity::{self, Identity};

/// Mint a `sheer:` capability link granting one service.
///
/// The link roots at this node's identity, so a connector needs no separate node id and the exposer needs
/// no allowlist to keep in sync. Bare it is a bearer slip (delegable with `--delegable`); `--for <who>` binds
/// it to a device or a fleet, which are theft-resistant and non-delegable by construction, so `--delegable`
/// conflicts with any bind.
#[derive(Debug, Args)]
pub struct ShareCmd {
    /// The service the link grants (as named in `serve`, e.g. `ssh`).
    #[arg(value_name = "service")]
    pub service: Service,
    /// How long the link is valid, e.g. `2h`, `30m`, `90s`. Short-expiry is the bearer revocation story.
    #[arg(long, value_name = "duration", default_value = "1h")]
    pub expires: Lifetime,
    /// Bind to a device or fleet: `<person>/<device>`, a key, or `fleet:<person>`.
    #[arg(
        long = "for",
        value_name = "who",
        long_help = "Bind the grant to a device or a fleet. `<person>/<device>` or a raw key binds ONE \
                     device (theft-resistant, non-delegable); `fleet:<person>` (resolved to their stored \
                     signet) or `fleet:<signet-key>` binds a whole fleet. A bare person is refused: you \
                     must type `fleet:` to widen, so a device bind can never silently become a fleet bind."
    )]
    pub bind: Option<GrantFor>,
    /// Let the holder narrow and re-share the link (a delegable bearer slip); not valid with a bind.
    #[arg(long)]
    pub delegable: bool,
}

impl ShareCmd {
    /// Sign the link under swoosh's persisted identity, record it, frame the mint on stderr, and print the
    /// link on stdout. Reads the store to resolve a `--for` device address to its key or a `--for fleet:<person>`
    /// to that person's stored signet; the bearer path never touches the address book.
    pub async fn run(self, store: ContactsStore, key: Option<&Path>) -> eyre::Result<()> {
        // A bound grant is theft-resistant, so it cannot be re-shared: `--delegable` is only meaningful for a
        // bearer link. Reject the combination with a message that says WHY (a bound slip cannot be delegated),
        // rather than clap's generic "cannot be used with" line.
        if self.delegable && self.bind.is_some() {
            eyre::bail!(
                "a bound grant (--for) is theft-resistant and cannot be delegated; drop --delegable, or issue a bearer link (no --for) if you need to delegate"
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
        // One `--for` token, kind carried in its typed prefix: a device bind, a fleet bind, or (no `--for`) a
        // bearer slip. The shape of the grant (its link, kind, delegability, and recorded holder) follows from
        // which. One `Option` cannot hold two binds, so a device-AND-fleet state is unrepresentable here.
        let (link, kind, delegation, holder) = match &self.bind {
            Some(GrantFor::Device(target)) => {
                let node = resolve_one_device(target, store.contacts())?;
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
            Some(GrantFor::Fleet(target)) => {
                let fleet = resolve_fleet_root(target, store.contacts())?;
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
            None => {
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

/// The WHO a `grant issue --for` token names: one device, or a whole fleet.
///
/// Parsed SYNTACTICALLY at the clap boundary (no store needed); the petname arms resolve against the contact
/// store in [`run`](ShareCmd::run), the exact pattern the reach `Peer` type uses. The guardrail lives in the
/// PARSE: widening to a fleet REQUIRES the literal `fleet:` prefix, so a bare `alice` can never silently widen
/// to a whole person; it is a hard parse error that teaches the two explicit forms.
#[derive(Debug, Clone)]
pub enum GrantFor {
    /// Bind ONE device: a raw node id, or a `petname/device` address (never a bare person).
    Device(DeviceTarget),
    /// Bind a whole FLEET: `fleet:<petname>` (resolved to the person's stored signet) or `fleet:<raw-signet-key>`.
    Fleet(FleetTarget),
}

/// The device a `--for` token binds to: a raw node id, or a `petname/device` address resolved at issue time.
#[derive(Debug, Clone)]
pub enum DeviceTarget {
    /// A raw node id: one canonical device, no store lookup (preserves the old `--for <key>` = one device).
    Raw(NodeId),
    /// A `petname/device` address, resolved to one device against the store at issue time.
    Named(ContactRef),
}

/// The fleet a `--for fleet:` token binds to: a raw signet key, or a petname whose stored signet is the root.
#[derive(Debug, Clone)]
pub enum FleetTarget {
    /// A raw signet key: the fleet root, verbatim (preserves the old `--for-fleet <key>`).
    Raw(NodeId),
    /// A petname whose stored signet is the fleet root (resolved against the store at issue time).
    Named(Petname),
}

impl FromStr for GrantFor {
    type Err = GrantForParseError;

    /// Encode the whole grammar and every guardrail as a parse decision. The kind is split on the FIRST `:`,
    /// so the typed prefix decides device-vs-fleet before any body parse: widening is explicit, never silent.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // Typed prefix first: the kind is in the token, so widening is explicit.
        if let Some(body) = text.strip_prefix("fleet:") {
            // A fleet is a whole PERSON: a raw signet key, or a bare petname. NOT a device address.
            if let Ok(node) = body.parse::<NodeId>() {
                return Ok(Self::Fleet(FleetTarget::Raw(node)));
            }
            let petname = body
                .parse::<Petname>()
                .map_err(|_| GrantForParseError::FleetBody(body.to_owned()))?;
            return Ok(Self::Fleet(FleetTarget::Named(petname)));
        }
        if let Some(name) = text.strip_prefix("cluster:") {
            // Reserved but not built: bail cleanly, the same defer the old fleet-not-built path used.
            return Err(GrantForParseError::ReservedCluster(name.to_owned()));
        }
        if let Some((kind, _)) = text.split_once(':') {
            return Err(GrantForParseError::UnknownKind(kind.to_owned()));
        }
        // No prefix. A raw key is one device; a `petname/device` is one device; a BARE person is refused.
        if let Ok(node) = text.parse::<NodeId>() {
            return Ok(Self::Device(DeviceTarget::Raw(node)));
        }
        let reference: ContactRef = text.parse()?;
        if reference.device().is_none() {
            // The guardrail: no bare-person widening. You must TYPE `fleet:` to widen, or name a device.
            return Err(GrantForParseError::BarePerson(reference.petname().clone()));
        }
        Ok(Self::Device(DeviceTarget::Named(reference)))
    }
}

/// Why a `--for` token was not a valid [`GrantFor`]. Every arm teaches the explicit forms, so a mistyped or
/// too-wide target is refused at parse with the fix, never a silent misbind.
#[derive(Debug, thiserror::Error)]
pub enum GrantForParseError {
    /// The token was a `petname/device` address whose parts were invalid.
    #[error("invalid `--for` target")]
    Contact(#[from] ContactRefParseError),
    /// A bare person: the widening guardrail. You must type `fleet:` to bind a whole fleet, or name a device.
    #[error(
        "`--for {0}` is a whole person; type `--for fleet:{0}` to bind their fleet, or `--for {0}/laptop` \
         for one device"
    )]
    BarePerson(Petname),
    /// A `fleet:<body>` whose body was neither a petname nor a raw signet key (a device address, say).
    #[error(
        "`--for fleet:{0}` is neither a petname nor a signet key; a fleet names a whole person \
         (`fleet:alice` or `fleet:<signet-key>`), not a device"
    )]
    FleetBody(String),
    /// A `cluster:<name>` token: reserved for named recipient sets, not built yet.
    #[error(
        "`--for cluster:{0}` is reserved but not built yet; use `--for fleet:<person>` for a fleet, or \
         `--for <person>/<device>` for one device"
    )]
    ReservedCluster(String),
    /// A `<kind>:...` token whose prefix is not a known target kind.
    #[error(
        "`--for {0}:` is not a known kind; use `fleet:<person>` for a fleet, or `<person>/<device>` / \
         `<key>` for one device"
    )]
    UnknownKind(String),
}

/// Resolve a `--for fleet:<who>` token to the SIGNET root it binds. A raw signet key resolves to itself; a
/// petname resolves to that person's STORED signet. A petname with no signet on file is a teaching error
/// naming the fix (record it with `swoosh contact signet`), never a paste-a-raw-key dead end.
fn resolve_fleet_root(
    target: &FleetTarget,
    contacts: &Contacts,
) -> eyre::Result<nauthy::VerifyKey> {
    match target {
        FleetTarget::Raw(node) => Ok(node.verify_key()),
        FleetTarget::Named(petname) => {
            let binding = contacts.signet(petname).ok_or_else(|| {
                eyre::eyre!(
                    "no signet on file for `{petname}`; ask them for their signet key (`swoosh identity`) \
                     and record it with `swoosh contact signet {petname} <key>`, then retry `--for fleet:{petname}`"
                )
            })?;
            Ok(binding.node.verify_key())
        }
    }
}

/// Resolve a `--for` device token to exactly ONE device, returning its canonical node id. A raw node id
/// already names one device. A `petname/device` resolves against the address book. A bare person can never
/// reach here: `GrantFor::from_str` refused it at parse, so a `DeviceTarget::Named` always carries a device
/// by construction.
fn resolve_one_device(target: &DeviceTarget, contacts: &Contacts) -> eyre::Result<NodeId> {
    match target {
        DeviceTarget::Raw(node) => Ok(*node),
        DeviceTarget::Named(reference) => {
            match contacts.resolve_candidates(reference)?.as_slice() {
                [one] => Ok(one.node),
                [] => eyre::bail!(
                    "no device `{reference}` in your contacts; add it with `swoosh contact add {reference} <node-id>`"
                ),
                _ => {
                    eyre::bail!("`{reference}` resolves to more than one device; name exactly one")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn petname(name: &str) -> Petname {
        name.parse().expect("valid petname in test")
    }

    /// A raw signet key resolves to the [`VerifyKey`](nauthy::VerifyKey) it names: `--for fleet:<raw-key>`
    /// treats the node id as a whole fleet (a signet), so the resolved key is exactly the bound fleet root.
    /// (The old `--for-fleet <key>` path, preserved.)
    #[test]
    fn resolve_fleet_root_accepts_a_raw_signet_key() {
        let signet = NodeId::from_ed25519_secret(&[5u8; 32]);
        let contacts = Contacts::default();
        let resolved =
            resolve_fleet_root(&FleetTarget::Raw(signet), &contacts).expect("a raw key resolves");
        assert_eq!(
            resolved,
            signet.verify_key(),
            "the resolved fleet root is the key the token named"
        );
    }

    /// `--for fleet:<petname>` resolves to that person's STORED signet, then a signet slip minted for it
    /// records `GrantKind::Fleet` with the resolved signet key as its holder (the whole-fleet blast radius,
    /// revocable at that one key). Proves piece 1's resolution wires into the mint.
    #[test]
    fn resolve_fleet_root_by_petname_resolves_the_stored_signet_and_mints_a_fleet_grant() {
        let signet = NodeId::from_ed25519_secret(&[5u8; 32]);
        let mut contacts = Contacts::default();
        contacts.set_signet(petname("alice"), signet);

        let resolved = resolve_fleet_root(&FleetTarget::Named(petname("alice")), &contacts)
            .expect("alice's stored signet resolves");
        assert_eq!(
            resolved,
            signet.verify_key(),
            "the fleet root is alice's stored signet"
        );

        // Mint a signet slip for the resolved root and record it exactly as `run` does; the holder is the
        // resolved signet key, so revoke-by-holder cuts the whole fleet.
        let work = nauthy::Identity::from_secret(&[1u8; 32]).expect("valid work secret");
        let service: Service = "ssh".parse().expect("valid service");
        let cap = work
            .mint_signet_slip(
                &service,
                resolved,
                nauthy::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint signet slip");
        let record = GrantRecord {
            service: Service::clone(&service),
            kind: GrantKind::Fleet,
            delegation: Delegation::Sealed,
            holder: resolved.to_string(),
            root_id: cap.root_revocation_id().expect("root id"),
            expiry: nauthy::expires_in(core::time::Duration::from_secs(3600)),
        };
        assert_eq!(record.kind, GrantKind::Fleet);
        assert_eq!(
            record.holder,
            signet.verify_key().to_string(),
            "the recorded holder is the resolved signet key"
        );
    }

    /// A petname with NO signet on file is a TEACHING error naming the fix (`swoosh contact signet`), never a
    /// paste-a-raw-key dead end. This is the whole point of piece 1: a name never bottoms out at "go paste a
    /// key".
    #[test]
    fn resolve_fleet_root_missing_signet_teaches_the_hand_add_recipe() {
        let contacts = Contacts::default();
        let error = resolve_fleet_root(&FleetTarget::Named(petname("bob")), &contacts)
            .expect_err("bob has no signet on file");
        let message = format!("{error:#}");
        assert!(
            message.contains("bob") && message.contains("swoosh contact signet"),
            "the error names the person and the hand-add recipe: {message}"
        );
        assert!(
            !message.contains("paste"),
            "the error must not dead-end at 'paste a raw key': {message}"
        );
    }

    /// The typed prefix decides device-vs-fleet at PARSE: `fleet:alice` is a named fleet, `fleet:<key>` a raw
    /// fleet, `alice/laptop` a named device, a raw key a raw device.
    #[test]
    fn grant_for_parses_each_target_shape() {
        let key = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();

        assert!(matches!(
            "fleet:alice".parse::<GrantFor>(),
            Ok(GrantFor::Fleet(FleetTarget::Named(_)))
        ));
        assert!(matches!(
            format!("fleet:{key}").parse::<GrantFor>(),
            Ok(GrantFor::Fleet(FleetTarget::Raw(_)))
        ));
        assert!(matches!(
            "alice/laptop".parse::<GrantFor>(),
            Ok(GrantFor::Device(DeviceTarget::Named(_)))
        ));
        assert!(matches!(
            key.parse::<GrantFor>(),
            Ok(GrantFor::Device(DeviceTarget::Raw(_)))
        ));
    }

    /// A BARE person is refused at PARSE (the widening guardrail), with a message naming BOTH explicit forms:
    /// `fleet:alice` to widen, `alice/<device>` for one device. Stricter and earlier than a run-time bail.
    #[test]
    fn grant_for_refuses_a_bare_person_at_parse() {
        let error = "alice"
            .parse::<GrantFor>()
            .expect_err("a bare person is refused");
        assert!(matches!(error, GrantForParseError::BarePerson(_)));
        let message = format!("{error}");
        assert!(
            message.contains("fleet:alice") && message.contains("alice/laptop"),
            "the refusal names both explicit forms: {message}"
        );
    }

    /// `fleet:alice/laptop` is a device address behind a `fleet:` prefix: it is neither a petname (the slash
    /// fails) nor a raw key, so it is a `FleetBody` error teaching that a fleet names a whole person.
    #[test]
    fn grant_for_rejects_a_device_address_under_the_fleet_prefix() {
        let error = "fleet:alice/laptop"
            .parse::<GrantFor>()
            .expect_err("a fleet is not a device");
        assert!(matches!(error, GrantForParseError::FleetBody(_)));
    }

    /// `cluster:` is reserved-not-built (a clean teaching bail), and an unknown `<kind>:` prefix is a
    /// distinct `UnknownKind`. The grammar is closed: every prefixed token gets a teaching error, never a
    /// silent miss.
    #[test]
    fn grant_for_reserves_cluster_and_rejects_an_unknown_kind() {
        assert!(matches!(
            "cluster:home".parse::<GrantFor>(),
            Err(GrantForParseError::ReservedCluster(_))
        ));
        assert!(matches!(
            "foo:bar".parse::<GrantFor>(),
            Err(GrantForParseError::UnknownKind(_))
        ));
    }

    /// A `--for fleet:` mint's stderr frame echoes the RESOLVED signet key (so the issuer can catch a wrong
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
