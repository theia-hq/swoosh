//! The one thing every reaching verb must state: how it authenticates.
//!
//! A reaching verb's auth need used to be spread across five hand-synced match arms in `main.rs`, one of
//! which (`self_badge()`) ended in a `_ => Ok(None)` wildcard: a verb the author forgot to list reached a
//! family-gated service carrying no badge, and it still compiled. The [`Reaching`] trait replaces that
//! with a method the compiler forces: a verb cannot compile without stating its [`Credential`], and
//! `Credential` has no "unset" arm to fall through to, so the fleet/fetch badge-omission bug is now a
//! COMPILE error, not a runtime refusal against a real node.
//!
//! [`resolve`] is the ONE home of the `--present`-overrides-self-badge rule that used to be copy-pasted
//! into six verbs: it turns a declared [`Credential`] into the concrete badge to present, once, in the
//! composition root.

use core::future::Future;
use std::path::Path;

use bifrost::{Discovery, Node, Session, Transport};
use tightbeam::identity::AsVerifyKey as _;

use crate::contacts::Contacts;
use crate::credential::{Credential, MemberBadge};
use crate::identity::{Identity, Secret};
use crate::{config, transport};

/// The uniform context every reaching verb runs against, so dispatch is ONE line (`self.run(node, ctx)`)
/// instead of a per-verb argument-threading match with a different signature per arm.
///
/// It carries what a reach-outward verb needs and no more: the [`contacts`](Self::contacts) to resolve a
/// petname, the bound [`transport`](Self::transport) label a verb reports and a failed dial names, the
/// ALREADY-RESOLVED [`present`](Self::present) badge (minted once by [`resolve`], so the verb never
/// re-derives it), and the [`key`](Self::key) path a verb that opens its own store needs. A verb ignores
/// the fields it does not use. `serve`'s `ExposeContext` is DELIBERATELY not here (Craftsman): it lives on
/// [`ServeCmd`](crate::commands::serve::ServeCmd), which reads its own, so this context stays uniform.
pub struct ReachCtx<'a> {
    /// The address book, to resolve a petname in a verb's peer slot.
    pub contacts: &'a Contacts,
    /// The bound transport label: a verb reports which backend carried the session, and a failed dial
    /// names the fix that backend needs.
    pub transport: transport::Transport,
    /// Slot 1, the grant to present, resolved ONCE in the composition root via [`resolve`]: a `--present`
    /// slip if given, else the stored/self-signed member badge (the plain member dial). `None` for an
    /// `Anonymous` dial.
    pub present: Option<String>,
    /// Slot 2, the membership badge under the dialing key, for a signet-bound slip's AND: the badge the
    /// far gate verifies under the FOREIGN fleet a slip in slot 1 names. Always the stored/self-signed
    /// badge on a `Family` dial (mirrored into slot 1 when no slip overrides), `None` for `Anonymous`.
    pub membership: Option<String>,
    /// The key path, for a verb that opens its OWN store (`fleet` writes contacts; a write, unlike the
    /// read-only `contacts` the reach verbs share).
    pub key: Option<&'a Path>,
}

/// A verb that reaches a peer over a transport, stating how it authenticates and how it runs.
///
/// The compiler forces every method on every reaching verb, so adding a verb that forgets its auth need
/// does not compile (the fleet/fetch bug class). [`credential`](Self::credential) is TOTAL: it returns a
/// [`Credential`], an enum with no "unset" arm, so "forgot to say" is unrepresentable. The identity mode
/// derives from the credential ([`Credential::identity`]), so identity and badge can never disagree.
pub trait Reaching {
    /// The reach-family flags this verb carries (`--transport`, `--peer`). One accessor, not a match arm.
    fn reach_args(&self) -> &transport::ReachArgs;

    /// How this verb authenticates to the service it dials. Required and self-contained: a new verb
    /// cannot compile without returning a [`Credential`], and there is no `None`/default to fall through
    /// to, so a verb that reaches a family-gated service without a badge is unrepresentable.
    fn credential(&self) -> Credential;

    /// Reject a redundant `--present` alongside a self-addressing `sheer:` link peer: the link already
    /// presents its own credential (it is folded into [`credential`](Self::credential)), so a second
    /// explicit one is ambiguous. REQUIRED with no default body and dispatched ONCE in the composition
    /// root, so a new dialing verb cannot silently skip the conflict check (the same no-forgettable-invariant
    /// discipline `credential`/`identity` enforce). A verb whose peer cannot be a self-addressing link, or
    /// that has no `--present`, returns `Ok(())`.
    fn reject_redundant_present(&self) -> eyre::Result<()>;

    /// The identity this verb binds under. REQUIRED with NO default body: a verb must state it, so a
    /// verb that needs a stable address (`serve`, `tunnel-connect`) cannot SILENTLY inherit
    /// [`Ephemeral`](Identity::Ephemeral) and come up as a broken node (a new address every run). The
    /// common reaching verbs write the one-liner `self.credential().identity()` (the derivation, so
    /// identity and badge cannot disagree); the two that need `Persisted` for a reason OTHER than
    /// family-rooting (a stable address / dialing under swoosh's own key) declare it EXPLICITLY here.
    /// This is the Adversary's non-forgettable override: `Persisted` is a written declaration, never a
    /// silent default.
    fn identity(&self) -> Identity;

    /// Run this verb against the composed node under the uniform [`ReachCtx`]. Every verb takes the same
    /// context, so the composition root dispatches with ONE line (`cmd.run(node, ctx)`), not a per-verb
    /// argument-threading match. A verb reads the ctx fields it needs and ignores the rest. The `Send`
    /// bounds on the session halves are stated once here (structured concurrency across `.await`s).
    ///
    /// Written as a returned `impl Future` (RPITIT), not `async fn`, matching the `Handler` trait: an
    /// `async fn` in a trait cannot state its auto-trait bounds and draws the `async_fn_in_trait` lint;
    /// the impls stay plain `async fn`, which coerces to this on the pinned toolchain.
    fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: ReachCtx<'_>,
    ) -> impl Future<Output = eyre::Result<()>>
    where
        Self: Sized,
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static;
}

/// The two concrete slots a resolved [`Credential`] presents on the wire: slot 1 the grant, slot 2 a
/// membership badge for a signet-bound slip's AND.
///
/// A named result rather than a bare pair so a caller reads intent, not two nullable strings:
/// [`None`](Self::None) is a deliberate stranger dial, [`Family`](Self::Family) a proven membership dial.
pub enum Resolved {
    /// Present nothing: an [`Anonymous`](Credential::Anonymous) dial (ungated service, or the verb presents
    /// its own link).
    None,
    /// A `Family` dial. `grant` (slot 1) is a `--present` slip if given, else the member badge. `membership`
    /// (slot 2) is the member badge under the dialing key, attached ONLY when the slot-1 slip is
    /// signet-bound (its gate ANDs a fleet badge under the foreign fleet). It is `None` for a plain member
    /// dial (no slip) and for a plain/bearer/device `--present` slip, so a non-signet dial never transmits
    /// this device's signet linkage to the peer.
    Family {
        /// Slot 1: the grant (a `--present` slip, or the member badge when none was given).
        grant: String,
        /// Slot 2: the member badge, present only for a signet-bound slip's AND, `None` otherwise.
        membership: Option<MemberBadge>,
    },
}

impl Resolved {
    /// The two links to hand a [`Connector`](tightbeam::tunnel::Connector): slot 1 (the grant) and slot 2
    /// (the membership badge, only for a signet-bound slip). The one place the resolved credential becomes
    /// the wire's nullable links.
    pub fn into_slots(self) -> (Option<String>, Option<String>) {
        match self {
            Self::None => (None, None),
            Self::Family { grant, membership } => {
                (Some(grant), membership.map(MemberBadge::into_link))
            }
        }
    }
}

/// Resolve a declared [`Credential`] into the concrete badge to present, ONCE, in the composition root.
///
/// The single home of the `--present`-overrides-self-badge rule copy-pasted into six verbs today:
///
/// - [`Anonymous`](Credential::Anonymous) presents nothing (a deliberate stranger dial).
/// - [`Family`](Credential::Family) presents the member badge rooted at the dialing key. A delegate's
///   explicit `--present` slip wins; else the STORED signet-signed device badge; else the signet
///   holder's own self-sign (person-zero: it IS the root, so its self-sign admits). A fresh install with
///   neither badge nor signet self-signs an ephemeral badge that the peer's gate correctly refuses.
pub async fn resolve(
    cred: Credential,
    secret: &Secret,
    key: Option<&Path>,
) -> eyre::Result<Resolved> {
    match cred {
        Credential::Anonymous => Ok(Resolved::None),
        Credential::Family { present } => {
            // The member badge rooted at the dialing key, AND the fleet key that badge roots under: a STORED
            // signet-signed device badge roots at the adopted signet; else the signet holder's self-sign
            // roots at this key. The badge is the whole grant on a plain member dial (slot 1), and its OWN
            // fleet is the only fleet a slot-2 badge can help admit (a badge never verifies at a fleet you
            // are not in), so the fleet is computed here beside the badge for the slot-2 decision below.
            let (badge, own_fleet) = match config::load_badge(key).await? {
                // A stored badge exists only after `adopt`, which also wrote the signet it roots at; fall
                // back to self defensively if the signet file is somehow absent (fails closed: no slot 2).
                Some(stored) => {
                    let signet = config::load_signet(key)
                        .await?
                        .unwrap_or_else(|| secret.node_id());
                    (MemberBadge::new(stored), signet)
                }
                None => (MemberBadge::new(secret.member_badge()?), secret.node_id()),
            };
            match present {
                // A `--present` (or link-as-peer) slip is slot 1. Attach the member badge in slot 2 ONLY when
                // the slip pins the SAME foreign fleet the dialer's own badge roots under: that is the only
                // dial where the badge can help admission (the far gate ANDs a fleet badge under the fleet
                // the slip names, and a badge for a fleet you are not in never verifies there). A slip
                // pinning any OTHER fleet, and a plain/bearer/device slip (no pinned fleet at all), attach
                // nothing, so a dial never leaks this device's fleet-signet linkage where it cannot help.
                Some(slip) => {
                    let pins_own_fleet = slip
                        .cap()
                        .ok()
                        .and_then(|cap| cap.authority_bound_root().ok().flatten())
                        .is_some_and(|pinned| pinned == own_fleet.verify_key());
                    Ok(Resolved::Family {
                        grant: slip.into_link(),
                        membership: pins_own_fleet.then_some(badge),
                    })
                }
                // A plain member dial: the badge is slot 1, slot 2 empty (byte-parity, no over-share).
                None => Ok(Resolved::Family {
                    grant: badge.link().to_owned(),
                    membership: None,
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::SheerLink;
    use crate::peer::Peer;

    /// An `Anonymous` credential (e.g. `forward`) resolves to NO slot: a deliberate stranger dial presents
    /// neither a grant nor a membership badge.
    #[tokio::test]
    async fn anonymous_presents_no_slots() {
        let secret = Secret::ephemeral();
        let resolved = resolve(Credential::Anonymous, &secret, None)
            .await
            .expect("anonymous resolves");
        assert_eq!(
            resolved.into_slots(),
            (None, None),
            "an Anonymous dial presents nothing in either slot"
        );
    }

    /// A `Family` credential with no `--present` slip and no stored badge falls back to the signet
    /// holder's self-sign, so it ALWAYS resolves to a grant, never `None`. This is the fleet/fetch fix
    /// at the resolver: a family verb (the diagnostic verbs, `beam`, `stop`, `fleet`, and now `fetch`)
    /// cannot reach a gated service carrying no badge, because `Family` has no arm that yields nothing.
    /// Slot 2 is `None` (no over-share): a plain member dial transmits only the badge in slot 1, exactly as
    /// it did before the signet-bound slice.
    #[tokio::test]
    async fn family_without_slip_presents_only_the_member_badge_in_slot_one() {
        let secret = Secret::ephemeral();
        let resolved = resolve(Credential::Family { present: None }, &secret, None)
            .await
            .expect("family resolves");
        let (grant, membership) = resolved.into_slots();
        let grant = grant.expect("a family dial always presents a grant (self-sign fallback)");
        assert!(
            grant.starts_with("sheer:"),
            "the presented grant is a sheer: capability link, got {grant}"
        );
        assert_eq!(
            membership, None,
            "a plain member dial attaches NO slot 2 (no signet linkage over-share)"
        );
    }

    /// REGRESSION (Adversary privacy fix): a `--present` slip that is NOT signet-bound (a plain member
    /// badge, a bearer or device slip) is slot 1 alone; slot 2 stays `None`, so the dialer never leaks its
    /// own device-to-signet membership badge on a non-signet dial.
    #[tokio::test]
    async fn family_with_a_plain_slip_attaches_no_membership_badge() {
        let secret = Secret::ephemeral();
        // A member badge stands in for a plain (non-signet-bound) `--present` slip.
        let slip_text = Secret::ephemeral()
            .member_badge()
            .expect("mint a stand-in plain slip");
        let slip: SheerLink = slip_text.parse().expect("a valid SheerLink");
        let resolved = resolve(
            Credential::Family {
                present: Some(slip),
            },
            &secret,
            None,
        )
        .await
        .expect("family-with-plain-slip resolves");
        let (grant, membership) = resolved.into_slots();
        assert_eq!(
            grant.as_deref(),
            Some(slip_text.as_str()),
            "the plain slip is slot 1 (the grant)"
        );
        assert_eq!(
            membership, None,
            "a non-signet-bound slip attaches NO slot 2 badge (privacy regression fixed)"
        );
    }

    /// A `--present` SIGNET-BOUND slip DOES attach the member badge in slot 2 when it pins the dialer's OWN
    /// fleet: this is the only dial that needs the two-cred AND (the work-issued slip in slot 1, the dialer's
    /// own fleet badge in slot 2), and the only dial where the badge can actually help admission.
    #[tokio::test]
    async fn family_with_a_signet_bound_slip_attaches_the_membership_badge() {
        let secret = Secret::ephemeral();
        // A real signet-bound slip pinning the DIALER'S OWN fleet (with no `--key`, the self-signed badge
        // roots at `secret.node_id()`, so that is the fleet slot 2 can help admit at). Work issues it.
        let work = nauthy::Identity::from_secret(&[1u8; 32]).expect("valid work secret");
        let fleet = secret.node_id().verify_key();
        let slip_text = tightbeam::tunnel::mint_signet_link(
            &work,
            &"ssh".parse().expect("valid service"),
            fleet,
            core::time::Duration::from_secs(3600),
        )
        .expect("mint a signet-bound slip");
        let slip: SheerLink = slip_text.parse().expect("a valid SheerLink");
        let resolved = resolve(
            Credential::Family {
                present: Some(slip),
            },
            &secret,
            None,
        )
        .await
        .expect("family-with-signet-slip resolves");
        let (grant, membership) = resolved.into_slots();
        assert_eq!(
            grant.as_deref(),
            Some(slip_text.as_str()),
            "the signet-bound slip is slot 1 (the grant)"
        );
        let membership = membership.expect("a signet-bound slip attaches slot 2 (the fleet badge)");
        assert!(
            membership.starts_with("sheer:") && membership != slip_text,
            "slot 2 is the self-signed member badge, not the slip: {membership}"
        );
    }

    /// ADV1: a signet-bound slip pinning a DIFFERENT (foreign/attacker) fleet attaches NO slot 2. The
    /// dialer's own fleet badge would never verify at that fleet's gate, so sending it only leaks this
    /// device's fleet-signet linkage for no admission gain. The predicate is a fleet MATCH, not the bare
    /// `is_authority_bound()` boolean the earlier slice used.
    #[tokio::test]
    async fn family_with_a_foreign_fleet_slip_attaches_no_membership_badge() {
        let secret = Secret::ephemeral();
        let work = nauthy::Identity::from_secret(&[1u8; 32]).expect("valid work secret");
        // A fleet that is NOT the dialer's own (the dialer self-signs at `secret.node_id()` with no --key).
        let foreign_fleet = nauthy::Identity::from_secret(&[2u8; 32])
            .expect("valid fleet secret")
            .verifying_key();
        let slip_text = tightbeam::tunnel::mint_signet_link(
            &work,
            &"ssh".parse().expect("valid service"),
            foreign_fleet,
            core::time::Duration::from_secs(3600),
        )
        .expect("mint a signet-bound slip");
        let slip: SheerLink = slip_text.parse().expect("a valid SheerLink");
        let (grant, membership) = resolve(
            Credential::Family {
                present: Some(slip),
            },
            &secret,
            None,
        )
        .await
        .expect("family-with-foreign-fleet-slip resolves")
        .into_slots();
        assert_eq!(
            grant.as_deref(),
            Some(slip_text.as_str()),
            "the slip is still slot 1 (the grant)"
        );
        assert_eq!(
            membership, None,
            "a slip pinning a fleet the dialer is not in attaches NO slot 2 (no fleet-signet over-share)"
        );
    }

    /// REGRESSION (defect #1): a signet-bound `sheer:` link passed AS THE PEER (not via `--present`) folds
    /// through `credential()` -> `resolve()` and attaches slot 2, IDENTICAL to passing it via `--present`.
    /// A `Peer::Capability` self-presents its own link, so the peer-link and a `--present` link resolve
    /// through ONE path. Before this consolidation a signet-bound link-as-peer dropped slot 2 (it dialed via
    /// `from_link`, which ignored the resolver).
    #[tokio::test]
    async fn a_signet_bound_link_as_peer_attaches_slot_two() {
        let secret = Secret::ephemeral();
        let work = nauthy::Identity::from_secret(&[1u8; 32]).expect("valid work secret");
        // Pin the DIALER'S OWN fleet, so the fleet-match slot-2 rule (ADV1) attaches the badge.
        let fleet = secret.node_id().verify_key();
        let link_text = tightbeam::tunnel::mint_signet_link(
            &work,
            &"ssh".parse().expect("valid service"),
            fleet,
            core::time::Duration::from_secs(3600),
        )
        .expect("mint a signet-bound slip");

        // The slip arrives AS THE PEER: a `Capability` peer self-presents its own link, which the verb's
        // `credential()` folds into `present` exactly as an explicit `--present` slip would be.
        let peer: Peer = link_text.parse().expect("a sheer: link is a peer");
        let cred = Credential::Family {
            present: peer.self_present(),
        };
        let (grant, membership) = resolve(cred, &secret, None)
            .await
            .expect("family-with-link-peer resolves")
            .into_slots();
        assert_eq!(
            grant.as_deref(),
            Some(link_text.as_str()),
            "slot 1 is the link, whether it came via --present or as the peer"
        );
        let membership = membership
            .expect("a signet-bound link-as-peer attaches slot 2 (defect #1: it used to drop it)");
        assert!(
            membership.starts_with("sheer:") && membership != link_text,
            "slot 2 is the self-signed member badge, not the slip: {membership}"
        );
    }

    /// A NON-signet `sheer:` link passed as the peer folds to slot 1 alone; slot 2 stays `None`, so a
    /// link-as-peer never over-shares this device's signet linkage, mirroring the `--present` privacy rule.
    #[tokio::test]
    async fn a_plain_link_as_peer_attaches_only_slot_one() {
        let secret = Secret::ephemeral();
        // A member badge stands in for a plain (non-signet-bound) `sheer:` link passed as the peer.
        let link_text = Secret::ephemeral()
            .member_badge()
            .expect("mint a stand-in plain slip");
        let peer: Peer = link_text.parse().expect("a sheer: link is a peer");
        let cred = Credential::Family {
            present: peer.self_present(),
        };
        let (grant, membership) = resolve(cred, &secret, None)
            .await
            .expect("family-with-plain-link-peer resolves")
            .into_slots();
        assert_eq!(
            grant.as_deref(),
            Some(link_text.as_str()),
            "the plain link-as-peer is slot 1 (the grant)"
        );
        assert_eq!(
            membership, None,
            "a non-signet link-as-peer attaches NO slot 2 (no signet-linkage over-share)"
        );
    }
}
