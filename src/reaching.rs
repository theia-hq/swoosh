//! The two things every reaching verb must state: how it authenticates, and what its bind does with the
//! home key's address record.
//!
//! A reaching verb's auth need used to be spread across five hand-synced match arms in `main.rs`, one of
//! which (`self_badge()`) ended in a `_ => Ok(None)` wildcard: a verb the author forgot to list reached a
//! family-gated service carrying no badge, and it still compiled. The [`Reaching`] trait replaces that
//! with a method the compiler forces: a verb cannot compile without stating its [`BindRole`], and a
//! `Dialing` role cannot be written without the [`Credential`] it dials with, so the fleet/fetch
//! badge-omission bug is now a COMPILE error, not a runtime refusal against a real node.
//!
//! Serving and dialing-as-someone are ONE declaration because they are one question. Only the process
//! that accepts connections under the home key publishes its address record (0.9.0 F1: every reaching
//! verb published, so a short-lived command overwrote the live `serve`'s record and dialers followed a
//! dead relay), and that is exactly the process that presents no credential (it RECEIVES badges). Split
//! across two declarations, the credential side has to spell "not applicable" for the serving verb, and
//! that spelling reads equally as "a deliberate stranger dial", so a dialing verb transcribed with it
//! reaches its own fleet carrying nothing and still compiles.
//!
//! [`resolve`] is the ONE home of the `--present`-overrides-self-badge rule that used to be copy-pasted
//! into six verbs: it turns a declared [`Credential`] into the concrete badge to present, once, in the
//! composition root. Being that one home makes it the one home of the badge's EXPIRY rule too: a stored
//! badge that is already dead is refused here, locally, before any dial, so the operator reads the cause
//! and the fix instead of the far gate's deliberately uniform `not admitted`.

use core::future::Future;
use core::net::SocketAddr;
use std::time::SystemTime;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use nauthy::Link;
use tightbeam::identity::AsVerifyKey as _;

use crate::contacts::Contacts;
use crate::credential::Credential;
use crate::home::Home;
use crate::identity::{Identity, Secret};
use crate::standing::{Standing, StandingError};
use crate::{badge, config, transport};

/// The uniform context every reaching verb runs against, so dispatch is ONE line (`self.run(node, ctx)`)
/// instead of a per-verb argument-threading match with a different signature per arm.
///
/// It carries what a reach-outward verb needs and no more: the [`contacts`](Self::contacts) to resolve a
/// petname, the [`bound`](Self::bound) facts a verb reports and a failed dial names, the
/// ALREADY-RESOLVED [`present`](Self::present) badge (minted once by [`resolve`], so the verb never
/// re-derives it), and the [`home`](Self::home) a verb that opens its own store needs. A verb ignores
/// the fields it does not use. `serve`'s `ExposeContext` is DELIBERATELY not here: it lives on
/// the serve command's own type (the CLI's `ServeCmd`), which reads its own, so this context stays uniform.
pub struct ReachCtx<'a> {
    /// The address book, to resolve a petname in a verb's peer slot.
    pub contacts: &'a Contacts,
    /// What this run bound: the backend a verb reports, the `--local` bit, and the two reach services.
    /// One value, composed once in the composition root, because a failed dial reads all three: iroh's
    /// own error names none of them, so without this an unreachable resolver of your own reads as "the
    /// peer is offline".
    pub bound: &'a transport::Bound,
    /// Slot 1, the grant to present, resolved ONCE in the composition root via [`resolve`]: a `--present`
    /// slip if given, else the stored member badge on a device (the plain member dial). `None` for the
    /// [`Serving`](BindRole::Serving) verb, which resolves no slots because it never dials, and for a
    /// plain dial from a machine that is not a device, which has no badge to present.
    pub present: Option<Link>,
    /// Slot 2, the membership badge under the dialing key, for a signet-bound slip's AND: the badge the
    /// far gate verifies under the FOREIGN fleet a slip in slot 1 names. `None` on a plain member dial
    /// (the badge is slot 1 there) and on every non-signet slip, so a dial never leaks this device's
    /// fleet-signet linkage where it cannot help.
    pub membership: Option<Link>,
    /// The node home, for a verb that opens its OWN store (`fleet` writes contacts; a write, unlike the
    /// read-only `contacts` the reach verbs share) or reads a trust file (its signet).
    pub home: &'a Home,
}

/// A verb that reaches a peer over a transport, stating how it authenticates and how it runs.
///
/// The compiler forces every method on every reaching verb, so adding a verb that forgets its auth need
/// does not compile (the fleet/fetch bug class). [`bind_role`](Self::bind_role) is TOTAL and carries the
/// auth need: a [`Dialing`](BindRole::Dialing) role cannot be written without a [`Credential`], and
/// `Credential` has no "present nothing" arm, so "forgot to say" is unrepresentable. The identity mode
/// derives from the same declaration ([`BindRole::identity`]), so identity and badge cannot disagree.
pub trait Reaching {
    /// The reach-family flags this verb carries (`--transport`, `--local`, `--peer`). One accessor,
    /// not a match arm.
    fn reach_args(&self) -> &transport::ReachArgs;

    /// The peer this verb dials, when it dials one. While the verb runs, the composition root makes one
    /// stale-list exchange with it when it is one of your devices ([`crate::sync::is_stale`]). REQUIRED
    /// with no default body, so a new dialing verb states it; a verb that dials no peer of its own says
    /// `None`.
    fn dialed(&self) -> Option<&crate::peer::Peer>;

    /// Reject a redundant `--present` alongside a self-addressing `swoosh:` link peer: the link already
    /// presents its own credential (it is folded into [`credential`](Self::credential)), so a second
    /// explicit one is ambiguous. REQUIRED with no default body and dispatched ONCE in the composition
    /// root, so a new dialing verb cannot silently skip the conflict check (the same no-forgettable-invariant
    /// discipline `credential`/`identity` enforce). A verb whose peer cannot be a self-addressing link, or
    /// that has no `--present`, returns `Ok(())`.
    fn reject_redundant_present(&self) -> eyre::Result<()>;

    /// The identity this verb binds under. REQUIRED with NO default body: a verb must state it, so a
    /// verb that needs the persisted key for a reason of its own (`serve` must come up at ONE address
    /// across runs, which an ephemeral key cannot do) cannot SILENTLY inherit the role's derivation. The
    /// reaching verbs write the one-liner `self.bind_role().identity()` (the derivation, so identity and
    /// badge cannot disagree); the one that needs `Persisted` for another reason declares it EXPLICITLY
    /// here. The override is non-forgettable by construction: `Persisted` is a written declaration,
    /// never a silent default, and it is the only intent that CREATES a key, so a verb claiming it is
    /// claiming to provision this node.
    fn identity(&self) -> Identity;

    /// What this verb's bind is for, and (when it dials) what it presents. `Serving` publishes the home
    /// key's address record so peers can dial the key, and states no credential; `Dialing` resolves only,
    /// MUST NOT publish (or a short-lived command overwrites a live `serve`'s record), and carries the
    /// credential it dials with. Required with no default body, like `identity`.
    fn bind_role(&self) -> BindRole;

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

/// What a reaching verb's bind is for: accepting connections under the home key, or dialing out as the
/// member this home is.
///
/// ONE declaration for what the address record and the presented credential both turn on, because it is
/// one question. The process that accepts connections under the key is the GATE: it receives badges and
/// presents none. Every other verb dials, and a dial always presents something. So `Serving` carries no
/// credential and `Dialing` cannot be written without one: "the serving verb's dial credential" and "a
/// dialing verb that presents nothing" are both unrepresentable, and there is no spelling of
/// not-applicable for a dialing verb to be transcribed with.
///
/// Deliberately no `Default`: omission must not silently pick a side.
#[derive(Debug, Clone)]
pub enum BindRole {
    /// The bind accepts connections under the key, so it publishes the key's address record (n0
    /// pkarr/DNS) and advertises its bind over LAN mDNS, and peers reach it by key. Only `serve` is
    /// `Serving`, and it declares no credential: it is the gate, so it verifies badges rather than
    /// presenting one.
    Serving,
    /// The bind only dials peers, as the [`Credential`] it carries: n0 resolution and relays, no address
    /// record, and no mDNS record (it browses the LAN, never advertises). A dialing process is not
    /// reachable at its key, so publishing here overwrites the live `serve` under the same key with a
    /// relay that dies when the command exits (0.9.0 F1), and an mDNS record would tell every host on
    /// the LAN which key is running here while nobody needs to find it.
    Dialing(Credential),
}

impl BindRole {
    /// The identity this role binds under, derived rather than restated per verb. A `Dialing` verb
    /// inherits its credential's ([`Credential::identity`]), so the badge roots at the key the dial binds
    /// under and the two can never disagree; a `Serving` verb binds `Persisted`, because a node peers
    /// dial by key must answer at the same address across runs. A verb needing `Persisted` for some OTHER
    /// reason overrides this in its own [`identity`](Reaching::identity), which the trait requires anyway.
    pub fn identity(&self) -> Identity {
        match self {
            Self::Serving => Identity::Persisted,
            Self::Dialing(credential) => credential.identity(),
        }
    }

    /// The sockets this role hands to the LAN mDNS advertisement.
    ///
    /// Bind truth for a serving node, never `local_addr`'s hints: the hints rewrite an unspecified bind
    /// to loopback, so handing them over would advertise `127.0.0.1` for a node bound to every interface
    /// and point every dialer at its own machine. Discovery owns what of the bind is publishable. A
    /// dialing node hands over nothing and reads nothing off the transport, so no record on the wire
    /// names its key; it still browses.
    pub fn advertised<T: Transport>(&self, transport: &T) -> Vec<SocketAddr> {
        match self {
            Self::Serving => transport.bound_sockets(),
            Self::Dialing(_) => Vec::new(),
        }
    }
}

/// The two concrete slots a resolved [`Credential`] presents on the wire: slot 1 the grant, slot 2 a
/// membership badge for a signet-bound slip's AND.
///
/// A named pair rather than a bare tuple so a caller reads intent, not two links of one type. Slot 1 is
/// empty only on a plain dial from a machine that is not a device: it has no badge, and this machine's
/// own key never signs one for itself.
pub struct Resolved {
    /// Slot 1: the grant (a `--present` slip, or the stored member badge when none was given).
    pub grant: Option<Link>,
    /// Slot 2: the member badge under the dialing key, attached ONLY when the slot-1 slip is signet-bound
    /// and pins the dialer's own fleet (its gate ANDs a fleet badge under the fleet it names). `None` for
    /// a plain member dial and for a plain/bearer/device slip, so a non-signet dial never transmits this
    /// device's signet linkage to the peer.
    pub membership: Option<Link>,
}

impl Resolved {
    /// The two links to hand a [`Connector`](tightbeam::tunnel::Connector): slot 1 (the grant) and slot 2
    /// (the membership badge, only for a signet-bound slip). The one place the resolved credential becomes
    /// the connector's typed slots.
    pub fn into_slots(self) -> (Option<Link>, Option<Link>) {
        (self.grant, self.membership)
    }
}

/// Resolve a declared [`Credential`] into the concrete badge to present, ONCE, in the composition root,
/// before the transport binds.
///
/// It presents by standing, and the choice never depends on the peer. On a `Device` or `HoldsRoot` home
/// the stored badge is slot 1 of a plain dial, and the pin is this device's own fleet, so a `--present`
/// slip naming that fleet carries the badge in slot 2. On any other standing (`Unpinned`,
/// `InterruptedMint`, or a damaged home) there is no badge and no own fleet: a plain dial presents
/// nothing, and a slip dials alone. A delegate's explicit `--present` slip is always slot 1. Reached only
/// from a [`Dialing`](BindRole::Dialing) verb: a serving verb resolves no slots because it presents none.
///
/// A stored badge that is already dead REFUSES the dial here (see [`into_slot`]), and one inside
/// [`badge::DEVICE_WARN_WINDOW`] warns on stderr and dials anyway.
pub async fn resolve(cred: Credential, secret: &Secret, home: &Home) -> eyre::Result<Resolved> {
    resolve_to(cred, secret, home, &mut std::io::stderr()).await
}

/// The body of [`resolve`], with the expiry warning routed to an injected `warn` sink so a test can
/// drive it with its own writer and assert precisely when the line is (and is not) emitted, rather than
/// trying to capture the process stderr. Mirrors [`SecretSource::resolve_to`](crate::secret::SecretSource).
async fn resolve_to<W: std::io::Write>(
    cred: Credential,
    secret: &Secret,
    home: &Home,
    warn: &mut W,
) -> eyre::Result<Resolved> {
    let present = match cred {
        // An `anyone` link presents alone: no badge is read or sent, so nothing ties the throwaway key
        // it dials under to this home.
        Credential::Anyone(link) => {
            return Ok(Resolved {
                grant: Some(link),
                membership: None,
            });
        }
        Credential::Family { present } => present,
    };
    let badge = device_badge(home).await?;
    let node = secret.node_id();
    match present {
        // A `--present` (or link-as-peer) slip is slot 1. Attach the member badge in slot 2 ONLY when
        // the slip pins the SAME fleet the dialer's own badge roots under: that is the only dial where
        // the badge can help admission (the far gate ANDs a fleet badge under the fleet the slip names,
        // and a badge for a fleet you are not in never verifies there). A slip pinning any OTHER fleet,
        // and a plain/bearer/device slip (no pinned fleet at all), attach nothing, so a dial never leaks
        // this device's fleet linkage where it cannot help.
        Some(slip) => {
            let pinned = slip.cap().authority_bound_root().ok().flatten();
            let membership = match badge {
                Some((stored, own_fleet))
                    if pinned.is_some_and(|pin| own_fleet.verify_key() == Ok(pin)) =>
                {
                    Some(into_slot(stored, node, warn)?)
                }
                _ => None,
            };
            Ok(Resolved {
                grant: Some(slip),
                membership,
            })
        }
        // A plain member dial: the badge is slot 1, slot 2 empty (byte-parity, no over-share). A machine
        // that is not a device has no badge and presents nothing.
        None => Ok(Resolved {
            grant: badge
                .map(|(stored, _)| into_slot(stored, node, warn))
                .transpose()?,
            membership: None,
        }),
    }
}

/// This machine's stored badge and the pin it roots at, when its standing is `Device` or `HoldsRoot`;
/// `None` on every other standing, a damaged home included. A home that cannot be read at all is an
/// error, never a dial with nothing.
async fn device_badge(home: &Home) -> eyre::Result<Option<(Link, NodeId)>> {
    let pin = match Standing::read(home).await {
        Ok(read) => match read.standing {
            Standing::Device { pin, .. } | Standing::HoldsRoot { pin, .. } => pin,
            Standing::Unpinned | Standing::InterruptedMint { .. } => {
                return Ok(None);
            }
        },
        Err(StandingError::Damaged(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(config::load_badge(home).await?.map(|badge| (badge, pin)))
}

/// Hand the stored badge over for the slot it will travel in, refusing the dial LOCALLY when it is
/// already dead and warning when it dies inside [`badge::DEVICE_WARN_WINDOW`].
///
/// Called at each site where the badge actually BECOMES a slot, and only there. That placement is the
/// guard, not an accident of structure: a dial whose slip pins a fleet this device is not in drops the
/// badge entirely, and refusing that dial over a credential it never sends would turn away a dial the far
/// gate would have admitted. It consumes the badge, so a slot cannot be filled around it.
///
/// The refusal never reaches the wire, so the gate's uniform `not admitted` stays uniform and no peer
/// learns anything: this is the dialer telling itself what it already knows about its own credential.
fn into_slot<W: std::io::Write>(badge: Link, node: NodeId, warn: &mut W) -> eyre::Result<Link> {
    // Exhaustive on purpose: a new reading is a compile error HERE, at the one site that decides whether
    // a badge travels, rather than a silent fall-through to dialing.
    match badge::Expiry::read(&badge, SystemTime::now())? {
        // Dead: the gate will refuse this, so say so now, with the cause and the fix, instead of spending
        // a dial to be told `not admitted` by a message that cannot say which of five reasons applied.
        expiry @ badge::Expiry::Expired { .. } => eyre::bail!(
            "this device's membership badge {expiry}, so a family-gated peer will refuse this dial; {}",
            badge::remedy(node)
        ),
        // Alive but inside the window: the dial goes ahead, and the operator is told once, on stderr, so
        // the line never pollutes a piped result.
        expiry @ badge::Expiry::Expiring { .. } => {
            // The write is discarded on failure, like every other warning in the tree: a closed stderr
            // must not fail the dial this line only annotates.
            let _ = writeln!(
                warn,
                "swoosh: this device's membership badge {expiry}; {}",
                badge::remedy(node)
            );
            Ok(badge)
        }
        // Outside the window, or minted before badges carried a readable expiry: nothing useful to say,
        // so nothing is said.
        badge::Expiry::Live { .. } | badge::Expiry::Unknown => Ok(badge),
    }
}

/// Reject `--present` on a BARE (local) invocation: the flag selects the slip to present when reaching
/// a PEER, and a bare `status`/`stop`/`service ls` reaches no peer (it queries the local resident over
/// the control socket). The bare arms return before the composition root's
/// [`reject_redundant_present`](Reaching::reject_redundant_present), so without this guard the flag
/// parsed and was silently ignored (I.3 forbids a flag with no effect). One home for the exact teaching
/// line, called by each bare arm before it resolves the local socket.
pub fn reject_bare_present(present: Option<&Link>) -> eyre::Result<()> {
    if present.is_some() {
        eyre::bail!("--present only applies when reaching a peer; drop it or name one");
    }
    Ok(())
}

/// Reject the reach-family flags on a BARE (local) invocation: `--transport`, `--local`, `--peer`,
/// `--relay`, and `--resolver` choose how a PEER is bound and found, and a bare `status`/`stop`/`service
/// ls` reaches no peer (it queries the local resident over the control socket). The bare arms return
/// before the composition root reads these flags, so without this guard they parsed and were silently
/// ignored (I.3 forbids a flag with no effect). One home for the teaching line, called by each bare arm
/// beside [`reject_bare_present`].
pub fn reject_bare_reach(reach: &transport::ReachArgs) -> eyre::Result<()> {
    if reach.transport != transport::Transport::default() {
        eyre::bail!("--transport only applies when reaching a peer; drop it or name one");
    }
    if reach.local {
        eyre::bail!("--local only applies when reaching a peer; drop it or name one");
    }
    if !reach.peer.is_empty() {
        eyre::bail!("--peer only applies when reaching a peer; drop it or name one");
    }
    if reach.relay.is_some() {
        eyre::bail!("--relay only applies when reaching a peer; drop it or name one");
    }
    if reach.resolver.is_some() {
        eyre::bail!("--resolver only applies when reaching a peer; drop it or name one");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use nauthy::Link;

    use super::*;
    use crate::peer::Peer;
    use crate::testkit::{TestNode, TestRoot};

    /// The parsed reach-family defaults: what clap hands a bare verb that named none of the flags. Each
    /// case below overrides exactly the one flag it is about, so a new flag joins the guard in one line.
    fn defaults() -> transport::ReachArgs {
        transport::ReachArgs {
            transport: transport::Transport::default(),
            local: false,
            peer: Vec::new(),
            relay: None,
            resolver: None,
        }
    }

    /// An UNPROVISIONED home for a resolver test: no stored badge and no signet, so its standing is
    /// `Unpinned` and a plain dial presents nothing.
    ///
    /// A unique empty dir, never the default home: the default is the developer's own
    /// `~/.config/swoosh`, so on any joined machine these cases would read that machine's real badge
    /// and the suite would pass or fail by whose laptop it ran on. That was invisible while the
    /// resolver ignored the badge's expiry; now that it refuses a dead one, it would be a suite that
    /// dies on the calendar.
    fn test_home() -> Home {
        provisioned_home("unprovisioned")
    }

    /// An `Unpinned` machine is no root's device, so a plain dial presents nothing in either slot: its
    /// own key never signs a badge for itself.
    #[tokio::test]
    async fn an_unpinned_dial_presents_no_member_badge() {
        let secret = Secret::ephemeral();
        let (grant, membership) =
            resolve(Credential::Family { present: None }, &secret, &test_home())
                .await
                .expect("an unpinned dial resolves")
                .into_slots();
        assert!(grant.is_none(), "slot 1 is empty on an unpinned dial");
        assert!(membership.is_none(), "and so is slot 2");
    }

    /// A damaged home (here, one whose pin names this machine's own key, as a home from before roots had
    /// their own keys holds) presents no badge either, even with one stored.
    #[tokio::test]
    async fn a_damaged_home_presents_no_member_badge() {
        let home = provisioned_home("damaged");
        let own = TestNode::seeded(0x61);
        crate::identity::write(&own.seed(), &home)
            .await
            .expect("write this machine's key");
        config::write_signet(&home, own.node_id())
            .await
            .expect("pin this machine's own key");
        let badge = TestRoot::from_seed(own.seed())
            .device_badge(own.node_id(), SystemTime::now() + 30 * DAY)
            .expect("sign a badge");
        config::write_badge(&home, &badge)
            .await
            .expect("write the badge");
        let secret = crate::identity::load(&home)
            .await
            .expect("load the key")
            .expect("the key is there");
        let (grant, _) = resolve(Credential::Family { present: None }, &secret, &home)
            .await
            .expect("a damaged home still resolves")
            .into_slots();
        assert!(grant.is_none(), "a damaged home presents no badge");
    }

    /// REGRESSION, the privacy rule: a `--present` slip that is NOT signet-bound (a plain member
    /// badge, a bearer or device slip) is slot 1 alone; slot 2 stays `None`, so the dialer never leaks its
    /// own device-to-signet membership badge on a non-signet dial.
    #[tokio::test]
    async fn family_with_a_plain_slip_attaches_no_membership_badge() {
        let secret = Secret::ephemeral();
        // A member badge stands in for a plain (non-signet-bound) `--present` slip.
        let slip = crate::testkit::TestRoot::seeded(0xb0)
            .device_badge(
                crate::testkit::TestNode::seeded(0xb1).node_id(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
            )
            .expect("mint a stand-in plain slip");
        let slip_text = slip.to_string();
        let resolved = resolve(
            Credential::Family {
                present: Some(slip),
            },
            &secret,
            &test_home(),
        )
        .await
        .expect("family-with-plain-slip resolves");
        let (grant, membership) = resolved.into_slots();
        assert_eq!(
            grant.as_ref().map(Link::as_str),
            Some(slip_text.as_str()),
            "the plain slip is slot 1 (the grant)"
        );
        assert!(
            membership.is_none(),
            "a non-signet-bound slip attaches NO slot 2 badge (privacy regression fixed)"
        );
    }

    /// A `--present` SIGNET-BOUND slip DOES attach the member badge in slot 2 when it pins the dialer's OWN
    /// fleet: this is the only dial that needs the two-cred AND (the work-issued slip in slot 1, the dialer's
    /// own fleet badge in slot 2), and the only dial where the badge can actually help admission.
    #[tokio::test]
    async fn family_with_a_signet_bound_slip_attaches_the_membership_badge() {
        let home = provisioned_home("signet-bound");
        let (secret, root) = joined_badge(&home, SystemTime::now() + 89 * DAY).await;
        // A real signet-bound slip pinning the DIALER'S OWN fleet, the root its badge roots at. Work
        // issues it.
        let work = crate::testkit::TestNode::seeded(1);
        let fleet = root.verify_key();
        let slip = work
            .fleet_slip(
                &"ssh".parse().expect("valid service"),
                fleet,
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint a signet-bound slip");
        let slip_text = slip.to_string();
        let resolved = resolve(
            Credential::Family {
                present: Some(slip),
            },
            &secret,
            &home,
        )
        .await
        .expect("family-with-signet-slip resolves");
        let (grant, membership) = resolved.into_slots();
        assert_eq!(
            grant.as_ref().map(Link::as_str),
            Some(slip_text.as_str()),
            "the signet-bound slip is slot 1 (the grant)"
        );
        let membership = membership.expect("a signet-bound slip attaches slot 2 (the fleet badge)");
        assert!(
            membership.as_str().starts_with("ed01") && membership.as_str() != slip_text,
            "slot 2 is the stored member badge, not the slip: {membership}"
        );
    }

    /// ADV1: a signet-bound slip pinning a DIFFERENT (foreign/attacker) fleet attaches NO slot 2. The
    /// dialer's own fleet badge would never verify at that fleet's gate, so sending it only leaks this
    /// device's fleet-signet linkage for no admission gain. The predicate is a fleet MATCH, not the bare
    /// `is_authority_bound()` boolean the earlier slice used.
    #[tokio::test]
    async fn family_with_a_foreign_fleet_slip_attaches_no_membership_badge() {
        let secret = Secret::ephemeral();
        let work = crate::testkit::TestNode::seeded(1);
        // A fleet that is NOT the dialer's own.
        let foreign_fleet = crate::testkit::TestRoot::seeded(2).verify_key();
        let slip = work
            .fleet_slip(
                &"ssh".parse().expect("valid service"),
                foreign_fleet,
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint a signet-bound slip");
        let slip_text = slip.to_string();
        let (grant, membership) = resolve(
            Credential::Family {
                present: Some(slip),
            },
            &secret,
            &test_home(),
        )
        .await
        .expect("family-with-foreign-fleet-slip resolves")
        .into_slots();
        assert_eq!(
            grant.as_ref().map(Link::as_str),
            Some(slip_text.as_str()),
            "the slip is still slot 1 (the grant)"
        );
        assert!(
            membership.is_none(),
            "a slip pinning a fleet the dialer is not in attaches NO slot 2 (no fleet-signet over-share)"
        );
    }

    /// REGRESSION (defect #1): a signet-bound `swoosh:` link passed AS THE PEER (not via `--present`) folds
    /// through `bind_role()` -> `resolve()` and attaches slot 2, IDENTICAL to passing it via `--present`.
    /// A `Peer::Capability` self-presents its own link, so the peer-link and a `--present` link resolve
    /// through ONE path. Before this consolidation a signet-bound link-as-peer dropped slot 2 (it dialed via
    /// `from_link`, which ignored the resolver).
    #[tokio::test]
    async fn a_signet_bound_link_as_peer_attaches_slot_two() {
        let home = provisioned_home("link-as-peer");
        let (secret, root) = joined_badge(&home, SystemTime::now() + 89 * DAY).await;
        let work = crate::testkit::TestNode::seeded(1);
        // Pin the DIALER'S OWN fleet, so the fleet-match slot-2 rule (ADV1) attaches the badge.
        let fleet = root.verify_key();
        let link_text = work
            .fleet_slip(
                &"ssh".parse().expect("valid service"),
                fleet,
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint a signet-bound slip")
            .to_string();

        // The slip arrives AS THE PEER: a `Capability` peer self-presents its own link, which the verb's
        // the credential fold puts it in `present` exactly as an explicit `--present` slip would be.
        let peer: Peer = format!("{}{link_text}", crate::link::PREFIX)
            .parse()
            .expect("a swoosh: link is a peer");
        let cred = Credential::Family {
            present: peer.self_present(),
        };
        let (grant, membership) = resolve(cred, &secret, &home)
            .await
            .expect("family-with-link-peer resolves")
            .into_slots();
        assert_eq!(
            grant.as_ref().map(Link::as_str),
            Some(link_text.as_str()),
            "slot 1 is the link, whether it came via --present or as the peer"
        );
        let membership = membership
            .expect("a signet-bound link-as-peer attaches slot 2 (defect #1: it used to drop it)");
        assert!(
            membership.as_str().starts_with("ed01") && membership.as_str() != link_text,
            "slot 2 is the stored member badge, not the slip: {membership}"
        );
    }

    /// A NON-signet `swoosh:` link passed as the peer folds to slot 1 alone; slot 2 stays `None`, so a
    /// link-as-peer never over-shares this device's signet linkage, mirroring the `--present` privacy rule.
    #[tokio::test]
    async fn a_plain_link_as_peer_attaches_only_slot_one() {
        let secret = Secret::ephemeral();
        // A member badge stands in for a plain (non-signet-bound) `swoosh:` link passed as the peer.
        let link_text = crate::testkit::TestRoot::seeded(0xb0)
            .device_badge(
                crate::testkit::TestNode::seeded(0xb1).node_id(),
                nauthy::Request::expires_in(core::time::Duration::from_secs(300)),
            )
            .expect("mint a stand-in plain slip")
            .to_string();
        let peer: Peer = format!("{}{link_text}", crate::link::PREFIX)
            .parse()
            .expect("a swoosh: link is a peer");
        let cred = Credential::Family {
            present: peer.self_present(),
        };
        let (grant, membership) = resolve(cred, &secret, &test_home())
            .await
            .expect("family-with-plain-link-peer resolves")
            .into_slots();
        assert_eq!(
            grant.as_ref().map(Link::as_str),
            Some(link_text.as_str()),
            "the plain link-as-peer is slot 1 (the grant)"
        );
        assert!(
            membership.is_none(),
            "a non-signet link-as-peer attaches NO slot 2 (no signet-linkage over-share)"
        );
    }

    /// A store dir unique to one case, resolved as an explicit [`Home`], so a resolver case can write a
    /// real badge and signet the way `join` does instead of reading whatever the developer's own home
    /// happens to hold.
    fn provisioned_home(tag: &str) -> Home {
        let dir = std::env::temp_dir().join(format!(
            "swoosh-reaching-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Home::resolve(Some(dir)).expect("resolve an explicit home")
    }

    /// Provision `home` as a `Device`: this machine's key, a pin to a root, and the badge that root
    /// signed for this machine, expiring at `expiry`. The badge is really signed and really parses, so a
    /// case cannot pass against a stand-in string the resolver would never see in the field. Returns this
    /// machine's key and the root.
    async fn joined_badge(home: &Home, expiry: SystemTime) -> (Secret, TestRoot) {
        let device = TestNode::seeded(0x52);
        crate::identity::write(&device.seed(), home)
            .await
            .expect("write this machine's key");
        let signet = TestRoot::seeded(0x51);
        let badge = signet
            .device_badge(device.node_id(), expiry)
            .expect("mint a device badge");
        config::write_signet(home, signet.node_id())
            .await
            .expect("write the signet");
        config::write_badge(home, &badge)
            .await
            .expect("write the badge");
        let secret = crate::identity::load(home)
            .await
            .expect("load the key")
            .expect("the key is there");
        (secret, signet)
    }

    /// A day, the unit the badge's life is measured in.
    const DAY: core::time::Duration = core::time::Duration::from_secs(24 * 60 * 60);

    /// THE dial-time refusal: a device whose stored badge has expired refuses LOCALLY and never dials.
    /// The far gate's answer for this is the uniform `not admitted`, which is byte-identical to revoked,
    /// wrong fleet, never joined and wrong service, so the one machine that can tell the operator which
    /// of the five it is has to do it before the dial. The message names the cause and the remedy.
    #[tokio::test]
    async fn an_expired_stored_badge_refuses_the_dial_locally() {
        let home = provisioned_home("expired");
        let (device, _) = joined_badge(&home, SystemTime::now() - 6 * DAY).await;

        let mut warned = Vec::new();
        // `let ... else` rather than `expect_err`: that would need `Debug` on `Resolved`, and a
        // credential-carrying type does not grow a derive that prints badge bytes for a test's sake.
        let Err(error) = resolve_to(
            Credential::Family { present: None },
            &device,
            &home,
            &mut warned,
        )
        .await
        else {
            panic!("a dead badge cannot be presented");
        };
        let report = format!("{error:#}");
        assert!(
            report.contains("expired") && report.contains("swoosh invite <name>"),
            "the refusal names the cause and the remedy, got: {report}"
        );
        assert!(
            !report.contains("not admitted"),
            "the gate's uniform refusal must never be spoken on this path: {report}"
        );
    }

    /// The warning half: a badge alive but inside the 14-day window dials anyway, and says so ONCE on
    /// the warn sink. The remedy needs the machine that holds the root, so the line has to arrive while
    /// there is still time to act on it.
    #[tokio::test]
    async fn a_badge_inside_the_window_warns_and_still_dials() {
        let home = provisioned_home("inside-window");
        let (device, _) = joined_badge(&home, SystemTime::now() + 12 * DAY).await;

        let mut warned = Vec::new();
        let resolved = resolve_to(
            Credential::Family { present: None },
            &device,
            &home,
            &mut warned,
        )
        .await
        .expect("a live badge still dials");
        assert!(
            resolved
                .grant
                .is_some_and(|grant| grant.as_str().starts_with("ed01")),
            "the dial goes ahead carrying the stored badge"
        );
        let warned = String::from_utf8(warned).expect("the warning is utf-8");
        assert_eq!(warned.lines().count(), 1, "one line, not a paragraph");
        assert!(
            warned.contains("expires in") && warned.contains("swoosh invite <name>"),
            "the warning names the remaining life and the remedy, got: {warned}"
        );
    }

    /// Outside the window there is nothing useful to say, so nothing is said: a warning that fires for
    /// the badge's whole life is a warning an operator learns to skip past.
    #[tokio::test]
    async fn a_badge_outside_the_window_says_nothing() {
        let home = provisioned_home("outside-window");
        let (device, _) = joined_badge(&home, SystemTime::now() + 89 * DAY).await;

        let mut warned = Vec::new();
        resolve_to(
            Credential::Family { present: None },
            &device,
            &home,
            &mut warned,
        )
        .await
        .expect("a live badge dials");
        assert!(
            warned.is_empty(),
            "a badge with 89 days to run warns about nothing, got: {}",
            String::from_utf8_lossy(&warned)
        );
    }

    /// The SAFE DIRECTION, and the reason the check sits where the badge becomes a slot rather than
    /// where it is loaded: a slip pinning a fleet this device is not in drops the stored badge, so the
    /// dial sends it nothing and the far gate never sees it. Refusing that dial over a dead credential
    /// it does not carry would turn away a dial the gate would have admitted, which is exactly the
    /// failure a local refusal must never introduce.
    #[tokio::test]
    async fn an_expired_badge_never_refuses_a_dial_that_does_not_carry_it() {
        let home = provisioned_home("foreign-fleet");
        let (device, _) = joined_badge(&home, SystemTime::now() - 6 * DAY).await;
        let work = crate::testkit::TestNode::seeded(1);
        let foreign_fleet = crate::testkit::TestRoot::seeded(2).verify_key();
        let slip = work
            .fleet_slip(
                &"ssh".parse().expect("valid service"),
                foreign_fleet,
                nauthy::Request::expires_in(core::time::Duration::from_secs(3600)),
            )
            .expect("mint a signet-bound slip");
        let slip_text = slip.to_string();

        let mut warned = Vec::new();
        let resolved = resolve_to(
            Credential::Family {
                present: Some(slip),
            },
            &device,
            &home,
            &mut warned,
        )
        .await
        .expect("a dial that never sends the dead badge is not this device's to refuse");
        assert_eq!(
            resolved.grant.as_ref().map(Link::as_str),
            Some(slip_text.as_str()),
            "the slip is still slot 1"
        );
        assert!(
            resolved.membership.is_none(),
            "the dead badge is dropped, as a foreign-fleet slip always drops it"
        );
        assert!(
            warned.is_empty(),
            "nothing is warned about a credential this dial does not carry"
        );
    }

    /// B4: the bare-form guard refuses each reach-family flag by name (never silently ignoring it), and
    /// the defaults pass through: a bare `stop`/`service ls`/`status` binds no transport and seeds no
    /// discovery, so there is nothing for the trio to do.
    #[test]
    fn bare_reach_flags_are_rejected_by_name() {
        assert!(
            reject_bare_reach(&defaults()).is_ok(),
            "the parsed defaults have nothing to refuse"
        );

        let hint = format!(
            "{}=127.0.0.1:9000",
            crate::identity::Secret::ephemeral().node_id()
        )
        .parse::<transport::PeerHint>()
        .expect("a valid peer hint");
        let cases = [
            (
                transport::ReachArgs {
                    transport: transport::Transport::Quirk,
                    ..defaults()
                },
                "--transport",
            ),
            (
                transport::ReachArgs {
                    local: true,
                    ..defaults()
                },
                "--local",
            ),
            (
                transport::ReachArgs {
                    peer: vec![hint],
                    ..defaults()
                },
                "--peer",
            ),
            (
                transport::ReachArgs {
                    relay: Some("https://relay.example".parse().expect("a valid relay url")),
                    ..defaults()
                },
                "--relay",
            ),
            (
                transport::ReachArgs {
                    resolver: Some(
                        "https://dns.example/pkarr"
                            .parse()
                            .expect("a valid resolver url"),
                    ),
                    ..defaults()
                },
                "--resolver",
            ),
        ];
        for (reach, flag) in cases {
            let error = reject_bare_reach(&reach)
                .expect_err("a flag with no effect on a bare form must refuse");
            assert_eq!(
                format!("{error:#}"),
                format!("{flag} only applies when reaching a peer; drop it or name one")
            );
        }
    }
}
