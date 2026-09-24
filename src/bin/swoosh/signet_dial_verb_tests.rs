// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The CLI wiring, proven through the real verb: a reach VERB dialed with a signet-bound `--present` slip
//! must put the fleet membership badge in wire slot 2, or the gate refuses "slip alone, no fleet badge".
//!
//! The 7 diagnostic/control verbs used to thread `--present` themselves and declare a credential of
//! `Family { present: None }`, so `resolve()` never saw the slip, never ran `is_authority_bound()`, and
//! left slot 2 empty. This test drives the REAL verb (clap-parsed, exactly as the CLI builds it) through
//! `bind_role() -> resolve() -> slots`, the chain the old `resolve()`-direct unit test bypassed by
//! hand-constructing `Family { present: Some(slip) }` (a state the verbs never produced). It also proves
//! the privacy rule survives the verb path: a NON-signet `--present` leaves slot 2 empty, so a
//! bearer/device dial never leaks the dialer's device-to-signet linkage.
//!
//! `reach` (the generic dial, spelled `forward` when this defect shipped) rides the same chain: it used
//! to derive slot 1 by hand inside its own `run`, which silently dropped slot 2 (the resolver is the only
//! code that computes it), so a signet-bound dial through it was capped at what slot 1 alone could open.

use core::time::Duration;

use bifrost::NodeId;
use clap::Parser;
use nauthy::{Link, Request, Service};
use swoosh::credential::LinkExt as _;
use swoosh::home::Home;
use swoosh::identity::Secret;
use swoosh::reaching::{self, BindRole, Reaching};
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;

use crate::commands::{ping, reach};

/// Clap-parse a `ping` verb exactly as the CLI would, so `--present <link>` runs through
/// [`Link`](nauthy::Link)'s `FromStr` and lands on the real command's field.
#[derive(Parser)]
struct PingWrap {
    #[command(flatten)]
    cmd: ping::PingCmd,
}

fn ping_with_present(peer: &str, present: &str) -> ping::PingCmd {
    PingWrap::try_parse_from(["ping", peer, "--present", present])
        .expect("the verb parses with a --present link")
        .cmd
}

/// Clap-parse a `reach` verb exactly as the CLI would: `reach <peer> <service>`, whose default sink is
/// stdout, the shape with no local port to bind. The peer string carries the same three forms `ping`'s does.
#[derive(Parser)]
struct ReachWrap {
    #[command(flatten)]
    cmd: reach::ReachCmd,
}

fn reach_to_peer(peer: &str) -> reach::ReachCmd {
    ReachWrap::try_parse_from(["reach", peer, "ssh"])
        .expect("the verb parses with a peer and a service")
        .cmd
}

/// Clap-parse a `ping` verb whose PEER is the given string (a raw key, a petname, or a `sheer:` link), with
/// no `--present`: the link-as-peer path, where the peer self-presents its own slip via the credential fold.
fn ping_with_peer(peer: &str) -> ping::PingCmd {
    PingWrap::try_parse_from(["ping", peer])
        .expect("the verb parses with a peer")
        .cmd
}

/// Drive the verb's declared credential through the ONE resolver under a caller-supplied `secret` (so the
/// test controls the dialer's own fleet, which the fleet-match slot-2 rule compares against) and read the
/// two wire slots, the exact path the composition root runs before dialing. Takes any reaching verb, so
/// `reach` is proven through the same chain as `ping`.
async fn slots_for(cmd: &impl Reaching, secret: &Secret) -> (Option<Link>, Option<Link>) {
    // The default home (no stored badge), so a `Family` dial falls back to the self-sign, exactly as an
    // unprovisioned dialer does.
    let home = Home::resolve(None).expect("resolve the default home");
    let BindRole::Dialing(credential) = cmd.bind_role() else {
        panic!("a reaching verb that dials states the credential it dials with");
    };
    reaching::resolve(credential, secret, &home)
        .await
        .expect("resolve the verb's credential into wire slots")
        .into_slots()
}

#[tokio::test]
async fn a_verb_with_a_signet_bound_present_slip_fills_slot_two() {
    // Work issues a signet-bound slip pinning the DIALER'S OWN fleet; a hire runs `ping <work> --present
    // <slip>`. On the default home, the dialer self-signs its badge at `secret.node_id()`, so the slip must pin
    // that fleet for slot 2 to help admission (and thus be attached) under the fleet-match rule.
    let secret = Secret::ephemeral();
    let work = TestNode::seeded(1);
    let fleet = secret.node_id().verify_key();
    let service: Service = "ping".parse().unwrap();
    let slip = work
        .fleet_slip(
            &service,
            fleet,
            Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();

    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
    let cmd = ping_with_present(&peer, slip.as_str());
    let (slot1, slot2) = slots_for(&cmd, &secret).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(slip.as_str()),
        "the signet-bound slip is slot 1 (the grant)"
    );
    let badge = slot2
        .expect("REGRESSION: a signet-bound --present dial must fill slot 2 with the fleet badge");
    assert!(
        badge.as_str().starts_with("sheer:") && badge.as_str() != slip.as_str(),
        "slot 2 is the dialer's own member badge, not the slip: {badge}"
    );
}

#[tokio::test]
async fn a_verb_with_a_bearer_present_slip_leaves_slot_two_empty() {
    // A plain bearer slip is NOT signet-bound, so no fleet badge is attached: a dial that does not already
    // prove fleet membership must not leak the dialer's device-to-signet linkage.
    let secret = Secret::ephemeral();
    let work = TestNode::seeded(1);
    let service: Service = "ping".parse().unwrap();
    let bearer = work
        .slip(&service, Request::expires_in(Duration::from_secs(3600)))
        .unwrap()
        .seal()
        .unwrap()
        .link()
        .unwrap();

    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
    let cmd = ping_with_present(&peer, bearer.as_str());
    let (slot1, slot2) = slots_for(&cmd, &secret).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(bearer.as_str()),
        "the bearer slip is slot 1 (the grant)"
    );
    assert!(
        slot2.is_none(),
        "a non-signet-bound slip attaches NO slot 2 badge (privacy preserved through the verb path)"
    );
}

#[tokio::test]
async fn a_verb_with_a_signet_bound_link_as_peer_fills_slot_two() {
    // Defect #1 at the VERB boundary: `ping sheer:<own-fleet-signet-link>` with NO `--present`. The link is
    // the PEER; the credential fold self-presents it, so `bind_role() -> resolve() -> slots` fills slot 1
    // (the link) AND slot 2 (the dialer's own fleet badge), IDENTICAL to passing it via `--present`. The
    // slip pins the dialer's OWN fleet so the fleet-match rule attaches slot 2.
    let secret = Secret::ephemeral();
    let work = TestNode::seeded(1);
    let fleet = secret.node_id().verify_key();
    let service: Service = "ping".parse().unwrap();
    let link = work
        .fleet_slip(
            &service,
            fleet,
            Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();

    let cmd = ping_with_peer(link.as_str());
    let (slot1, slot2) = slots_for(&cmd, &secret).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(link.as_str()),
        "a link-as-peer folds to slot 1 (the grant), the same slot a --present link fills"
    );
    let badge = slot2.expect(
        "REGRESSION (defect #1): a signet-bound link-as-peer must fill slot 2, not drop it as before",
    );
    assert!(
        badge.as_str().starts_with("sheer:") && badge.as_str() != link.as_str(),
        "slot 2 is the dialer's own member badge, not the link: {badge}"
    );
}

#[tokio::test]
async fn a_verb_with_a_foreign_fleet_link_as_peer_leaves_slot_two_empty() {
    // ADV1 at the verb boundary: a link-as-peer pinning a fleet the dialer is NOT in attaches no slot 2, so
    // pasting an attacker's signet-bound link as the peer never leaks the dialer's own fleet-signet badge.
    let secret = Secret::ephemeral();
    let work = TestNode::seeded(1);
    let foreign_fleet = TestRoot::seeded(2).verify_key();
    let service: Service = "ping".parse().unwrap();
    let link = work
        .fleet_slip(
            &service,
            foreign_fleet,
            Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();

    let cmd = ping_with_peer(link.as_str());
    let (slot1, slot2) = slots_for(&cmd, &secret).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(link.as_str()),
        "the link-as-peer is still slot 1 (the grant)"
    );
    assert!(
        slot2.is_none(),
        "a link-as-peer pinning a foreign fleet attaches NO slot 2 (no fleet-signet over-share)"
    );
}

#[tokio::test]
async fn reach_presents_the_member_badge_like_its_siblings() {
    // The shipped defect: the generic dial declared no badge, so a member reaching a service on their OWN
    // gated node was refused by their own fleet while `ping`/`speed`/`ssh` to the same node worked. A plain
    // `reach <key> <service>` must resolve slot 1 to the member badge, exactly as `ping <key>` does.
    let secret = Secret::ephemeral();
    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();

    let (reach_slot1, reach_slot2) = slots_for(&reach_to_peer(&peer), &secret).await;
    let badge = reach_slot1
        .expect("REGRESSION: `reach` must present the member badge, not dial as a stranger");
    assert!(
        badge.as_str().starts_with("sheer:"),
        "slot 1 is the member badge as a sheer: link, got {badge}"
    );
    assert_eq!(
        badge.dial_node(),
        secret.node_id(),
        "the badge roots at the key the dial binds under, which is what the family gate proves"
    );
    assert!(
        reach_slot2.is_none(),
        "a plain member dial attaches NO slot 2 (no signet-linkage over-share)"
    );

    // The same slots its siblings resolve, which is the whole claim: one fold, one resolver, one wire
    // shape, so a member is admitted (or refused) identically whichever verb they reach with.
    let (ping_slot1, ping_slot2) = slots_for(&ping_with_peer(&peer), &secret).await;
    assert_eq!(
        ping_slot1.map(|grant| grant.dial_node()),
        Some(secret.node_id()),
        "`ping` presents the same self-signed member badge `reach` now does"
    );
    assert!(
        ping_slot2.is_none(),
        "neither plain member dial attaches slot 2"
    );
}

#[tokio::test]
async fn reach_with_a_signet_bound_link_as_peer_fills_slot_two() {
    // The generic dial's bearer-only ceiling: it derived slot 1 by hand inside its own `run`, and the
    // resolver is the ONLY code that computes slot 2, so a signet-bound link through it arrived without the
    // fleet badge its gate ANDs. Reading both slots off the shared resolver is what lifts the ceiling.
    let secret = Secret::ephemeral();
    let work = TestNode::seeded(1);
    let fleet = secret.node_id().verify_key();
    let service: Service = "ssh".parse().unwrap();
    let link = work
        .fleet_slip(
            &service,
            fleet,
            Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();

    let (slot1, slot2) = slots_for(&reach_to_peer(link.as_str()), &secret).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(link.as_str()),
        "the link-as-peer is slot 1 (the grant)"
    );
    let badge = slot2.expect(
        "REGRESSION: a signet-bound `reach` must fill slot 2 with the dialer's fleet badge",
    );
    assert!(
        badge.as_str().starts_with("sheer:") && badge.as_str() != link.as_str(),
        "slot 2 is the dialer's own member badge, not the link: {badge}"
    );
}
