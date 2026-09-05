// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The CLI wiring the Operator caught live: a reach VERB dialed with a signet-bound `--present` slip must
//! put the fleet membership badge in wire slot 2, or the gate refuses "slip alone, no fleet badge".
//!
//! The 7 diagnostic/control verbs used to thread `--present` themselves and declare
//! `credential() -> Family { present: None }`, so `resolve()` never saw the slip, never ran
//! `is_authority_bound()`, and left slot 2 empty. This test drives the REAL verb (clap-parsed, exactly as the
//! CLI builds it) through `credential() -> resolve() -> slots`, the chain the old `resolve()`-direct unit
//! test bypassed by hand-constructing `Family { present: Some(slip) }` (a state the verbs never produced).
//! It also proves the Adversary privacy fix survives the verb path: a NON-signet `--present` leaves slot 2
//! empty, so a bearer/device dial never leaks the dialer's device-to-signet linkage.

use core::time::Duration;

use bifrost::NodeId;
use clap::Parser;
use nauthy::{Identity, Service};
use swoosh::commands::ping::PingCmd;
use swoosh::identity::Secret;
use swoosh::reaching::{self, Reaching};
use tightbeam::identity::AsVerifyKey as _;

/// Clap-parse a `ping` verb exactly as the CLI would, so `--present <link>` runs through
/// [`SheerLink`](swoosh::credential::SheerLink)'s `FromStr` and lands on the real command's field.
#[derive(Parser)]
struct PingWrap {
    #[command(flatten)]
    cmd: PingCmd,
}

fn ping_with_present(peer: &str, present: &str) -> PingCmd {
    PingWrap::try_parse_from(["ping", peer, "--present", present])
        .expect("the verb parses with a --present link")
        .cmd
}

/// Clap-parse a `ping` verb whose PEER is the given string (a raw key, a petname, or a `sheer:` link), with
/// no `--present`: the link-as-peer path, where the peer self-presents its own slip via the credential fold.
fn ping_with_peer(peer: &str) -> PingCmd {
    PingWrap::try_parse_from(["ping", peer])
        .expect("the verb parses with a peer")
        .cmd
}

/// Drive the verb's declared credential through the ONE resolver under a caller-supplied `secret` (so the
/// test controls the dialer's own fleet, which the fleet-match slot-2 rule compares against) and read the
/// two wire slots, the exact path the composition root runs before dialing.
async fn slots_for(cmd: &PingCmd, secret: &Secret) -> (Option<String>, Option<String>) {
    reaching::resolve(cmd.credential(), secret, None)
        .await
        .expect("resolve the verb's credential into wire slots")
        .into_slots()
}

#[tokio::test]
async fn a_verb_with_a_signet_bound_present_slip_fills_slot_two() {
    // Work issues a signet-bound slip pinning the DIALER'S OWN fleet; a hire runs `ping <work> --present
    // <slip>`. With no `--key`, the dialer self-signs its badge at `secret.node_id()`, so the slip must pin
    // that fleet for slot 2 to help admission (and thus be attached) under the fleet-match rule.
    let secret = Secret::ephemeral();
    let work = Identity::from_secret(&[1u8; 32]).unwrap();
    let fleet = secret.node_id().verify_key();
    let service: Service = "ping".parse().unwrap();
    let slip =
        tightbeam::tunnel::mint_signet_link(&work, &service, fleet, Duration::from_secs(3600))
            .unwrap();

    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
    let cmd = ping_with_present(&peer, &slip);
    let (slot1, slot2) = slots_for(&cmd, &secret).await;

    assert_eq!(
        slot1.as_deref(),
        Some(slip.as_str()),
        "the signet-bound slip is slot 1 (the grant)"
    );
    let badge = slot2
        .expect("REGRESSION: a signet-bound --present dial must fill slot 2 with the fleet badge");
    assert!(
        badge.starts_with("sheer:") && badge != slip,
        "slot 2 is the dialer's own member badge, not the slip: {badge}"
    );
}

#[tokio::test]
async fn a_verb_with_a_bearer_present_slip_leaves_slot_two_empty() {
    // A plain bearer slip is NOT signet-bound, so no fleet badge is attached: the Adversary privacy fix
    // survives the verb path (no device-to-signet leak on a non-signet dial).
    let secret = Secret::ephemeral();
    let work = Identity::from_secret(&[1u8; 32]).unwrap();
    let service: Service = "ping".parse().unwrap();
    let bearer =
        tightbeam::tunnel::mint_link(&work, &service, Duration::from_secs(3600), false).unwrap();

    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
    let cmd = ping_with_present(&peer, &bearer);
    let (slot1, slot2) = slots_for(&cmd, &secret).await;

    assert_eq!(
        slot1.as_deref(),
        Some(bearer.as_str()),
        "the bearer slip is slot 1 (the grant)"
    );
    assert_eq!(
        slot2, None,
        "a non-signet-bound slip attaches NO slot 2 badge (privacy preserved through the verb path)"
    );
}

#[tokio::test]
async fn a_verb_with_a_signet_bound_link_as_peer_fills_slot_two() {
    // Defect #1 at the VERB boundary: `ping sheer:<own-fleet-signet-link>` with NO `--present`. The link is
    // the PEER; the credential fold self-presents it, so `credential() -> resolve() -> slots` fills slot 1
    // (the link) AND slot 2 (the dialer's own fleet badge), IDENTICAL to passing it via `--present`. The
    // slip pins the dialer's OWN fleet so the fleet-match rule attaches slot 2.
    let secret = Secret::ephemeral();
    let work = Identity::from_secret(&[1u8; 32]).unwrap();
    let fleet = secret.node_id().verify_key();
    let service: Service = "ping".parse().unwrap();
    let link =
        tightbeam::tunnel::mint_signet_link(&work, &service, fleet, Duration::from_secs(3600))
            .unwrap();

    let cmd = ping_with_peer(&link);
    let (slot1, slot2) = slots_for(&cmd, &secret).await;

    assert_eq!(
        slot1.as_deref(),
        Some(link.as_str()),
        "a link-as-peer folds to slot 1 (the grant), the same slot a --present link fills"
    );
    let badge = slot2.expect(
        "REGRESSION (defect #1): a signet-bound link-as-peer must fill slot 2, not drop it as before",
    );
    assert!(
        badge.starts_with("sheer:") && badge != link,
        "slot 2 is the dialer's own member badge, not the link: {badge}"
    );
}

#[tokio::test]
async fn a_verb_with_a_foreign_fleet_link_as_peer_leaves_slot_two_empty() {
    // ADV1 at the verb boundary: a link-as-peer pinning a fleet the dialer is NOT in attaches no slot 2, so
    // pasting an attacker's signet-bound link as the peer never leaks the dialer's own fleet-signet badge.
    let secret = Secret::ephemeral();
    let work = Identity::from_secret(&[1u8; 32]).unwrap();
    let foreign_fleet = Identity::from_secret(&[2u8; 32]).unwrap().verifying_key();
    let service: Service = "ping".parse().unwrap();
    let link = tightbeam::tunnel::mint_signet_link(
        &work,
        &service,
        foreign_fleet,
        Duration::from_secs(3600),
    )
    .unwrap();

    let cmd = ping_with_peer(&link);
    let (slot1, slot2) = slots_for(&cmd, &secret).await;

    assert_eq!(
        slot1.as_deref(),
        Some(link.as_str()),
        "the link-as-peer is still slot 1 (the grant)"
    );
    assert_eq!(
        slot2, None,
        "a link-as-peer pinning a foreign fleet attaches NO slot 2 (no fleet-signet over-share)"
    );
}
