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
//!
//! Every dialer here is a `Device`: a scratch home holding this machine's key, a pin, and the badge that
//! root signed for it. That is the only standing whose dial carries a badge.

use core::time::Duration;

use bifrost::NodeId;
use clap::Parser;
use nauthy::{Link, Request, Service};
use swoosh::credential::LinkExt as _;
use swoosh::home::Home;
use swoosh::identity::Secret;
use swoosh::reaching::{self, BindRole, Reaching};
use swoosh::testkit::{TestNode, TestRoot};

use crate::commands::{ping, reach};

/// Clap-parse a `ping` verb exactly as the CLI would, so `--present <link>` runs through
/// [`Link`](nauthy::Link)'s `FromStr` and lands on the real command's field.
#[derive(Parser)]
struct PingWrap {
    #[command(flatten)]
    cmd: ping::PingCmd,
}

/// A minted link as a person types it: `swoosh:` then the bare text.
fn shown(link: &nauthy::Link) -> String {
    swoosh::link::Link::from(nauthy::Link::clone(link)).to_string()
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

/// Clap-parse a `ping` verb whose PEER is the given string (a raw key, a petname, or a `swoosh:` link), with
/// no `--present`: the link-as-peer path, where the peer self-presents its own slip via the credential fold.
fn ping_with_peer(peer: &str) -> ping::PingCmd {
    PingWrap::try_parse_from(["ping", peer])
        .expect("the verb parses with a peer")
        .cmd
}

/// The root the dialing device's badge roots at: its own fleet, which the fleet-match slot-2 rule
/// compares a slip against.
const ROOT: u8 = 0x71;
/// The dialing device's key.
const DEVICE: u8 = 0x72;

/// A dialing device: a scratch home with its key, a pin to [`ROOT`], and the badge [`ROOT`] signed for
/// it. Removed on drop.
struct Device {
    home: Home,
    secret: Secret,
}

impl Device {
    async fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "swoosh-dial-verb-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Home::resolve(Some(dir)).unwrap();
        let device = TestNode::seeded(DEVICE);
        swoosh::identity::write(&device.seed(), &home)
            .await
            .unwrap();
        let root = TestRoot::seeded(ROOT);
        swoosh::config::write_signet(&home, root.node_id())
            .await
            .unwrap();
        let badge = root
            .device_badge(
                device.node_id(),
                Request::expires_in(Duration::from_secs(60 * 24 * 60 * 60)),
            )
            .unwrap();
        swoosh::config::write_badge(&home, &badge).await.unwrap();
        let secret = swoosh::identity::load(&home).await.unwrap().unwrap();
        Self { home, secret }
    }

    /// Drive the verb's declared credential through the ONE resolver and read the two wire slots, the
    /// exact path the composition root runs before dialing. Takes any reaching verb, so `reach` is proven
    /// through the same chain as `ping`.
    async fn slots_for(&self, cmd: &impl Reaching) -> (Option<Link>, Option<Link>) {
        let BindRole::Dialing(credential) = cmd.bind_role() else {
            panic!("a reaching verb that dials states the credential it dials with");
        };
        reaching::resolve(credential, &self.secret, &self.home)
            .await
            .expect("resolve the verb's credential into wire slots")
            .into_slots()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.home.dir());
    }
}

#[tokio::test]
async fn a_verb_with_a_signet_bound_present_slip_fills_slot_two() {
    // Work issues a signet-bound slip pinning the DIALER'S OWN fleet (the root its badge roots at); a hire
    // runs `ping <work> --present <slip>`. The slip must pin that fleet for slot 2 to help admission (and
    // thus be attached) under the fleet-match rule.
    let device = Device::new("present").await;
    let work = TestNode::seeded(1);
    let fleet = TestRoot::seeded(ROOT).verify_key();
    let service: Service = "ping".parse().unwrap();
    let slip = work
        .fleet_slip(
            &service,
            fleet,
            Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();

    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
    let cmd = ping_with_present(&peer, &shown(&slip));
    let (slot1, slot2) = device.slots_for(&cmd).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(slip.as_str()),
        "the signet-bound slip is slot 1 (the grant)"
    );
    let badge = slot2
        .expect("REGRESSION: a signet-bound --present dial must fill slot 2 with the fleet badge");
    assert!(
        badge.as_str().starts_with("ed01") && badge.as_str() != slip.as_str(),
        "slot 2 is the dialer's own member badge, not the slip: {badge}"
    );
}

#[tokio::test]
async fn a_verb_with_a_bearer_present_slip_leaves_slot_two_empty() {
    // A plain bearer slip is NOT signet-bound, so no fleet badge is attached: a dial that does not already
    // prove fleet membership must not leak the dialer's device-to-signet linkage.
    let device = Device::new("bearer").await;
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
    let cmd = ping_with_present(&peer, &shown(&bearer));
    let (slot1, slot2) = device.slots_for(&cmd).await;

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
    // Defect #1 at the VERB boundary: `ping swoosh:<own-fleet-signet-link>` with NO `--present`. The link is
    // the PEER; the credential fold self-presents it, so `bind_role() -> resolve() -> slots` fills slot 1
    // (the link) AND slot 2 (the dialer's own fleet badge), IDENTICAL to passing it via `--present`. The
    // slip pins the dialer's OWN fleet so the fleet-match rule attaches slot 2.
    let device = Device::new("link-peer").await;
    let work = TestNode::seeded(1);
    let fleet = TestRoot::seeded(ROOT).verify_key();
    let service: Service = "ping".parse().unwrap();
    let link = work
        .fleet_slip(
            &service,
            fleet,
            Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();

    let cmd = ping_with_peer(&shown(&link));
    let (slot1, slot2) = device.slots_for(&cmd).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(link.as_str()),
        "a link-as-peer folds to slot 1 (the grant), the same slot a --present link fills"
    );
    let badge = slot2.expect(
        "REGRESSION (defect #1): a signet-bound link-as-peer must fill slot 2, not drop it as before",
    );
    assert!(
        badge.as_str().starts_with("ed01") && badge.as_str() != link.as_str(),
        "slot 2 is the dialer's own member badge, not the link: {badge}"
    );
}

#[tokio::test]
async fn a_verb_with_a_foreign_fleet_link_as_peer_leaves_slot_two_empty() {
    // ADV1 at the verb boundary: a link-as-peer pinning a fleet the dialer is NOT in attaches no slot 2, so
    // pasting an attacker's signet-bound link as the peer never leaks the dialer's own fleet-signet badge.
    let device = Device::new("foreign").await;
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

    let cmd = ping_with_peer(&shown(&link));
    let (slot1, slot2) = device.slots_for(&cmd).await;

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
    let device = Device::new("reach-badge").await;
    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();

    let (reach_slot1, reach_slot2) = device.slots_for(&reach_to_peer(&peer)).await;
    let badge = reach_slot1
        .expect("REGRESSION: `reach` must present the member badge, not dial as a stranger");
    assert!(
        badge.as_str().starts_with("ed01"),
        "slot 1 is the member badge as a swoosh: link, got {badge}"
    );
    assert_eq!(
        badge.dial_node().expect("the badge roots at a key"),
        TestRoot::seeded(ROOT).node_id(),
        "the badge is the stored one, rooted at this device's root"
    );
    assert!(
        reach_slot2.is_none(),
        "a plain member dial attaches NO slot 2 (no signet-linkage over-share)"
    );

    // The same slots its siblings resolve, which is the whole claim: one fold, one resolver, one wire
    // shape, so a member is admitted (or refused) identically whichever verb they reach with.
    let (ping_slot1, ping_slot2) = device.slots_for(&ping_with_peer(&peer)).await;
    assert_eq!(
        ping_slot1.as_ref().map(Link::as_str),
        Some(badge.as_str()),
        "`ping` presents the same member badge `reach` does"
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
    let device = Device::new("reach-link").await;
    let work = TestNode::seeded(1);
    let fleet = TestRoot::seeded(ROOT).verify_key();
    let service: Service = "ssh".parse().unwrap();
    let link = work
        .fleet_slip(
            &service,
            fleet,
            Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();

    let (slot1, slot2) = device.slots_for(&reach_to_peer(&shown(&link))).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(link.as_str()),
        "the link-as-peer is slot 1 (the grant)"
    );
    let badge = slot2.expect(
        "REGRESSION: a signet-bound `reach` must fill slot 2 with the dialer's fleet badge",
    );
    assert!(
        badge.as_str().starts_with("ed01") && badge.as_str() != link.as_str(),
        "slot 2 is the dialer's own member badge, not the link: {badge}"
    );
}

/// A link typed with its `swoosh:` mark reaches the dial bare: slot 1 carries nauthy's text, never the
/// printed form.
#[tokio::test]
async fn a_presented_link_carries_no_prefix_on_the_wire() {
    let device = Device::new("wire").await;
    let service: Service = "ping".parse().unwrap();
    let slip = TestNode::seeded(1)
        .bound_slip(
            &service,
            TestNode::seeded(DEVICE).verify_key(),
            Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();
    let typed = shown(&slip);
    assert!(typed.starts_with("swoosh:"), "{typed}");

    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();
    for cmd in [ping_with_present(&peer, &typed), ping_with_peer(&typed)] {
        let (slot1, _) = device.slots_for(&cmd).await;
        let slot1 = slot1.expect("the typed link is slot 1");
        assert_eq!(slot1.as_str(), slip.as_str(), "slot 1 is the bare link");
        assert!(!slot1.as_str().contains("swoosh:"), "{slot1:?}");
    }
}
