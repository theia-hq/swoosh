// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The CLI wiring, proven through the real verb: a reach VERB dialed with a signet-bound link typed as
//! the peer must put the fleet membership badge in wire slot 2, or the gate refuses "slip alone, no fleet
//! badge".
//!
//! The diagnostic/control verbs used to thread their slip themselves and declare a credential of
//! `Family { present: None }`, so `resolve()` never saw the slip, never ran `is_authority_bound()`, and
//! left slot 2 empty. This test drives the REAL verb (clap-parsed, exactly as the CLI builds it) through
//! `bind_role() -> resolve() -> slots`, the chain the old `resolve()`-direct unit test bypassed by
//! hand-constructing `Family { present: Some(slip) }`. It also proves the privacy rule survives the verb
//! path: a NON-signet link leaves slot 2 empty, so a bearer/device dial never leaks the dialer's
//! device-to-signet linkage.
//!
//! `forward` (the generic dial) rides the same chain: it used to derive slot 1 by hand inside its own
//! `run`, which silently dropped slot 2 (the resolver is the only code that computes it), so a
//! signet-bound dial through it was capped at what slot 1 alone could open.
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

use crate::commands::{forward, ping};

/// Clap-parse a `ping` verb exactly as the CLI would, so a link typed as the peer runs through the
/// peer parser and lands on the real command's field.
#[derive(Parser)]
struct PingWrap {
    #[command(flatten)]
    cmd: ping::PingCmd,
}

/// A minted link as a person types it: `swoosh:` then the bare text.
fn shown(link: &nauthy::Link) -> String {
    swoosh::link::Link::from(nauthy::Link::clone(link)).to_string()
}

/// Clap-parse a `forward` verb exactly as the CLI would: `forward <peer> <service> -`, the stdout local end,
/// the shape with no local port to bind. The peer string carries the same three forms `ping`'s does.
#[derive(Parser)]
struct ForwardWrap {
    #[command(flatten)]
    cmd: forward::ForwardCmd,
}

fn forward_to_peer(peer: &str) -> forward::ForwardCmd {
    ForwardWrap::try_parse_from(["forward", peer, "ssh", "-"])
        .expect("the verb parses with a peer, a service and a local end")
        .cmd
}

/// Clap-parse a `ping` verb whose PEER is the given string (a raw key, a petname, or a `swoosh:` link): a
/// link-as-peer self-presents its own slip via the credential fold.
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
        swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).unwrap();
        let badge = root
            .device_badge(
                device.node_id(),
                Request::expires_in(Duration::from_secs(60 * 24 * 60 * 60)),
            )
            .unwrap();
        swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
        let secret = swoosh::identity::load(&home).await.unwrap().unwrap();
        Self { home, secret }
    }

    /// Drive the verb's declared credential through the ONE resolver and read the two wire slots, the
    /// exact path the composition root runs before dialing. Takes any reaching verb, so `forward` is proven
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
async fn a_verb_with_a_bearer_link_as_peer_leaves_slot_two_empty() {
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

    let cmd = ping_with_peer(&shown(&bearer));
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
    // Defect #1 at the VERB boundary: `ping swoosh:<own-fleet-signet-link>`. The link is the PEER; the
    // credential fold self-presents it, so `bind_role() -> resolve() -> slots` fills slot 1 (the link) AND
    // slot 2 (the dialer's own fleet badge). The slip pins the dialer's OWN fleet so the fleet-match rule
    // attaches slot 2.
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
        "a link-as-peer folds to slot 1 (the grant)"
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
async fn forward_presents_the_member_badge_like_its_siblings() {
    // The shipped defect: the generic dial declared no badge, so a member reaching a service on their OWN
    // gated node was refused by their own fleet while `ping`/`speed`/`ssh` to the same node worked. A plain
    // `forward <key> <service> -` must resolve slot 1 to the member badge, exactly as `ping <key>` does.
    let device = Device::new("forward-badge").await;
    let peer = NodeId::from_ed25519_secret(&[5u8; 32]).to_string();

    let (forward_slot1, forward_slot2) = device.slots_for(&forward_to_peer(&peer)).await;
    let badge = forward_slot1
        .expect("REGRESSION: `forward` must present the member badge, not dial as a stranger");
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
        forward_slot2.is_none(),
        "a plain member dial attaches NO slot 2 (no signet-linkage over-share)"
    );

    // The same slots its siblings resolve, which is the whole claim: one fold, one resolver, one wire
    // shape, so a member is admitted (or refused) identically whichever verb they reach with.
    let (ping_slot1, ping_slot2) = device.slots_for(&ping_with_peer(&peer)).await;
    assert_eq!(
        ping_slot1.as_ref().map(Link::as_str),
        Some(badge.as_str()),
        "`ping` presents the same member badge `forward` does"
    );
    assert!(
        ping_slot2.is_none(),
        "neither plain member dial attaches slot 2"
    );
}

#[tokio::test]
async fn forward_with_a_signet_bound_link_as_peer_fills_slot_two() {
    // The generic dial's bearer-only ceiling: it derived slot 1 by hand inside its own `run`, and the
    // resolver is the ONLY code that computes slot 2, so a signet-bound link through it arrived without the
    // fleet badge its gate ANDs. Reading both slots off the shared resolver is what lifts the ceiling.
    let device = Device::new("forward-link").await;
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

    let (slot1, slot2) = device.slots_for(&forward_to_peer(&shown(&link))).await;

    assert_eq!(
        slot1.as_ref().map(Link::as_str),
        Some(link.as_str()),
        "the link-as-peer is slot 1 (the grant)"
    );
    let badge = slot2.expect(
        "REGRESSION: a signet-bound `forward` must fill slot 2 with the dialer's fleet badge",
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

    let (slot1, _) = device.slots_for(&ping_with_peer(&typed)).await;
    let slot1 = slot1.expect("the typed link is slot 1");
    assert_eq!(slot1.as_str(), slip.as_str(), "slot 1 is the bare link");
    assert!(!slot1.as_str().contains("swoosh:"), "{slot1:?}");
}
