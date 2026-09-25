//! The test fixtures sign what they say and count what they say: each badge and slip grants exactly the
//! dialer it names at the key it names, and a prompt event is one question, whatever it reads.

use core::time::Duration;
use std::path::Path;
use std::time::SystemTime;

use nauthy::{Request, Service};
use tightbeam::identity::AsVerifyKey as _;

use super::{Counting, TestNode, TestRoot, hand_signed};
use crate::passphrase::Prompt as _;

fn hour() -> SystemTime {
    SystemTime::now() + Duration::from_secs(3600)
}

fn ssh() -> Service {
    "ssh".parse().expect("a service name")
}

/// One `choose` is one event, though a person types the passphrase twice for it.
#[test]
fn a_choose_is_one_prompt_event() {
    let mut prompt = Counting::new(["first", "second"]);
    prompt
        .choose(Path::new("root.key"))
        .expect("the script answers");
    assert_eq!(prompt.events(), 1);
    prompt
        .unlock(Path::new("root.key"))
        .expect("the script answers");
    assert_eq!(prompt.events(), 2);
}

/// A question with no answer left is still a question asked: it counts, then refuses.
#[test]
fn a_refused_prompt_is_still_an_event() {
    let mut prompt = Counting::refusing();
    assert_eq!(prompt.events(), 0, "nothing asked yet");
    assert!(prompt.unlock(Path::new("root.key")).is_err());
    assert!(prompt.choose(Path::new("root.key")).is_err());
    assert_eq!(prompt.events(), 2);
}

/// A seed names one key: the same byte gives the same key in either role, and the node id a transport
/// binds under matches the key a badge roots at.
#[test]
fn a_seed_names_one_key() {
    let root = TestRoot::seeded(7);
    assert_eq!(root.seed(), [7; 32]);
    assert_eq!(root.verify_key(), TestNode::seeded(7).verify_key());
    assert_eq!(root.node_id().verify_key(), Ok(root.verify_key()));
    assert_ne!(root.verify_key(), TestRoot::seeded(8).verify_key());
}

/// A device badge admits its device as a member at the root that signed it, and no other dialer.
#[test]
fn a_device_badge_admits_its_device_and_no_other() {
    let root = TestRoot::seeded(1);
    let device = TestNode::seeded(2);
    let badge = root
        .device_badge(device.node_id(), hour())
        .expect("mint a badge");
    let cap = badge.cap();
    assert_eq!(cap.root(), root.verify_key());
    cap.verify_member_at_root_without_revocation(
        SystemTime::now(),
        device.verify_key(),
        root.verify_key(),
    )
    .expect("the bound device is a member");
    assert!(
        cap.verify_member_at_root_without_revocation(
            SystemTime::now(),
            TestNode::seeded(3).verify_key(),
            root.verify_key(),
        )
        .is_err(),
        "another dialer is refused"
    );
}

/// A bound slip grants its service to its peer only; a plain slip grants it to anyone.
#[test]
fn a_bound_slip_grants_its_peer_only() {
    let node = TestNode::seeded(4);
    let peer = TestNode::seeded(5).verify_key();
    let link = node
        .bound_slip(&ssh(), peer, hour())
        .expect("mint a bound slip");
    let bound = link.cap();
    bound
        .verify_at_root_without_revocation(&Request::now(ssh()).bound_to(peer), node.verify_key())
        .expect("the peer is granted");
    assert!(
        bound
            .verify_at_root_without_revocation(
                &Request::now(ssh()).bound_to(TestNode::seeded(6).verify_key()),
                node.verify_key(),
            )
            .is_err(),
        "another dialer is refused"
    );
    node.slip(&ssh(), hour())
        .expect("mint a slip")
        .verify_at_root_without_revocation(&Request::now(ssh()), node.verify_key())
        .expect("a plain slip needs no proven dialer");
}

/// A fleet slip names the fleet it grants, and grants nothing alone.
#[test]
fn a_fleet_slip_names_its_fleet() {
    let node = TestNode::seeded(1);
    let fleet = TestRoot::seeded(2).verify_key();
    let link = node
        .fleet_slip(&ssh(), fleet, hour())
        .expect("mint a fleet slip");
    let slip = link.cap();
    assert_eq!(
        slip.authority_bound_root().expect("reads"),
        Some(fleet),
        "the slip names the fleet it grants"
    );
    assert!(
        slip.verify_at_root_without_revocation(&Request::now(ssh()), node.verify_key())
            .is_err(),
        "without the fleet's badge beside it, the slip grants nothing"
    );
}

/// A signed document verifies under the key that signed it, and under no other.
#[test]
fn a_signed_document_verifies_under_its_signer_only() {
    let root = TestRoot::seeded(9);
    let signed = root.sign(b"roster");
    assert_eq!(
        signed.verify(root.verify_key()).expect("verifies"),
        b"roster"
    );
    assert!(signed.verify(TestRoot::seeded(10).verify_key()).is_err());
}

/// Each hand-signed badge is the root's, bound to its node, and differs from a minted one only in its end
/// date.
#[test]
fn each_hand_signed_badge_is_a_badge_with_only_its_end_date_off() {
    let root = TestRoot::seeded(hand_signed::ROOT_SEED);
    let device = TestNode::seeded(hand_signed::DEVICE_SEED);
    let now = SystemTime::now();
    let without = hand_signed::without_end_date();
    assert_eq!(
        without.cap().expiry().expect("no end date is no error"),
        None
    );
    let unreadable = hand_signed::unreadable_end_date();
    assert!(unreadable.cap().expiry().is_err());
    for badge in [without, unreadable] {
        assert_eq!(badge.root(), root.verify_key());
        badge
            .cap()
            .verify_member_at_root_without_revocation(now, device.verify_key(), root.verify_key())
            .expect("admits its device");
        assert!(
            badge
                .cap()
                .verify_member_at_root_without_revocation(
                    now,
                    TestNode::seeded(0x42).verify_key(),
                    root.verify_key()
                )
                .is_err(),
            "admits no other"
        );
    }
}
