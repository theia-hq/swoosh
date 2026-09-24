//! A node slip grants what it names, to whom it names, at this machine's key, and a bound slip is never
//! left open for its holder to pass on.

use core::time::Duration;
use std::time::SystemTime;

use nauthy::{Link, Request, Service, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;

use super::{Bind, NodeSigner, SlipError};
use crate::grants::Delegation;
use crate::identity::Secret;
use crate::testkit::{TestNode, TestRoot};

const HOUR: Duration = Duration::from_secs(3600);

fn ssh() -> Service {
    "ssh".parse().expect("a service name")
}

fn key_of(secret: &Secret) -> VerifyKey {
    secret.node_id().verify_key()
}

fn mint(secret: &Secret, bind: Bind, delegation: Delegation) -> Result<Link, SlipError> {
    mint_for(secret, bind, HOUR, delegation)
}

fn mint_for(
    secret: &Secret,
    bind: Bind,
    lifetime: Duration,
    delegation: Delegation,
) -> Result<Link, SlipError> {
    NodeSigner::from(secret).mint_slip(&ssh(), bind, lifetime, delegation)
}

fn expiry_of(link: &Link) -> SystemTime {
    link.cap()
        .expiry()
        .expect("reads")
        .expect("the slip carries its expiry")
}

/// Every kind of slip lasts the lifetime it is asked for, not a default: two lifetimes, neither an hour,
/// give each its own expiry, to the second it is recorded in.
#[test]
fn every_slip_lasts_the_lifetime_it_is_given() {
    let secret = Secret::ephemeral();
    let key = TestNode::seeded(7).verify_key();
    let week = Duration::from_secs(7 * 24 * 3600);
    let seven_hours = Duration::from_secs(7 * 3600);
    for (bind, delegation) in [
        (Bind::Anyone, Delegation::Sealed),
        (Bind::Anyone, Delegation::Delegable),
        (Bind::Device(key), Delegation::Sealed),
        (Bind::Fleet(key), Delegation::Sealed),
    ] {
        let mut expiries = Vec::new();
        for lifetime in [seven_hours, week] {
            let before = SystemTime::now();
            let link = mint_for(&secret, bind, lifetime, delegation).expect("mint");
            let after = SystemTime::now();
            let expiry = expiry_of(&link);
            assert!(
                expiry + Duration::from_secs(1) >= before + lifetime && expiry <= after + lifetime,
                "{bind:?} {delegation:?} slip asked for {lifetime:?} expires at {expiry:?}"
            );
            expiries.push(expiry);
        }
        assert_ne!(
            expiries[0], expiries[1],
            "{bind:?} {delegation:?} slips with different lifetimes expire apart"
        );
    }
}

/// A sealed bearer slip grants its service to anyone at this machine's key, for its lifetime, and cannot
/// be narrowed and passed on.
#[test]
fn a_sealed_bearer_slip_grants_anyone_and_cannot_be_narrowed() {
    let secret = Secret::ephemeral();
    let before = SystemTime::now();
    let link = mint(&secret, Bind::Anyone, Delegation::Sealed).expect("mint");
    let cap = link.cap();
    assert_eq!(
        cap.root(),
        key_of(&secret),
        "the slip roots at this machine"
    );
    cap.verify_at_root_without_revocation(&Request::now(ssh()), key_of(&secret))
        .expect("anyone holding it is granted");
    let expiry = cap
        .expiry()
        .expect("reads")
        .expect("the slip carries its expiry");
    assert!(
        expiry + Duration::from_secs(1) >= before + HOUR && expiry <= SystemTime::now() + HOUR,
        "the slip lasts its lifetime, to the second it is recorded in"
    );
    assert!(
        link.narrow(Some(&ssh()), None).is_err(),
        "a sealed slip cannot be narrowed"
    );
}

/// A delegable bearer slip is left open, so its holder can narrow it and pass it on.
#[test]
fn a_delegable_bearer_slip_can_be_narrowed() {
    let secret = Secret::ephemeral();
    let link = mint(&secret, Bind::Anyone, Delegation::Delegable).expect("mint");
    link.narrow(Some(&ssh()), None)
        .expect("a delegable slip narrows");
}

/// A device slip grants only the device it names.
#[test]
fn a_device_slip_grants_its_device_only() {
    let secret = Secret::ephemeral();
    let device = TestNode::seeded(2).verify_key();
    let link = mint(&secret, Bind::Device(device), Delegation::Sealed).expect("mint");
    let cap = link.cap();
    cap.verify_at_root_without_revocation(&Request::now(ssh()).bound_to(device), key_of(&secret))
        .expect("the device is granted");
    assert!(
        cap.verify_at_root_without_revocation(
            &Request::now(ssh()).bound_to(TestNode::seeded(3).verify_key()),
            key_of(&secret),
        )
        .is_err(),
        "another dialer is refused"
    );
    assert!(
        cap.verify_at_root_without_revocation(&Request::now(ssh()), key_of(&secret))
            .is_err(),
        "no proven dialer is refused"
    );
}

/// A fleet slip names the root whose devices it grants, and grants nothing on its own.
#[test]
fn a_fleet_slip_names_its_fleet() {
    let secret = Secret::ephemeral();
    let fleet = TestRoot::seeded(4).verify_key();
    let link = mint(&secret, Bind::Fleet(fleet), Delegation::Sealed).expect("mint");
    let cap = link.cap();
    assert_eq!(cap.authority_bound_root().expect("reads"), Some(fleet));
    assert!(
        cap.verify_at_root_without_revocation(&Request::now(ssh()), key_of(&secret))
            .is_err(),
        "without the fleet's badge beside it, the slip grants nothing"
    );
}

/// Asking for a delegable slip bound to a device or a fleet is refused, not quietly sealed.
#[test]
fn a_bound_slip_is_never_delegable() {
    let secret = Secret::ephemeral();
    let key = TestNode::seeded(5).verify_key();
    for bind in [Bind::Device(key), Bind::Fleet(key)] {
        assert!(
            matches!(
                mint(&secret, bind, Delegation::Delegable),
                Err(SlipError::BoundIsSealed)
            ),
            "{bind:?} with a delegable ask is refused"
        );
    }
}

/// A bound slip is sealed: the holder cannot narrow it and pass it on.
#[test]
fn a_bound_slip_cannot_be_narrowed() {
    let secret = Secret::ephemeral();
    let key = TestNode::seeded(6).verify_key();
    for bind in [Bind::Device(key), Bind::Fleet(key)] {
        let link = mint(&secret, bind, Delegation::Sealed).expect("mint");
        assert!(
            link.narrow(Some(&ssh()), None).is_err(),
            "{bind:?} slip cannot be narrowed"
        );
    }
}
