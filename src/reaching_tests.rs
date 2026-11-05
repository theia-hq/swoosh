use std::time::SystemTime;

use super::into_slot_at;
use crate::badge;
use crate::testkit::{TestNode, TestRoot};

#[test]
fn a_stored_badge_covers_its_effective_second_without_extending_advisory_warnings() {
    use core::time::Duration;

    let node = TestNode::seeded(2).node_id();
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_788_400_000);
    let badge = TestRoot::seeded(1).device_badge(node, base).expect("badge");
    let until = badge
        .cap()
        .valid_until()
        .expect("effective expiry")
        .expect("bound");
    for now in [
        base - Duration::from_nanos(1),
        base,
        base + Duration::from_millis(500),
        until,
    ] {
        let mut warned = Vec::new();
        let presented = into_slot_at(badge.clone(), node, &mut warned, now).expect("live bound");
        assert_eq!(presented.as_str(), badge.as_str());
        let advisory = badge::Expiry::read(&badge, now).expect("advisory expiry");
        let expected = match advisory {
            badge::Expiry::Expiring { .. } => format!(
                "swoosh: this device's membership badge {advisory}; {}\n",
                badge::remedy(node)
            ),
            badge::Expiry::Expired { .. } => String::new(),
            other => panic!("unexpected advisory reading: {other:?}"),
        };
        assert_eq!(String::from_utf8(warned).expect("utf-8"), expected);
    }
    let next = base + Duration::from_secs(1);
    let mut warned = Vec::new();
    let Err(error) = into_slot_at(badge, node, &mut warned, next) else {
        panic!("the next second must refuse the badge");
    };
    let expiry = badge::Expiry::at(Some(until), next);
    assert_eq!(
        error.to_string(),
        format!(
            "this device's membership badge {expiry}, so a family-gated peer will refuse this dial; {}",
            badge::remedy(node)
        )
    );
    assert!(warned.is_empty());
}

#[test]
fn badge_refusal_reads_attenuation_and_propagates_unreadable_bounds() {
    use core::time::Duration;

    let node = TestNode::seeded(2).node_id();
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_788_400_000);
    let cap = TestRoot::seeded(1)
        .member_badge(
            TestNode::seeded(2).verify_key(),
            base + Duration::from_secs(10),
        )
        .expect("badge")
        .attenuate(None, Some(base))
        .expect("earlier check");
    let badge = cap.link().expect("link");
    let until = cap.valid_until().expect("effective expiry").expect("bound");
    assert_eq!(
        cap.expiry().expect("advisory date"),
        Some(base + Duration::from_secs(10))
    );
    let mut warned = Vec::new();
    into_slot_at(badge.clone(), node, &mut warned, until).expect("inclusive narrowed endpoint");
    assert_eq!(String::from_utf8(warned).expect("utf-8").lines().count(), 1);
    let mut warned = Vec::new();
    let next = base + Duration::from_secs(1);
    let Err(error) = into_slot_at(badge, node, &mut warned, next) else {
        panic!("the earlier effective bound must refuse");
    };
    let expiry = badge::Expiry::at(Some(until), next);
    assert_eq!(
        error.to_string(),
        format!(
            "this device's membership badge {expiry}, so a family-gated peer will refuse this dial; {}",
            badge::remedy(node)
        )
    );
    assert!(warned.is_empty());
    let unreadable = crate::testkit::hand_signed::unreadable_end_date();
    let Err(error) = into_slot_at(unreadable, node, &mut warned, base) else {
        panic!("an unreadable bound must propagate");
    };
    assert!(matches!(
        error.downcast_ref::<nauthy::CapError>(),
        Some(nauthy::CapError::UnreadableExpiry)
    ));
    assert!(warned.is_empty());
    let no_advisory = crate::testkit::hand_signed::without_end_date();
    assert_eq!(no_advisory.cap().expiry().expect("no advisory date"), None);
    into_slot_at(no_advisory, node, &mut warned, base).expect("readable live effective bound");
    assert!(warned.is_empty());
}
