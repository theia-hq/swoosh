use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use super::{Known, Rows};
use crate::home::Home;
use crate::testkit::{TestNode, TestRoot};

#[test]
fn cached_renewal_eligibility_includes_the_whole_expiry_second() {
    let second = 1_788_400_000;
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(second);
    let device = TestNode::seeded(2);
    let badge = TestRoot::seeded(1)
        .device_badge(device.node_id(), base)
        .expect("badge");
    let until = badge
        .cap()
        .valid_until()
        .expect("effective expiry")
        .expect("bound");
    let home = Home::resolve(Some(std::env::temp_dir().join(format!(
        "swoosh-renewal-cache-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))))
    .expect("isolated home path");
    let known = Known {
        home,
        rows: Arc::new(RwLock::new(Rows {
            seen: None,
            live: HashMap::from([(device.verify_key(), second)]),
        })),
    };
    for now in [
        base - Duration::from_nanos(1),
        base,
        base + Duration::from_millis(500),
        until,
    ] {
        let now = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs();
        assert!(known.knows_at(&device.verify_key(), now));
        assert!(!known.knows_at(&TestNode::seeded(3).verify_key(), now));
    }
    assert!(!known.knows_at(&device.verify_key(), second + 1));
}
