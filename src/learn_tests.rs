//! Learning a root, below the words: what a standing teaches, what the book keeps, and that the `root:` a
//! line prints never reaches the disk or the wire.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Protection};

use super::{Asked, Found, Shown, save, vouching};
use crate::config;
use crate::contacts::{ContactsStore, Source, Taken};
use crate::home::Home;
use crate::root_key::RootKey;
use crate::testkit::{TestNode, TestRoot};

/// Alice's root.
const ALICE_ROOT: u8 = 0x61;
/// Alice's laptop, saved here as `alice/laptop`.
const LAPTOP: u8 = 0x62;
/// Another root, one alice's laptop might also show.
const OTHER_ROOT: u8 = 0x63;
/// This machine.
const DESK: u8 = 0x64;

fn node(seed: u8) -> NodeId {
    TestNode::seeded(seed).node_id()
}

fn root(seed: u8) -> RootKey {
    RootKey::from(TestRoot::seeded(seed).node_id())
}

fn hours(hours: u64) -> Duration {
    Duration::from_secs(hours * 60 * 60)
}

/// A fresh home holding the key `seed`.
fn machine(tag: &str, seed: u8) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-learn-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut secret = TestNode::seeded(seed).seed();
    crate::identity::make_machine_dir(&home).unwrap();
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    home
}

/// This machine, saving alice's laptop as `alice/laptop`, and nothing else.
async fn desk(tag: &str) -> Home {
    let home = machine(tag, DESK);
    let mut store = ContactsStore::open(&home).await.unwrap();
    store.contacts_mut().add(
        "alice".parse().unwrap(),
        Some("laptop".parse().unwrap()),
        node(LAPTOP),
    );
    store.save(&crate::testkit::lock()).unwrap();
    home
}

/// Alice's laptop, as a dial asks it.
fn laptop() -> Asked {
    Asked {
        person: "alice".parse().unwrap(),
        device: "laptop".parse().unwrap(),
        key: node(LAPTOP),
    }
}

/// A standing that verifies under the root it names, is bound to the key dialed and outlives now teaches
/// that root; a lapsed one, one bound to another machine, and one whose end has passed teach nothing, and
/// so nothing is offered or saved.
#[test]
fn a_lapsed_or_unverified_standing_teaches_no_root() {
    let now = SystemTime::now();
    let alice = TestRoot::seeded(ALICE_ROOT);
    let live = alice.device_badge(node(LAPTOP), now + hours(1)).unwrap();
    assert_eq!(vouching(&live, node(LAPTOP), now), Some(root(ALICE_ROOT)));

    let lapsed = alice.device_badge(node(LAPTOP), now - hours(1)).unwrap();
    assert_eq!(vouching(&lapsed, node(LAPTOP), now), None, "lapsed");
    let someone_elses = alice.device_badge(node(DESK), now + hours(1)).unwrap();
    assert_eq!(
        vouching(&someone_elses, node(LAPTOP), now),
        None,
        "bound to another machine"
    );
    assert_eq!(
        vouching(&live, node(LAPTOP), now + hours(2)),
        None,
        "it does not outlive the time asked"
    );
}

/// A root saved from a machine's answer carries that machine as its source, on disk and back, and is
/// remembered as the root that machine showed.
#[tokio::test]
async fn a_learned_root_is_marked_with_the_device_it_came_from() {
    let home = desk("marked").await;
    let shown = Shown {
        asked: laptop(),
        root: root(ALICE_ROOT),
    };
    assert!(
        save(&home, &shown).await.unwrap().is_ok(),
        "an empty slot fills"
    );
    let store = ContactsStore::open(&home).await.unwrap();
    let alice = "alice".parse().unwrap();
    let saved = store
        .contacts()
        .signet(&alice)
        .expect("alice's root is saved");
    assert_eq!(saved.node, root(ALICE_ROOT).key());
    assert_eq!(saved.source, Source::Learned("laptop".parse().unwrap()));
    assert_eq!(
        store
            .contacts()
            .seen_root(&alice, &"laptop".parse().unwrap()),
        Some(root(ALICE_ROOT).key())
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A learned root fills only an empty slot: over a saved root it saves nothing, and a root another name
/// holds is never offered.
#[tokio::test]
async fn a_learned_root_fills_only_an_empty_slot() {
    let home = desk("empty-slot").await;
    let mut store = ContactsStore::open(&home).await.unwrap();
    store
        .contacts_mut()
        .set_signet("alice".parse().unwrap(), root(ALICE_ROOT).key());
    store.save(&crate::testkit::lock()).unwrap();
    let other = Shown {
        asked: laptop(),
        root: root(OTHER_ROOT),
    };
    assert_eq!(
        Found::of(ContactsStore::open(&home).await.unwrap().contacts(), &other),
        Found::Conflict {
            saved: root(ALICE_ROOT)
        }
    );
    assert!(
        matches!(save(&home, &other).await.unwrap(), Err(Taken::Name { .. })),
        "nothing is replaced"
    );
    let store = ContactsStore::open(&home).await.unwrap();
    assert_eq!(
        store
            .contacts()
            .signet(&"alice".parse().unwrap())
            .map(|saved| saved.node),
        Some(root(ALICE_ROOT).key())
    );
    let _ = std::fs::remove_dir_all(home.dir());
}

/// The `root:` a person reads and types is never stored or sent: the book keeps a learned root, its
/// source and each machine's last-shown root as bare keys, and the root route sends a standing, which
/// holds no marker.
#[tokio::test]
async fn root_prefix_never_reaches_disk_or_wire() {
    let home = desk("no-prefix").await;
    let shown = Shown {
        asked: laptop(),
        root: root(ALICE_ROOT),
    };
    assert!(save(&home, &shown).await.unwrap().is_ok());
    let text = std::fs::read_to_string(home.contacts()).unwrap();
    assert!(!text.to_ascii_lowercase().contains("root:"), "{text}");
    assert!(
        text.contains(&root(ALICE_ROOT).key().to_string()),
        "the root is kept, bare: {text}"
    );

    // The answer the root route sends, from a device of alice's root.
    let laptop_home = machine("no-prefix-wire", LAPTOP);
    let alice = TestRoot::seeded(ALICE_ROOT);
    config::write_signet(&crate::testkit::lock(), &laptop_home, alice.node_id()).unwrap();
    config::write_badge(
        &crate::testkit::lock(),
        &laptop_home,
        &alice
            .device_badge(node(LAPTOP), SystemTime::now() + hours(24))
            .unwrap(),
    )
    .unwrap();
    // The asker is saved on the laptop, so it is answered.
    let mut store = ContactsStore::open(&laptop_home).await.unwrap();
    store.contacts_mut().add(
        "bob".parse().unwrap(),
        Some("desk".parse().unwrap()),
        node(DESK),
    );
    store.save(&crate::testkit::lock()).unwrap();
    let mut bytes = Vec::new();
    crate::serve::lookup_answer(
        &laptop_home,
        TestNode::seeded(DESK).verify_key(),
        &mut bytes,
    )
    .await
    .unwrap();
    assert_eq!(bytes.first(), Some(&0x01), "a hit");
    assert!(
        !String::from_utf8_lossy(&bytes)
            .to_ascii_lowercase()
            .contains("root:"),
        "the wire carries no marker"
    );
    let _ = std::fs::remove_dir_all(home.dir());
    let _ = std::fs::remove_dir_all(laptop_home.dir());
}
