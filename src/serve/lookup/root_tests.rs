//! The root route over in-memory streams: who it answers, and with what.
//!
//! The answering home is a device of a root, built on disk the way `join` leaves one. It is asked for a key
//! directly, as the route asks it for the key the transport proved, and its in-memory list of saved machines
//! is read as the router reads it before a slot is taken.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Protection};
use nauthy::{Link, VerifyKey};

use super::{Devices, answer};
use crate::config;
use crate::contacts::ContactsStore;
use crate::grants::{Delegation, GrantKind, GrantRecord, Grants};
use crate::home::Home;
use crate::testkit::{TestNode, TestRoot};

/// The root the answering machine is a device of.
const ROOT: u8 = 0x51;
/// The answering machine, alice's laptop.
const LAPTOP: u8 = 0x52;
/// A machine the laptop saves as one of bob's.
const BOB_DESK: u8 = 0x53;
/// A proven key the laptop knows nothing of.
const STRANGER: u8 = 0x54;
/// A key the laptop's ledger lists: it shared a link with it, and never saved it.
const HOLDER: u8 = 0x55;
/// A root the laptop saves for bob, and no machine.
const BOB_ROOT: u8 = 0x56;

fn key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

fn node(seed: u8) -> NodeId {
    TestNode::seeded(seed).node_id()
}

/// A device of `ROOT` whose standing ends in a day, saving bob's desk as `bob/desk` and bob's root.
async fn laptop(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-lookup-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut secret = TestNode::seeded(LAPTOP).seed();
    crate::identity::make_machine_dir(&home).unwrap();
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    let root = TestRoot::seeded(ROOT);
    config::write_signet(&crate::testkit::lock(), &home, root.node_id()).unwrap();
    let until = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
    config::write_badge(
        &crate::testkit::lock(),
        &home,
        &root.device_badge(node(LAPTOP), until).unwrap(),
    )
    .unwrap();
    let mut store = ContactsStore::open(&home).await.unwrap();
    store.contacts_mut().add(
        "bob".parse().unwrap(),
        Some("desk".parse().unwrap()),
        node(BOB_DESK),
    );
    store
        .contacts_mut()
        .set_signet("bob".parse().unwrap(), TestRoot::seeded(BOB_ROOT).node_id());
    store.save(&crate::testkit::lock()).unwrap();
    home
}

/// What `home` answers the key `seed`: the standing on a hit, `None` on the miss.
async fn asked(home: &Home, seed: u8) -> Option<Link> {
    let mut bytes = Vec::new();
    answer(home, key(seed), &mut bytes).await.unwrap();
    crate::renewal::read_answer(bytes.as_slice()).await.unwrap()
}

/// A machine saved as one of a person's learns the root: the answer is this machine's own standing, which
/// names its root, and the router lets the key through.
#[tokio::test]
async fn a_saved_machine_learns_the_root() {
    let home = laptop("saved").await;
    let standing = asked(&home, BOB_DESK)
        .await
        .expect("a saved machine is answered");
    assert_eq!(standing.root(), TestRoot::seeded(ROOT).verify_key());
    assert!(Devices::load(&home).await.knows(&key(BOB_DESK)));
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A proven key nobody saved here learns nothing: the router turns it away before a slot is taken, and the
/// handler, asked anyway, answers the one miss. A key saved only as a root is no machine, and misses too.
#[tokio::test]
async fn a_stranger_learns_no_root_from_a_device() {
    let home = laptop("stranger").await;
    let devices = Devices::load(&home).await;
    for seed in [STRANGER, BOB_ROOT] {
        assert!(!devices.knows(&key(seed)), "{seed:#x}: no slot");
        assert!(asked(&home, seed).await.is_none(), "{seed:#x}: the miss");
    }
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A link this machine gave a key, recorded in its ledger, admits nothing on the root route: the route looks
/// the key up among saved machines only, never in the ledger.
#[tokio::test]
async fn the_root_route_never_admits_from_the_ledger() {
    let home = laptop("ledger").await;
    gave(&home, HOLDER, "ssh").await;
    assert!(!Devices::load(&home).await.knows(&key(HOLDER)));
    assert!(asked(&home, HOLDER).await.is_none());
    let _ = std::fs::remove_dir_all(home.dir());
}

/// A peer holding a link for `ssh` asks the root route with nothing saved for it: a link names its own
/// service, never this route, so the route misses.
#[tokio::test]
async fn a_link_for_ssh_does_not_open_the_root_route() {
    let home = laptop("ssh-link").await;
    gave(&home, STRANGER, "ssh").await;
    assert!(!Devices::load(&home).await.knows(&key(STRANGER)));
    assert!(asked(&home, STRANGER).await.is_none());
    let _ = std::fs::remove_dir_all(home.dir());
}

/// Record a link for `service` given to the key `seed`, as `share` does.
async fn gave(home: &Home, seed: u8, service: &str) {
    let ends = SystemTime::now() + Duration::from_secs(3600);
    let slip = TestNode::seeded(LAPTOP)
        .slip(&service.parse().unwrap(), ends)
        .unwrap();
    Grants::at(home.links())
        .append(
            &crate::testkit::lock(),
            &GrantRecord {
                target: service.parse().unwrap(),
                serves: None,
                kind: GrantKind::Device,
                delegation: Delegation::Sealed,
                holder: node(seed).to_string(),
                root_id: slip.root_revocation_id().unwrap(),
                expiry: ends,
            },
        )
        .unwrap();
}

/// A machine saved after the route started is known once the book is read again, with no restart.
#[tokio::test]
async fn a_machine_saved_later_is_known_at_the_next_read() {
    let home = laptop("later").await;
    let devices = Devices::load(&home).await;
    assert!(!devices.knows(&key(STRANGER)));
    let mut store = ContactsStore::open(&home).await.unwrap();
    store.contacts_mut().add(
        "carol".parse().unwrap(),
        Some("phone".parse().unwrap()),
        node(STRANGER),
    );
    store.save(&crate::testkit::lock()).unwrap();
    // The book's stamp moves with the write; a write within the same stamp is caught by the next one.
    tokio::time::sleep(Duration::from_millis(20)).await;
    devices.refresh().await;
    assert!(devices.knows(&key(STRANGER)));
    let _ = std::fs::remove_dir_all(home.dir());
}
