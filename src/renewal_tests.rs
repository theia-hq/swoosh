//! The pick-up route over in-memory streams: what the server hands out, and what the dialer takes.
//!
//! Each home is built on disk the way the product leaves a device: its key, a pin, a standing the root
//! signed for it, and the update it holds, folded. The server is asked for a key directly, as the route
//! asks it for the key the transport proved.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::os::unix::fs::MetadataExt as _;
use std::sync::Mutex;
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Protection};
use nauthy::{Link, VerifyKey};

use super::{Fetch, FetchError, answer, is_due, pick_up, read_answer};
use crate::config;
use crate::contacts::{ContactsStore, DeviceLabel};
use crate::home::Home;
use crate::roster::{Epoch, Folded, Member, RosterDoc, fold};
use crate::testkit::{STANDING_UNTIL, TestNode, TestRoot};

/// The root every device here belongs to.
const ROOT: u8 = 0x31;
/// Another root.
const OTHER_ROOT: u8 = 0x32;
/// The device that serves the route.
const NAS: u8 = 0x41;
/// The device whose standing ended, and asks.
const LAPTOP: u8 = 0x42;
/// Another of your devices.
const PHONE: u8 = 0x43;
/// A machine outside `me`: a contact's device, and the seed an invite named.
const STRANGER: u8 = 0x44;

const DAY: u64 = 24 * 60 * 60;

fn root() -> TestRoot {
    TestRoot::seeded(ROOT)
}

fn key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

fn node(seed: u8) -> NodeId {
    TestNode::seeded(seed).node_id()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn at(unix: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(unix)
}

/// `root`'s standing for the device `seed`, ending at `until`.
fn standing(root: &TestRoot, seed: u8, until: u64) -> Link {
    root.device_badge(node(seed), at(until)).unwrap()
}

/// A row for the device `seed`, named `label`, whose standing ends at `until`.
fn row(seed: u8, label: &str, until: u64) -> Member {
    Member {
        node: key(seed),
        label: label.parse::<DeviceLabel>().unwrap(),
        until,
        duration: 0,
        invite_until: 0,
        ids: Vec::new(),
        standing: standing(&root(), seed, until),
    }
}

/// The update at `number` listing `members`, revoking `keys`, signed by the root.
fn update(number: u64, members: Vec<Member>, keys: Vec<VerifyKey>) -> Vec<u8> {
    let doc = RosterDoc::with_revocations(
        Epoch(number),
        members,
        Vec::new(),
        keys.into_iter().map(crate::testkit::revoked).collect(),
    )
    .unwrap();
    root().sign_update(&doc)
}

/// A fresh home for the device `seed`: its key, the pin, and a standing the root signed for it, ending
/// at `until`.
async fn device(tag: &str, seed: u8, until: u64) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-renewal-{tag}-{seed}-{}-{:?}",
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
    config::write_signet(&crate::testkit::lock(), &home, root().node_id()).unwrap();
    config::write_badge(
        &crate::testkit::lock(),
        &home,
        &standing(&root(), seed, until),
    )
    .unwrap();
    home
}

/// Make `bytes` the update `home` holds, the way a fold leaves it.
async fn holding(home: &Home, bytes: &[u8]) {
    assert_eq!(
        fold(
            &crate::home::HomeWrite::take(home).await.unwrap(),
            home,
            bytes
        )
        .await
        .unwrap(),
        Folded::Newer
    );
}

/// What `server` answers the key `seed`, as the route's bytes.
async fn asked(server: &Home, seed: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    answer(server, key(seed), &mut bytes).await.unwrap();
    bytes
}

/// The one miss.
const MISSED: [u8; 1] = [0x00];

/// The route's answer read back: the standing on a hit.
async fn read(bytes: &[u8]) -> Option<Link> {
    read_answer(bytes).await.unwrap()
}

/// A nas that holds an update renewing the laptop until `renewed`, and the laptop's renewed standing.
async fn nas_renewing(tag: &str, renewed: u64) -> (Home, Link) {
    let nas = device(tag, NAS, STANDING_UNTIL).await;
    let laptop = row(LAPTOP, "laptop", renewed);
    let standing = laptop.standing.clone();
    holding(
        &nas,
        &update(2, vec![row(NAS, "nas", STANDING_UNTIL), laptop], Vec::new()),
    )
    .await;
    (nas, standing)
}

/// A laptop whose standing ended a day ago, that holds the update it had then and knows `me/nas`.
async fn lapsed_laptop(tag: &str) -> Home {
    let ended = now() - DAY;
    let laptop = device(tag, LAPTOP, ended).await;
    holding(
        &laptop,
        &update(
            1,
            vec![
                row(NAS, "nas", STANDING_UNTIL),
                row(LAPTOP, "laptop", ended),
            ],
            Vec::new(),
        ),
    )
    .await;
    laptop
}

/// A [`Fetch`] that asks each device's route in process, as the key `asker` the transport would prove.
/// A key with no home here does not answer. Every ask is recorded.
struct Door {
    asker: VerifyKey,
    devices: Vec<(NodeId, Home)>,
    asked: Mutex<Vec<NodeId>>,
}

impl Door {
    fn new(asker: u8, devices: impl IntoIterator<Item = (u8, Home)>) -> Self {
        Self {
            asker: key(asker),
            devices: devices
                .into_iter()
                .map(|(seed, home)| (node(seed), home))
                .collect(),
            asked: Mutex::default(),
        }
    }

    fn asked(&self) -> Vec<NodeId> {
        self.asked.lock().unwrap().clone()
    }
}

impl Fetch for Door {
    async fn fetch(&self, peer: NodeId) -> Result<Option<Link>, FetchError> {
        self.asked.lock().unwrap().push(peer);
        let Some((_, server)) = self.devices.iter().find(|(key, _)| *key == peer) else {
            return Err(eyre::eyre!("no device answers at that key").into());
        };
        let mut bytes = Vec::new();
        answer(server, self.asker, &mut bytes).await?;
        read_answer(bytes.as_slice()).await
    }
}

#[tokio::test]
async fn the_door_hands_a_device_its_renewed_standing() {
    let (nas, renewed) = nas_renewing("hit", now() + 90 * DAY).await;

    let got = read(&asked(&nas, LAPTOP).await).await;

    assert_eq!(
        got.map(|link| link.as_str().to_owned()),
        Some(renewed.as_str().to_owned()),
    );
}

#[tokio::test]
async fn the_door_misses_a_lapsed_row_nobody_renewed() {
    let nas = device("lapsed-row", NAS, STANDING_UNTIL).await;
    holding(
        &nas,
        &update(
            2,
            vec![
                row(NAS, "nas", STANDING_UNTIL),
                row(LAPTOP, "laptop", now() - DAY),
            ],
            Vec::new(),
        ),
    )
    .await;

    assert_eq!(asked(&nas, LAPTOP).await, MISSED);
}

#[tokio::test]
async fn the_door_misses_a_revoked_key_even_on_a_stale_update() {
    let (nas, _) = nas_renewing("revoked-key", now() + 90 * DAY).await;
    // Revoked here since the update was cut: the update still lists the laptop live.
    crate::revoked::add(
        &crate::testkit::lock(),
        &nas,
        [nauthy::Revocation::Key(key(LAPTOP))],
    )
    .unwrap();

    assert_eq!(asked(&nas, LAPTOP).await, MISSED);
}

#[tokio::test]
async fn the_door_misses_a_revoked_standing_id() {
    let (nas, renewed) = nas_renewing("revoked-id", now() + 90 * DAY).await;
    let id = renewed.cap().root_revocation_id().unwrap();
    crate::revoked::add(&crate::testkit::lock(), &nas, [nauthy::Revocation::Id(id)]).unwrap();

    assert_eq!(asked(&nas, LAPTOP).await, MISSED);
}

#[tokio::test]
async fn the_door_never_sends_the_device_list() {
    let nas = device("one-row", NAS, STANDING_UNTIL).await;
    let laptop = row(LAPTOP, "laptop", now() + 90 * DAY);
    let own = laptop.standing.clone();
    holding(
        &nas,
        &update(
            2,
            vec![
                row(NAS, "nas", STANDING_UNTIL),
                laptop,
                row(PHONE, "phone", STANDING_UNTIL),
            ],
            Vec::new(),
        ),
    )
    .await;

    let bytes = asked(&nas, LAPTOP).await;

    // The status byte, the length, and the laptop's own standing: nothing of any other row.
    assert_eq!(bytes.len(), 1 + 2 + own.as_str().len());
    assert_eq!(&bytes[3..], own.as_str().as_bytes());
}

#[tokio::test]
async fn a_lapsed_device_picks_up_its_renewal() {
    let renewed = now() + 90 * DAY;
    let (nas, standing) = nas_renewing("pick-up-nas", renewed).await;
    let laptop = lapsed_laptop("pick-up-laptop").await;
    assert!(is_due(&laptop, SystemTime::now()).await);

    let took = pick_up(&laptop, &Door::new(LAPTOP, [(NAS, nas)]))
        .await
        .unwrap()
        .expect("the nas hands the laptop its renewal");

    assert_eq!(took.from, "me/nas");
    assert_eq!(took.name, "me/laptop");
    assert_eq!(took.until, at(renewed));
    assert_eq!(
        config::load_badge(&laptop).await.unwrap().unwrap().as_str(),
        standing.as_str(),
    );
    assert!(!is_due(&laptop, SystemTime::now()).await);
}

#[tokio::test]
async fn a_door_standing_that_does_not_outlive_the_stored_one_is_ignored() {
    // The nas holds a renewal that ends before the one the laptop holds.
    let (nas, _) = nas_renewing("shorter-nas", now() + DAY).await;
    let laptop = device("shorter-laptop", LAPTOP, now() + 2 * DAY).await;
    holding(
        &laptop,
        &update(1, vec![row(NAS, "nas", STANDING_UNTIL)], Vec::new()),
    )
    .await;
    let before = config::load_badge(&laptop).await.unwrap().unwrap();

    let took = pick_up(&laptop, &Door::new(LAPTOP, [(NAS, nas)]))
        .await
        .unwrap();

    assert_eq!(took, None);
    assert_eq!(
        config::load_badge(&laptop).await.unwrap().unwrap().as_str(),
        before.as_str(),
    );
}

#[tokio::test]
async fn a_door_renewal_never_writes_the_pin() {
    let renewed = now() + 90 * DAY;
    let (nas, _) = nas_renewing("pin-nas", renewed).await;
    let laptop = lapsed_laptop("pin-laptop").await;
    let pin = |home: &Home| {
        let meta = std::fs::metadata(home.root_pub()).unwrap();
        (meta.ino(), meta.mtime(), meta.mtime_nsec())
    };
    let before = pin(&laptop);

    let took = pick_up(&laptop, &Door::new(LAPTOP, [(NAS, nas)]))
        .await
        .unwrap();

    assert!(took.is_some(), "the renewal is taken");
    assert_eq!(pin(&laptop), before, "the pin file is never written");

    // A standing bound to this key under another root is never taken, so it cannot move the pin.
    let other = crate::joining::take_renewal(
        &crate::home::HomeWrite::take(&laptop).await.unwrap(),
        &laptop,
        &standing(&TestRoot::seeded(OTHER_ROOT), LAPTOP, renewed + DAY),
    )
    .await
    .unwrap();
    assert_eq!(other, None);
    assert_eq!(pin(&laptop), before);
}

#[tokio::test]
async fn pick_up_never_dials_a_machine_outside_me() {
    let laptop = lapsed_laptop("outside-me").await;
    // The invite's `from`, and a contact's device: neither is under `me`.
    std::fs::write(laptop.invited_by(), format!("{}\n", node(STRANGER))).unwrap();
    let mut store = ContactsStore::open(&laptop).await.unwrap();
    store.contacts_mut().add(
        "alice".parse().unwrap(),
        Some("laptop".parse().unwrap()),
        node(STRANGER),
    );
    store.save(&crate::testkit::lock()).unwrap();
    let door = Door::new(LAPTOP, []);

    let took = pick_up(&laptop, &door).await.unwrap();

    assert_eq!(took, None);
    assert_eq!(door.asked(), vec![node(NAS)], "only `me/nas` is asked");
}
