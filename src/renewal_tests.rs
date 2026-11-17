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
use tokio::sync::Semaphore;
use tokio::time::Instant;

use super::{
    Asking, Fetch, FetchError, OPEN_ASKS, OPEN_BACK_OFF, OPEN_LOCK, OpenRenewal, PickUp, answer,
    is_due, pick_up, read_answer,
};
use crate::config;
use crate::contacts::{ContactsStore, DeviceLabel};
use crate::home::Home;
use crate::roster::{Epoch, Folded, Member, RosterDoc, fold};
use crate::serve::control_codec::{OpenLane, OpenRequest};
use crate::serve::{LOOKUP_ROOT_SERVICE, RENEWAL_SERVICE, SYNC_SERVICE};
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
/// A third of your devices.
const TV: u8 = 0x45;

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
async fn renewal_hands_out_a_standing_through_its_effective_endpoint() {
    let second = 1_788_400_000;
    let base = at(second);
    let (nas, standing) = nas_renewing("inclusive-endpoint", second).await;
    let until = standing.cap().valid_until().unwrap().unwrap();
    for now in [
        base - Duration::from_nanos(1),
        base,
        base + Duration::from_millis(500),
        until,
    ] {
        let found = super::standing_for(&nas, key(LAPTOP), now).await.unwrap();
        assert_eq!(found.as_str(), standing.as_str());
    }
    assert!(matches!(
        super::standing_for(&nas, key(LAPTOP), at(second + 1)).await,
        Err(super::Miss::Ended)
    ));
    crate::revoked::add(
        &crate::testkit::lock(),
        &nas,
        [nauthy::Revocation::Id(
            standing.cap().root_revocation_id().unwrap(),
        )],
    )
    .unwrap();
    assert!(matches!(
        super::standing_for(&nas, key(LAPTOP), until).await,
        Err(super::Miss::IdRevoked)
    ));
    crate::revoked::add(
        &crate::testkit::lock(),
        &nas,
        [nauthy::Revocation::Key(key(LAPTOP))],
    )
    .unwrap();
    assert!(matches!(
        super::standing_for(&nas, key(LAPTOP), until).await,
        Err(super::Miss::KeyRevoked)
    ));
    std::fs::remove_dir_all(nas.dir()).unwrap();
}

#[tokio::test]
async fn renewal_uses_the_narrowed_bound_and_refuses_an_unreadable_bound() {
    let second = 1_788_400_000;
    let base = at(second);
    let nas = device("narrowed-endpoint", NAS, STANDING_UNTIL).await;
    let narrowed = root()
        .member_badge(key(LAPTOP), at(second + 10))
        .unwrap()
        .attenuate(None, Some(base))
        .unwrap()
        .seal()
        .unwrap()
        .link()
        .unwrap();
    let until = narrowed.cap().valid_until().unwrap().unwrap();
    let member = Member {
        standing: narrowed.clone(),
        ..row(LAPTOP, "laptop", second + 10)
    };
    holding(
        &nas,
        &update(2, vec![row(NAS, "nas", STANDING_UNTIL), member], Vec::new()),
    )
    .await;
    assert_eq!(
        super::standing_for(&nas, key(LAPTOP), until)
            .await
            .unwrap()
            .as_str(),
        narrowed.as_str()
    );
    assert!(matches!(
        super::standing_for(&nas, key(LAPTOP), at(second + 1)).await,
        Err(super::Miss::Ended)
    ));
    let unreadable = crate::testkit::hand_signed::unreadable_end_date();
    assert!(matches!(
        unreadable.cap().valid_until(),
        Err(nauthy::CapError::UnreadableExpiry)
    ));
    let member = Member {
        standing: unreadable,
        ..row(LAPTOP, "laptop", second + 10)
    };
    holding(
        &nas,
        &update(3, vec![row(NAS, "nas", STANDING_UNTIL), member], Vec::new()),
    )
    .await;
    assert!(matches!(
        super::standing_for(&nas, key(LAPTOP), base).await,
        Err(super::Miss::Ended)
    ));
    std::fs::remove_dir_all(nas.dir()).unwrap();
}

#[tokio::test]
async fn renewal_pickup_remains_due_before_the_effective_endpoint() {
    let second = 1_788_400_000;
    let base = at(second);
    let laptop = device("early-pickup", LAPTOP, second).await;
    let badge = config::load_badge(&laptop).await.unwrap().unwrap();
    let until = badge.cap().valid_until().unwrap().unwrap();
    assert!(!is_due(&laptop, base - Duration::from_nanos(1)).await);
    for now in [base, base + Duration::from_millis(500), until] {
        assert!(now <= until);
        assert!(is_due(&laptop, now).await);
    }
    std::fs::remove_dir_all(laptop.dir()).unwrap();
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

/// A laptop whose standing ended a day ago, holding an update that lists `me/nas`, `me/phone` and `me/tv`.
async fn lapsed_laptop_of_three(tag: &str) -> Home {
    let ended = now() - DAY;
    let laptop = device(tag, LAPTOP, ended).await;
    holding(
        &laptop,
        &update(
            1,
            vec![
                row(NAS, "nas", STANDING_UNTIL),
                row(PHONE, "phone", STANDING_UNTIL),
                row(TV, "tv", STANDING_UNTIL),
                row(LAPTOP, "laptop", ended),
            ],
            Vec::new(),
        ),
    )
    .await;
    laptop
}

/// A [`Door`] whose every answer waits for a permit of `gate`: with none given, devices that never
/// answer. Every ask is recorded as it arrives.
struct Held {
    door: Door,
    gate: Semaphore,
    asked: Mutex<Vec<NodeId>>,
}

impl Held {
    fn new(door: Door) -> Self {
        Self {
            door,
            gate: Semaphore::new(0),
            asked: Mutex::default(),
        }
    }

    fn asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

impl Fetch for Held {
    async fn fetch(&self, peer: NodeId) -> Result<Option<Link>, FetchError> {
        self.asked.lock().unwrap().push(peer);
        let _permit = self.gate.acquire().await.unwrap();
        self.door.fetch(peer).await
    }
}

/// An `Open` for `service` at the nas, presenting `slip` when given.
fn open(service: &str, slip: Option<Link>) -> OpenRequest {
    OpenRequest::new(
        node(NAS),
        Vec::new(),
        service.parse().unwrap(),
        OpenLane::Main,
        slip,
    )
    .unwrap()
}

#[tokio::test]
async fn an_open_renews_first_only_when_it_presents_this_homes_standing() {
    let (nas, _) = nas_renewing("presents-nas", now() + 90 * DAY).await;
    let laptop = lapsed_laptop("presents-laptop").await;
    let door = Door::new(LAPTOP, [(NAS, nas)]);
    let renewal = OpenRenewal::new(&laptop, &door);
    // A slip the nas issued, so it addresses the nas the Open names.
    let slip = TestNode::seeded(NAS)
        .slip(&"ssh".parse().unwrap(), at(now() + DAY))
        .unwrap()
        .link()
        .unwrap();

    // A slip presents itself; an exchange presents its standing as it is; a proven-only route presents
    // nothing. None of them asks a device.
    for skipped in [
        open("ssh", Some(slip)),
        open(SYNC_SERVICE, None),
        open(RENEWAL_SERVICE, None),
        open(LOOKUP_ROOT_SERVICE, None),
    ] {
        assert_eq!(renewal.before(&skipped).await, PickUp::Skipped);
    }
    assert!(door.asked().is_empty(), "no Open above asks a device");

    let took = renewal.before(&open("ssh", None)).await;
    assert!(matches!(took, PickUp::Took(renewed) if renewed.from == "me/nas"));
    assert_eq!(door.asked(), vec![node(NAS)]);

    // Renewed, the standing is no longer due, so the next Open asks nobody.
    assert_eq!(renewal.before(&open("ssh", None)).await, PickUp::Skipped);
    assert_eq!(door.asked(), vec![node(NAS)]);
}

#[tokio::test(start_paused = true)]
async fn an_opens_device_asks_end_together_within_six_seconds() {
    let laptop = lapsed_laptop_of_three("asks-share").await;
    let silent = Held::new(Door::new(LAPTOP, []));
    let renewal = OpenRenewal::new(&laptop, &silent);
    let start = Instant::now();

    let missed = renewal.before(&open("ssh", None)).await;

    assert_eq!(missed, PickUp::Missed);
    assert_eq!(
        start.elapsed(),
        OPEN_ASKS,
        "one whole ask, then the share's last second"
    );
    assert_eq!(silent.asked(), 2, "the third device is never asked");
}

#[tokio::test(start_paused = true)]
async fn an_open_waits_two_seconds_for_home_lock_and_writes_nothing() {
    let (nas, _) = nas_renewing("lock-nas", now() + 90 * DAY).await;
    let laptop = lapsed_laptop("lock-laptop").await;
    let before = config::load_badge(&laptop).await.unwrap().unwrap();
    let door = Door::new(LAPTOP, [(NAS, nas)]);
    let renewal = OpenRenewal::new(&laptop, &door);
    let held = crate::home::HomeWrite::take(&laptop).await.unwrap();
    let start = Instant::now();

    // Bounded from outside too, so a lock wait with no timeout fails the test rather than hanging it.
    let missed = tokio::time::timeout(Duration::from_secs(60), renewal.before(&open("ssh", None)))
        .await
        .expect("the renewal gives up on home.lock");

    assert_eq!(missed, PickUp::Missed);
    assert_eq!(start.elapsed(), OPEN_LOCK);
    drop(held);
    assert_eq!(
        config::load_badge(&laptop).await.unwrap().unwrap().as_str(),
        before.as_str(),
    );
}

#[tokio::test(start_paused = true)]
async fn after_a_miss_an_open_does_not_ask_again_for_five_minutes() {
    let laptop = lapsed_laptop("back-off").await;
    // The nas is not there to answer.
    let door = Door::new(LAPTOP, []);
    let renewal = OpenRenewal::new(&laptop, &door);
    let ssh = open("ssh", None);

    assert_eq!(renewal.before(&ssh).await, PickUp::Missed);
    assert_eq!(door.asked().len(), 1);

    tokio::time::advance(OPEN_BACK_OFF - Duration::from_secs(1)).await;
    assert_eq!(renewal.before(&ssh).await, PickUp::Skipped);
    assert_eq!(
        door.asked().len(),
        1,
        "no ask inside five minutes of the miss"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(renewal.before(&ssh).await, PickUp::Missed);
    assert_eq!(door.asked().len(), 2, "five minutes on, an Open asks again");
}

#[tokio::test]
async fn opens_that_arrive_together_share_one_renewal() {
    let (nas, _) = nas_renewing("one-flight-nas", now() + 90 * DAY).await;
    let laptop = lapsed_laptop("one-flight-laptop").await;
    let gated = Held::new(Door::new(LAPTOP, [(NAS, nas)]));
    let renewal = OpenRenewal::new(&laptop, &gated);
    let (ssh, web) = (open("ssh", None), open("web", None));
    // Answer only once both Opens are waiting: on one flight, or each on its own ask.
    let release = async {
        loop {
            let waiting = match &*renewal.state.borrow() {
                Asking::Flying(flight) => flight.waiters.get(),
                Asking::Idle | Asking::Missed(_) => 0,
            };
            if waiting == 2 || gated.asked() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        gated.gate.add_permits(2);
    };

    let (first, second, ()) = tokio::join!(renewal.before(&ssh), renewal.before(&web), release);

    assert!(matches!(first, PickUp::Took(_)));
    assert_eq!(first, second, "both Opens read the one flight's outcome");
    assert_eq!(gated.asked(), 1, "one ask for both Opens");
}

#[tokio::test(start_paused = true)]
async fn an_open_after_an_abandoned_renewal_asks_afresh() {
    let laptop = lapsed_laptop_of_three("abandoned").await;
    let silent = Held::new(Door::new(LAPTOP, []));
    let renewal = OpenRenewal::new(&laptop, &silent);
    let ssh = open("ssh", None);

    // The only Open waiting leaves a second into the first ask.
    assert!(
        tokio::time::timeout(Duration::from_secs(1), renewal.before(&ssh))
            .await
            .is_err()
    );
    assert_eq!(silent.asked(), 1);
    tokio::time::advance(Duration::from_secs(10)).await;

    let start = Instant::now();
    assert_eq!(renewal.before(&ssh).await, PickUp::Missed);
    assert_eq!(
        start.elapsed(),
        OPEN_ASKS,
        "a whole bound, not the abandoned flight's"
    );
    assert_eq!(silent.asked(), 3, "two fresh asks");
}

/// Open A starts a flight and B joins it, then A leaves before the flight lands: B's outcome, once
/// `gated`'s devices answer.
async fn after_the_starter_leaves(renewal: &OpenRenewal<'_, Held>, gated: &Held) -> PickUp {
    let (ssh, web) = (open("ssh", None), open("web", None));
    let mut first = Box::pin(renewal.before(&ssh));
    let mut second = Box::pin(renewal.before(&web));
    while gated.asked() == 0 {
        assert!(futures::poll!(&mut first).is_pending());
        tokio::task::yield_now().await;
    }
    assert!(futures::poll!(&mut second).is_pending());
    assert!(matches!(
        &*renewal.state.borrow(),
        Asking::Flying(flight) if flight.waiters.get() == 2
    ));
    drop(first);
    gated.gate.add_permits(8);
    second.await
}

#[tokio::test]
async fn a_joined_open_takes_the_renewal_after_its_starter_leaves() {
    let (nas, _) = nas_renewing("starter-leaves-nas", now() + 90 * DAY).await;
    let laptop = lapsed_laptop("starter-leaves-laptop").await;
    let gated = Held::new(Door::new(LAPTOP, [(NAS, nas)]));
    let renewal = OpenRenewal::new(&laptop, &gated);

    let took = after_the_starter_leaves(&renewal, &gated).await;

    assert!(matches!(took, PickUp::Took(renewed) if renewed.from == "me/nas"));
    assert_eq!(gated.asked(), 1, "the joined Open read the one flight");
}

#[tokio::test]
async fn a_joined_open_reads_the_miss_after_its_starter_leaves() {
    let laptop = lapsed_laptop("starter-leaves-miss").await;
    // The nas is not there to answer.
    let gated = Held::new(Door::new(LAPTOP, []));
    let renewal = OpenRenewal::new(&laptop, &gated);

    let missed = after_the_starter_leaves(&renewal, &gated).await;

    assert_eq!(missed, PickUp::Missed);
    assert_eq!(gated.asked(), 1, "the joined Open read the one flight");
}
