//! The exchange between two devices, and the fold behind it, over in-memory streams.
//!
//! Each home is built on disk the way the product leaves a device: its key, a pin, and a standing the root
//! signed for it. An update is signed by that root and written as the one the home holds, or folded.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Protection};
use nauthy::{RevocationId, Revocations as _, VerifyKey};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

use super::{Answer, Device, Dial as _, ExchangeError, Until, answer, digest, exchange, round};
use crate::codec::Id;
use crate::config;
use crate::contacts::{ContactsStore, DeviceLabel};
use crate::gate::KeyedDenylist;
use crate::home::Home;
use crate::roster::{Epoch, Folded, Member, RosterDoc, fold};
use crate::testkit::{Loopback, STANDING_UNTIL, TestNode, TestRoot};

/// The root every device here belongs to.
const ROOT: u8 = 0x21;
/// This machine.
const DESK: u8 = 0x11;
/// Another device.
const NAS: u8 = 0x12;
/// A third.
const PHONE: u8 = 0x13;
/// A device revoked in an update.
const STOLEN: u8 = 0x14;
/// A fourth device.
const LAPTOP: u8 = 0x15;

fn root() -> TestRoot {
    TestRoot::seeded(ROOT)
}

fn key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

fn node(seed: u8) -> NodeId {
    TestNode::seeded(seed).node_id()
}

fn name(text: &str) -> DeviceLabel {
    text.parse().unwrap()
}

/// An id the update revokes, ending far in the future.
fn id(byte: u8) -> Id {
    Id {
        expires: STANDING_UNTIL,
        id: RevocationId::from_bytes(vec![byte; 64]),
    }
}

/// The devices every update lists.
fn members() -> Vec<Member> {
    [(DESK, "desk"), (NAS, "nas"), (PHONE, "phone")]
        .into_iter()
        .map(|(seed, label)| root().member(key(seed), name(label)).unwrap())
        .collect()
}

/// The update at `number`, revoking `ids` and `keys`, signed by the root.
fn update(number: u64, ids: Vec<Id>, keys: Vec<VerifyKey>) -> Vec<u8> {
    let doc = RosterDoc::with_revocations(Epoch(number), members(), ids, keys).unwrap();
    root().sign_update(&doc)
}

/// A fresh home for the device `seed`: its key, the pin, and a standing the root signed for it, ending
/// at `until`.
async fn device_until(tag: &str, seed: u8, until: u64) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-sync-{tag}-{seed}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut secret = TestNode::seeded(seed).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    config::write_signet(&home, root().node_id()).await.unwrap();
    let badge = root()
        .device_badge(
            node(seed),
            SystemTime::UNIX_EPOCH + Duration::from_secs(until),
        )
        .unwrap();
    config::write_badge(&home, &badge).await.unwrap();
    home
}

async fn device(tag: &str, seed: u8) -> Home {
    device_until(tag, seed, STANDING_UNTIL).await
}

/// Make `bytes` the update `home` holds, the way a fold leaves it.
async fn holding(home: &Home, bytes: &[u8]) {
    assert_eq!(fold(home, bytes).await.unwrap(), Folded::Newer);
}

/// Whether `home`'s gate refuses the device `seed` whatever it presents.
async fn refuses(home: &Home, seed: u8) -> bool {
    KeyedDenylist::load(home)
        .await
        .unwrap()
        .is_revoked_peer(&key(seed))
}

/// Whether `home` has revoked `id`.
async fn revoked(home: &Home, id: &Id) -> bool {
    nauthy::FileDenylist::load(home.revoked())
        .await
        .unwrap()
        .is_revoked_any([&id.id])
}

fn named(seed: u8, text: &str) -> Device {
    Device {
        key: node(seed),
        name: text.to_owned(),
    }
}

#[tokio::test]
async fn sync_gives_a_held_cut_to_a_reachable_device() {
    let desk = device("gives", DESK).await;
    let nas = device("gives", NAS).await;
    holding(&nas, &update(1, vec![], vec![])).await;
    holding(&desk, &update(1, vec![], vec![])).await;
    holding(&desk, &update(2, vec![], vec![key(STOLEN)])).await;
    assert!(!refuses(&nas, STOLEN).await);

    let dial = Loopback::new(desk.clone(), [(node(NAS), nas.clone())]);
    let answers = round(
        &dial,
        &[named(NAS, "me/nas")],
        Until::Every,
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(answers[0].1.answer(), Some(Answer::Gave));
    assert!(
        refuses(&nas, STOLEN).await,
        "nas stops admitting the key the cut revoked"
    );
}

#[tokio::test]
async fn sync_takes_a_newer_update() {
    let desk = device("takes", DESK).await;
    let nas = device("takes", NAS).await;
    holding(&desk, &update(1, vec![], vec![])).await;
    holding(&nas, &update(2, vec![], vec![key(STOLEN)])).await;

    let dial = Loopback::new(desk.clone(), [(node(NAS), nas.clone())]);
    let answers = round(
        &dial,
        &[named(NAS, "me/nas")],
        Until::Every,
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(answers[0].1.answer(), Some(Answer::Took));
    assert!(
        refuses(&desk, STOLEN).await,
        "this machine stops admitting the key the newer update revoked"
    );
}

#[tokio::test]
async fn sync_gives_what_it_took_to_every_device_it_asked_before() {
    let desk = device("again", DESK).await;
    let phone = device("again", PHONE).await;
    let laptop = device("again", LAPTOP).await;
    let nas = device("again", NAS).await;
    // me/phone is behind this machine, me/laptop holds what it holds, and me/nas holds a newer list.
    holding(&phone, &update(1, vec![], vec![])).await;
    let second = update(2, vec![], vec![]);
    holding(&desk, &second).await;
    holding(&laptop, &second).await;
    holding(&nas, &update(3, vec![], vec![key(STOLEN)])).await;

    let dial = Loopback::new(
        desk.clone(),
        [
            (node(PHONE), phone.clone()),
            (node(LAPTOP), laptop.clone()),
            (node(NAS), nas.clone()),
        ],
    );
    let answers = round(
        &dial,
        &[
            named(PHONE, "me/phone"),
            named(LAPTOP, "me/laptop"),
            named(NAS, "me/nas"),
        ],
        Until::Every,
        Duration::from_secs(20),
    )
    .await;

    let read: Vec<(&str, Option<Answer>)> = answers
        .iter()
        .map(|(device, answer)| (device.name.as_str(), answer.answer()))
        .collect();
    assert_eq!(
        read,
        vec![
            ("me/phone", Some(Answer::Gave)),
            ("me/laptop", Some(Answer::Gave)),
            ("me/nas", Some(Answer::Took)),
        ]
    );
    for (home, name) in [(&phone, "me/phone"), (&laptop, "me/laptop")] {
        assert!(
            refuses(home, STOLEN).await,
            "{name} holds the list taken from me/nas"
        );
    }
}

/// A stream that counts the bytes read through it.
struct Counted<S> {
    inner: S,
    count: Arc<AtomicUsize>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = buf.filled().len() - before;
        self.count.fetch_add(read, Ordering::SeqCst);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            self.count.fetch_add(written, Ordering::SeqCst);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn an_exchange_between_equals_sends_no_update_bytes() {
    let desk = device("equals", DESK).await;
    let nas = device("equals", NAS).await;
    let held = update(3, vec![id(1)], vec![]);
    holding(&desk, &held).await;
    holding(&nas, &held).await;

    let (near, far) = tokio::io::duplex(64 * 1024);
    let (near_read, near_write) = tokio::io::split(near);
    let (far_read, far_write) = tokio::io::split(far);
    let count = Arc::new(AtomicUsize::new(0));
    let reader = Counted {
        inner: near_read,
        count: Arc::clone(&count),
    };
    let writer = Counted {
        inner: near_write,
        count: Arc::clone(&count),
    };
    let (dialed, answered) = tokio::join!(
        exchange(&desk, reader, writer),
        answer(&nas, far_read, far_write)
    );
    answered.unwrap();
    assert_eq!(dialed.unwrap(), Answer::Same);
    // The request is a byte, a number and a digest; the answer is a byte and a digest; each side's kept
    // fork, none here, is a zero length. Nothing else crossed.
    let update_bytes = count.load(Ordering::SeqCst) - (1 + 8 + 32) - (1 + 32) - 2 * 4;
    assert_eq!(update_bytes, 0, "equals send no update");
}

#[tokio::test]
async fn a_receipt_triggers_no_further_exchange() {
    let desk = device("receipt", DESK).await;
    let nas = device("receipt", NAS).await;
    let phone = device("receipt", PHONE).await;
    for home in [&desk, &nas, &phone] {
        holding(home, &update(1, vec![], vec![])).await;
    }
    holding(&desk, &update(2, vec![], vec![key(STOLEN)])).await;

    let dial = Loopback::new(
        desk.clone(),
        [(node(NAS), nas.clone()), (node(PHONE), phone.clone())],
    );
    let answers = round(
        &dial,
        &[named(NAS, "me/nas")],
        Until::Every,
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(answers[0].1.answer(), Some(Answer::Gave));
    assert_eq!(
        dial.dialed(),
        vec![node(NAS)],
        "only the device asked is dialed"
    );
    assert!(
        !refuses(&phone, STOLEN).await,
        "the phone never heard of the update nas took"
    );
}

#[tokio::test]
async fn an_unpinned_server_never_asks_for_an_update() {
    let desk = device("unpinned", DESK).await;
    holding(&desk, &update(1, vec![], vec![key(STOLEN)])).await;
    let bare = device("unpinned", NAS).await;
    std::fs::remove_file(bare.badge()).unwrap();
    std::fs::remove_file(bare.signet()).unwrap();

    let (near, far) = tokio::io::duplex(64 * 1024);
    let (near_read, near_write) = tokio::io::split(near);
    let (far_read, far_write) = tokio::io::split(far);
    let (dialed, answered) = tokio::join!(
        exchange(&desk, near_read, near_write),
        answer(&bare, far_read, far_write)
    );
    answered.unwrap();
    assert!(
        matches!(dialed, Err(ExchangeError::NotHeld)),
        "a machine with no pin asks for nothing, and never reads as holding the dialer's update"
    );
    assert!(!bare.roster().exists(), "and takes nothing");
}

#[tokio::test]
async fn an_exchange_with_a_fork_keeps_both_revocation_lists() {
    let desk = device("fork", DESK).await;
    let nas = device("fork", NAS).await;
    holding(&desk, &update(4, vec![id(1)], vec![])).await;
    holding(&nas, &update(4, vec![id(2)], vec![])).await;

    let dial = Loopback::new(desk.clone(), [(node(NAS), nas.clone())]);
    let answers = round(
        &dial,
        &[named(NAS, "me/nas")],
        Until::Every,
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(answers[0].1.answer(), Some(Answer::Forked));
    assert!(revoked(&desk, &id(1)).await && revoked(&desk, &id(2)).await);
    let pin = root().verify_key();
    let kept: Vec<Id> = [desk.roster(), desk.roster_fork()]
        .iter()
        .filter_map(|path| crate::roster::read_held(path, pin))
        .flat_map(|(doc, _)| doc.revoked().to_vec())
        .collect();
    assert!(
        kept.contains(&id(1)) && kept.contains(&id(2)),
        "the updates kept here carry both lists, for the root to bring forward"
    );
}

/// The update a fold writes, the fork it keeps, and the record of the exchange are each owner-only.
#[tokio::test]
async fn every_update_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let desk = device("modes", DESK).await;
    let nas = device("modes", NAS).await;
    holding(&desk, &update(4, vec![id(1)], vec![])).await;
    holding(&nas, &update(4, vec![id(2)], vec![])).await;
    let dial = Loopback::new(desk.clone(), [(node(NAS), nas.clone())]);
    round(
        &dial,
        &[named(NAS, "me/nas")],
        Until::Every,
        Duration::from_secs(20),
    )
    .await;

    for home in [&desk, &nas] {
        for path in [home.roster(), home.roster_fork(), home.roster_synced()] {
            let mode = std::fs::metadata(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{} is owner-only", path.display());
        }
    }
}

/// A `revoked_keys` others can write fails the device list with its refusal, rather than reading as no
/// keys and dialing a device revoked here; owner-only again, it is read and the device is left out.
#[tokio::test]
async fn a_loose_revoked_keys_never_reads_as_empty() {
    use std::os::unix::fs::PermissionsExt as _;

    let desk = device("keys-loose", DESK).await;
    holding(&desk, &update(1, vec![], vec![])).await;
    std::fs::write(desk.revoked_keys(), format!("{}\n", node(PHONE))).unwrap();
    let mode = |mode| {
        std::fs::set_permissions(desk.revoked_keys(), std::fs::Permissions::from_mode(mode))
            .unwrap();
    };

    for loose in [0o620, 0o602] {
        mode(loose);
        let error = super::devices(&desk, [])
            .await
            .expect_err("a loose revoked_keys fails the list");
        let source = error
            .downcast_ref::<std::io::Error>()
            .expect("the refusal is the read's own error");
        assert_eq!(
            crate::home::loose_in(source),
            Some(crate::home::Loose::Writable),
            "{loose:o} is refused as loose"
        );
    }

    mode(0o600);
    let listed = super::devices(&desk, []).await.unwrap();
    assert!(
        listed.iter().any(|device| device.key == node(NAS)),
        "the list is made"
    );
    assert!(
        listed.iter().all(|device| device.key != node(PHONE)),
        "a key revoked here is not dialed"
    );
}

#[tokio::test]
async fn an_exchange_at_one_number_with_two_digests_folds_both_ways() {
    let desk = device("both-ways", DESK).await;
    let nas = device("both-ways", NAS).await;
    holding(&desk, &update(4, vec![id(1)], vec![key(STOLEN)])).await;
    holding(&nas, &update(4, vec![id(2)], vec![])).await;

    let dial = Loopback::new(desk.clone(), [(node(NAS), nas.clone())]);
    let answers = round(
        &dial,
        &[named(NAS, "me/nas")],
        Until::Every,
        Duration::from_secs(20),
    )
    .await;

    assert_eq!(answers[0].1.answer(), Some(Answer::Forked));
    assert!(
        revoked(&desk, &id(2)).await,
        "this machine holds the other's revocations"
    );
    assert!(
        revoked(&nas, &id(1)).await && refuses(&nas, STOLEN).await,
        "and the other device holds this machine's, after one exchange"
    );
}

/// The stale-fork run: a laptop that holds the root cuts 2, revoking the phone, and reaches nobody; a
/// desk with another copy of the root, still at 1, cuts its own 2 without that revocation and gives it to
/// the nas. The laptop dials the nas, then the nas dials the desk.
#[tokio::test]
async fn a_kept_fork_reaches_the_device_it_is_exchanged_with() {
    let laptop = device("stale-fork", LAPTOP).await;
    let desk = device("stale-fork", DESK).await;
    let nas = device("stale-fork", NAS).await;
    for home in [&laptop, &desk, &nas] {
        holding(home, &update(1, vec![], vec![])).await;
    }
    holding(&laptop, &update(2, vec![], vec![key(STOLEN)])).await;
    let desk_cut = update(2, vec![], vec![]);
    holding(&desk, &desk_cut).await;
    let desk_dial = Loopback::new(desk.clone(), [(node(NAS), nas.clone())]);
    assert_eq!(
        desk_dial
            .offer(node(NAS), Epoch(2), &desk_cut)
            .await
            .unwrap(),
        Answer::Gave
    );

    let laptop_dial = Loopback::new(laptop.clone(), [(node(NAS), nas.clone())]);
    assert_eq!(
        laptop_dial.exchange(node(NAS)).await.unwrap(),
        Answer::Forked
    );
    let nas_dial = Loopback::new(nas.clone(), [(node(DESK), desk.clone())]);
    assert_eq!(
        nas_dial.exchange(node(DESK)).await.unwrap(),
        Answer::Same,
        "the nas and the desk hold the same update"
    );

    for (home, name) in [(&laptop, "laptop"), (&desk, "desk"), (&nas, "nas")] {
        assert!(
            refuses(home, STOLEN).await,
            "the {name} refuses the phone once the nas has met both"
        );
    }
    assert_eq!(
        std::fs::read(desk.roster()).unwrap(),
        desk_cut,
        "a fork passed on is never the update held"
    );
}

#[tokio::test]
async fn a_kept_fork_below_the_held_update_still_adds_its_revocations() {
    let nas = device("fork-below", NAS).await;
    let laptop = device("fork-below", LAPTOP).await;
    holding(&nas, &update(2, vec![], vec![])).await;
    assert_eq!(
        fold(&nas, &update(2, vec![], vec![key(STOLEN)]))
            .await
            .unwrap(),
        Folded::Fork { floor: Epoch(2) }
    );
    let third = update(3, vec![], vec![]);
    holding(&nas, &third).await;
    holding(&laptop, &third).await;
    assert!(nas.roster_fork().exists(), "3 lacks the fork's revocation");

    let dial = Loopback::new(nas.clone(), [(node(LAPTOP), laptop.clone())]);
    assert_eq!(dial.exchange(node(LAPTOP)).await.unwrap(), Answer::Same);

    assert!(
        refuses(&laptop, STOLEN).await,
        "a fork below the update held still revokes"
    );
    assert!(
        laptop.roster_fork().exists(),
        "and is kept, to pass on at the next exchange"
    );
}

#[tokio::test]
async fn an_update_taken_is_still_the_answer_when_the_forks_do_not_pass() {
    let desk = device("forks-break", DESK).await;
    holding(&desk, &update(1, vec![], vec![])).await;
    let newer = update(2, vec![], vec![key(STOLEN)]);
    let sent = newer.clone();
    let (near, far) = tokio::io::duplex(64 * 1024);
    let (near_read, near_write) = tokio::io::split(near);
    let (mut far_read, mut far_write) = tokio::io::split(far);
    // A server that gives its newer update, then closes before the forks pass.
    let server = async move {
        let mut request = [0_u8; 1 + 8 + 32];
        far_read.read_exact(&mut request).await.unwrap();
        far_write.write_all(&[0x01]).await.unwrap();
        let len = u32::try_from(sent.len()).unwrap();
        far_write.write_all(&len.to_be_bytes()).await.unwrap();
        far_write.write_all(&sent).await.unwrap();
        far_write.shutdown().await.unwrap();
    };
    let (dialed, ()) = tokio::join!(exchange(&desk, near_read, near_write), server);
    assert_eq!(dialed.unwrap(), Answer::Took);
    assert_eq!(std::fs::read(desk.roster()).unwrap(), newer);
}

#[tokio::test]
async fn a_none_yet_exchange_carries_digest_zero() {
    assert_eq!(digest(&[]), [0; 32]);
    let desk = device("none-yet", DESK).await;
    let (near, far) = tokio::io::duplex(64 * 1024);
    let (near_read, near_write) = tokio::io::split(near);
    let (mut far_read, mut far_write) = tokio::io::split(far);
    let server = async move {
        let mut request = [0xff_u8; 1 + 8 + 32];
        far_read.read_exact(&mut request).await.unwrap();
        far_write.write_all(&[0x00]).await.unwrap();
        far_write.write_all(&[0; 32]).await.unwrap();
        far_write.shutdown().await.unwrap();
        request
    };
    let (dialed, request) = tokio::join!(exchange(&desk, near_read, near_write), server);
    assert_eq!(dialed.unwrap(), Answer::Same);
    assert_eq!(request[0], 0x01);
    assert_eq!(request[1..9], [0; 8], "none yet is number zero");
    assert_eq!(request[9..], [0; 32], "and digest zero");
}

#[tokio::test]
async fn a_fold_never_removes_a_revoked_id() {
    let desk = device("never-removes", DESK).await;
    holding(&desk, &update(1, vec![id(1)], vec![key(STOLEN)])).await;
    holding(&desk, &update(2, vec![id(2)], vec![])).await;
    assert!(revoked(&desk, &id(1)).await, "union, never replace");
    assert!(revoked(&desk, &id(2)).await);
    assert!(refuses(&desk, STOLEN).await);
}

#[tokio::test]
async fn a_forked_updates_revocation_is_kept_and_carried_forward() {
    let desk = device("fork-kept", DESK).await;
    holding(&desk, &update(5, vec![], vec![])).await;
    let fork = update(5, vec![], vec![key(STOLEN)]);

    assert_eq!(
        fold(&desk, &fork).await.unwrap(),
        Folded::Fork { floor: Epoch(5) }
    );

    assert!(
        refuses(&desk, STOLEN).await,
        "the fork's revoked device is refused here"
    );
    assert_eq!(
        std::fs::read(desk.roster_fork()).unwrap(),
        fork,
        "and the fork is kept, for the root to carry its revocation forward"
    );
}

#[tokio::test]
async fn the_fork_file_survives_a_newer_update_that_drops_its_revocation() {
    let desk = device("fork-survives", DESK).await;
    holding(&desk, &update(5, vec![], vec![])).await;
    let _ = fold(&desk, &update(5, vec![], vec![key(STOLEN)]))
        .await
        .unwrap();
    holding(&desk, &update(6, vec![], vec![])).await;
    assert!(
        desk.roster_fork().exists(),
        "an update that lacks the fork's revocation leaves the fork"
    );
    holding(&desk, &update(7, vec![], vec![key(STOLEN)])).await;
    assert!(
        !desk.roster_fork().exists(),
        "one that carries it clears the fork"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_folds_never_lose_a_revocation() {
    let desk = device("concurrent", DESK).await;
    holding(&desk, &update(1, vec![], vec![])).await;
    let first = update(2, vec![id(1)], vec![]);
    let second = update(2, vec![id(2)], vec![]);

    crate::roster::SLOW.store(true, Ordering::SeqCst);
    let (one, two) = tokio::join!(
        tokio::spawn({
            let desk = desk.clone();
            async move { fold(&desk, &first).await.unwrap() }
        }),
        tokio::spawn({
            let desk = desk.clone();
            async move { fold(&desk, &second).await.unwrap() }
        }),
    );
    crate::roster::SLOW.store(false, Ordering::SeqCst);

    let mut outcomes = [one.unwrap(), two.unwrap()];
    outcomes.sort_by_key(|folded| matches!(folded, Folded::Newer));
    assert_eq!(
        outcomes,
        [Folded::Fork { floor: Epoch(2) }, Folded::Newer],
        "one fold takes the update, the other records the fork"
    );
    let pin = root().verify_key();
    let kept: Vec<Id> = [desk.roster(), desk.roster_fork()]
        .iter()
        .filter_map(|path| crate::roster::read_held(path, pin))
        .flat_map(|(doc, _)| doc.revoked().to_vec())
        .collect();
    assert!(
        kept.contains(&id(1)) && kept.contains(&id(2)),
        "both updates' revocations are kept"
    );
}

/// A `contact add` holds `roster.lock` from its read of the book to its save, so a fold that lands meanwhile
/// waits, and the book keeps both the added contact and the devices the fold wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_contact_writers_never_lose_an_update() {
    let desk = device("contact-writers", DESK).await;
    holding(&desk, &update(1, vec![], vec![])).await;
    let mut devices = members();
    devices.push(root().member(key(LAPTOP), name("laptop")).unwrap());
    let newer = root()
        .sign_update(&RosterDoc::with_revocations(Epoch(2), devices, vec![], vec![]).unwrap());

    let mut book = ContactsStore::open_to_edit(&desk).await.unwrap();
    let folding = tokio::spawn({
        let desk = desk.clone();
        async move { fold(&desk, &newer).await.unwrap() }
    });
    // Long enough for a fold that takes no notice of the edit to finish and write the book first.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = book
        .contacts_mut()
        .add("alice".parse().unwrap(), None, node(PHONE));
    book.save().await.unwrap();
    drop(book);
    assert_eq!(folding.await.unwrap(), Folded::Newer);

    let book = ContactsStore::open(desk.contacts()).await.unwrap();
    let contacts = book.contacts();
    assert!(
        contacts
            .petnames()
            .any(|petname| petname.as_str() == "alice"),
        "the added contact is kept"
    );
    assert!(
        contacts
            .devices(&"me".parse().unwrap())
            .is_some_and(|mut devices| devices.any(|(label, _)| label.as_str() == "laptop")),
        "the device the fold wrote is kept"
    );
}
