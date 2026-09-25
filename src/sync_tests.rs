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

use super::{Answer, Device, Until, answer, digest, exchange, round, when_stale};
use crate::codec::Id;
use crate::config;
use crate::contacts::DeviceLabel;
use crate::gate::KeyedDenylist;
use crate::home::Home;
use crate::roster::{Epoch, Folded, Member, RosterDoc, fold};
use crate::testkit::{Answering, Loopback, STANDING_UNTIL, TestNode, TestRoot};

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
    KeyFile::device(home.identity_key())
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

    assert_eq!(answers[0].1, Some(Answer::Gave));
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

    assert_eq!(answers[0].1, Some(Answer::Took));
    assert!(
        refuses(&desk, STOLEN).await,
        "this machine stops admitting the key the newer update revoked"
    );
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
    // The request is a byte, a number and a digest; the answer is one byte. Nothing else crossed.
    let update_bytes = count.load(Ordering::SeqCst) - (1 + 8 + 32) - 1;
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

    assert_eq!(answers[0].1, Some(Answer::Gave));
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
    assert_eq!(
        dialed.unwrap(),
        Answer::Same,
        "a machine with no pin asks for nothing"
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

    assert_eq!(answers[0].1, Some(Answer::Forked));
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

#[tokio::test]
async fn a_dialing_verb_pulls_when_stale() {
    let desk = device("stale", DESK).await;
    let dial = Answering::with(Answer::Same);
    let hours_ago = |hours: u64| {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(desk.roster_synced(), format!("{}\n", now - hours * 3600)).unwrap();
    };

    hours_ago(2);
    assert_eq!(
        when_stale(&dial, &desk, node(NAS)).await,
        Some(Answer::Same)
    );
    assert_eq!(dial.calls(), 1, "one exchange on a dial past an hour");

    hours_ago(0);
    assert_eq!(when_stale(&dial, &desk, node(NAS)).await, None);
    assert_eq!(dial.calls(), 1, "none on a fresh one");
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

#[tokio::test]
async fn a_device_that_missed_its_renewal_update_gets_it_from_the_next() {
    let first = STANDING_UNTIL - 2_000_000;
    let renewed = STANDING_UNTIL - 1_000_000;
    let desk = device_until("missed", DESK, first).await;
    let with_desk_until = |number: u64, until: u64| {
        let mut devices = members();
        devices[0] = Member {
            node: key(DESK),
            label: name("desk"),
            until,
            duration: 90 * 24 * 60 * 60,
            ids: Vec::new(),
            standing: root()
                .device_badge(
                    node(DESK),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(until),
                )
                .unwrap(),
        };
        let doc = RosterDoc::with_revocations(Epoch(number), devices, vec![], vec![]).unwrap();
        root().sign_update(&doc)
    };
    holding(&desk, &with_desk_until(1, first)).await;

    // Update 2 renewed this device, and it never arrived here. Update 3 revokes something else, and still
    // carries every device's newest standing.
    let third = {
        let mut devices = members();
        devices[0] = crate::roster::verify(&with_desk_until(2, renewed), root().verify_key())
            .unwrap()
            .members()
            .iter()
            .find(|member| member.node == key(DESK))
            .unwrap()
            .clone();
        let doc =
            RosterDoc::with_revocations(Epoch(3), devices, vec![], vec![key(STOLEN)]).unwrap();
        root().sign_update(&doc)
    };
    holding(&desk, &third).await;

    let badge = config::load_badge(&desk).await.unwrap().unwrap();
    assert_eq!(
        badge.cap().expiry().unwrap(),
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(renewed)),
        "the device takes its renewed standing from the next update"
    );
}
