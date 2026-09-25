//! `serve`'s gate as its files move under it: a pin that goes away or turns to garbage is no pin at the
//! next admission, a same-root rewrite never reads as no pin, the gate and the cut read one pin, a ledger
//! that cannot be read admits no link this machine signed, and a revoked device key is refused.

use core::time::Duration;
use std::path::PathBuf;
use std::time::SystemTime;

use nauthy::{Cap, Decision, Gate, PinSource as _, ProvenPeer, STAT_DEBOUNCE, Service, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::LiveCuts as _;

use super::{AnchorCut, FilePin, KeyedDenylist, anchored};
use crate::config;
use crate::grants::{Delegation, GrantKind, GrantRecord, GrantTarget, Grants};
use crate::home::Home;
use crate::testkit::{TestNode, TestRoot};

/// The serving machine's own key.
const OWN: u8 = 0x31;
/// The root the pin names.
const ROOT: u8 = 0x32;
/// A second root, for a pin that moves.
const OTHER_ROOT: u8 = 0x33;
/// The device that dials.
const DEVICE: u8 = 0x34;

/// A scratch home removed on drop.
struct Scratch {
    dir: PathBuf,
    home: Home,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "swoosh-gate-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch home");
        let home = Home::resolve(Some(dir.clone())).expect("an explicit home");
        Self { dir, home }
    }

    async fn pin(&self, root: u8) {
        config::write_signet(&self.home, TestRoot::seeded(root).node_id())
            .await
            .expect("write the pin");
    }

    async fn gate(&self) -> (Gate, AnchorCut) {
        anchored(&self.home, TestNode::seeded(OWN).node_id())
            .await
            .expect("the gate builds")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn service() -> Service {
    "demo".parse().expect("a service name")
}

fn in_an_hour() -> SystemTime {
    nauthy::Request::expires_in(Duration::from_secs(3600))
}

fn device() -> VerifyKey {
    TestNode::seeded(DEVICE).verify_key()
}

/// A membership badge `root` signed for the dialing device.
fn badge(root: u8) -> Cap {
    TestRoot::seeded(root)
        .member_badge(device(), in_an_hour())
        .expect("mint a badge")
}

fn admits(gate: &Gate, cap: &Cap) -> bool {
    matches!(
        gate.admit(ProvenPeer::from_handshake(device()), Some(cap), &service()),
        Decision::Admit
    )
}

/// Wait out the pin's debounce, so the next admission stats the file again.
fn past_the_debounce() {
    std::thread::sleep(STAT_DEBOUNCE + Duration::from_millis(50));
}

#[tokio::test]
async fn a_removed_pin_is_untrusted_at_the_next_admission() {
    let scratch = Scratch::new("removed");
    scratch.pin(ROOT).await;
    let (gate, _cut) = scratch.gate().await;
    assert!(
        admits(&gate, &badge(ROOT)),
        "the pinned root's device is admitted"
    );

    std::fs::remove_file(scratch.home.signet()).expect("remove the pin");
    past_the_debounce();
    assert!(
        !admits(&gate, &badge(ROOT)),
        "with the pin gone, the old root's device is refused"
    );
}

#[tokio::test]
async fn a_malformed_pin_reads_as_none() {
    let scratch = Scratch::new("malformed");
    scratch.pin(ROOT).await;
    let (gate, _cut) = scratch.gate().await;
    assert!(
        admits(&gate, &badge(ROOT)),
        "the pinned root's device is admitted"
    );

    std::fs::write(scratch.home.signet(), b"bf01 not a key\n").expect("garble the pin");
    past_the_debounce();
    assert!(
        !admits(&gate, &badge(ROOT)),
        "a garbled pin admits nobody as a member"
    );
}

/// Serve reads the pin while it is rewritten to the same root, as a same-root `join` does. Each probe is
/// a fresh reader, so no debounce can hide a torn read: a write that truncated the file in place would be
/// read as no pin, and the cut would end every session under it.
#[tokio::test]
async fn a_same_root_pin_rewrite_under_serve_never_cuts_a_session() {
    let scratch = Scratch::new("rewrite");
    scratch.pin(ROOT).await;
    let root = TestRoot::seeded(ROOT).verify_key();
    let stop = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));

    let latch = std::sync::Arc::new(nauthy::Latch::new(
        nauthy::DisabledRoots::load(scratch.home.disabled_roots())
            .await
            .expect("the latch loads"),
        KeyedDenylist::load(&scratch.home)
            .await
            .expect("the denylist loads"),
    ));

    let reader = {
        let home = scratch.home.clone();
        let stop = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut probes = 0usize;
            let mut missed = 0usize;
            while !stop.load(core::sync::atomic::Ordering::Relaxed) {
                probes += 1;
                if FilePin::open(&home, std::sync::Arc::clone(&latch)).current() != Some(root) {
                    missed += 1;
                }
            }
            (probes, missed)
        })
    };
    for _ in 0..10 {
        scratch.pin(ROOT).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    stop.store(true, core::sync::atomic::Ordering::Relaxed);
    let (probes, missed) = reader.join().expect("the reader ends");
    assert!(probes > 0, "the reader probed while the pin was rewritten");
    assert_eq!(
        missed, 0,
        "no probe of {probes} read the same-root pin as anything but that root"
    );
}

/// One admission and one sweep inside one debounce agree on the pin, because they read one instance: the
/// gate admits under the root it read, the pin moves, and the cut asked at once still trusts that root.
/// Two readers would disagree, the second seeing the new root while the first admitted under the old.
#[tokio::test]
async fn the_gate_and_the_cut_read_one_pin() {
    let scratch = Scratch::new("one-pin");
    scratch.pin(ROOT).await;
    let (gate, cut) = scratch.gate().await;
    let other = format!("{}\n", TestRoot::seeded(OTHER_ROOT).node_id());

    // The check means something only while the admission's read is inside the debounce, so a slow
    // machine that lets it lapse retries rather than asserting on a window it missed.
    let mut checked = false;
    for _ in 0..20 {
        scratch.pin(ROOT).await;
        past_the_debounce();
        let read_at = std::time::Instant::now();
        assert!(admits(&gate, &badge(ROOT)), "admitted under the first root");
        std::fs::write(scratch.home.signet(), &other).expect("move the pin");
        let trusted = cut.trusts(&TestRoot::seeded(ROOT).verify_key());
        if read_at.elapsed() < STAT_DEBOUNCE {
            assert!(
                trusted,
                "inside the debounce the cut reads the pin the admission read"
            );
            checked = true;
            break;
        }
    }
    assert!(checked, "one attempt stayed inside the debounce");

    past_the_debounce();
    assert!(
        !cut.trusts(&TestRoot::seeded(ROOT).verify_key()),
        "past it, the cut moves with the pin"
    );
    assert!(admits(&gate, &badge(OTHER_ROOT)), "and so does the gate");
}

/// A link this machine signed, recorded in the ledger.
async fn issued_slip(home: &Home) -> Cap {
    let slip = TestNode::seeded(OWN)
        .slip(&service(), in_an_hour())
        .expect("mint a slip");
    Grants::at(home.grants())
        .append(&GrantRecord {
            target: GrantTarget::Service(service()),
            kind: GrantKind::Bearer,
            delegation: Delegation::Delegable,
            holder: crate::grants::ANYONE.to_owned(),
            root_id: slip.root_revocation_id().expect("a root id"),
            expiry: in_an_hour(),
        })
        .await
        .expect("record the slip");
    slip
}

#[tokio::test]
async fn an_unreadable_ledger_admits_no_self_slip() {
    let readable = Scratch::new("ledger-readable");
    let slip = issued_slip(&readable.home).await;
    let (gate, _cut) = readable.gate().await;
    assert!(admits(&gate, &slip), "a recorded self slip is admitted");

    let unreadable = Scratch::new("ledger-unreadable");
    let slip = issued_slip(&unreadable.home).await;
    // A directory where the file was: it can be statted but not read.
    std::fs::remove_file(unreadable.home.grants()).expect("remove the ledger");
    std::fs::create_dir(unreadable.home.grants()).expect("a directory in its place");
    let (gate, _cut) = unreadable.gate().await;
    assert!(
        !admits(&gate, &slip),
        "a ledger that cannot be read admits no self slip"
    );
}

#[tokio::test]
async fn a_key_in_revoked_keys_is_refused_whatever_it_presents() {
    let scratch = Scratch::new("revoked-key");
    scratch.pin(ROOT).await;
    let (gate, cut) = scratch.gate().await;
    assert!(
        admits(&gate, &badge(ROOT)),
        "admitted before the revocation"
    );

    std::fs::write(
        scratch.home.revoked_keys(),
        format!("{}\n", TestNode::seeded(DEVICE).node_id()),
    )
    .expect("revoke the device key");
    past_the_debounce();
    assert!(
        !admits(&gate, &badge(ROOT)),
        "its badge no longer admits it"
    );
    assert!(
        cut.revoked_peer(&device()),
        "and the cut ends its open session"
    );
}

#[test]
fn a_pin_is_exactly_one_key() {
    let key = TestRoot::seeded(ROOT).node_id();
    assert_eq!(super::one_key(&format!("{key}\n")), Some(key.verify_key()));
    assert_eq!(super::one_key(&format!("{key}\n{key}\n")), None);
    assert_eq!(super::one_key(""), None);
}

/// Three device keys, revoked in a file whose witness then records three.
fn three_revoked_keys(home: &Home) -> String {
    let body: String = [0x41, 0x42, 0x43]
        .into_iter()
        .map(|seed| format!("{}\n", TestNode::seeded(seed).node_id()))
        .collect();
    std::fs::write(home.revoked_keys(), &body).expect("write the revoked keys");
    std::fs::write(home.revoked_keys_written(), "3\n").expect("write the witness");
    body
}

#[tokio::test]
async fn a_revoked_keys_file_shorter_than_its_witness_refuses_to_load() {
    let scratch = Scratch::new("keys-lost");
    let body = three_revoked_keys(&scratch.home);
    assert!(
        KeyedDenylist::load(&scratch.home).await.is_ok(),
        "the file loads while it holds what its witness says"
    );

    let first = body.lines().next().expect("a line");
    std::fs::write(scratch.home.revoked_keys(), format!("{first}\n{first}\n"))
        .expect("truncate the keys");
    let Err(error) = KeyedDenylist::load(&scratch.home).await else {
        panic!("a truncated file must not load");
    };
    assert!(
        matches!(
            error,
            super::GateError::RevokedKeys(super::RevokedKeysError::Lost {
                expected: 3,
                found: 1,
                ..
            })
        ),
        "a repeated key counts once: {error}"
    );
    assert!(
        error
            .to_string()
            .contains(&scratch.home.revoked_keys().display().to_string()),
        "the refusal names the file: {error}"
    );

    std::fs::remove_file(scratch.home.revoked_keys()).expect("remove the keys");
    assert!(
        anchored(&scratch.home, TestNode::seeded(OWN).node_id())
            .await
            .is_err(),
        "a removed file beside its witness keeps serve's gate from building"
    );
}

#[tokio::test]
async fn an_unreadable_revoked_keys_refuses_to_load() {
    let scratch = Scratch::new("keys-unreadable");
    std::fs::create_dir(scratch.home.revoked_keys()).expect("a directory where the file goes");
    assert!(
        matches!(
            KeyedDenylist::load(&scratch.home).await,
            Err(super::GateError::RevokedKeys(
                super::RevokedKeysError::Io { .. }
            ))
        ),
        "a keys file that cannot be read refuses the load"
    );
}

#[tokio::test]
async fn an_oversized_revoked_keys_refuses_to_load() {
    let scratch = Scratch::new("keys-large");
    let line = format!("{}\n", TestNode::seeded(0x41).node_id());
    let copies = usize::try_from(super::MAX_REVOKED_KEYS_LEN).expect("fits") / line.len() + 1;
    std::fs::write(scratch.home.revoked_keys(), line.repeat(copies)).expect("write the keys");
    assert!(
        matches!(
            KeyedDenylist::load(&scratch.home).await,
            Err(super::GateError::RevokedKeys(
                super::RevokedKeysError::TooLarge { .. }
            ))
        ),
        "a keys file past the cap refuses the load"
    );
}

#[tokio::test]
async fn a_missing_revoked_keys_with_no_witness_holds_no_keys() {
    let scratch = Scratch::new("keys-fresh");
    let denylist = KeyedDenylist::load(&scratch.home)
        .await
        .expect("a fresh home loads");
    assert!(!nauthy::Revocations::is_revoked_peer(&denylist, &device()));
}
