//! `serve`'s gate as its files move under it: a pin that goes away or turns to garbage is no pin at the
//! next admission, a same-root rewrite never reads as no pin, the gate and the cut read one pin, a ledger
//! that cannot be read admits no link this machine signed, and a revoked device key is refused.

use core::time::Duration;
use std::path::PathBuf;
use std::time::SystemTime;

use nauthy::{
    Cap, Decision, Gate, PinSource as _, ProvenPeer, Revocation, STAT_DEBOUNCE, Service, VerifyKey,
};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::LiveCuts as _;

use super::{AnchorCut, FilePin, GateError, anchored};
use crate::config;
use crate::grants::{Delegation, GrantKind, GrantRecord, Grants};
use crate::home::Home;
use crate::revoked::RevokedError;
use crate::serve::BoundTargets;
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
        config::write_signet(
            &crate::testkit::lock(),
            &self.home,
            TestRoot::seeded(root).node_id(),
        )
        .expect("write the pin");
    }

    async fn gate(&self) -> (Gate, AnchorCut) {
        anchored(
            &self.home,
            TestNode::seeded(OWN).node_id(),
            BoundTargets::default(),
        )
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

    std::fs::remove_file(scratch.home.root_pub()).expect("remove the pin");
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

    std::fs::write(scratch.home.root_pub(), b"ed01 not a key\n").expect("garble the pin");
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

    let revoked =
        std::sync::Arc::new(crate::revoked::open(&scratch.home).expect("the revocations load"));

    let reader = {
        let home = scratch.home.clone();
        let stop = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut probes = 0usize;
            let mut missed = 0usize;
            while !stop.load(core::sync::atomic::Ordering::Relaxed) {
                probes += 1;
                if FilePin::open(&home, std::sync::Arc::clone(&revoked)).current() != Some(root) {
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
        std::fs::write(scratch.home.root_pub(), &other).expect("move the pin");
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
    Grants::at(home.links())
        .append(
            &crate::testkit::lock(),
            &GrantRecord {
                target: service(),
                serves: None,
                kind: GrantKind::Bearer,
                delegation: Delegation::Delegable,
                holder: crate::grants::ANYONE.to_owned(),
                root_id: slip.root_revocation_id().expect("a root id"),
                expiry: in_an_hour(),
            },
        )
        .expect("record the slip");
    slip
}

/// A one-use link this machine signed, sealed and recorded as [`GrantKind::Once`].
async fn one_use_slip(home: &Home) -> Cap {
    let slip = TestNode::seeded(OWN)
        .slip(&service(), in_an_hour())
        .expect("mint a slip")
        .seal()
        .expect("seal it");
    Grants::at(home.links())
        .append(
            &crate::testkit::lock(),
            &GrantRecord {
                target: service(),
                serves: None,
                kind: GrantKind::Once,
                delegation: Delegation::Sealed,
                holder: crate::grants::ANYONE.to_owned(),
                root_id: slip.root_revocation_id().expect("a root id"),
                expiry: in_an_hour(),
            },
        )
        .expect("record the slip");
    slip
}

/// A one-use link is admitted once, by its root id: refused after, and still refused once the ledger has
/// been rewritten and read again, since what a run admitted stays admitted.
#[tokio::test]
async fn a_one_use_link_stays_used_when_the_ledger_is_read_again() {
    let scratch = Scratch::new("once");
    let once = one_use_slip(&scratch.home).await;
    let (gate, _cut) = scratch.gate().await;
    assert!(admits(&gate, &once), "the first admission");
    assert!(!admits(&gate, &once), "the second is refused");

    let other = issued_slip(&scratch.home).await;
    past_the_debounce();
    assert!(admits(&gate, &other), "the ledger was read again");
    assert!(
        admits(&gate, &other),
        "a link that is not one-use admits again"
    );
    assert!(!admits(&gate, &once), "the one-use link stays used");
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
    std::fs::remove_file(unreadable.home.links()).expect("remove the ledger");
    std::fs::create_dir(unreadable.home.links()).expect("a directory in its place");
    let (gate, _cut) = unreadable.gate().await;
    assert!(
        !admits(&gate, &slip),
        "a ledger that cannot be read admits no self slip"
    );
}

/// Add `entries` to `home`'s `revoked` through its one writer.
fn revoke(home: &Home, entries: impl IntoIterator<Item = Revocation>) {
    crate::revoked::add(&crate::testkit::lock(), home, entries).expect("write the revocations");
}

#[tokio::test]
async fn a_key_in_revoked_is_refused_whatever_it_presents() {
    let scratch = Scratch::new("revoked-key");
    scratch.pin(ROOT).await;
    let (gate, cut) = scratch.gate().await;
    assert!(
        admits(&gate, &badge(ROOT)),
        "admitted before the revocation"
    );

    revoke(&scratch.home, [Revocation::Key(device())]);
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

/// One `revoked` answers both questions: a root key in it is no pin, so the gate admits none of its
/// devices and the cut no longer trusts it, and a device key in it is refused as a peer, at admission and by
/// the cut, whatever it presents.
#[tokio::test]
async fn a_revoked_root_is_refused_as_a_pin_and_a_revoked_device_as_a_peer() {
    let scratch = Scratch::new("pin-and-peer");
    scratch.pin(ROOT).await;
    let (gate, cut) = scratch.gate().await;
    let other = TestNode::seeded(0x35).verify_key();
    let badge_for = |device: VerifyKey| {
        TestRoot::seeded(ROOT)
            .member_badge(device, in_an_hour())
            .expect("mint a badge")
    };
    let admits_as = |device: VerifyKey| {
        matches!(
            gate.admit(
                ProvenPeer::from_handshake(device),
                Some(&badge_for(device)),
                &service()
            ),
            Decision::Admit
        )
    };
    assert!(
        admits_as(device()) && admits_as(other),
        "both devices admit"
    );

    revoke(&scratch.home, [Revocation::Key(device())]);
    past_the_debounce();
    assert!(!admits_as(device()), "a revoked device key is refused");
    assert!(cut.revoked_peer(&device()), "and the cut ends its session");
    assert!(admits_as(other), "the root's other device still admits");
    assert!(cut.trusts(&TestRoot::seeded(ROOT).verify_key()));

    revoke(
        &scratch.home,
        [Revocation::Key(TestRoot::seeded(ROOT).verify_key())],
    );
    past_the_debounce();
    assert!(
        !cut.trusts(&TestRoot::seeded(ROOT).verify_key()),
        "a revoked root is no pin"
    );
    assert!(!admits_as(other), "so none of its devices admits");
}

#[test]
fn a_pin_is_exactly_one_key() {
    let key = TestRoot::seeded(ROOT).node_id();
    assert_eq!(super::one_key(&format!("{key}\n")), key.verify_key().ok());
    assert_eq!(super::one_key(&format!("{key}\n{key}\n")), None);
    assert_eq!(super::one_key(""), None);
}

/// Three device keys revoked through the one writer, which leaves a witness of three; the file's text.
fn three_revoked_keys(home: &Home) -> String {
    revoke(
        home,
        [0x41, 0x42, 0x43]
            .into_iter()
            .map(|seed| Revocation::Key(TestNode::seeded(seed).verify_key())),
    );
    std::fs::read_to_string(home.revoked()).expect("read the revocations")
}

/// A `revoked` cut by hand to fewer entries than its witness: the next `serve` start refuses to build
/// its gate, and the refusal names the file. A file removed beside its witness refuses the same way.
#[tokio::test]
async fn a_revoked_that_lost_entries_reads_as_damaged() {
    let scratch = Scratch::new("revoked-lost");
    let body = three_revoked_keys(&scratch.home);
    assert!(
        anchored(
            &scratch.home,
            TestNode::seeded(OWN).node_id(),
            BoundTargets::default()
        )
        .await
        .is_ok(),
        "the file loads while it holds what its witness says"
    );

    let first = body.lines().next().expect("a line");
    std::fs::write(scratch.home.revoked(), format!("{first}\n{first}\n"))
        .expect("truncate the revocations");
    let Err(error) = anchored(
        &scratch.home,
        TestNode::seeded(OWN).node_id(),
        BoundTargets::default(),
    )
    .await
    else {
        panic!("a truncated file must not load");
    };
    assert!(
        matches!(
            error,
            GateError::Revoked(RevokedError::Lost {
                expected: 3,
                found: 1,
                ..
            })
        ),
        "a repeated entry counts once: {error}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "{} has lost revocations: it holds 1 where it held 3, and swoosh will not read it with entries missing",
            scratch.home.revoked().display()
        ),
        "the refusal names the file and no command: restoring it or accepting the loss is the person's call"
    );

    std::fs::remove_file(scratch.home.revoked()).expect("remove the revocations");
    assert!(
        anchored(
            &scratch.home,
            TestNode::seeded(OWN).node_id(),
            BoundTargets::default()
        )
        .await
        .is_err(),
        "a removed file beside its witness keeps serve's gate from building"
    );
}

#[tokio::test]
async fn an_unreadable_revoked_refuses_to_load() {
    let scratch = Scratch::new("revoked-unreadable");
    std::fs::create_dir(scratch.home.revoked()).expect("a directory where the file goes");
    assert!(
        matches!(
            anchored(
                &scratch.home,
                TestNode::seeded(OWN).node_id(),
                BoundTargets::default()
            )
            .await,
            Err(GateError::Revoked(RevokedError::Io { .. }))
        ),
        "a file that cannot be read refuses the load"
    );
}

#[tokio::test]
async fn an_oversized_revoked_refuses_to_load() {
    let scratch = Scratch::new("revoked-large");
    let line = format!("key {}\n", TestNode::seeded(0x41).node_id());
    let copies = (4 << 20) / line.len() + 1;
    std::fs::write(scratch.home.revoked(), line.repeat(copies)).expect("write the revocations");
    assert!(
        matches!(
            anchored(
                &scratch.home,
                TestNode::seeded(OWN).node_id(),
                BoundTargets::default()
            )
            .await,
            Err(GateError::Revoked(RevokedError::TooLarge { .. }))
        ),
        "a file past the cap refuses the load"
    );
}

#[tokio::test]
async fn a_missing_revoked_with_no_witness_holds_nothing() {
    let scratch = Scratch::new("revoked-fresh");
    let revoked = crate::revoked::open(&scratch.home).expect("a fresh home loads");
    assert!(!revoked.is_revoked_key(&device()));
}

/// A `join --switch` stopped between its writes leaves a standing from one root under a pin to another,
/// which reads as damaged. The gate still admits a link this machine signed, so its owner can reach it to
/// run `leave`, which starts it over.
#[tokio::test]
async fn a_damaged_server_serves_a_link_it_signed() {
    let scratch = Scratch::new("damaged-link");
    let mut seed = TestNode::seeded(OWN).seed();
    crate::identity::make_machine_dir(&scratch.home).unwrap();
    keystore::KeyFile::device(scratch.home.key())
        .write(
            &keystore::Secret::take(&mut seed),
            keystore::Protection::Plain,
        )
        .expect("this machine's key");
    let standing = TestRoot::seeded(OTHER_ROOT)
        .device_badge(TestNode::seeded(OWN).node_id(), in_an_hour())
        .expect("a standing");
    config::write_badge(&crate::testkit::lock(), &scratch.home, &standing)
        .expect("the new root's standing");
    scratch.pin(ROOT).await;
    assert!(
        matches!(
            crate::standing::Standing::read(&scratch.home).await,
            Err(crate::standing::StandingError::Damaged(_))
        ),
        "the home reads as damaged"
    );

    let slip = issued_slip(&scratch.home).await;
    let (gate, _cut) = scratch.gate().await;
    assert!(admits(&gate, &slip), "the link it signed is admitted");

    crate::joining::leave(&crate::testkit::lock(), &scratch.home).expect("leave");
    assert_eq!(
        crate::standing::Standing::read(&scratch.home)
            .await
            .expect("a readable home"),
        crate::standing::Standing::Unpinned
    );
}

/// `serve --admit` trusts the devices of the root it names for the run, with no pin on disk, and never a
/// root revoked here.
#[tokio::test]
async fn an_admitted_root_is_trusted_for_the_run_and_writes_no_pin() {
    let scratch = Scratch::new("admitting");
    let (gate, cut) = super::anchored_admitting(
        &scratch.home,
        TestNode::seeded(OWN).node_id(),
        Some(TestRoot::seeded(ROOT).verify_key()),
        crate::serve::BoundTargets::default(),
    )
    .await
    .expect("the gate builds");
    assert!(admits(&gate, &badge(ROOT)), "the admitted root's device");
    assert!(!admits(&gate, &badge(OTHER_ROOT)), "no other root's");
    assert!(cut.trusts(&TestRoot::seeded(ROOT).verify_key()));
    assert!(!scratch.home.root_pub().exists(), "no pin is written");

    let revoked = Scratch::new("admitting-revoked");
    revoke(
        &revoked.home,
        [Revocation::Key(TestRoot::seeded(ROOT).verify_key())],
    );
    let (gate, _cut) = super::anchored_admitting(
        &revoked.home,
        TestNode::seeded(OWN).node_id(),
        Some(TestRoot::seeded(ROOT).verify_key()),
        crate::serve::BoundTargets::default(),
    )
    .await
    .expect("the gate builds");
    assert!(
        !admits(&gate, &badge(ROOT)),
        "a root revoked here is not admitted"
    );
}

/// Set the mode of the file at `path`.
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set the mode");
}

/// A pin swapped to another root and left group-writable while `serve` runs is refused at the next
/// admission: the check runs on each read, not only when the process starts.
#[tokio::test]
async fn a_pin_others_can_write_is_refused_while_serve_runs() {
    let scratch = Scratch::new("pin-loose");
    scratch.pin(ROOT).await;
    let (gate, _cut) = scratch.gate().await;
    assert!(
        admits(&gate, &badge(ROOT)),
        "the pinned root's device is admitted"
    );

    let signet = scratch.home.root_pub();
    std::fs::write(
        &signet,
        format!("{}\n", TestRoot::seeded(OTHER_ROOT).node_id()),
    )
    .expect("swap the pin");
    set_mode(&signet, 0o620);
    past_the_debounce();
    assert!(
        !admits(&gate, &badge(OTHER_ROOT)),
        "a pin others can write admits nobody"
    );
    assert!(!admits(&gate, &badge(ROOT)), "nor the root it named before");

    set_mode(&signet, 0o600);
    past_the_debounce();
    assert!(
        admits(&gate, &badge(OTHER_ROOT)),
        "made owner-only again, it is read"
    );
}

/// A writer the log lands in, read back by the test.
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the capture lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A home whose directory name holds CR, ESC and a newline prints that path escaped, in the loose-file
/// refusal and in the serve log, so neither can be rewritten or given a forged line.
#[tokio::test]
async fn a_home_path_with_control_bytes_prints_escaped() {
    let raw = "home\r\u{1b}[8m\nfake";
    let escaped = r"home\r\u{1b}[8m\nfake";
    let scratch = Scratch::new(raw);
    scratch.pin(ROOT).await;
    set_mode(&scratch.home.root_pub(), 0o620);

    let refusal = crate::home::LooseFile {
        path: scratch.home.root_pub(),
        why: crate::home::Loose::Writable,
    }
    .to_string();
    assert!(
        refusal.contains(escaped) && !refusal.contains(raw),
        "the refusal prints the home path escaped: {refusal:?}"
    );

    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = std::sync::Arc::clone(&log);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || LogCapture(std::sync::Arc::clone(&writer)))
        .finish();
    let _capturing = tracing::subscriber::set_default(subscriber);
    let (gate, _cut) = scratch.gate().await;
    assert!(!admits(&gate, &badge(ROOT)), "a loose pin admits nobody");

    let log =
        String::from_utf8(log.lock().expect("the capture lock").clone()).expect("the log is utf-8");
    let refused = log
        .lines()
        .find(|line| line.contains("the pin is refused"))
        .unwrap_or_else(|| panic!("the loose pin is logged: {log:?}"));
    assert!(
        refused.contains(escaped),
        "the log names the home path escaped: {log:?}"
    );
    assert!(
        !log.contains(['\r', '\u{1b}']) && !log.contains(raw),
        "no raw byte of the path reaches the log: {log:?}"
    );
    assert_eq!(
        log.lines().filter(|line| line.contains("fake")).count(),
        1,
        "the path's newline forges no second line: {log:?}"
    );
}

/// A ledger left group-writable while `serve` runs admits no link this machine signed.
#[tokio::test]
async fn a_ledger_others_can_write_admits_no_self_slip() {
    let scratch = Scratch::new("ledger-loose");
    let slip = issued_slip(&scratch.home).await;
    let (gate, _cut) = scratch.gate().await;
    assert!(admits(&gate, &slip), "a recorded self slip is admitted");

    set_mode(&scratch.home.links(), 0o602);
    past_the_debounce();
    assert!(
        !admits(&gate, &slip),
        "a ledger others can write admits no self slip"
    );
}

/// A `revoked` others can write refuses the load.
#[tokio::test]
async fn a_revoked_others_can_write_refuses_to_load() {
    let scratch = Scratch::new("revoked-loose");
    revoke(&scratch.home, [Revocation::Key(device())]);
    set_mode(&scratch.home.revoked(), 0o660);
    let Err(GateError::Revoked(RevokedError::Loose(loose))) = anchored(
        &scratch.home,
        TestNode::seeded(OWN).node_id(),
        BoundTargets::default(),
    )
    .await
    else {
        panic!("a file others can write must refuse the load");
    };
    assert_eq!(loose.why, crate::home::Loose::Writable);
}
