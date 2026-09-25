//! Bare `status` over homes built on disk the way the product leaves them: a fresh home, a device of a
//! root, and the machine where the root is kept.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::time::SystemTime;

use keystore::{KeyFile, Passphrase, Protection};
use nauthy::VerifyKey;
use swoosh::config;
use swoosh::contacts::DeviceLabel;
use swoosh::home::Home;
use swoosh::roster::{Epoch, RosterDoc};
use swoosh::state::{self, Row, State};
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};
use zeroize::Zeroizing;

use super::{Report, SERVING_NOTHING, unix_now};

/// This machine's key.
const OWN: u8 = 0x11;
/// The root this machine trusts or keeps.
const ROOT: u8 = 0x21;
/// Another device of the root.
const LAPTOP: u8 = 0x41;
/// A device the root revoked.
const OLD: u8 = 0x42;

const DAY: u64 = 24 * 60 * 60;

static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A fresh home holding this machine's key, plain.
fn home(tag: &str) -> Home {
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("swoosh-status-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).expect("the scratch home");
    let home = Home::resolve(Some(dir)).expect("the scratch home resolves");
    let mut seed = TestNode::seeded(OWN).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .expect("this machine's key");
    home
}

fn key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

/// A live row for the device `seed`.
fn row(seed: u8, label: &str) -> Row {
    Row {
        key: key(seed),
        label: label.parse::<DeviceLabel>().expect("a device name"),
        until: STANDING_UNTIL,
        duration: 90 * DAY,
        seeded: false,
        invite_until: 0,
        revoked_on: 0,
        ids: Vec::new(),
        standing: TestRoot::seeded(ROOT)
            .standing(key(seed))
            .expect("a standing"),
    }
}

/// Make `home` a device of `ROOT`: its pin, and a standing the root signed for it.
async fn device_of(home: &Home) {
    let root = TestRoot::seeded(ROOT);
    config::write_signet(home, root.node_id())
        .await
        .expect("the pin");
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
    let badge = root
        .device_badge(TestNode::seeded(OWN).node_id(), until)
        .expect("a standing");
    config::write_badge(home, &badge)
        .await
        .expect("the standing");
}

/// Make `home` keep `ROOT`, sealed, with this machine, a laptop, and a revoked device in its records.
async fn holds(home: &Home) {
    device_of(home).await;
    let dir = home.root();
    config::create_store_dir(&dir).expect("the root's directory");
    let passphrase =
        Passphrase::try_from(Zeroizing::new("a passphrase".to_owned())).expect("a passphrase");
    let mut seed = TestRoot::seeded(ROOT).seed();
    KeyFile::root(dir.join("root.key"))
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .expect("the sealed root");
    let old = Row {
        revoked_on: STANDING_UNTIL - 400 * DAY,
        ..row(OLD, "old")
    };
    let records = State::new(
        Epoch(1),
        vec![row(OWN, "desk"), row(LAPTOP, "laptop"), old],
        Vec::new(),
        vec![key(OLD)],
    )
    .expect("the records");
    state::write(&dir, &TestRoot::seeded(ROOT).sign_state(&records)).expect("the records");
}

/// The report `home` reads as, rendered.
async fn status(home: &Home) -> String {
    let stored = swoosh::identity::inspect(home)
        .expect("the key")
        .into_stored();
    Report::gather(home, &stored, unix_now())
        .await
        .expect("status reads the home")
        .render()
}

/// With no `serve` running here, `serving:` says so, and the report is still whole.
#[tokio::test]
async fn status_with_no_node_prints_serving_nothing() {
    let home = home("serving");
    let out = status(&home).await;
    assert!(
        out.lines().any(|line| line == SERVING_NOTHING),
        "the serving line is printed with nothing running: {out}"
    );
}

/// A machine with no root names joining one first, then making one, as three lines under `lock:`.
#[tokio::test]
async fn status_with_no_root_names_join_first() {
    let home = home("no-root");
    let out = status(&home).await;
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[2..5],
        [
            "root: none yet.",
            "  to join yours: swoosh join",
            "  to make one here: swoosh invite <name> <key>",
        ],
        "{out}"
    );
}

/// While `roster.fork` holds an update, the warning prints and names `revoke --help`; with it empty or
/// gone, it does not.
#[tokio::test]
async fn status_warns_while_two_copies_disagree() {
    let home = home("fork");
    device_of(&home).await;
    let warning = "two copies of your root have been used: your devices hold two different lists. Keep \
                   one copy; the next time you use it, it settles this. If you did not use two copies, \
                   your root may be stolen: swoosh revoke --help";
    assert!(!status(&home).await.contains("two copies"));

    std::fs::write(home.roster_fork(), b"").expect("an empty fork file");
    assert!(
        !status(&home).await.contains("two copies"),
        "an empty file holds no update"
    );

    let fork = RosterDoc::new(Epoch(3), Vec::new()).expect("an update");
    std::fs::write(
        home.roster_fork(),
        TestRoot::seeded(ROOT).sign_update(&fork),
    )
    .expect("the fork");
    let out = status(&home).await;
    assert!(
        out.lines().any(|line| line == warning),
        "the warning prints while two copies disagree: {out}"
    );
}

/// No standing prints a `revocations:` line: a revoked device stays a row under `devices:` instead.
#[tokio::test]
async fn status_prints_no_revocations_line() {
    let unpinned = home("revocations-none");

    let device = home("revocations-device");
    device_of(&device).await;
    let update = RosterDoc::with_revocations(
        Epoch(2),
        vec![
            TestRoot::seeded(ROOT)
                .member(key(LAPTOP), "laptop".parse().expect("a name"))
                .expect("a member"),
        ],
        Vec::new(),
        vec![key(OLD)],
    )
    .expect("an update");
    swoosh::roster::fold(&device, &TestRoot::seeded(ROOT).sign_update(&update))
        .await
        .expect("the device holds the update");

    let keeps = home("revocations-root");
    holds(&keeps).await;

    for home in [&unpinned, &device, &keeps] {
        let out = status(home).await;
        assert!(!out.contains("revocations"), "{out}");
    }
    let out = status(&keeps).await;
    assert!(
        out.lines()
            .any(|line| line.starts_with("  me/old ") && line.contains("revoked")),
        "a revoked device stays a row: {out}"
    );
    assert!(
        out.contains("root: root:") && out.contains("kept on this machine"),
        "{out}"
    );
    let out = status(&device).await;
    assert!(
        out.contains("devices (as of the last sync, "),
        "a device's list is as of its last sync: {out}"
    );
}

/// The ledger is issuer-side audit only: `status` reads it, and the gate never does, so it must never
/// appear on the admit path. This fails the moment `serve` (the CLI half or the library's node engine) or
/// the bin root names [`Grants`](swoosh::grants::Grants).
#[test]
fn the_gate_never_reads_the_ledger() {
    for (name, text) in [
        ("bin serve.rs", include_str!("../serve.rs")),
        ("bin main.rs", include_str!("../../main.rs")),
        ("lib serve.rs", include_str!("../../../../serve.rs")),
    ] {
        assert!(
            !text.contains("Grants"),
            "{name} must not name the mint-log ledger: the gate never reads it"
        );
    }
}
