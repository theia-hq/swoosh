//! Bare `status` over homes built on disk the way the product leaves them: a fresh home, a device of a
//! root, and the machine where the root is kept.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::time::SystemTime;

use keystore::{KeyFile, Passphrase, Protection};
use nauthy::{RevocationId, VerifyKey};
use swoosh::config;
use swoosh::contacts::DeviceLabel;
use swoosh::grants::{ANYONE, Delegation, GrantKind, GrantRecord};
use swoosh::home::Home;
use swoosh::root::Date;
use swoosh::roster::{Epoch, Member, RevokedDevice, RosterDoc};
use swoosh::serve::control_codec::{DisabledList, ServiceMenu};
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};
use tightbeam::tunnel::ServiceCatalog;
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
    swoosh::identity::make_machine_dir(&home).unwrap();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .expect("this machine's key");
    home
}

fn key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

/// A live row for the device `seed`.
fn row(seed: u8, label: &str) -> Member {
    Member {
        node: key(seed),
        label: label.parse::<DeviceLabel>().expect("a device name"),
        until: STANDING_UNTIL,
        duration: 90 * DAY,
        invite_until: 0,
        ids: Vec::new(),
        standing: TestRoot::seeded(ROOT)
            .standing(key(seed))
            .expect("a standing"),
    }
}

/// Make `home` a device of `ROOT`: its pin, and a standing the root signed for it.
async fn device_of(home: &Home) {
    let root = TestRoot::seeded(ROOT);
    config::write_signet(&swoosh::testkit::lock(), home, root.node_id()).expect("the pin");
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
    let badge = root
        .device_badge(TestNode::seeded(OWN).node_id(), until)
        .expect("a standing");
    config::write_badge(&swoosh::testkit::lock(), home, &badge).expect("the standing");
}

/// `ROOT`, sealed, as `home`'s `root.key`.
fn root_key(home: &Home) {
    let passphrase =
        Passphrase::try_from(Zeroizing::new("a passphrase".to_owned())).expect("a passphrase");
    let mut seed = TestRoot::seeded(ROOT).seed();
    KeyFile::root(home.root_key())
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .expect("the sealed root");
}

/// `list`, signed by `ROOT`, as `home`'s `devices`.
fn list(home: &Home, list: &RosterDoc) {
    std::fs::write(home.devices(), TestRoot::seeded(ROOT).sign_update(list)).expect("the list");
}

/// Make `home` keep `ROOT`, sealed, beside a list of this machine and a laptop that revokes an old device.
async fn holds(home: &Home) {
    holds_rows(home, vec![row(LAPTOP, "laptop")], vec![gone(OLD, "old")]).await;
}

/// The device `seed`, revoked under the name `label`.
fn gone(seed: u8, label: &str) -> RevokedDevice {
    RevokedDevice {
        node: key(seed),
        label: label.parse().expect("a name"),
    }
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

/// While a `serve --admit` runs here, `serving:` names the root it admits.
#[tokio::test]
async fn status_names_the_root_a_running_serve_admits() {
    let home = home("admitting");
    let root = TestRoot::seeded(ROOT).node_id();
    let running = swoosh::testkit::serving(&home, Some(root));
    let out = status(&home).await;
    assert!(
        out.lines()
            .any(|line| line == format!("serving: admitting root root:{root}")),
        "{out}"
    );
    drop(running);
    let out = status(&home).await;
    assert!(
        out.lines().any(|line| line == SERVING_NOTHING),
        "once it stops, nothing: {out}"
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

/// While `devices.conflict` holds an update, the warning prints and names `revoke --help`; with it empty or
/// gone, it does not.
#[tokio::test]
async fn status_warns_while_two_copies_disagree() {
    let home = home("fork");
    device_of(&home).await;
    let warning = "two copies of your root have been used: your devices hold two different lists. Keep \
                   one copy; the next time you use it, it settles this. If you did not use two copies, \
                   your root may be stolen: swoosh revoke --help";
    assert!(!status(&home).await.contains("two copies"));

    std::fs::write(home.devices_conflict(), b"").expect("an empty fork file");
    assert!(
        !status(&home).await.contains("two copies"),
        "an empty file holds no update"
    );

    let fork = RosterDoc::new(Epoch(3), Vec::new()).expect("an update");
    std::fs::write(
        home.devices_conflict(),
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
        vec![gone(OLD, "old")],
    )
    .expect("an update");
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&device).await.unwrap(),
        &device,
        &TestRoot::seeded(ROOT).sign_update(&update),
    )
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
            .any(|line| names(line, "me/old", OLD) && line.contains("revoked")),
        "a revoked device stays a row, by its name: {out}"
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
    assert!(
        out.lines()
            .any(|line| names(line, "me/old", OLD) && line.contains("revoked")),
        "a device keeps a revoked device as a row, by its name: {out}"
    );
}

/// Whether the devices row `line` opens with `name` and then the short key of `seed`.
fn names(line: &str, name: &str, seed: u8) -> bool {
    line.split_whitespace()
        .take(2)
        .eq([name, short_key(seed).as_str()])
}

/// A row's short form of the key `seed`.
fn short_key(seed: u8) -> String {
    super::short(&key(seed).to_string())
}

/// The update `ROOT` signed revoking `revoked`, with `laptop` still a member unless it is revoked too.
fn revoking(epoch: u64, revoked: Vec<RevokedDevice>) -> Vec<u8> {
    let members = if revoked.iter().any(|device| device.node == key(LAPTOP)) {
        Vec::new()
    } else {
        vec![
            TestRoot::seeded(ROOT)
                .member(key(LAPTOP), "laptop".parse().expect("a name"))
                .expect("a member"),
        ]
    };
    let update =
        RosterDoc::with_revocations(Epoch(epoch), members, Vec::new(), revoked).expect("an update");
    TestRoot::seeded(ROOT).sign_update(&update)
}

/// A device revoked with another copy of the root shows as revoked, where the root is kept and on a device,
/// by the name the update carries for it.
#[tokio::test]
async fn status_shows_a_device_revoked_by_another_copy_as_revoked() {
    let keeps = home("revoked-elsewhere-root");
    holds(&keeps).await;
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&keeps).await.unwrap(),
        &keeps,
        &revoking(2, vec![gone(OLD, "old"), gone(LAPTOP, "laptop")]),
    )
    .await
    .expect("the machine that keeps the root holds the other copy's update");
    let out = status(&keeps).await;
    // The list kept beside the root is the one folded: it carries the laptop's key and no row for it.
    let laptop = out
        .lines()
        .find(|line| names(line, "me/laptop", LAPTOP))
        .unwrap_or_else(|| panic!("the laptop is a row: {out}"));
    assert!(
        laptop.contains("revoked") && !laptop.contains("live"),
        "{out}"
    );

    let device = home("revoked-elsewhere-device");
    device_of(&device).await;
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&device).await.unwrap(),
        &device,
        &revoking(2, vec![gone(OLD, "old"), gone(LAPTOP, "laptop")]),
    )
    .await
    .expect("the device holds the update");
    let out = status(&device).await;
    for (name, seed) in [("me/old", OLD), ("me/laptop", LAPTOP)] {
        assert!(
            out.lines()
                .any(|line| names(line, name, seed) && line.contains("revoked")),
            "{name} is a revoked row: {out}"
        );
    }
}

/// A damaged home and an unfinished root say so last, under everything else, never as line 3.
#[tokio::test]
async fn status_prints_a_damaged_or_unfinished_root_last() {
    let damaged = home("damaged");
    std::fs::write(damaged.root_pub(), b"not a key").expect("a torn pin");
    let unfinished = home("unfinished");
    root_key(&unfinished);
    for (home, start) in [
        (&damaged, "root: this machine's records disagree ("),
        (&unfinished, "root: root:"),
    ] {
        let out = status(home).await;
        let lines: Vec<&str> = out.lines().collect();
        assert!(!lines[2].starts_with("root:"), "{out}");
        assert!(
            lines.last().is_some_and(|line| line.starts_with(start)),
            "{out}"
        );
    }
}

/// Once the day has passed, the line counts devices as "devices", one or many, as quoted.
#[test]
fn use_your_root_now_counts_devices_as_quoted() {
    let now = 1_000 * DAY;
    let due = super::DeviceRow {
        label: "laptop".parse().expect("a name"),
        key: key(LAPTOP),
        until: now + 10 * DAY,
        duration: 90 * DAY,
        seeded: false,
        revoked: false,
    };
    assert_eq!(
        super::use_your_root(&[due], now, 1).as_deref(),
        Some("use your root now: swoosh invite (1 devices due)")
    );
}

/// A catalog of `names`, decoded from the wire form the way `serve` sends it.
fn catalog(names: &[&str]) -> ServiceCatalog {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(names.len() as u32).to_be_bytes());
    for name in names {
        bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
    }
    ServiceCatalog::decode(&bytes).expect("the test catalog decodes")
}

/// `serving:` names what is on; when the list of what is off could not be read, it claims nothing.
#[test]
fn serving_is_unknown_when_what_is_off_cannot_be_read() {
    let menu = |disabled| ServiceMenu {
        catalog: catalog(&["ssh", "ping"]),
        disabled,
    };
    assert_eq!(
        super::serving(&menu(DisabledList::Known(vec!["ssh".to_owned()]))),
        Ok("serving: ping".to_owned())
    );
    assert!(
        super::serving(&menu(DisabledList::Unknown("too long".to_owned())))
            .is_err_and(|why| why.contains("too long"))
    );
}

/// A link's holder: `anyone`, a device's short key, or a person's root as `root:` and its short key.
#[tokio::test]
async fn a_link_row_prints_its_holder_by_kind() {
    let home = home("links");
    let revoked = swoosh::revoked::open(&home).expect("no revocations");
    let holder = |kind, holder: String| {
        let record = GrantRecord {
            target: "ssh".parse().expect("a service"),
            kind,
            delegation: Delegation::Sealed,
            holder,
            root_id: RevocationId::from_bytes(vec![7; 64]),
            expiry: SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
        };
        super::link_row(&record, &revoked, unix_now())[2].clone()
    };
    let other = TestNode::seeded(LAPTOP).node_id().to_string();
    assert_eq!(holder(GrantKind::Bearer, ANYONE.to_owned()), "anyone");
    assert_eq!(holder(GrantKind::Device, other.clone()), short_key(LAPTOP));
    assert_eq!(
        holder(GrantKind::Fleet, other),
        format!("root:{}", short_key(LAPTOP))
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

/// Make `home` keep `ROOT`, sealed, beside a list of this machine and `rows` that revokes `revoked`.
async fn holds_rows(home: &Home, rows: Vec<Member>, revoked: Vec<RevokedDevice>) {
    device_of(home).await;
    root_key(home);
    let mut all = vec![row(OWN, "desk")];
    all.extend(rows);
    list(
        home,
        &RosterDoc::with_revocations(Epoch(1), all, Vec::new(), revoked).expect("the list"),
    );
}

/// Where the root is kept, a device whose key came in its invite is warned for in the 14 days before
/// that invite ends: read from when the invite ends, never from the device's own date; silent once it
/// has ended, and for a revoked device.
#[tokio::test]
async fn status_warns_before_a_key_carrying_invite_ends() {
    let now = unix_now();
    let carrying = |seed, label: &str, until, invite_until| Member {
        until,
        invite_until,
        ..row(seed, label)
    };
    let home = home("invite-ends");
    // The revoked device's invite would end in five days: its list carries its key and name, and no row.
    holds_rows(
        &home,
        vec![
            carrying(LAPTOP, "ci", now + 80 * DAY, now + 10 * DAY),
            carrying(0x43, "later", now + 10 * DAY, now + 60 * DAY),
            carrying(0x44, "ended", now + 80 * DAY, now - DAY),
        ],
        vec![gone(OLD, "old")],
    )
    .await;
    let out = status(&home).await;
    let warned: Vec<&str> = out
        .lines()
        .filter(|line| line.contains("key came in its invite"))
        .collect();
    assert_eq!(
        warned,
        [format!(
            "me/ci's key came in its invite, which ends on {}. If it starts from that invite each time (a \
             runner summoned from a secret): swoosh invite ci --new-key, then set its secret again.",
            Date(now + 10 * DAY)
        )],
        "{out}"
    );
}

/// Where the root is kept, "use your root now" counts what the renewal renews: a device in its window with
/// four renewals in force is skipped by the renewal, so it is not counted.
#[tokio::test]
async fn status_counts_only_what_the_renewal_renews() {
    let now = unix_now();
    let id = |byte: u8, expires| swoosh::roster::Id {
        expires,
        id: RevocationId::from_bytes(vec![byte; 64]),
    };
    let home = home("due-count");
    holds_rows(
        &home,
        vec![
            Member {
                until: now + 20 * DAY,
                ids: vec![
                    id(1, now + 5 * DAY),
                    id(2, now + 10 * DAY),
                    id(3, now + 15 * DAY),
                    id(4, now + 20 * DAY),
                ],
                ..row(LAPTOP, "laptop")
            },
            Member {
                until: now + 20 * DAY,
                ..row(0x43, "nas")
            },
        ],
        Vec::new(),
    )
    .await;
    let out = status(&home).await;
    assert!(
        out.lines()
            .any(|line| line == "use your root now: swoosh invite (1 devices due)"),
        "{out}"
    );
}

/// A device reads "use your root by <date>" from the update it holds, not only where the root is kept.
#[tokio::test]
async fn a_device_shows_use_your_root_by_from_the_update() {
    let now = unix_now();
    let home = home("use-by-device");
    device_of(&home).await;
    let until = now + 80 * DAY;
    let laptop = swoosh::roster::Member {
        until,
        duration: 90 * DAY,
        ..TestRoot::seeded(ROOT)
            .member(key(LAPTOP), "laptop".parse().expect("a name"))
            .expect("a member")
    };
    let update = RosterDoc::new(Epoch(2), vec![laptop]).expect("an update");
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&home).await.unwrap(),
        &home,
        &TestRoot::seeded(ROOT).sign_update(&update),
    )
    .await
    .expect("the device holds the update");
    let out = status(&home).await;
    let line = format!(
        "use your root by {}: swoosh invite (it lists what is due)",
        Date(until - 45 * DAY)
    );
    assert!(out.lines().any(|found| found == line), "{out}");
}
