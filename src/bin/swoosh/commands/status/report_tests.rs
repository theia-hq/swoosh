//! Bare `status` over homes built on disk the way the product leaves them: a fresh home, a device of a
//! root, the machine where the root is kept, and every state a crash or a revocation leaves. Each runs
//! `status` through [`run_to`](super::run_to), the function the binary calls.

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
use swoosh::standing::Standing;
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};
use zeroize::Zeroizing;

use super::{Print, run_to, unix_now};

/// This machine's key.
const OWN: u8 = 0x11;
/// The root this machine trusts or keeps.
const ROOT: u8 = 0x21;
/// Another device of the root.
const LAPTOP: u8 = 0x41;
/// A device the root revoked.
const OLD: u8 = 0x42;
/// Another root.
const OTHER: u8 = 0x31;

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
    KeyFile::new(home.key())
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
    KeyFile::strict(home.root_key())
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

/// The report `status` prints on stdout for `home`.
async fn status(home: &Home) -> String {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    run_to(home, Print::Report, &mut out, &mut err)
        .await
        .expect("status reads the home");
    String::from_utf8(out).expect("the report is text")
}

/// A device with no recorded list reports the default when no resident runs.
#[tokio::test]
async fn status_with_no_node_prints_the_default() {
    let home = home("serving");
    device_of(&home).await;
    let out = status(&home).await;
    assert!(
        out.lines()
            .any(|line| line == "serving: ping, speed, when swoosh serve runs"),
        "the serving line is printed with nothing running: {out}"
    );
}

/// While a `serve --admit` runs here, `serving:` names the root it admits.
#[tokio::test]
async fn status_names_the_root_a_running_serve_admits() {
    let home = home("admitting");
    let root = TestRoot::seeded(ROOT).node_id();
    let running = LocalResident::start(&home, &["ping", "speed"], Some(root));
    let out = status(&home).await;
    assert!(
        out.lines()
            .any(|line| line == format!("serving: ping, speed, admitting root:{root}")),
        "{out}"
    );
    drop(running);
    let out = status(&home).await;
    assert!(
        out.contains("serving: ping, speed, when swoosh serve runs"),
        "once it stops, a non-device still reports the default: {out}"
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
    let unpinned = home("unrevoked-none");

    let device = home("unrevoked-device");
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

    let keeps = home("unrevoked-root");
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
        out.contains(&format!(
            "root:{} on this machine",
            TestRoot::seeded(ROOT).node_id()
        )),
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
    swoosh::credential::short(&key(seed))
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
        (&damaged, "this machine's records disagree ("),
        (&unfinished, "making your root did not finish"),
    ] {
        let out = status(home).await;
        let lines: Vec<&str> = out.lines().collect();
        assert!(!lines[3].starts_with("root"), "{out}");
        assert!(
            lines.last().is_some_and(|line| line.starts_with(start)),
            "{out}"
        );
    }
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

/// A link's holder: `anyone`, a device's short key, or a person's root as `root:` and its short key.
#[tokio::test]
async fn a_link_row_prints_its_holder_by_kind() {
    let home = home("links");
    let revoked = swoosh::revoked::open(&home).expect("no revocations");
    let holder = |kind, holder: String| {
        let record = GrantRecord {
            target: "ssh".parse().expect("a service"),
            serves: None,
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

/// Where the root is kept, a due line is printed for each device the renewal renews: a device in its window
/// with four renewals in force is skipped by the renewal, so it has none.
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
    let due: Vec<&str> = out
        .lines()
        .filter(|line| line.starts_with("renew me/"))
        .collect();
    assert_eq!(
        due,
        [format!(
            "renew me/nas by {}: swoosh invite nas",
            Date(now - 25 * DAY)
        )],
        "{out}"
    );
}

/// A device reads each due line from the update it holds, not only where the root is kept, and names the
/// copy of the root the command needs.
#[tokio::test]
async fn a_device_shows_the_due_lines_from_the_update() {
    let now = unix_now();
    let home = home("use-by-device");
    device_of(&home).await;
    let until = now + 20 * DAY;
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
        "renew me/laptop by {}: swoosh invite laptop --root <dir>",
        Date(until - 45 * DAY)
    );
    assert!(out.lines().any(|found| found == line), "{out}");
    assert!(!out.contains("use your root"), "{out}");
}

/// A home with no key: its directory and nothing in it.
fn keyless(tag: &str) -> Home {
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("swoosh-status-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).expect("the scratch home");
    Home::resolve(Some(dir)).expect("the scratch home resolves")
}

/// `home`'s directory as `home:` prints it.
fn home_line(home: &Home) -> String {
    format!("home: {}", home.dir().display())
}

/// `home` as a device of `ROOT` whose standing ends at `until`, in unix seconds.
async fn device_until(home: &Home, until: u64) {
    let root = TestRoot::seeded(ROOT);
    config::write_signet(&swoosh::testkit::lock(), home, root.node_id()).expect("the pin");
    let badge = root
        .device_badge(
            TestNode::seeded(OWN).node_id(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(until),
        )
        .expect("a standing");
    config::write_badge(&swoosh::testkit::lock(), home, &badge).expect("the standing");
}

/// Revoke `ROOT` on `home`.
fn revoke_root(home: &Home) {
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        home,
        [nauthy::Revocation::Key(TestRoot::seeded(ROOT).verify_key())],
    )
    .expect("revoke the root here");
}

/// One home in each state `status` reports, by name, built the way the product or a crash leaves it.
async fn every_state() -> Vec<(&'static str, Home)> {
    let now = unix_now();
    let mut homes = Vec::new();

    let keeps = home("state-holder");
    holds_rows(
        &keeps,
        vec![Member {
            until: now + 20 * DAY,
            ..row(LAPTOP, "nas")
        }],
        Vec::new(),
    )
    .await;
    homes.push(("holder", keeps));

    let device = home("state-device");
    device_of(&device).await;
    list(
        &device,
        &RosterDoc::new(Epoch(2), vec![row(LAPTOP, "desk"), row(OWN, "nas")]).expect("a list"),
    );
    homes.push(("device", device));

    homes.push(("unpinned", home("state-unpinned")));
    homes.push(("no key", keyless("state-no-key")));

    let conflict = home("state-conflict");
    device_of(&conflict).await;
    std::fs::write(
        conflict.devices_conflict(),
        TestRoot::seeded(ROOT).sign_update(&RosterDoc::new(Epoch(3), Vec::new()).expect("a fork")),
    )
    .expect("the fork");
    homes.push(("conflict", conflict));

    let removed = home("state-removed");
    device_of(&removed).await;
    list(
        &removed,
        &RosterDoc::with_revocations(
            Epoch(2),
            vec![row(LAPTOP, "laptop")],
            Vec::new(),
            vec![gone(OWN, "desk")],
        )
        .expect("a list"),
    );
    homes.push(("removed", removed));

    let ended = home("state-ended");
    device_until(&ended, now - DAY).await;
    list(
        &ended,
        &RosterDoc::new(
            Epoch(2),
            vec![Member {
                until: now - DAY,
                ..row(OWN, "desk")
            }],
        )
        .expect("a list"),
    );
    homes.push(("ended", ended));

    let restored = home("state-restored");
    device_of(&restored).await;
    std::fs::remove_dir_all(restored.machine()).expect("a backup leaves machine/ out");
    homes.push(("restored", restored));

    let keeper = home("state-restored-keeper");
    holds(&keeper).await;
    std::fs::remove_dir_all(keeper.machine()).expect("a backup leaves machine/ out");
    homes.push(("restored keeper", keeper));

    // A restored keeper after `leave`: the root, half made, and no key.
    let left = keyless("state-left-keeper");
    root_key(&left);
    homes.push(("left keeper", left));

    let mint = home("state-mint");
    root_key(&mint);
    homes.push(("mint", mint));

    let join = home("state-join");
    let badge = TestRoot::seeded(ROOT)
        .device_badge(
            TestNode::seeded(OWN).node_id(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
        )
        .expect("a standing");
    config::write_badge(&swoosh::testkit::lock(), &join, &badge).expect("the standing");
    homes.push(("join", join));

    let leave = home("state-leave");
    config::write_signet(
        &swoosh::testkit::lock(),
        &leave,
        TestRoot::seeded(ROOT).node_id(),
    )
    .expect("the pin");
    homes.push(("leave", leave));

    let revoked = home("state-revoked-root");
    root_key(&revoked);
    device_of(&revoked).await;
    revoke_root(&revoked);
    homes.push(("revoked root", revoked));

    let damaged = home("state-damaged");
    std::fs::write(damaged.root_pub(), b"not a key").expect("a torn pin");
    homes.push(("damaged", damaged));

    let torn_root = home("state-torn-root");
    std::fs::write(torn_root.root_key(), b"not a key").expect("a torn root key");
    // Owner-only, as swoosh writes a key: a key others can read is refused as loose, not as torn.
    std::fs::set_permissions(
        torn_root.root_key(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .unwrap();
    homes.push(("torn root", torn_root));

    let keyless_torn_root = keyless("state-keyless-torn-root");
    std::fs::write(keyless_torn_root.root_key(), b"not a key").expect("a torn root key");
    // Owner-only, as swoosh writes a key: a key others can read is refused as loose, not as torn.
    std::fs::set_permissions(
        keyless_torn_root.root_key(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .unwrap();
    homes.push(("keyless torn root", keyless_torn_root));

    let another = home("state-another-root");
    root_key(&another);
    config::write_signet(
        &swoosh::testkit::lock(),
        &another,
        TestRoot::seeded(OTHER).node_id(),
    )
    .expect("a pin to another root");
    homes.push(("another root", another));

    // A `join --switch` writes the standing before the pin: one that stopped between them.
    let switch = home("state-switch");
    device_of(&switch).await;
    let badge = TestRoot::seeded(OTHER)
        .device_badge(
            TestNode::seeded(OWN).node_id(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
        )
        .expect("a standing");
    config::write_badge(&swoosh::testkit::lock(), &switch, &badge).expect("the standing");
    homes.push(("switch", switch));

    homes
}

/// Every file and directory under `dir`, by path, with its length and modification time.
fn tree(dir: &std::path::Path) -> Vec<(std::path::PathBuf, u64, SystemTime)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).expect("list the directory") {
        let entry = entry.expect("an entry");
        let meta = entry.metadata().expect("its metadata");
        found.push((
            entry.path(),
            meta.len(),
            meta.modified().expect("its mtime"),
        ));
        if meta.is_dir() {
            found.extend(tree(&entry.path()));
        }
    }
    found.sort();
    found
}

/// `status` reads and never writes: in every state, a revoked root and a restored home included, the
/// home's listing and every modification time are what they were.
#[tokio::test]
async fn status_writes_nothing() {
    for (state, home) in every_state().await {
        let before = tree(home.dir());
        let _ = status(&home).await;
        assert_eq!(tree(home.dir()), before, "status wrote in the {state} home");
    }
}

/// `status` names no path inside the home but on `home:`: in every state, no other line holds the home's
/// directory.
#[tokio::test]
async fn status_prints_no_path_in_the_home_but_home() {
    for (state, home) in every_state().await {
        let dir = home.dir().display().to_string();
        let out = status(&home).await;
        let named: Vec<&str> = out
            .lines()
            .filter(|line| !line.starts_with("home: ") && line.contains(&dir))
            .collect();
        assert!(named.is_empty(), "the {state} home names its path: {out}");
    }
}

/// A home with no key prints `key: none yet` and makes none: no `machine/` appears.
#[tokio::test]
async fn status_on_a_home_with_no_key_makes_none() {
    let home = keyless("no-key-made");
    let out = status(&home).await;
    assert_eq!(out.lines().next(), Some("key: none yet"), "{out}");
    assert!(!home.machine().exists(), "status made a key");
}

/// `status --key` with no key refuses, names `join`, and makes nothing.
#[tokio::test]
async fn status_key_with_no_key_refuses_and_names_join() {
    let home = keyless("no-key-key");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let refused = run_to(&home, Print::Key, &mut out, &mut err)
        .await
        .expect_err("no key to print");
    assert_eq!(
        refused.to_string(),
        "this machine has no key yet; to make one and print it: swoosh join"
    );
    assert!(out.is_empty() && err.is_empty());
    assert!(!home.machine().exists(), "status made a key");
}

/// Line 2 is `key lock:` naming the method, and line 3 `home:`, on every home with a key.
#[tokio::test]
async fn status_prints_key_lock_then_home() {
    let plain = home("lock-plain");
    let sealed = keyless("lock-sealed");
    swoosh::identity::make_machine_dir(&sealed).unwrap();
    let passphrase =
        Passphrase::try_from(Zeroizing::new("a passphrase".to_owned())).expect("a passphrase");
    let mut seed = TestNode::seeded(OWN).seed();
    KeyFile::new(sealed.key())
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .expect("a sealed key");
    for (home, lock) in [
        (&plain, "key lock: none"),
        (&sealed, "key lock: passphrase"),
    ] {
        let out = status(home).await;
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[1..3], [lock, home_line(home).as_str()], "{out}");
    }
}

/// The devices table has no `live` column: a live row leaves its state blank.
#[tokio::test]
async fn status_prints_no_live_column() {
    let home = home("state-column");
    holds(&home).await;
    let out = status(&home).await;
    assert!(!out.contains("live"), "{out}");
    let laptop = out
        .lines()
        .find(|line| names(line, "me/laptop", LAPTOP))
        .unwrap_or_else(|| panic!("the laptop is a row: {out}"));
    assert_eq!(
        laptop.split_whitespace().collect::<Vec<_>>(),
        [
            "me/laptop",
            short_key(LAPTOP).as_str(),
            "until",
            Date(STANDING_UNTIL).to_string().as_str()
        ],
        "{out}"
    );
}

/// Each state prints its block, or its last lines, as written.
#[tokio::test]
async fn status_prints_every_state_verbatim() {
    let now = unix_now();
    let own = TestNode::seeded(OWN).node_id();
    let root = TestRoot::seeded(ROOT).node_id();
    let until = Date(STANDING_UNTIL);
    let homes = every_state().await;
    let home = |name: &str| {
        &homes
            .iter()
            .find(|(state, _)| *state == name)
            .expect("the state")
            .1
    };

    let keeps = home("holder");
    let renew = format!("renew by {}", Date(now - 25 * DAY));
    let state = renew.chars().count();
    assert_eq!(
        status(keeps).await,
        [
            format!("key: {own}"),
            "key lock: none".to_owned(),
            home_line(keeps),
            format!("root:{root} on this machine, locked with a passphrase."),
            String::new(),
            "devices:".to_owned(),
            format!(
                "  me/desk  {}  {:<state$}  until {until}",
                short_key(OWN),
                "this machine"
            ),
            format!(
                "  me/nas   {}  {renew}  until {}",
                short_key(LAPTOP),
                Date(now + 20 * DAY)
            ),
            "serving: ping, speed, when swoosh serve runs".to_owned(),
            String::new(),
            format!(
                "renew me/nas by {}: swoosh invite nas",
                Date(now - 25 * DAY)
            ),
        ]
        .map(|line| line + "\n")
        .concat()
    );

    let device = home("device");
    assert_eq!(
        status(device).await,
        [
            format!("key: {own}"),
            "key lock: none".to_owned(),
            home_line(device),
            format!("root:{root} not on this machine."),
            String::new(),
            format!(
                "devices (as of the last sync, {}):",
                swoosh::sync::ago(device)
            ),
            format!("  me/nas   {}  this machine  until {until}", short_key(OWN)),
            format!(
                "  me/desk  {}                until {until}",
                short_key(LAPTOP)
            ),
            "serving: ping, speed, when swoosh serve runs".to_owned(),
        ]
        .map(|line| line + "\n")
        .concat()
    );

    let unpinned = home("unpinned");
    assert_eq!(
        status(unpinned).await,
        [
            format!("key: {own}"),
            "key lock: none".to_owned(),
            home_line(unpinned),
            "this machine: not one of your devices yet".to_owned(),
            "to join yours, paste its invite into: swoosh join".to_owned(),
            "to make your root on this machine: swoosh invite <name> <key>".to_owned(),
            String::new(),
            "serving: ping, speed, when swoosh serve runs".to_owned(),
        ]
        .map(|line| line + "\n")
        .concat()
    );

    let keyless = home("no key");
    assert_eq!(
        status(keyless).await,
        [
            "key: none yet".to_owned(),
            home_line(keyless),
            "this machine: not one of your devices yet".to_owned(),
            "to join yours, paste its invite into: swoosh join".to_owned(),
            "to make your root on this machine: swoosh invite <name> <key>".to_owned(),
        ]
        .map(|line| line + "\n")
        .concat()
    );

    let missing = "this machine's key is not in this home, because system backups leave it out.";
    let kept = format!("{missing} A root kept on this machine stays. To start over: swoosh leave");
    // A torn `root.key` names no command: `leave` keeps the root, so it would print the same line again.
    let torn = "this machine's records disagree (root.key is not a root key); swoosh cannot \
                tell which root it trusts"
        .to_owned();
    let restored: [(&str, &[String]); 4] = [
        (
            "restored",
            &[
                format!("{missing} To start over: swoosh leave"),
                "then: swoosh join".to_owned(),
            ],
        ),
        (
            "restored keeper",
            &[kept, "then: swoosh invite <name> <key>".to_owned()],
        ),
        ("keyless torn root", core::slice::from_ref(&torn)),
        (
            "left keeper",
            &[
                "making your root did not finish; to finish it: swoosh invite <name> <key>"
                    .to_owned(),
            ],
        ),
    ];
    for (state, last) in restored {
        let restored = home(state);
        let mut lines = vec![
            "key: none yet".to_owned(),
            home_line(restored),
            String::new(),
        ];
        lines.extend_from_slice(last);
        assert_eq!(
            status(restored).await,
            lines
                .into_iter()
                .map(|line| line + "\n")
                .collect::<String>(),
            "the {state} home"
        );
    }

    let ended = Date(now - DAY);
    let disagree = |what: &str| {
        format!(
            "this machine's records disagree ({what}): swoosh cannot tell which root it trusts. A root \
             kept on this machine stays. To start over: swoosh leave"
        )
    };
    let root_short = |seed: u8| {
        format!(
            "root:{}",
            swoosh::credential::short(&TestRoot::seeded(seed).node_id())
        )
    };
    let last: [(&str, &[String]); 11] = [
        (
            "conflict",
            &["two copies of your root have been used: your devices hold two different lists. Keep one \
               copy; the next time you use it, it settles this. If you did not use two copies, your root \
               may be stolen: swoosh revoke --help"
                .to_owned()],
        ),
        (
            "removed",
            &[
                "this machine is no longer one of your devices: your root revoked it. To join again: \
                 swoosh leave --new-key"
                    .to_owned(),
                "then: swoosh join".to_owned(),
            ],
        ),
        (
            "ended",
            &[
                format!(
                    "me/desk ended on {ended}; your devices refuse it. Where your root is kept: swoosh \
                     invite desk"
                ),
                "this machine picks it up the next time it reaches one of your devices, or now: swoosh \
                 sync"
                    .to_owned(),
            ],
        ),
        (
            "mint",
            &["making your root did not finish; to finish it: swoosh invite <name> <key>".to_owned()],
        ),
        (
            "join",
            &["joining did not finish; to finish it: swoosh join".to_owned()],
        ),
        (
            "switch",
            &["joining did not finish; to finish it: swoosh join".to_owned()],
        ),
        (
            "leave",
            &["leaving did not finish; to finish it: swoosh leave".to_owned()],
        ),
        (
            "revoked root",
            &[format!(
                "a revoked root is still on this machine; to delete it: swoosh revoke root:{}",
                TestRoot::seeded(ROOT).node_id()
            )],
        ),
        ("damaged", &[disagree("root.pub is not one root key")]),
        ("torn root", &[torn]),
        (
            "another root",
            &[disagree(&format!(
                "this machine keeps {}, and trusts {}",
                root_short(ROOT),
                root_short(OTHER)
            ))],
        ),
    ];
    for (state, lines) in last {
        let out = status(home(state)).await;
        let printed: Vec<&str> = out.lines().collect();
        assert!(
            printed.ends_with(&lines.iter().map(String::as_str).collect::<Vec<_>>()),
            "the {state} home ends with its lines: {out}"
        );
    }
}

/// A device that joined and has not synced yet is named by its invite, with its key in the short form, until a
/// list of your devices lands.
#[tokio::test]
async fn a_device_before_its_first_sync_is_named_by_its_invite() {
    let home = home("first-sync");
    device_of(&home).await;
    std::fs::write(
        home.invited_by(),
        format!("{}\nb\n", TestNode::seeded(LAPTOP).node_id()),
    )
    .expect("invited-by");
    let out = status(&home).await;
    assert!(
        out.lines().any(|line| line
            == format!(
                "this machine: me/b, your device until {}",
                Date(STANDING_UNTIL)
            )),
        "{out}"
    );

    // The invite's name is an unsigned hint: no line that gives a command takes it.
    let ended = self::home("first-sync-ended");
    let now = unix_now();
    device_until(&ended, now - DAY).await;
    std::fs::write(
        ended.invited_by(),
        format!("{}\nb\n", TestNode::seeded(LAPTOP).node_id()),
    )
    .expect("invited-by");
    let out = status(&ended).await;
    assert!(
        out.lines()
            .any(|line| line == format!("this machine: me/b, ended {}", Date(now - DAY))),
        "{out}"
    );
    assert!(
        out.lines().any(|line| line
            == format!(
                "this machine ended on {}; your devices refuse it. Where your root is kept: swoosh invite \
                 <name>",
                Date(now - DAY)
            )),
        "{out}"
    );
    assert!(!out.contains("invite b"), "{out}");

    std::fs::remove_file(home.invited_by()).expect("no invite to name it");
    let out = status(&home).await;
    assert!(
        out.lines().any(|line| line
            == format!(
                "this machine: {}, your device until {}",
                short_key(OWN),
                Date(STANDING_UNTIL)
            )),
        "{out}"
    );
}

/// The command a line gives, after its last `: swoosh `, with each placeholder filled the way a person
/// fills it; `None` when the line gives none.
fn command(line: &str) -> Option<Vec<String>> {
    let (_, command) = line.rsplit_once(": swoosh ")?;
    let key = TestNode::seeded(LAPTOP).node_id().to_string();
    Some(
        core::iter::once("swoosh".to_owned())
            .chain(command.split_whitespace().map(|word| match word {
                "<name>" => "laptop".to_owned(),
                "<key>" => key.clone(),
                "<dir>" => "/tmp".to_owned(),
                word => word.to_owned(),
            }))
            .collect(),
    )
}

/// Every command `status` prints, in every state, parses as printed: a line never names a form no verb
/// takes, such as a `revoke` of a root.
#[tokio::test]
async fn every_command_status_prints_parses() {
    use clap::Parser as _;

    for (state, home) in every_state().await {
        let out = status(&home).await;
        for args in out.lines().filter_map(command) {
            if let Err(error) = crate::Cli::try_parse_from(&args) {
                assert_eq!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp,
                    "the {state} home prints {args:?}, which does not parse: {error}"
                );
            }
        }
    }
}

/// A home restored from a system backup where the root is kept names only verbs that run there: `leave`,
/// which keeps the root, then the `invite` that finishes the root under a new key. Never `join`, which
/// refuses where a root is kept.
#[tokio::test]
async fn a_restored_root_keeper_is_told_only_verbs_that_run() {
    let home = home("restored-keeper-verbs");
    holds(&home).await;
    std::fs::remove_dir_all(home.machine()).expect("a backup leaves machine/ out");
    let named = |out: &str| -> Vec<String> {
        out.lines()
            .filter_map(command)
            .map(|args| args[1].clone())
            .collect()
    };

    let out = status(&home).await;
    assert_eq!(named(&out), ["leave", "invite"], "{out}");
    let (mut left, mut err) = (Vec::new(), Vec::new());
    crate::commands::leave::LeaveCmd { new_key: false }
        .leave(
            &home,
            &mut swoosh::testkit::Counting::refusing(),
            SystemTime::now(),
            &mut left,
            &mut err,
        )
        .await
        .expect("leave runs on a restored root keeper");
    assert!(home.root_key().exists(), "leave keeps the root");

    // `invite` finishes the root before it invites: under a new key, at one prompt.
    let out = status(&home).await;
    assert_eq!(named(&out), ["invite"], "{out}");
    swoosh::root::Root::mint_to(
        &home,
        &mut swoosh::testkit::Counting::new(["a passphrase"]),
        &mut Vec::new(),
    )
    .await
    .expect("the invite's first step finishes the root");
    assert!(
        matches!(Standing::read(&home).await, Ok(Standing::HoldsRoot { .. })),
        "{}",
        status(&home).await
    );
}

/// Overwrite `path` with `bytes`, owner-only.
fn overwrite(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The report for `home`, each `touch-id` lock reading `health`.
async fn status_reading(home: &Home, health: keystore::Health) -> String {
    let key = KeyFile::new(home.key()).load().unwrap();
    let prompt = swoosh::testkit::Counting::refusing().at_this_mac(health);
    super::Report::gather_with(home, key.as_ref(), unix_now(), &prompt)
        .await
        .unwrap()
        .render()
}

/// `key lock:` names a `touch-id` lock with how it reads: plain when live, and never dead when it cannot be
/// checked. Red when an unchecked lock reads as dead.
#[tokio::test]
async fn key_lock_names_touch_id_with_how_it_reads() {
    let home = home("key-lock-touch-id");
    overwrite(
        &home.key(),
        &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
    );
    for (health, line) in [
        (keystore::Health::Live, "key lock: touch-id"),
        (
            keystore::Health::Dead,
            "key lock: touch-id (does not open on this Mac now)",
        ),
        (
            keystore::Health::Unchecked,
            "key lock: touch-id (cannot be checked now)",
        ),
    ] {
        let out = status_reading(&home, health).await;
        assert_eq!(out.lines().nth(1), Some(line), "{out}");
        assert_eq!(
            out.contains("does not open"),
            health == keystore::Health::Dead,
            "{out}"
        );
    }
}

/// A dead one-lock key where no root is kept says how to mend it: the finger, else a new key.
#[tokio::test]
async fn a_dead_touch_id_key_says_how_to_mend_it() {
    let home = home("key-lock-touch-id-dead");
    overwrite(
        &home.key(),
        &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
    );
    let out = status_reading(&home, keystore::Health::Dead).await;
    assert!(
        out.trim_end().ends_with(
            "touch-id does not open this machine's key on this Mac now.\n\
             if you added a fingerprint, removing it lets touch-id open the key again.\n\
             otherwise, give this machine a new key and join again: swoosh leave --new-key"
        ),
        "{out}"
    );
}

/// The root's line names its `touch-id` lock with how it reads, and a dead one says how to set it again,
/// after the check on a fingerprint nobody added. Red when an unchecked lock gets the dead line.
#[tokio::test]
async fn the_root_line_names_touch_id_with_how_it_reads() {
    let home = home("root-touch-id");
    holds(&home).await;
    overwrite(
        &home.root_key(),
        &swoosh::testkit::touch_id::ROOT_PASSPHRASE_AND_TOUCH_ID,
    );
    let root = TestRoot::seeded(ROOT).node_id();
    let dead_line = "touch-id does not open your root on this Mac now.\n\
                     check Touch ID & Password for a fingerprint you did not add, then set touch-id again: \
                     swoosh root lock touch-id";
    for (health, locks) in [
        (keystore::Health::Live, "a passphrase and touch-id"),
        (
            keystore::Health::Dead,
            "a passphrase and touch-id, which does not open on this Mac now",
        ),
        (
            keystore::Health::Unchecked,
            "a passphrase and touch-id, which cannot be checked now",
        ),
    ] {
        let out = status_reading(&home, health).await;
        let line = format!("root:{root} on this machine, locked with {locks}.");
        assert!(out.lines().any(|seen| seen == line), "{line}\n{out}");
        assert_eq!(
            out.contains(dead_line),
            health == keystore::Health::Dead,
            "{out}"
        );
    }
}

/// On a build with no enclave, a `touch-id` lock is named with a note that it opens only on a Mac, on the
/// key's line and the root's, so nobody there reads it as a way in. Red when it reads as a live lock.
#[tokio::test]
async fn touch_id_unasked_says_it_opens_only_on_a_mac() {
    let home = home("touch-id-unasked");
    holds(&home).await;
    overwrite(
        &home.key(),
        &swoosh::testkit::touch_id::DEVICE_PASSPHRASE_AND_TOUCH_ID,
    );
    overwrite(
        &home.root_key(),
        &swoosh::testkit::touch_id::ROOT_PASSPHRASE_AND_TOUCH_ID,
    );
    let key = KeyFile::new(home.key()).load().unwrap();
    let out = super::Report::gather_with(
        &home,
        key.as_ref(),
        unix_now(),
        &swoosh::testkit::Counting::refusing(),
    )
    .await
    .unwrap()
    .render();
    assert!(
        out.lines().any(
            |line| line == "key lock: passphrase, touch-id (opens only on the Mac that set it)"
        ),
        "{out}"
    );
    let root = TestRoot::seeded(ROOT).node_id();
    let line = format!(
        "root:{root} on this machine, locked with a passphrase and touch-id, which opens only on the Mac \
         that set it."
    );
    assert!(out.lines().any(|seen| seen == line), "{line}\n{out}");
}

/// A key under `touch-id` alone beside a root kept here is nagged about, as a root made or restored beside
/// it says, until the passphrase goes beside the touch. Red when the nag is dropped.
#[tokio::test]
async fn a_touch_id_only_key_beside_a_root_is_nagged() {
    let home = home("touch-id-alone-beside-root");
    holds(&home).await;
    overwrite(
        &home.key(),
        &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
    );
    let out = status_reading(&home, keystore::Health::Live).await;
    assert!(
        out.lines()
            .any(|line| line == swoosh::identity::TOUCH_ID_ALONE_BESIDE_ROOT),
        "{out}"
    );
    overwrite(
        &home.key(),
        &swoosh::testkit::touch_id::DEVICE_PASSPHRASE_AND_TOUCH_ID,
    );
    let out = status_reading(&home, keystore::Health::Live).await;
    assert!(
        !out.contains(swoosh::identity::TOUCH_ID_ALONE_BESIDE_ROOT),
        "{out}"
    );
}

/// A learned root's row in `contacts` names the machine it was learned from; a typed root's says nothing more.
/// No row carries a kind word: the key's shape says it.
#[test]
fn status_marks_a_learned_root() {
    let mut contacts = swoosh::contacts::Contacts::default();
    let alice = "alice".parse().expect("a name");
    contacts.add(
        "alice".parse().expect("a name"),
        Some("laptop".parse().expect("a name")),
        TestNode::seeded(LAPTOP).node_id(),
    );
    let learned = TestRoot::seeded(0x71).node_id();
    contacts
        .learn(&alice, learned, "laptop".parse().expect("a name"))
        .expect("an empty slot");
    contacts.set_signet(
        "bob".parse().expect("a name"),
        TestRoot::seeded(0x72).node_id(),
    );
    let section = super::contacts_section(&contacts);
    let rows: Vec<&[String; 4]> = section.rows.iter().collect();
    assert_eq!(
        rows[0],
        &[
            "alice".to_owned(),
            format!("root:{}", swoosh::credential::short(&learned)),
            "learned from alice/laptop".to_owned(),
            String::new(),
        ]
    );
    assert_eq!(
        rows[1],
        &[
            "alice/laptop".to_owned(),
            swoosh::credential::short(&TestNode::seeded(LAPTOP).node_id()),
            String::new(),
            String::new(),
        ],
        "a machine's row is its name and key"
    );
    let bob = rows
        .iter()
        .find(|row| row[0] == "bob")
        .expect("bob's root is listed");
    assert_eq!(bob[2..], ["", ""], "a typed root carries no mark");
}

/// Record through the same locked writer the service commands use.
async fn service_list(home: &Home, entries: &[&str], off: &[&str]) {
    let lock = swoosh::home::HomeWrite::take(home).await.unwrap();
    swoosh::serve_toml::ServeToml::update(&lock, home, |file| {
        file.services = Some(entries.iter().map(|entry| (*entry).to_owned()).collect());
        file.off = off.iter().map(|name| (*name).to_owned()).collect();
    })
    .unwrap();
}

/// A real local resident, without any transport or service target bound.
struct LocalResident {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<eyre::Result<()>>,
    socket: std::path::PathBuf,
    _lock: swoosh::home::ServeLock,
}

impl LocalResident {
    fn start(home: &Home, names: &[&str], admit: Option<bifrost::NodeId>) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::Arc;

        let socket = home.control_socket().unwrap();
        let dir = socket.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let cancel = CancellationToken::new();
        let resident = Arc::new(swoosh::serve::Resident::new(
            TestNode::seeded(OWN).node_id(),
            None,
            catalog(names),
            swoosh::serve_toml::LiveServeToml::load(home).unwrap(),
            cancel.clone(),
            Arc::default(),
        ));
        let task = tokio::spawn(async move { resident.serve(listener).await });
        Self {
            cancel,
            task,
            socket,
            _lock: swoosh::testkit::serving(home, admit),
        }
    }
}

impl Drop for LocalResident {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(self.socket.parent().unwrap());
    }
}

/// The actual toggle leaf must accept the same bare name the report prints.
async fn turn(home: &Home, name: &str, way: crate::commands::service::toggle::Way) {
    use crate::commands::service::toggle::{ServiceToggleCmd, Slot};

    ServiceToggleCmd {
        service: Slot::Service(swoosh::names::service(name).unwrap()),
        machine: None,
    }
    .run(home, way)
    .await
    .unwrap();
}

fn serving_row(out: &str) -> &str {
    out.lines()
        .find(|line| line.starts_with("serving:"))
        .unwrap()
}

#[tokio::test]
async fn status_marks_a_listed_service_turned_off() {
    let home = home("listed-off");
    service_list(&home, &["ssh=ssh:", "web=tcp:localhost:3000"], &[]).await;
    // Catalog order and internal entries cannot become the printable-name source.
    let _resident = LocalResident::start(&home, &["control.stop", "web", "ssh"], None);
    assert_eq!(serving_row(&status(&home).await), "serving: ssh, web");
    turn(&home, "web", crate::commands::service::toggle::Way::Off).await;
    let before = tree(home.dir());
    assert_eq!(serving_row(&status(&home).await), "serving: ssh, web (off)");
    assert_eq!(tree(home.dir()), before, "the report must not write");
}

#[tokio::test]
async fn status_leaves_out_a_service_added_or_removed_while_serving() {
    use crate::commands::service::edit::{ServiceAddCmd, ServiceRmCmd};

    let home = home("added-removed");
    service_list(&home, &["ssh=ssh:", "web=tcp:localhost:3000"], &[]).await;
    let _resident = LocalResident::start(&home, &["ssh", "web", "control.stop"], None);
    ServiceAddCmd {
        entries: vec![swoosh::serve::service_entry("proxy:https://example.com").unwrap()],
    }
    .run(&home)
    .await
    .unwrap();
    ServiceRmCmd {
        names: vec!["web".parse().unwrap()],
    }
    .run(&home)
    .await
    .unwrap();
    assert_eq!(serving_row(&status(&home).await), "serving: ssh");

    // Reusing the removed name with a new target still has the old bound route until restart.
    ServiceAddCmd {
        entries: vec!["web=tcp:localhost:9090".to_owned()],
    }
    .run(&home)
    .await
    .unwrap();
    assert_eq!(serving_row(&status(&home).await), "serving: ssh, web");
    service_list(&home, &[], &[]).await;
    assert_eq!(serving_row(&status(&home).await), "serving: nothing");
}

#[tokio::test]
async fn status_shows_what_a_bare_serve_starts_when_none_runs() {
    let home = home("down-listed");
    assert!(matches!(
        Standing::read(&home).await,
        Ok(Standing::Unpinned)
    ));
    service_list(&home, &["ssh=ssh:", "web=tcp:localhost:3000"], &["web"]).await;
    let before = tree(home.dir());
    assert_eq!(
        serving_row(&status(&home).await),
        "serving: ssh, web (off), when swoosh serve runs"
    );
    assert_eq!(tree(home.dir()), before);
}

#[tokio::test]
async fn status_tells_the_default_from_an_emptied_list() {
    let home = home("default-empty");
    assert!(!home.serve_toml().exists());
    assert_eq!(
        serving_row(&status(&home).await),
        "serving: ping, speed, when swoosh serve runs"
    );
    // A present file that has only off marks is still a never-named list.
    turn(&home, "ping", crate::commands::service::toggle::Way::Off).await;
    assert_eq!(
        serving_row(&status(&home).await),
        "serving: ping (off), speed, when swoosh serve runs"
    );
    service_list(&home, &[], &[]).await;
    assert_eq!(
        serving_row(&status(&home).await),
        "serving: nothing, even when swoosh serve runs"
    );
}

#[tokio::test]
async fn status_reports_a_damaged_serve_toml_as_unknown() {
    let home = home("damaged-services");
    for bytes in [
        b"services = ['web=tcp:localhost:3000', 'web=tcp:localhost:4000']\n".as_slice(),
        b"services = ['--public']\n",
        b"services = ['tcp:localhost:3000']\n",
        b"this is not TOML\n",
    ] {
        overwrite(&home.serve_toml(), bytes);
        let before = tree(home.dir());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        run_to(&home, Print::Report, &mut out, &mut err)
            .await
            .unwrap();
        assert_eq!(
            serving_row(&String::from_utf8(out).unwrap()),
            "serving: unknown"
        );
        let err = String::from_utf8(err).unwrap();
        assert!(
            err.contains(&home.serve_toml().display().to_string()),
            "{err}"
        );
        assert!(!err.contains("running swoosh serve"), "{err}");
        assert!(!err.starts_with("could not read "), "{err}");
        assert_eq!(err.matches("serve.toml").count(), 1, "{err}");
        if bytes.starts_with(b"services = ['web=") {
            assert_eq!(
                err,
                format!(
                    "web is named twice in {}\n  Each service needs its own name; swoosh will not guess which one to keep.\n",
                    home.serve_toml().display()
                )
            );
        }
        assert_eq!(tree(home.dir()), before);
    }
    overwrite(&home.serve_toml(), b"services = ['ssh=ssh:']\n");
    let _resident = LocalResident::start(&home, &["ssh"], None);
    overwrite(&home.serve_toml(), b"services = ['ssh=ssh:', 'ssh=ssh:']\n");
    assert_eq!(serving_row(&status(&home).await), "serving: unknown");
    drop(_resident);

    // A trusted-file opener refusal is not an absent file, nor a daemon-read failure.
    overwrite(&home.serve_toml(), b"services = ['ssh=ssh:']\n");
    std::fs::set_permissions(
        home.serve_toml(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o666),
    )
    .unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    run_to(&home, Print::Report, &mut out, &mut err)
        .await
        .unwrap();
    assert_eq!(
        serving_row(&String::from_utf8(out).unwrap()),
        "serving: unknown"
    );
    let err = String::from_utf8(err).unwrap();
    assert!(err.contains("serve.toml"), "{err}");
    assert!(!err.contains("running swoosh serve"), "{err}");

    // A valid file beside a planted non-socket retains the existing, distinct daemon notice.
    overwrite(&home.serve_toml(), b"services = ['ssh=ssh:']\n");
    let socket = home.control_socket().unwrap();
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        socket.parent().unwrap(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    overwrite(&socket, b"not a socket");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    run_to(&home, Print::Report, &mut out, &mut err)
        .await
        .unwrap();
    assert_eq!(
        serving_row(&String::from_utf8(out).unwrap()),
        "serving: unknown"
    );
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.starts_with("could not read the running swoosh serve:"),
        "{err}"
    );
    std::fs::remove_file(&socket).unwrap();
    std::fs::remove_dir(socket.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn the_name_status_prints_is_the_name_service_on_takes() {
    use clap::Parser as _;

    use crate::commands::service::toggle::Way;

    let home = home("names-for-on");
    service_list(
        &home,
        &["web=tcp:localhost:3000", "proxy=proxy:https://example.com"],
        &[],
    )
    .await;
    let _resident = LocalResident::start(&home, &["web", "proxy"], None);
    for name in ["web", "proxy"] {
        turn(&home, name, Way::Off).await;
    }
    let out = status(&home).await;
    assert_eq!(serving_row(&out), "serving: web (off), proxy (off)");
    for marked in serving_row(&out)
        .strip_prefix("serving: ")
        .unwrap()
        .split(", ")
    {
        let name = marked.strip_suffix(" (off)").unwrap();
        crate::Cli::try_parse_from(["swoosh", "service", "on", name]).unwrap();
        turn(&home, name, Way::On).await;
    }
    assert_eq!(serving_row(&status(&home).await), "serving: web, proxy");
}

#[tokio::test]
async fn status_keeps_the_marks_when_admitting() {
    let home = home("admit-marks");
    service_list(&home, &["ssh=ssh:", "web=tcp:localhost:3000"], &["web"]).await;
    let root = TestRoot::seeded(ROOT).node_id();
    let _resident = LocalResident::start(&home, &["ssh", "web"], Some(root));
    assert_eq!(
        serving_row(&status(&home).await),
        format!("serving: ssh, web (off), admitting root:{root}")
    );
    service_list(&home, &[], &[]).await;
    assert_eq!(
        serving_row(&status(&home).await),
        format!("serving: nothing, admitting root:{root}")
    );
    overwrite(&home.serve_toml(), b"services = ['ssh=ssh:', 'ssh=ssh:']\n");
    assert_eq!(
        serving_row(&status(&home).await),
        format!("serving: unknown, admitting root:{root}")
    );
}

/// Existing typed file/list errors keep one filename and the useful I/O source, while a command-line
/// error that has no file gets only that missing context.
#[test]
fn serving_file_notices_preserve_sources_without_repeating_the_file() {
    use std::io;

    use swoosh::escape::EscapedPath;
    use swoosh::serve::{Mistyped, ServingError};
    use swoosh::serve_toml::ServeTomlError;

    use crate::commands::service_state::ReadError;

    let home = home("file-notices");
    let path = home.serve_toml();
    let error = ReadError::File(ServeTomlError::Io {
        path: path.clone(),
        source: io::Error::new(io::ErrorKind::PermissionDenied, "fixture permission denied"),
    });
    let notice = super::serving_file_notice(&home, error);
    assert_eq!(
        notice,
        format!(
            "could not use {}: fixture permission denied",
            EscapedPath(&path)
        )
    );
    let error = ServingError::Mistyped(Mistyped::Twice("web".to_owned()));
    let expected = format!("{}: {error}", EscapedPath(&path));
    assert_eq!(
        super::serving_file_notice(&home, ReadError::List(error)),
        expected
    );
}

#[tokio::test]
async fn status_refuses_uncallable_names_before_intersecting_the_catalog() {
    use crate::commands::service_state::{ReadError, ServiceState};

    let home = home("uncallable-services");
    for name in ["control", "lookup"] {
        let entry = format!("{name}=ping:");
        service_list(&home, &["ssh=ssh:", &entry], &[]).await;
        let before = tree(home.dir());
        assert!(matches!(
            ServiceState::read(&home).await,
            Err(ReadError::List(swoosh::serve::ServingError::NotAService { path, line }))
                if path == home.serve_toml() && line == entry
        ));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        run_to(&home, Print::Report, &mut out, &mut err)
            .await
            .unwrap();
        assert_eq!(
            serving_row(&String::from_utf8(out).unwrap()),
            "serving: unknown"
        );
        let err = String::from_utf8(err).unwrap();
        assert_eq!(err.matches("serve.toml").count(), 1, "{err}");
        assert!(
            err.contains(&home.serve_toml().display().to_string()),
            "{err}"
        );
        assert!(
            err.contains(&entry) && err.contains("which is not a service"),
            "{err}"
        );
        assert_eq!(tree(home.dir()), before);

        service_list(&home, &["ssh=ssh:"], &[]).await;
        let resident = LocalResident::start(&home, &["ssh", "control.stop"], None);
        // The invalid entry is absent from the bound catalog, but the whole file still refuses.
        service_list(&home, &["ssh=ssh:", &entry], &[]).await;
        assert_eq!(serving_row(&status(&home).await), "serving: unknown");
        drop(resident);
    }
}

#[tokio::test]
async fn status_preserves_current_callable_names_without_new_reservations() {
    let home = home("current-service-names");
    service_list(&home, &["me=ping:", "root=ping:", "anyone=ping:"], &[]).await;
    assert_eq!(
        serving_row(&status(&home).await),
        "serving: me, root, anyone, when swoosh serve runs"
    );
    let resident = LocalResident::start(&home, &["me", "root", "anyone", "control.stop"], None);
    assert_eq!(
        serving_row(&status(&home).await),
        "serving: me, root, anyone"
    );
    drop(resident);
}
