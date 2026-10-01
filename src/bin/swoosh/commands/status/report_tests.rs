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
use swoosh::serve::control_codec::{DisabledList, ServiceMenu};
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};
use tightbeam::tunnel::ServiceCatalog;
use zeroize::Zeroizing;

use super::{Print, SERVING_NOTHING, run_to, unix_now};

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

/// The report `status` prints on stdout for `home`.
async fn status(home: &Home) -> String {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    run_to(home, Print::Report, &mut out, &mut err)
        .await
        .expect("status reads the home");
    String::from_utf8(out).expect("the report is text")
}

/// With no `serve` running on a device, `serving:` says so, and the report is still whole.
#[tokio::test]
async fn status_with_no_node_prints_serving_nothing() {
    let home = home("serving");
    device_of(&home).await;
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
            .any(|line| line == format!("serving: admitting root:{root}")),
        "{out}"
    );
    drop(running);
    let out = status(&home).await;
    assert!(
        !out.contains("serving:"),
        "once it stops, a machine that is no device has nothing served to say: {out}"
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
        (&damaged, "root: this machine's records disagree ("),
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
    std::fs::write(
        ended.invited_by(),
        format!("{}\ndesk\n", TestNode::seeded(LAPTOP).node_id()),
    )
    .expect("invited-by");
    homes.push(("ended", ended));

    let restored = home("state-restored");
    device_of(&restored).await;
    std::fs::remove_dir_all(restored.machine()).expect("a backup leaves machine/ out");
    homes.push(("restored", restored));

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
    KeyFile::device(sealed.key())
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
            SERVING_NOTHING.to_owned(),
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
            SERVING_NOTHING.to_owned(),
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

    let restored = home("restored");
    assert_eq!(
        status(restored).await,
        [
            "key: none yet".to_owned(),
            home_line(restored),
            String::new(),
            "this machine's key is not in this home, because system backups leave it out. To start \
             over: swoosh leave"
                .to_owned(),
            "then: swoosh join".to_owned(),
        ]
        .map(|line| line + "\n")
        .concat()
    );

    let ended = Date(now - DAY);
    let last: [(&str, &[String]); 8] = [
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
            "leave",
            &["leaving did not finish; to finish it: swoosh leave".to_owned()],
        ),
        (
            "revoked root",
            &[format!(
                "a revoked root is still on this machine; to delete it: swoosh revoke root:{root}"
            )],
        ),
        (
            "damaged",
            &[format!(
                "root: this machine's records disagree ({} is not one root key): swoosh cannot tell \
                 which root it trusts. A root kept on this machine stays. To start over: swoosh leave",
                home("damaged").root_pub().display()
            )],
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
