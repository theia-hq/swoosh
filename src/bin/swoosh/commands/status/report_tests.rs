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
use swoosh::serve::{Internet, Lan, Reachable};
use swoosh::standing::Standing;
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};
use zeroize::Zeroizing;

use super::{Print, run_to, unix_now};
use crate::screen::law::Rule;

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

/// The report `status` prints on stdout for `home`, its stdout and stderr held to the screen law.
async fn status(home: &Home) -> String {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    run_to(home, Print::Report, &mut out, &mut err)
        .await
        .expect("status reads the home");
    held(&String::from_utf8(err).expect("the notices are text"));
    held(&String::from_utf8(out).expect("the report is text")).to_owned()
}

/// Lines `status` prints as another module words them for every command that prints them, and that break
/// the screen law: who words each, how it starts, and the rule it breaks. [`held`] holds every other line,
/// and holds each of these to breaking exactly its rule, so a change to one goes red here: fixed, it no
/// longer breaks, and reworded, it no longer matches. [`every_unheld_line_still_breaks`] fails when one is
/// no longer printed. The first match wins.
const UNHELD: [(&str, &str, Rule); 4] = [
    // `standing`'s line for a torn root key runs past 80.
    (
        "standing",
        "this machine's records disagree (root.key is not a root key); swoosh cannot tell which root it \
         trusts",
        Rule::Width,
    ),
    // `standing`'s line for any other disagreement is two sentences, then its command.
    (
        "standing",
        "this machine's records disagree (",
        Rule::TwoSentences,
    ),
    // `touch`'s line for a dead Touch ID lock beside a passphrase runs past 80.
    (
        "touch",
        "check Touch ID & Password for a fingerprint you did not add, then set Touch ID again: swoosh ",
        Rule::Width,
    ),
    // A `serve.toml` that cannot be used is named on stderr by its whole path, then why.
    ("serve_toml", "/serve.toml", Rule::Width),
];

/// The [`UNHELD`] entry `line` is, by its start (a path for a `serve.toml` notice, which leads with one).
fn unheld(line: &str) -> Option<&'static (&'static str, &'static str, Rule)> {
    UNHELD.iter().find(|(_, start, _)| {
        line.starts_with(start) || (start.starts_with('/') && line.contains(start))
    })
}

/// `line` with a `serve.toml` notice's home, the temp directory a runner chose, put in a fixed 64-column
/// stand-in, so the rule it breaks is the same on every runner: a notice that names a home of that length
/// runs past 80 by its path alone. Any other line as it is.
fn runner_free(line: &str) -> String {
    match line.split_once("/serve.toml") {
        Some((_, rest)) => format!("/{}/serve.toml{rest}", "h".repeat(52)),
        None => line.to_owned(),
    }
}

/// Hold `captured`, what `status` printed on one stream, to the screen law: each line [`UNHELD`] names to
/// breaking its rule, and the rest together; give it back as it was.
fn held(captured: &str) -> &str {
    let mut rest = String::new();
    for line in captured.lines() {
        match unheld(line) {
            Some((owner, _, rule)) => match crate::screen::law::read(&runner_free(line)) {
                Err(breach) if breach.rule == *rule => {}
                held => {
                    panic!("{owner}'s {line:?} no longer breaks {rule:?} ({held:?}): fix UNHELD")
                }
            },
            None => {
                rest.push_str(line);
                rest.push('\n');
            }
        }
    }
    if let Err(breach) = crate::screen::law::holds(&rest) {
        panic!("{breach}\n{captured}");
    }
    captured
}

/// A row of a head block, `label` and its value at column 17, as `status` prints it.
fn head_row(label: &str, value: &str) -> String {
    format!("  {label:<13}  {value}")
}

/// A device with no recorded list reports the default when no resident runs.
#[tokio::test]
async fn status_with_no_node_prints_the_default() {
    let home = home("serving");
    device_of(&home).await;
    let out = status(&home).await;
    assert!(
        out.lines()
            .any(|line| line == head_row("serving", "ping, speed, when swoosh serve runs")),
        "the serving row is printed with nothing running: {out}"
    );
}

/// While a `serve --admit` runs here, the `serving` row names the root it admits: past 80 beside the label,
/// so the row stacks, wrapped between its words and never inside the key.
#[tokio::test]
async fn status_names_the_root_a_running_serve_admits() {
    let home = home("admitting");
    let root = TestRoot::seeded(ROOT).node_id();
    let running = LocalResident::start(&home, &["ping", "speed"], Some(root));
    let out = status(&home).await;
    assert!(
        out.contains(&format!(
            "\n  serving\n    ping, speed, admitting\n    root:{root}\n"
        )),
        "{out}"
    );
    drop(running);
    let out = status(&home).await;
    assert!(
        out.lines()
            .any(|line| line == head_row("serving", "ping, speed, when swoosh serve runs")),
        "once it stops, a non-device still reports the default: {out}"
    );
}

/// While `devices.conflict` holds an update, the warning prints and names `revoke --help`; with it empty or
/// gone, it does not.
#[tokio::test]
async fn status_warns_while_two_copies_disagree() {
    let home = home("fork");
    device_of(&home).await;
    let warning = "Two copies of your root have been used: your devices hold two different lists.\n\
                   Keep one copy; the next time you use it, it settles this.\n\
                   If you did not use two copies, your root may be stolen:\n  \
                   swoosh revoke --help\n";
    assert!(!status(&home).await.contains("copies"));

    std::fs::write(home.devices_conflict(), b"").expect("an empty fork file");
    assert!(
        !status(&home).await.contains("copies"),
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
        out.ends_with(&format!("\n\n{warning}")),
        "the warning prints, its own block, while two copies disagree: {out}"
    );
}

/// No standing prints a `revocations` line: a revoked device stays a row under `devices` instead.
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
            "your root        on this machine\n{}\n",
            head_row("key", &format!("root:{}", TestRoot::seeded(ROOT).node_id()))
        )),
        "{out}"
    );
    let out = status(&device).await;
    assert!(
        out.contains(&format!(
            "\n\ndevices (as of the last sync, {})\n",
            swoosh::sync::ago(&device)
        )),
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
        assert!(
            !lines.iter().any(|line| line.starts_with("your root")),
            "{out}"
        );
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
    assert_eq!(
        out.matches("key came in its invite").count(),
        1,
        "one device is warned for: {out}"
    );
    let warned = format!(
        "\n\nme/ci's key came in its invite, which ends on {}.\n\
         If it starts from that invite each time (a CI job, for example), run:\n  \
         swoosh invite ci --new-key\n\
         Then set its secret again.\n",
        Date(now + 10 * DAY)
    );
    assert!(out.ends_with(&warned), "{out}");
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
    assert_eq!(out.matches("Renew me/").count(), 1, "{out}");
    let due = format!(
        "\n\nRenew me/nas by {}:\n  swoosh invite nas\n",
        Date(now - 25 * DAY)
    );
    assert!(out.ends_with(&due), "{out}");
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
    let due = format!(
        "\n\nRenew me/laptop by {}:\n  swoosh invite laptop --root <dir>\n",
        Date(until - 45 * DAY)
    );
    assert!(out.contains(&due), "{out}");
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

/// `home`'s directory as its `home` row prints it, escaped: beside the label where it fits 80, else on the
/// line below at indent four, since a path never splits.
fn home_line(home: &Home) -> String {
    let dir = swoosh::escape::EscapedPath(home.dir()).to_string();
    if 17 + dir.chars().count() <= 80 {
        head_row("home", &dir)
    } else {
        format!("  home\n    {dir}")
    }
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

/// `status` names no path inside the home but on its `home` row: in every state, no other line holds the
/// home's directory.
#[tokio::test]
async fn status_prints_no_path_in_the_home_but_home() {
    for (state, home) in every_state().await {
        let dir = home.dir().display().to_string();
        let out = status(&home).await;
        let row = home_line(&home);
        let named = out.replace(&row, "").matches(&dir).count();
        assert_eq!(named, 0, "the {state} home names its path: {out}");
    }
}

/// `home` is the `this machine` block's last row on every home, whatever else the block holds. Red when it
/// is dropped or moved.
#[tokio::test]
async fn home_row_is_last_and_always() {
    for (state, home) in every_state().await {
        let out = status(&home).await;
        let head = out.split("\n\n").next().unwrap_or_default().trim_end();
        assert!(
            head.starts_with("this machine") && head.ends_with(&home_line(&home)),
            "the {state} home's head block ends with its home row: {out}"
        );
        assert_eq!(out.matches(&home_line(&home)).count(), 1, "{out}");
    }
}

/// A home with no key says `none yet` on its `key` row and makes none: no `machine/` appears.
#[tokio::test]
async fn status_on_a_home_with_no_key_makes_none() {
    let home = keyless("no-key-made");
    let out = status(&home).await;
    assert_eq!(
        out.lines().nth(1),
        Some(head_row("key", "none yet").as_str()),
        "{out}"
    );
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

/// Under the `this machine` title come the `key` row and the `lock` row naming the method, on every home
/// with a key.
#[tokio::test]
async fn status_prints_key_then_its_lock() {
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
    let own = TestNode::seeded(OWN).node_id().to_string();
    for (home, lock) in [(&plain, "none"), (&sealed, "passphrase")] {
        let out = status(home).await;
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[1..3],
            [head_row("key", &own), head_row("lock", lock)],
            "{out}"
        );
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
            "this machine     me/desk".to_owned(),
            head_row("key", &own.to_string()),
            head_row("lock", "none"),
            head_row("serving", "ping, speed, when swoosh serve runs"),
            home_line(keeps),
            String::new(),
            "your root        on this machine".to_owned(),
            head_row("key", &format!("root:{root}")),
            head_row("lock", "passphrase"),
            String::new(),
            "devices".to_owned(),
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
            String::new(),
            format!("Renew me/nas by {}:", Date(now - 25 * DAY)),
            "  swoosh invite nas".to_owned(),
        ]
        .map(|line| line + "\n")
        .concat()
    );

    let device = home("device");
    assert_eq!(
        status(device).await,
        [
            "this machine     me/nas".to_owned(),
            head_row("key", &own.to_string()),
            head_row("lock", "none"),
            head_row("serving", "ping, speed, when swoosh serve runs"),
            home_line(device),
            String::new(),
            "your root        on another machine".to_owned(),
            head_row("key", &format!("root:{root}")),
            String::new(),
            format!(
                "devices (as of the last sync, {})",
                swoosh::sync::ago(device)
            ),
            format!("  me/nas   {}  this machine  until {until}", short_key(OWN)),
            format!(
                "  me/desk  {}                until {until}",
                short_key(LAPTOP)
            ),
        ]
        .map(|line| line + "\n")
        .concat()
    );

    let unpinned = home("unpinned");
    assert_eq!(
        status(unpinned).await,
        [
            "this machine     not one of your devices yet".to_owned(),
            head_row("key", &own.to_string()),
            head_row("lock", "none"),
            head_row("serving", "ping, speed, when swoosh serve runs"),
            home_line(unpinned),
            String::new(),
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
            "this machine     not one of your devices yet".to_owned(),
            head_row("key", "none yet"),
            home_line(keyless),
            String::new(),
            "to join yours, paste its invite into: swoosh join".to_owned(),
            "to make your root on this machine: swoosh invite <name> <key>".to_owned(),
        ]
        .map(|line| line + "\n")
        .concat()
    );

    let missing = "This machine's key is not in this home, because system backups leave it out.";
    // A torn `root.key` names no command: `leave` keeps the root, so it would print the same line again.
    let torn = "this machine's records disagree (root.key is not a root key); swoosh cannot \
                tell which root it trusts"
        .to_owned();
    let restored: [(&str, String); 4] = [
        (
            "restored",
            format!("{missing}\nTo start over:\n  swoosh leave\nThen:\n  swoosh join"),
        ),
        (
            "restored keeper",
            format!(
                "{missing}\nA root kept on this machine stays.\nTo start over:\n  swoosh leave\nThen:\n  \
                 swoosh invite <name> <key>"
            ),
        ),
        ("keyless torn root", torn.clone()),
        (
            "left keeper",
            "making your root did not finish; to finish it: swoosh invite <name> <key>".to_owned(),
        ),
    ];
    for (state, last) in restored {
        let restored = home(state);
        assert_eq!(
            status(restored).await,
            format!(
                "this machine\n{}\n{}\n\n{last}\n",
                head_row("key", "none yet"),
                home_line(restored)
            ),
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
    let last: [(&str, String); 11] = [
        (
            "conflict",
            "Two copies of your root have been used: your devices hold two different lists.\n\
             Keep one copy; the next time you use it, it settles this.\n\
             If you did not use two copies, your root may be stolen:\n  \
             swoosh revoke --help"
                .to_owned(),
        ),
        (
            "removed",
            "This machine is no longer one of your devices: your root revoked it.\nTo join again:\n  \
             swoosh leave --new-key\nThen:\n  swoosh join"
                .to_owned(),
        ),
        (
            "ended",
            format!(
                "me/desk ended on {ended}; your devices refuse it.\nWhere your root is kept:\n  swoosh \
                 invite desk\nThis machine picks up the renewal the next time it reaches one of your \
                 devices.\nTo pick it up now:\n  swoosh sync"
            ),
        ),
        (
            "mint",
            "making your root did not finish; to finish it: swoosh invite <name> <key>".to_owned(),
        ),
        (
            "join",
            "joining did not finish; to finish it: swoosh join".to_owned(),
        ),
        (
            "switch",
            "joining did not finish; to finish it: swoosh join".to_owned(),
        ),
        (
            "leave",
            "leaving did not finish; to finish it: swoosh leave".to_owned(),
        ),
        (
            "revoked root",
            format!(
                "A revoked root is still on this machine; to delete it:\n  swoosh revoke root:{}",
                TestRoot::seeded(ROOT).node_id()
            ),
        ),
        ("damaged", disagree("root.pub is not one root key")),
        ("torn root", torn),
        (
            "another root",
            disagree(&format!(
                "this machine keeps {}, and trusts {}",
                root_short(ROOT),
                root_short(OTHER)
            )),
        ),
    ];
    for (state, last) in last {
        let out = status(home(state)).await;
        assert!(
            out.ends_with(&format!("\n\n{last}\n")),
            "the {state} home ends with its own block: {out}"
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
    assert_eq!(
        out.lines().next(),
        Some(
            format!(
                "this machine     me/b, your device until {}",
                Date(STANDING_UNTIL)
            )
            .as_str()
        ),
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
    assert_eq!(
        out.lines().next(),
        Some(format!("this machine     me/b, ended {}", Date(now - DAY)).as_str()),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "\n\nThis machine ended on {}; your devices refuse it.\nWhere your root is kept:\n  swoosh \
             invite <name>\nThis machine picks up the renewal the next time it reaches one of your \
             devices.\nTo pick it up now:\n  swoosh sync\n",
            Date(now - DAY)
        )),
        "{out}"
    );
    assert!(!out.contains("invite b"), "{out}");

    std::fs::remove_file(home.invited_by()).expect("no invite to name it");
    let out = status(&home).await;
    assert_eq!(
        out.lines().next(),
        Some(
            format!(
                "this machine     {}, your device until {}",
                short_key(OWN),
                Date(STANDING_UNTIL)
            )
            .as_str()
        ),
        "{out}"
    );
}

/// The command a line gives, alone on it at indent two or after its last `: swoosh `, with each placeholder
/// filled the way a person fills it; `None` when the line gives none.
fn command(line: &str) -> Option<Vec<String>> {
    let command = match line.strip_prefix("  swoosh ") {
        Some(command) => command,
        None => line.rsplit_once(": swoosh ")?.1,
    };
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
    let out = super::Report::gather_with(home, key.as_ref(), unix_now(), &prompt)
        .await
        .unwrap()
        .render();
    held(&out).to_owned()
}

/// The `lock` row reads OR as OR: each lock set, and Touch ID with how it reads here, gives its one value, never a
/// comma list, an `and`, or `touch-id` in prose; and an unchecked lock never reads as dead. Red when any value
/// differs.
#[tokio::test]
async fn the_lock_row_reads_or_as_or() {
    let home = home("key-lock-touch-id");
    let alone: &[u8] = &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE;
    let both: &[u8] = &swoosh::testkit::touch_id::DEVICE_PASSPHRASE_AND_TOUCH_ID;
    let reading = |health| match health {
        Some(health) => swoosh::testkit::Counting::refusing().at_this_mac(health),
        None => swoosh::testkit::Counting::refusing(),
    };
    for (bytes, health, value) in [
        (
            alone,
            Some(keystore::Health::Live),
            "Touch ID, on this Mac only",
        ),
        (
            alone,
            Some(keystore::Health::Dead),
            "Touch ID (does not open on this Mac now)",
        ),
        (
            alone,
            Some(keystore::Health::Unchecked),
            "Touch ID (cannot be checked now)",
        ),
        (alone, None, "Touch ID (opens only on the Mac that set it)"),
        (
            both,
            Some(keystore::Health::Live),
            "Touch ID or a passphrase",
        ),
        (
            both,
            Some(keystore::Health::Dead),
            "Touch ID (does not open on this Mac now) or a passphrase",
        ),
        (
            both,
            Some(keystore::Health::Unchecked),
            "Touch ID (cannot be checked now) or a passphrase",
        ),
        (
            both,
            None,
            "Touch ID (opens only on the Mac that set it) or a passphrase",
        ),
    ] {
        overwrite(&home.key(), bytes);
        let key = KeyFile::new(home.key()).load().unwrap();
        let out = super::Report::gather_with(&home, key.as_ref(), unix_now(), &reading(health))
            .await
            .unwrap()
            .render();
        let out = held(&out);
        assert_eq!(
            out.lines().nth(2),
            Some(head_row("lock", value).as_str()),
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
            "Touch ID does not open this machine's key on this Mac now.\n\
             if you added a fingerprint, removing it lets Touch ID open the key again.\n\
             otherwise, give this machine a new key and join again: swoosh leave --new-key"
        ),
        "{out}"
    );
}

/// A dead Touch ID lock on this machine's key still prints the line that says how to mend it, alone or beside
/// a passphrase, below the `lock` row: the bare `lock` read points here for it. Red when the nag is dropped.
#[tokio::test]
async fn a_dead_key_lock_still_says_how_to_mend_it() {
    let home = home("key-lock-dead-nag");
    for (bytes, passphrase, value) in [
        (
            &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE[..],
            false,
            "Touch ID (does not open on this Mac now)",
        ),
        (
            &swoosh::testkit::touch_id::DEVICE_PASSPHRASE_AND_TOUCH_ID,
            true,
            "Touch ID (does not open on this Mac now) or a passphrase",
        ),
    ] {
        overwrite(&home.key(), bytes);
        let out = status_reading(&home, keystore::Health::Dead).await;
        let dead = swoosh::touch::Lines::of(
            swoosh::passphrase::Asked::MachineKey,
            &KeyFile::new(home.key()),
            passphrase,
        )
        .dead();
        assert_eq!(
            out.lines().nth(2),
            Some(head_row("lock", value).as_str()),
            "{out}"
        );
        assert!(out.contains(&format!("\n\n{dead}\n")), "{dead}\n{out}");
    }
}

/// A root whose header this read did not see is never claimed: `status` prints no `your root` block from
/// it, and the nag that says the root is here stays silent where whether it is cannot be
/// told. Red when either claims it.
#[tokio::test]
async fn an_unreadable_root_is_never_claimed() {
    let home = home("unreadable-root");
    holds(&home).await;
    let key = KeyFile::new(home.key()).load().unwrap();
    let prompt = swoosh::testkit::Counting::refusing();
    let mut report = super::Report::gather_with(&home, key.as_ref(), unix_now(), &prompt)
        .await
        .unwrap();
    assert!(report.your_root.is_some());
    // The header read failed, as a root changed between its two reads leaves it.
    report.root = None;
    report.your_root = None;
    let standing = Standing::read(&home).await.unwrap();
    report.standing(&home, standing, unix_now()).await.unwrap();
    let out = held(&report.render()).to_owned();
    assert!(
        !out.lines().any(|line| line.starts_with("your root")),
        "{out}"
    );

    overwrite(
        &home.key(),
        &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
    );
    std::fs::remove_file(home.root_key()).unwrap();
    // A link to itself: whether a root is there cannot be told.
    std::os::unix::fs::symlink(home.root_key(), home.root_key()).unwrap();
    assert!(home.keeps_root().is_err());
    assert!(!swoosh::identity::touch_id_alone_beside_root(&home));
}

/// The root's `lock` row reads OR as OR, Touch ID with how it reads, and a dead one says how to set it again,
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
    let dead_line = "Touch ID does not open your root on this Mac now.\n\
                     check Touch ID & Password for a fingerprint you did not add, then set Touch ID again: \
                     swoosh root lock touch-id";
    for (health, locks) in [
        (keystore::Health::Live, "Touch ID or a passphrase"),
        (
            keystore::Health::Dead,
            "Touch ID (does not open on this Mac now) or a passphrase",
        ),
        (
            keystore::Health::Unchecked,
            "Touch ID (cannot be checked now) or a passphrase",
        ),
    ] {
        let out = status_reading(&home, health).await;
        let block = format!(
            "\n\nyour root        on this machine\n{}\n{}\n\n",
            head_row("key", &format!("root:{root}")),
            head_row("lock", locks)
        );
        assert!(out.contains(&block), "{block}\n{out}");
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
    let out = held(&out);
    let lock = head_row(
        "lock",
        "Touch ID (opens only on the Mac that set it) or a passphrase",
    );
    assert_eq!(out.lines().nth(2), Some(lock.as_str()), "{out}");
    let root = TestRoot::seeded(ROOT).node_id();
    let block = format!(
        "\n\nyour root        on this machine\n{}\n{lock}\n",
        head_row("key", &format!("root:{root}"))
    );
    assert!(out.contains(&block), "{block}\n{out}");
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
        out.contains(swoosh::identity::TOUCH_ID_ALONE_BESIDE_ROOT),
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
/// A machine saved by hand says `one machine`, so its row and a person's differ by words as well as by the
/// key's shape. Red when the machine's row loses the word, or a root's row gains it.
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
            "one machine".to_owned(),
            String::new(),
        ],
        "a machine's row is its name, key and kind"
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
        let live = swoosh::serve_toml::LiveServeToml::load(home).unwrap();
        Self::with(home, names, admit, live)
    }

    /// A resident that started bare from the saved file, so its gate refuses a name later removed from it.
    fn bare(home: &Home, names: &[&str], admit: Option<bifrost::NodeId>) -> Self {
        let live = swoosh::serve_toml::LiveServeToml::load(home).unwrap();
        let file = swoosh::serve_toml::ServeToml::read(home).unwrap();
        live.serving(&swoosh::serve::Started::bare(&file).unwrap());
        Self::with(home, names, admit, live)
    }

    fn with(
        home: &Home,
        names: &[&str],
        admit: Option<bifrost::NodeId>,
        live: swoosh::serve_toml::LiveServeToml,
    ) -> Self {
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
            swoosh::testkit::loopback_source(),
            catalog(names),
            live,
            cancel.clone(),
            Arc::default(),
        ));
        let task =
            tokio::spawn(async move { resident.serve(listener, &swoosh::testkit::NoOpens).await });
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

/// The `serving` row's value: beside its label, or wrapped on the lines below it where the row stacks.
fn serving_row(out: &str) -> String {
    let mut lines = out
        .lines()
        .skip_while(|line| !line.starts_with("  serving"));
    let row = lines.next().unwrap();
    match row.strip_prefix("  serving        ") {
        Some(value) => value.to_owned(),
        None => lines
            .take_while(|line| line.starts_with("    "))
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" "),
    }
}

#[tokio::test]
async fn status_marks_a_listed_service_turned_off() {
    let home = home("listed-off");
    service_list(&home, &["ssh=sshd:", "web=tcp:localhost:3000"], &[]).await;
    // Saved order leads, and internal entries never print.
    let _resident = LocalResident::start(&home, &["control.stop", "web", "ssh"], None);
    assert_eq!(serving_row(&status(&home).await), "ssh, web");
    turn(&home, "web", crate::commands::service::toggle::Way::Off).await;
    let before = tree(home.dir());
    assert_eq!(serving_row(&status(&home).await), "ssh, web (off)");
    assert_eq!(tree(home.dir()), before, "the report must not write");
}

/// A saved name the serve did not bind is left out; a bound name the file no longer holds stays, with no claim
/// about why it is bound, and keeps an off mark the file still holds.
#[tokio::test]
async fn status_distinguishes_saved_only_from_bound_only() {
    use crate::commands::service::edit::{ServiceAddCmd, ServiceRmCmd};

    let home = home("added-removed");
    service_list(&home, &["ssh=sshd:", "web=tcp:localhost:3000"], &[]).await;
    let _resident = LocalResident::start(&home, &["ssh", "web", "control.stop"], None);
    ServiceAddCmd {
        entries: vec!["proxy:https://example.com".to_owned()],
    }
    .run(&home)
    .await
    .unwrap();
    ServiceRmCmd {
        names: vec![Some("web".parse().unwrap())],
    }
    .run(&home)
    .await
    .unwrap();
    assert_eq!(serving_row(&status(&home).await), "ssh, web");

    // Reusing the removed name with a new target still has the old bound route until restart.
    ServiceAddCmd {
        entries: vec!["web=tcp:localhost:9090".to_owned()],
    }
    .run(&home)
    .await
    .unwrap();
    assert_eq!(serving_row(&status(&home).await), "ssh, web");
    service_list(&home, &[], &["web"]).await;
    assert_eq!(serving_row(&status(&home).await), "ssh, web (off)");
}

/// The live row prints plain bound names, never a target or `name=`, never an internal route, and never
/// catalog text that is not a stored name.
#[tokio::test]
async fn status_names_do_not_imply_toggle_eligibility() {
    let home = home("bound-only");
    service_list(&home, &[], &[]).await;
    let _resident = LocalResident::start(
        &home,
        &["api", "control.stop", "lookup.root", "x\u{1b}[2J", "api"],
        None,
    );
    let out = status(&home).await;
    assert_eq!(serving_row(&out), "api");
    assert!(!out.contains('\u{1b}'), "{out:?}");
}

/// A bound name the serve refuses with no off mark reads apart from `(off)`, saved or not; the file's mark
/// wins where both hold; a bound name not refused prints plain. A gate that cannot read its file refuses all
/// it bound.
#[test]
fn status_tells_a_refusal_from_off() {
    use swoosh::serve::control_codec::DisabledList;

    use crate::commands::service_state::{ResidentObservation, ServiceState};

    let observed = |disabled| ServiceState {
        started: swoosh::serve::Started::Resumed(vec![
            "ssh=tcp:localhost:22".to_owned(),
            "web=tcp:localhost:3000".to_owned(),
        ]),
        off: ["ssh".to_owned()].into(),
        resident: ResidentObservation::Membership(Some((
            catalog(&["old", "ssh", "web"]),
            disabled,
            swoosh::testkit::loopback_reach(),
        ))),
    };
    let known = DisabledList::Known(vec!["old".to_owned(), "ssh".to_owned(), "web".to_owned()]);
    assert_eq!(
        super::serving(&observed(known)),
        "ssh (off), web (refusing new connections), old (refusing new connections)"
    );
    assert_eq!(
        super::serving(&observed(DisabledList::Known(vec!["web".to_owned()]))),
        "ssh (off), web (refusing new connections), old"
    );
    assert_eq!(
        super::serving(&observed(DisabledList::Known(vec![]))),
        "ssh (off), web, old"
    );
    assert_eq!(
        super::serving(&observed(DisabledList::Unknown("unreadable".to_owned()))),
        "ssh (off), web (refusing new connections), old (refusing new connections)"
    );
}

#[tokio::test]
async fn status_shows_what_a_bare_serve_starts_when_none_runs() {
    let home = home("down-listed");
    assert!(matches!(
        Standing::read(&home).await,
        Ok(Standing::Unpinned)
    ));
    service_list(&home, &["ssh=sshd:", "web=tcp:localhost:3000"], &["web"]).await;
    let before = tree(home.dir());
    assert_eq!(
        serving_row(&status(&home).await),
        "ssh, web (off), when swoosh serve runs"
    );
    assert_eq!(tree(home.dir()), before);
}

#[tokio::test]
async fn status_tells_the_default_from_an_emptied_list() {
    let home = home("default-empty");
    assert!(!home.serve_toml().exists());
    assert_eq!(
        serving_row(&status(&home).await),
        "ping, speed, when swoosh serve runs"
    );
    // A present file that has only off marks is still a never-named list.
    turn(&home, "ping", crate::commands::service::toggle::Way::Off).await;
    assert_eq!(
        serving_row(&status(&home).await),
        "ping (off), speed, when swoosh serve runs"
    );
    service_list(&home, &[], &[]).await;
    assert_eq!(
        serving_row(&status(&home).await),
        "nothing, even when swoosh serve runs"
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
            serving_row(held(&String::from_utf8(out).unwrap())),
            "unknown"
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
                    "{}: invalid saved service definition at index 2: service name already used\n",
                    home.serve_toml().display()
                )
            );
        }
        assert_eq!(tree(home.dir()), before);
    }
    overwrite(&home.serve_toml(), b"services = ['ssh=sshd:']\n");
    let _resident = LocalResident::start(&home, &["ssh"], None);
    overwrite(
        &home.serve_toml(),
        b"services = ['ssh=sshd:', 'ssh=sshd:']\n",
    );
    assert_eq!(serving_row(&status(&home).await), "unknown");
    drop(_resident);

    // A trusted-file opener refusal is not an absent file, nor a daemon-read failure.
    overwrite(&home.serve_toml(), b"services = ['ssh=sshd:']\n");
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
        serving_row(held(&String::from_utf8(out).unwrap())),
        "unknown"
    );
    let err = String::from_utf8(err).unwrap();
    assert!(err.contains("serve.toml"), "{err}");
    assert!(!err.contains("running swoosh serve"), "{err}");

    // A valid file beside a planted non-socket retains the existing, distinct daemon notice.
    overwrite(&home.serve_toml(), b"services = ['ssh=sshd:']\n");
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
        serving_row(held(&String::from_utf8(out).unwrap())),
        "unknown"
    );
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.starts_with("could not read the running swoosh serve.\n"),
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
    assert_eq!(serving_row(&out), "web (off), proxy (off)");
    for marked in serving_row(&out).split(", ") {
        let name = marked.strip_suffix(" (off)").unwrap();
        crate::Cli::try_parse_from(["swoosh", "service", "on", name]).unwrap();
        turn(&home, name, Way::On).await;
    }
    // `(off)` reads the file, but whether the serve still refuses a name is its own view of the file,
    // re-statted at most once per `STAT_DEBOUNCE`: having seen both off, it can refuse both for up to one
    // debounce after they are turned on, so the plain row shows within a few of them.
    let serving = "web, proxy";
    let mut row = String::new();
    for _ in 0..20 {
        row = serving_row(&status(&home).await).to_owned();
        if row == serving {
            break;
        }
        tokio::time::sleep(nauthy::STAT_DEBOUNCE).await;
    }
    assert_eq!(row, serving);
}

#[tokio::test]
async fn status_keeps_the_marks_when_admitting() {
    let home = home("admit-marks");
    service_list(&home, &["ssh=sshd:", "web=tcp:localhost:3000"], &["web"]).await;
    let root = TestRoot::seeded(ROOT).node_id();
    let _resident = LocalResident::bare(&home, &["ssh", "web"], Some(root));
    assert_eq!(
        serving_row(&status(&home).await),
        format!("ssh, web (off), admitting root:{root}")
    );
    // Emptying the file unbinds nothing, but a bare serve now refuses both: neither reads as plainly serving.
    service_list(&home, &[], &[]).await;
    let refused = format!(
        "ssh (refusing new connections), web (refusing new connections), admitting root:{root}"
    );
    // The serve re-stats the file at most once per `STAT_DEBOUNCE`, so the edit shows within a few of them.
    let mut row = String::new();
    for _ in 0..20 {
        row = serving_row(&status(&home).await).to_owned();
        if row == refused {
            break;
        }
        tokio::time::sleep(nauthy::STAT_DEBOUNCE).await;
    }
    assert_eq!(row, refused);
    overwrite(
        &home.serve_toml(),
        b"services = ['ssh=sshd:', 'ssh=sshd:']\n",
    );
    assert_eq!(
        serving_row(&status(&home).await),
        format!("unknown, admitting root:{root}")
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
    let error = ServingError::Mistyped(Mistyped(swoosh::serve::DefinitionError {
        operand: swoosh::serve::Operand::Saved,
        index: 2,
        cause: swoosh::serve::DefinitionCause::Collision,
    }));
    let expected = format!("{}: {error}", EscapedPath(&path));
    assert_eq!(
        super::serving_file_notice(&home, ReadError::List(error)),
        expected
    );
}

#[tokio::test]
async fn status_refuses_uncallable_names_before_intersecting_the_catalog() {
    use crate::commands::service_state::{ReadError, ReadMode, ServiceState};

    let home = home("uncallable-services");
    for reserved in swoosh::names::Reserved::ALL {
        let name = reserved.as_str();
        let entry = format!("{name}=ping:");
        service_list(&home, &["ssh=sshd:", &entry], &[]).await;
        let before = tree(home.dir());
        assert!(matches!(
            ServiceState::read(&home, ReadMode::Membership).await,
            Err(ReadError::List(swoosh::serve::ServingError::Definition(
                swoosh::serve::DefinitionError {
                    operand: swoosh::serve::Operand::Saved,
                    index: 2,
                    cause: swoosh::serve::DefinitionCause::Reserved(found),
                }
            ))) if found == reserved
        ));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        run_to(&home, Print::Report, &mut out, &mut err)
            .await
            .unwrap();
        assert_eq!(
            serving_row(held(&String::from_utf8(out).unwrap())),
            "unknown"
        );
        let err = String::from_utf8(err).unwrap();
        assert_eq!(err.matches("serve.toml").count(), 1, "{err}");
        assert!(
            err.contains(&home.serve_toml().display().to_string()),
            "{err}"
        );
        assert!(
            !err.contains(&entry)
                && err.contains(&format!(
                    "{name} is reserved; no service can have that name"
                )),
            "{err}"
        );
        assert_eq!(tree(home.dir()), before);

        service_list(&home, &["ssh=sshd:"], &[]).await;
        let resident = LocalResident::start(&home, &["ssh", "control.stop"], None);
        // The invalid entry is absent from the bound catalog, but the whole file still refuses, and a
        // serve whose list is unknown lists no internal route.
        service_list(&home, &["ssh=sshd:", &entry], &[]).await;
        let out = status(&home).await;
        assert_eq!(serving_row(&out), "unknown");
        assert!(!out.contains("internal routes"), "{out}");
        drop(resident);
    }
}

/// While a `serve` answers here, bare `status` lists every internal route in its own block: a blank line
/// after `reach`, the title, one row per route in the table's order with who reaches it and what it
/// does, then the lines that say what to do. With no `serve` running, the block is not there.
#[tokio::test]
async fn status_lists_internal_routes_while_serving() {
    const BLOCK: &str = "internal routes\n\
                         \x20 control.serve    your devices                  stops it, lists its services\n\
                         \x20 control.sync     your devices                  syncs your device list\n\
                         \x20 control.renewal  your devices                  renews your devices\n\
                         \x20 lookup.root      your devices, saved machines  says which root vouches for it\n";

    let home = home("internal-routes");
    device_of(&home).await;
    service_list(&home, &["ssh=sshd:"], &[]).await;
    let fork = RosterDoc::new(Epoch(3), Vec::new()).expect("an update");
    std::fs::write(
        home.devices_conflict(),
        TestRoot::seeded(ROOT).sign_update(&fork),
    )
    .expect("the fork");
    let idle = status(&home).await;
    assert!(!idle.contains("internal routes"), "{idle}");
    assert!(!idle.contains("control."), "{idle}");

    let resident = LocalResident::start(&home, &["ssh", "control.stop"], None);
    let out = status(&home).await;
    // The resident binds a dotted name, and it never joins the `serving` row: the block is where routes
    // print.
    assert_eq!(serving_row(&out), "ssh", "{out}");
    assert!(
        out.contains(&format!(
            "\n\nreach\n  internet       on\n  this computer  127.0.0.1:51006\n\n{BLOCK}\nTwo copies"
        )),
        "{out}"
    );
    assert_eq!(out.matches("internal routes").count(), 1, "{out}");
    assert!(
        BLOCK.lines().all(|line| line.chars().count() < 80),
        "every row fits 80 columns"
    );
    drop(resident);
    assert!(!status(&home).await.contains("internal routes"));
}

/// Every internal route has its words: a route added to the table with none fails here, before `status`
/// prints a row with an empty cell.
#[test]
fn every_internal_route_has_its_words() {
    for route in &swoosh::serve::control::INTERNAL {
        assert!(!super::what(route.name).is_empty(), "{}", route.name);
        assert!(!super::who(route.admits).is_empty(), "{}", route.name);
    }
}

/// A resident that answers one `status` with `reply`, serving `names`, then is gone: a `StatusReply` with
/// `reach`, or bytes that are no reply at all.
fn answer_once(home: &Home, reply: Option<(&[&str], Reachable)>) -> tokio::task::JoinHandle<()> {
    use std::os::unix::fs::PermissionsExt as _;

    use swoosh::serve::control_codec::{DisabledList, Request, Response, ServiceMenu, StatusReply};
    use tokio::io::AsyncWriteExt as _;

    let socket = home.control_socket().unwrap();
    let dir = socket.parent().unwrap();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(home.serve_lock(), std::process::id().to_string()).unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let bytes = reply.map(|(names, reach)| {
        Response::Status(StatusReply {
            node_id: TestNode::seeded(OWN).node_id(),
            pid: std::process::id(),
            reach,
            uptime_secs: 0,
            menu: ServiceMenu {
                catalog: catalog(names),
                disabled: DisabledList::Known(vec![]),
            },
            warm: vec![],
        })
    });
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            Request::read(&mut stream).await.unwrap(),
            Request::Status
        ));
        match bytes {
            Some(reply) => reply.write(&mut stream).await.unwrap(),
            None => stream.write_all(b"not a reply").await.unwrap(),
        }
        drop(stream);
        std::fs::remove_file(socket).unwrap();
    })
}

/// `status` on a home whose resident answers once with `reply`.
async fn status_answered(home: &Home, reply: Option<(&[&str], Reachable)>) -> String {
    let resident = answer_once(home, reply);
    let out = status(home).await;
    resident.await.unwrap();
    out
}

/// The `reach` rows of a screen: the lines under the title `title`, up to the blank line.
fn reach_rows<'s>(screen: &'s str, title: &str) -> Vec<&'s str> {
    screen
        .lines()
        .skip_while(|line| *line != title)
        .skip(1)
        .take_while(|line| !line.is_empty())
        .collect()
}

/// While a `serve` answers, `status` says how it is reached in a `reach` block after the head blocks and
/// before `internal routes`: every class, one row each, in class order, the loopback address beside a
/// network address too, with or without `--local`.
#[tokio::test]
async fn status_prints_reach_while_serving() {
    use crate::commands::serve::serve_tests::{LAN, LOOPBACK, PUBLIC, TUNNEL, host, reachable};

    let every = || host(&[LOOPBACK, TUNNEL, PUBLIC, LAN]);
    let local = home("reach-local");
    let out = status_answered(
        &local,
        Some((&["ssh"], reachable(Internet::Off, Lan::Announced, every()))),
    )
    .await;
    assert_eq!(serving_row(&out), "ssh", "{out}");
    assert!(
        out.contains(
            "\n\nreach\n\
             \x20 internet       off (--local)\n\
             \x20 public         [2001:db8:85a3::8a2e:370:7334]:51006\n\
             \x20 this network   192.168.1.20:51006\n\
             \x20 tunnel         100.101.102.103:51006\n\
             \x20 this computer  127.0.0.1:51006\n\
             \ninternal routes\n"
        ),
        "{out}"
    );
    let default = home("reach-default");
    let out = status_answered(
        &default,
        Some((
            &["ssh"],
            reachable(Internet::On, Lan::ByAddressOnly, every()),
        )),
    )
    .await;
    assert_eq!(serving_row(&out), "ssh", "{out}");
    assert!(
        out.contains(
            "\n\nreach\n\
             \x20 internet       on\n\
             \x20 public         [2001:db8:85a3::8a2e:370:7334]:51006\n\
             \x20 this network   192.168.1.20:51006, by address only\n\
             \x20 tunnel         100.101.102.103:51006\n\
             \x20 this computer  127.0.0.1:51006\n\
             \ninternal routes\n"
        ),
        "{out}"
    );
}

/// A home that does not serve prints no `reach` block: none when no `serve` runs, and none when one is
/// there and could not be read, which the `serving` row's `unknown` says instead.
#[tokio::test]
async fn no_resident_no_reach() {
    let home = home("no-reach");
    let idle = status(&home).await;
    assert!(!idle.lines().any(|line| line == "reach"), "{idle}");
    let out = status_answered(&home, None).await;
    assert_eq!(serving_row(&out), "unknown");
    assert!(!out.lines().any(|line| line == "reach"), "{out}");
}

/// `status` and the banner print the same rows for the same reach, each through its own path: the banner
/// through `banner`, and `status` through the status reply on the control socket, the read of it and the
/// report. Under `--local` they are the same rows; by default `status` adds only the public, tunnel and
/// loopback rows, and the rows both print read the same, in the same order.
#[tokio::test]
async fn status_and_the_banner_print_the_same_rows() {
    use crate::commands::serve::serve_tests::{banner_for, reach_fixtures};

    for (name, reach) in reach_fixtures() {
        let at = home("reach-same");
        let banner = banner_for(&reach);
        let out = status_answered(&at, Some((&["ping"], reach.clone()))).await;
        let (shown, listed) = (reach_rows(&banner, "reach"), reach_rows(&out, "reach"));
        assert!(!shown.is_empty(), "{name}: {banner}");
        if reach.internet == Internet::Off {
            // Every class, less the loopback row the banner keeps from beside `unknown`.
            let unknown = listed.contains(&"  this network   unknown");
            let kept: Vec<&str> = listed
                .iter()
                .copied()
                .filter(|line| !(unknown && line.starts_with("  this computer ")))
                .collect();
            assert_eq!(kept, shown, "{name}");
            continue;
        }
        let both: Vec<&str> = listed
            .iter()
            .copied()
            .filter(|line| shown.contains(line))
            .collect();
        assert_eq!(both, shown, "{name}: the banner's rows, in order:\n{out}");
        assert!(
            listed
                .iter()
                .filter(|line| !shown.contains(line))
                .all(|line| {
                    ["  public ", "  tunnel ", "  this computer "]
                        .iter()
                        .any(|label| line.starts_with(label))
                }),
            "{name}: {out}"
        );
    }
}

/// The name serve's banner and `status` both give this machine comes from a list: the root's where it is
/// kept, the last synced one on a device, a revoked row by the name it had. An invite's name, unsigned, never names it, and a machine no list
/// names has none.
#[tokio::test]
async fn own_name_reads_a_list_never_an_invite() {
    let own = TestNode::seeded(OWN).node_id();
    let name = |home| async move {
        super::own_name(home, own)
            .await
            .map(|name| name.to_string())
    };

    let keeps = home("own-name-holder");
    holds(&keeps).await;
    assert_eq!(name(&keeps).await.as_deref(), Some("desk"));

    let synced = home("own-name-device");
    device_of(&synced).await;
    list(
        &synced,
        &RosterDoc::new(Epoch(1), vec![row(OWN, "nas"), row(LAPTOP, "laptop")]).expect("a list"),
    );
    assert_eq!(name(&synced).await.as_deref(), Some("nas"));
    // A list that revoked this machine still names it, by the name it had, as `status` names it then.
    let revoked = home("own-name-revoked");
    device_of(&revoked).await;
    list(
        &revoked,
        &RosterDoc::with_revocations(
            Epoch(1),
            vec![row(LAPTOP, "laptop")],
            Vec::new(),
            vec![gone(OWN, "nas")],
        )
        .expect("a list"),
    );
    assert_eq!(name(&revoked).await.as_deref(), Some("nas"));

    let hinted = home("own-name-hint");
    device_of(&hinted).await;
    std::fs::write(
        hinted.invited_by(),
        format!("{}\nb\n", TestNode::seeded(LAPTOP).node_id()),
    )
    .expect("invited-by");
    assert_eq!(name(&hinted).await, None);

    assert_eq!(name(&home("own-name-fresh")).await, None);
}

/// The old record labels, each with its colon: no line of the report starts with one.
const RECORDS: [&str; 11] = [
    "key:",
    "key lock:",
    "lock:",
    "home:",
    "this machine:",
    "serving:",
    "devices:",
    "contacts:",
    "links you shared:",
    "reach:",
    "internal routes:",
];

/// A home with every block: its root kept here, a `serve` answering, a machine saved by hand, a link it
/// shared, and two copies of its root that disagree.
async fn every_block(tag: &str) -> Home {
    let home = home(tag);
    holds(&home).await;
    let mut store = swoosh::contacts::ContactsStore::open(&home).await.unwrap();
    store.contacts_mut().add(
        "bob".parse().unwrap(),
        None,
        TestNode::seeded(0x51).node_id(),
    );
    store
        .save(&swoosh::home::HomeWrite::take(&home).await.unwrap())
        .unwrap();
    swoosh::grants::Grants::at(home.links())
        .append(
            &swoosh::testkit::lock(),
            &GrantRecord {
                target: "ping".parse().expect("a service"),
                serves: None,
                kind: GrantKind::Bearer,
                delegation: Delegation::Sealed,
                holder: ANYONE.to_owned(),
                root_id: RevocationId::from_bytes(vec![7; 64]),
                expiry: SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
            },
        )
        .unwrap();
    std::fs::write(
        home.devices_conflict(),
        TestRoot::seeded(ROOT).sign_update(&RosterDoc::new(Epoch(3), Vec::new()).expect("a fork")),
    )
    .expect("the fork");
    home
}

/// The report reads as blocks in the ruled order, one blank line apart: `this machine`, `your root`,
/// `reach`, `internal routes`, `devices`, `contacts`, `links you shared`, then what to do; a block with
/// nothing in it drops out, and no line is a `label:` record. Red when a colon comes back, two blocks swap,
/// or an empty block prints its title.
#[tokio::test]
async fn status_reads_as_blocks_in_order() {
    let home = every_block("blocks-in-order").await;
    let _resident = LocalResident::start(&home, &["ping"], None);
    let out = status(&home).await;
    let titles: Vec<&str> = out
        .split("\n\n")
        .map(|block| block.lines().next().unwrap_or_default())
        .collect();
    assert_eq!(
        titles,
        [
            "this machine     me/desk",
            "your root        on this machine",
            "reach",
            "internal routes",
            "devices",
            "contacts",
            "links you shared",
            "Two copies of your root have been used: your devices hold two different lists.",
        ],
        "{out}"
    );
    assert!(!out.contains("\n\n\n"), "one blank line apart: {out}");
    assert!(
        out.contains(&format!(
            "\ncontacts\n  bob  {}  one machine\n",
            short_key(0x51)
        )),
        "{out}"
    );

    for (state, home) in every_state().await {
        let out = status(&home).await;
        for line in out.lines() {
            let body = line.trim_start();
            assert!(
                !RECORDS.iter().any(|label| body.starts_with(label)),
                "the {state} home prints a record line {line:?}: {out}"
            );
            assert!(
                !(body.starts_with("devices") && body.ends_with(':')),
                "{out}"
            );
        }
        for title in ["contacts", "links you shared", "reach", "internal routes"] {
            assert!(
                !out.lines().any(|line| line == title),
                "the {state} home prints an empty {title} block: {out}"
            );
        }
    }
}

/// `this machine` and `your root` start their values at column 17, the title row's and each row's alike,
/// where the labels fit. Red when a head block drifts.
#[tokio::test]
async fn head_blocks_share_column_17() {
    let home = every_block("column-17").await;
    let out = status(&home).await;
    let heads: Vec<&str> = out.split("\n\n").take(2).collect();
    let stacked = home_line(&home);
    // Two titles, `key`, `lock` and `serving`, the root's `key` and `lock`, and `home` where it fits.
    let rows = 7 + usize::from(!stacked.contains('\n'));
    let mut seen = 0;
    for line in heads.iter().flat_map(|block| block.lines()) {
        if stacked.contains('\n') && stacked.lines().any(|part| part == line) {
            continue;
        }
        assert_eq!(
            line.char_indices().nth(16).map(|(_, c)| c),
            Some(' '),
            "{out}"
        );
        assert!(
            line.chars().nth(17).is_some_and(|c| c != ' '),
            "{line:?} starts its value at 17: {out}"
        );
        seen += 1;
    }
    assert_eq!(seen, rows, "{out}");
}

/// Every screen `status` prints in every state, and on a home with every block, holds the screen law on
/// stdout and stderr, but for the lines [`UNHELD`] names. Red when a line breaks it.
#[tokio::test]
async fn every_status_screen_holds_the_law() {
    let home = every_block("law").await;
    let resident = LocalResident::start(&home, &["ping"], Some(TestRoot::seeded(ROOT).node_id()));
    let mut screens = vec![status(&home).await];
    drop(resident);
    for (_, home) in every_state().await {
        screens.push(status(&home).await);
    }
    for screen in &screens {
        // `status` holds each run already; this says so where a reader looks for it.
        held(screen);
    }
    assert!(
        screens
            .iter()
            .any(|screen| screen.contains("Two copies of your root")),
        "a nag is among the screens held"
    );
}

/// The ways forward a machine that is no device prints stay as they were, word for word, last on the
/// screen: they are another change's words. Red when this one rewrites them.
#[tokio::test]
async fn no_device_footer_untouched() {
    let footer = "\n\nto join yours, paste its invite into: swoosh join\n\
                  to make your root on this machine: swoosh invite <name> <key>\n";
    for home in [home("footer-unpinned"), keyless("footer-keyless")] {
        let out = status(&home).await;
        assert!(out.ends_with(footer), "{out}");
    }
}

/// The home's directory is escaped once on its `home` row: a quote and a backslash in it print as one
/// escape each, never an escape of an escape. Red when the row escapes the escaped path again.
#[tokio::test]
async fn the_home_row_escapes_its_path_once() {
    let home = keyless("quote\"back\\slash");
    let out = status(&home).await;
    let row = home_line(&home);
    assert!(row.contains("quote\\\"back\\\\slash"), "{row}");
    assert!(out.contains(&format!("{row}\n")), "{row}\n{out}");
}

/// Every line [`UNHELD`] names is still printed somewhere `status` runs, and breaks its rule there (held
/// checks the rule): the states with records that disagree, a dead Touch ID root, and a `serve.toml` that
/// cannot be read. Red when an entry is left behind by a line that is gone.
#[tokio::test]
async fn every_unheld_line_still_breaks() {
    let mut printed: Vec<String> = Vec::new();
    for (_, home) in every_state().await {
        printed.push(status(&home).await);
    }
    let root = home("unheld-touch");
    holds(&root).await;
    overwrite(
        &root.root_key(),
        &swoosh::testkit::touch_id::ROOT_PASSPHRASE_AND_TOUCH_ID,
    );
    printed.push(status_reading(&root, keystore::Health::Dead).await);
    let toml = home("unheld-toml");
    overwrite(&toml.serve_toml(), b"this is not TOML\n");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    run_to(&toml, Print::Report, &mut out, &mut err)
        .await
        .unwrap();
    printed.push(held(&String::from_utf8(err).unwrap()).to_owned());
    for (owner, start, _) in &UNHELD {
        let met = printed
            .iter()
            .flat_map(|screen| screen.lines())
            .any(|line| unheld(line).is_some_and(|(_, at, _)| at == start));
        assert!(met, "{owner}'s `{start}` is no longer printed: fix UNHELD");
    }
}
