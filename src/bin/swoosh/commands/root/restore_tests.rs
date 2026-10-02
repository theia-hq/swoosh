//! `swoosh root restore <dir>`: a root put back on a machine where none is kept, brought up to date by your
//! devices, and taken off again when they say this machine's key is revoked.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use clap::Parser as _;
use keystore::{KeyFile, Passphrase, Protection};
use nauthy::VerifyKey;
use swoosh::home::Home;
use swoosh::roster::RosterDoc;
use swoosh::standing::Standing;
use swoosh::sync::Dial;
use swoosh::testkit::{Answering, Counting, Loopback, TestNode, TestRoot};
use zeroize::Zeroizing;

use super::RestoreCmd;
use crate::Cli;
use crate::commands::invite::invite_tests::{
    LAPTOP, OWN, PASS, ROOT, copy, device_of, holds, key, lapsed, live, node, records, revoked,
    scratch, standing,
};

/// Another machine's key: one that was never a device of the root.
const SPARE: u8 = 0x61;

/// The root's key.
fn root() -> bifrost::NodeId {
    TestRoot::seeded(ROOT).node_id()
}

/// A copy of `ROOT` holding `list`, beside `home`.
fn stick(home: &Home, list: &RosterDoc) -> PathBuf {
    let dir = home.dir().with_extension("stick");
    let _ = std::fs::remove_dir_all(&dir);
    copy(&dir, list);
    dir
}

/// A device `seed` of `ROOT` beside `home`, holding `list`, with a live standing.
async fn sibling(home: &Home, seed: u8, list: &RosterDoc) -> Home {
    let dir = home.dir().with_extension(format!("device-{seed}"));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let device = Home::resolve(Some(dir)).unwrap();
    swoosh::identity::make_machine_dir(&device).unwrap();
    let mut secret = TestNode::seeded(seed).seed();
    KeyFile::device(device.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    swoosh::config::write_signet(&swoosh::testkit::lock(), &device, root()).unwrap();
    let until = crate::commands::invite::invite_tests::now() + 80 * 24 * 60 * 60;
    swoosh::config::write_badge(&swoosh::testkit::lock(), &device, &standing(seed, until)).unwrap();
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&device).await.unwrap(),
        &device,
        &TestRoot::seeded(ROOT).sign_update(list),
    )
    .await
    .unwrap();
    device
}

/// A fresh home whose own key is the one seeded `seed`.
fn machine(tag: &str, seed: u8) -> Home {
    let home = scratch(tag);
    std::fs::remove_file(home.key()).unwrap();
    let mut secret = TestNode::seeded(seed).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    home
}

/// Restore `dir` on `home`, exchanging through `dial`: the result, and stderr.
async fn restore(home: &Home, dir: &Path, dial: &impl Dial) -> (eyre::Result<()>, String) {
    let mut err = Vec::new();
    let result = match (RestoreCmd {
        dir: dir.to_path_buf(),
    })
    .restore(home, &mut Counting::new([PASS]))
    .await
    {
        Ok(sync) => sync.finish(home, dial, &mut err).await,
        Err(refused) => Err(refused),
    };
    (result, String::from_utf8(err).unwrap())
}

/// The list this home holds.
fn held(home: &Home) -> RosterDoc {
    swoosh::roster::held(home, TestRoot::seeded(ROOT).verify_key()).unwrap()
}

/// The row the list held here has for `key`.
fn row_for(home: &Home, key: VerifyKey) -> Option<swoosh::roster::Member> {
    held(home)
        .members()
        .iter()
        .find(|member| member.node == key)
        .cloned()
}

fn own_key(home: &Home) -> bifrost::NodeId {
    swoosh::testkit::stored_key(&KeyFile::device(home.key()))
}

/// `--replace-key` is gone: a lost machine is replaced, not restored. Red when the flag is kept.
#[test]
fn restore_takes_no_replace_key_flag() {
    let refused = Cli::try_parse_from(["swoosh", "root", "restore", "/tmp/copy", "--replace-key"])
        .unwrap_err();
    assert_eq!(refused.exit_code(), 2, "{refused}");
}

/// A machine that was never a device restores with its own key: kept when it has one, made when it has
/// none, and never one from the copy. Red when an old key is put back.
#[tokio::test]
async fn restore_on_a_new_machine_keeps_its_own_key() {
    let list = records(1, &[live(LAPTOP, "laptop")], Vec::new());
    let home = machine("restore-own-key", SPARE);
    let dir = stick(&home, &list);
    let (result, err) = restore(&home, &dir, &Answering::nobody()).await;
    result.unwrap();
    assert_eq!(own_key(&home), node(SPARE), "its own key, unchanged");
    assert!(
        row_for(&home, key(SPARE)).is_some(),
        "a row for its own key"
    );
    assert!(
        matches!(Standing::read(&home).await.unwrap(), Standing::HoldsRoot { pin, .. } if pin == root())
    );
    assert!(
        err.contains(
            "a copy of your root, locked with its passphrase, is wherever the lost copy is."
        ),
        "{err}"
    );

    // With no key at all: one is made, and it is no key from the copy.
    let home = machine("restore-no-key", SPARE);
    std::fs::remove_file(home.key()).unwrap();
    let dir = stick(&home, &list);
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();
    let made = own_key(&home);
    assert_ne!(made, node(LAPTOP));
    assert_ne!(made, root());
}

/// A machine keeping another root names the two steps that take it off first. Red when it names
/// `move-root`.
#[tokio::test]
async fn restore_on_a_machine_keeping_another_root_names_backup_then_forget() {
    let home = scratch("restore-keeps-another");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    // A copy of another root.
    let dir = home.dir().with_extension("other");
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let mut seed = TestRoot::seeded(0x31).seed();
    let passphrase = Passphrase::try_from(Zeroizing::new(PASS.to_owned())).unwrap();
    KeyFile::root(dir.join("root.key"))
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .unwrap();
    let (result, _) = restore(&home, &dir, &Answering::nobody()).await;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "your root is on this machine: swoosh root backup <dir>, then swoosh root forget <dir>"
    );

    // And this same root, already kept here.
    let dir = stick(&home, &records(1, &[live(OWN, "desk")], Vec::new()));
    let (result, _) = restore(&home, &dir, &Answering::nobody()).await;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "your root is already on this machine."
    );
}

/// A copy whose list revokes this machine's key is refused before the passphrase. Red when the check is
/// skipped.
#[tokio::test]
async fn restore_refuses_a_revoked_own_key() {
    let home = scratch("restore-revoked-own");
    let dir = stick(
        &home,
        &records(
            1,
            &[live(LAPTOP, "laptop"), revoked(OWN, "desk")],
            Vec::new(),
        ),
    );
    let mut prompt = Counting::refusing();
    let refused = RestoreCmd { dir }
        .restore(&home, &mut prompt)
        .await
        .expect_err("refused");
    assert_eq!(
        format!("{refused:#}"),
        "this machine's key was revoked: swoosh leave --new-key first"
    );
    assert_eq!(prompt.events(), 0);
    assert!(!home.root_key().exists());
}

/// A lapsed row for this machine is renewed in place: one row, a new date. Red when a second row is added.
#[tokio::test]
async fn restore_renews_a_lapsed_own_row_instead_of_adding_one() {
    let home = scratch("restore-lapsed-own");
    let dir = stick(
        &home,
        &records(
            1,
            &[lapsed(OWN, "desk"), live(LAPTOP, "laptop")],
            Vec::new(),
        ),
    );
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();
    let list = held(&home);
    let own: Vec<_> = list
        .members()
        .iter()
        .filter(|member| member.node == key(OWN))
        .collect();
    assert_eq!(own.len(), 1, "one row for this machine");
    assert!(own[0].until > crate::commands::invite::invite_tests::now());
    assert_eq!(own[0].label.as_str(), "desk");
}

/// When your devices say this machine's key was revoked after the copy was made, the root's files go again,
/// the pin last, and the restore refuses: no root is left kept beside a revoked standing. Red when it keeps
/// the root.
#[tokio::test]
async fn restore_on_a_machine_revoked_after_the_copy_stops_before_commit() {
    let home = scratch("restore-revoked-later");
    let copied = records(1, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new());
    let dir = stick(&home, &copied);
    let later = records(
        2,
        &[live(LAPTOP, "laptop"), revoked(OWN, "desk")],
        Vec::new(),
    );
    let laptop = sibling(&home, LAPTOP, &later).await;
    let dial = Loopback::new(home.clone(), [(node(LAPTOP), laptop)]);
    let (result, _) = restore(&home, &dir, &dial).await;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "this machine's key was revoked: swoosh leave --new-key first"
    );
    assert!(!home.root_key().exists());
    assert!(!home.key_cert().exists());
    assert!(!home.root_pub().exists());
}

/// A copy that cannot be written restores: restore never writes its source. Red when it probes for write.
#[tokio::test]
async fn restore_from_a_read_only_copy() {
    let home = scratch("restore-read-only");
    let dir = stick(&home, &records(1, &[live(OWN, "desk")], Vec::new()));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (result, _) = restore(&home, &dir, &Answering::nobody()).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    result.unwrap();
    assert!(home.root_key().exists());
}

/// A restore stopped after `root.key` and before its pin is finished by running it again. Red when that
/// home is left as it is, or refused as keeping another root.
#[tokio::test]
async fn a_restore_killed_before_its_pin_is_finished_by_running_it_again() {
    let home = scratch("restore-killed");
    let list = records(1, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new());
    let dir = stick(&home, &list);
    // What a restore killed after its first write leaves: the key, and no pin.
    std::fs::copy(dir.join("root.key"), home.root_key()).unwrap();
    assert!(matches!(
        Standing::read(&home).await.unwrap(),
        Standing::InterruptedMint { .. }
    ));
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();
    assert!(
        matches!(Standing::read(&home).await.unwrap(), Standing::HoldsRoot { pin, .. } if pin == root())
    );
}

/// A restored copy is brought forward from your devices, and the next act cuts above them. Red when the
/// stale copy's number is cut from.
#[tokio::test]
async fn a_restored_backup_is_brought_forward_and_cuts_above_the_fleet() {
    let home = scratch("restore-forward");
    let rows = [live(OWN, "desk"), live(LAPTOP, "laptop")];
    let dir = stick(&home, &records(1, &rows, Vec::new()));
    let fleet = records(3, &rows, Vec::new());
    let laptop = sibling(&home, LAPTOP, &fleet).await;
    let dial = Loopback::new(home.clone(), [(node(LAPTOP), laptop.clone())]);
    let (result, err) = restore(&home, &dir, &dial).await;
    result.unwrap();
    assert!(err.contains("brought up to date from me/laptop."), "{err}");
    assert_eq!(held(&home).epoch(), swoosh::roster::Epoch(3));

    let mut root = swoosh::root::Root::present_to(
        &home,
        swoosh::root::RootPlace::Home,
        swoosh::root::RootVerb::Revoke,
        &mut Counting::new([PASS]),
        &dial,
        &mut Vec::new(),
    )
    .await
    .unwrap();
    root.revoke_device(&"laptop".parse().unwrap(), key(LAPTOP), &[])
        .unwrap();
    let committed = root.commit_to(&mut Vec::new()).await.unwrap();
    assert_eq!(
        committed.number,
        swoosh::roster::Epoch(4),
        "above the fleet"
    );
}

/// A restore renews no device but this machine, so one revoked after the copy was made is never brought
/// back. Red when the restore renews or keeps it.
#[tokio::test]
async fn a_restored_backup_never_renews_a_device_revoked_after_it() {
    let home = scratch("restore-no-revived");
    let copied = records(
        1,
        &[
            live(OWN, "desk"),
            lapsed(LAPTOP, "laptop"),
            live(0x43, "nas"),
        ],
        Vec::new(),
    );
    let dir = stick(&home, &copied);
    let later = records(
        2,
        &[
            live(OWN, "desk"),
            revoked(LAPTOP, "laptop"),
            live(0x43, "nas"),
        ],
        Vec::new(),
    );
    let nas = sibling(&home, 0x43, &later).await;
    let dial = Loopback::new(home.clone(), [(node(0x43), nas)]);
    restore(&home, &dir, &dial).await.0.unwrap();
    let list = held(&home);
    assert!(list.is_revoked_key(&key(LAPTOP)));
    assert!(row_for(&home, key(LAPTOP)).is_none(), "not renewed");
}

/// On a spare machine, the exchange asks the devices the copy lists. Red when it has no one to ask.
#[tokio::test]
async fn restore_on_a_spare_machine_syncs_from_the_devices_in_the_copy() {
    let home = machine("restore-spare", SPARE);
    let list = records(1, &[live(LAPTOP, "laptop")], Vec::new());
    let dir = stick(&home, &list);
    let laptop = sibling(&home, LAPTOP, &list).await;
    let dial = Loopback::new(home.clone(), [(node(LAPTOP), laptop)]);
    let (result, err) = restore(&home, &dir, &dial).await;
    result.unwrap();
    assert_eq!(dial.dialed().first(), Some(&node(LAPTOP)));
    assert!(
        err.starts_with(&format!(
            "restored root:{}, your root, on this machine; brought up to date from me/laptop.\n",
            swoosh::credential::short(&root())
        )),
        "{err}"
    );
}

/// A restore renews nothing but this machine's own row: a device due to renew is left as it is. Red when the
/// restore renews in its commit.
#[tokio::test]
async fn restore_renews_nothing() {
    let home = scratch("restore-renews-nothing");
    let due = crate::commands::invite::invite_tests::due(LAPTOP, "laptop");
    let dir = stick(
        &home,
        &records(1, &[live(OWN, "desk"), due.clone()], Vec::new()),
    );
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();
    assert_eq!(row_for(&home, key(LAPTOP)).unwrap().until, due.until);
}

/// With nobody answering and this machine's row live in the copy, nothing is cut or offered: the list here
/// is the copy's, byte for byte. Red when it cuts anyway.
#[tokio::test]
async fn restore_with_no_answer_publishes_nothing() {
    let home = scratch("restore-silent");
    // A device of the root: it gets back the root it was a device of.
    device_of(&home, &live(OWN, "desk")).await;
    let dir = stick(
        &home,
        &records(1, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new()),
    );
    let dial = Answering::nobody();
    let (result, err) = restore(&home, &dir, &dial).await;
    result.unwrap();
    assert_eq!(
        std::fs::read(home.devices()).unwrap(),
        std::fs::read(dir.join("devices")).unwrap(),
        "nothing cut"
    );
    assert!(
        err.starts_with(&format!(
            "restored root:{}, your root, on this machine. No device answered: your other devices learn of \
             this machine the next time you use your root.\n",
            swoosh::credential::short(&root())
        )),
        "{err}"
    );
    assert!(
        !err.contains("wherever the lost copy is"),
        "a device of the root was restored: {err}"
    );
}

/// A row the restore made, with nobody answering, goes out with the next act that cuts. Red when that act
/// cuts only its own change.
#[tokio::test]
async fn a_pending_restore_row_is_published_by_the_next_cutting_act() {
    let home = machine("restore-pending", SPARE);
    let list = records(1, &[live(LAPTOP, "laptop")], Vec::new());
    let dir = stick(&home, &list);
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();

    let laptop = sibling(&home, LAPTOP, &list).await;
    let dial = Loopback::new(home.clone(), [(node(LAPTOP), laptop.clone())]);
    let mut root = swoosh::root::Root::present_to(
        &home,
        swoosh::root::RootPlace::Home,
        swoosh::root::RootVerb::Invite,
        &mut Counting::new([PASS]),
        &dial,
        &mut Vec::new(),
    )
    .await
    .unwrap();
    root.sign_standing(
        TestNode::seeded(0x44).verify_key(),
        "tv".parse().unwrap(),
        core::time::Duration::from_secs(30 * 24 * 60 * 60),
    )
    .unwrap();
    let committed = root.commit_to(&mut Vec::new()).await.unwrap();
    let _ = committed.offer(&dial).await;
    let theirs = swoosh::roster::held(&laptop, TestRoot::seeded(ROOT).verify_key())
        .expect("me/laptop holds it");
    assert!(
        theirs
            .members()
            .iter()
            .any(|member| member.node == key(SPARE)),
        "the restored machine's row reached me/laptop"
    );
}

/// A machine that is a device of another root names `leave`. Red when it goes on.
#[tokio::test]
async fn restore_on_a_device_of_another_root_names_leave() {
    let home = scratch("restore-other-device");
    device_of(&home, &live(OWN, "desk")).await;
    // A copy of another root.
    let dir = home.dir().with_extension("other");
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let other = TestRoot::seeded(0x31);
    let mut seed = other.seed();
    let passphrase = Passphrase::try_from(Zeroizing::new(PASS.to_owned())).unwrap();
    KeyFile::root(dir.join("root.key"))
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .unwrap();
    let (result, _) = restore(&home, &dir, &Answering::nobody()).await;
    let refusal = format!("{:#}", result.unwrap_err());
    assert!(
        refusal.ends_with("to start over: swoosh leave"),
        "{refusal}"
    );
}
