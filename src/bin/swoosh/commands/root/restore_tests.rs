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

/// `swoosh root restore <dir>`, parsed as the command line gives it.
fn restore_cmd(dir: &Path) -> RestoreCmd {
    let cli = Cli::try_parse_from(["swoosh", "root", "restore", dir.to_str().unwrap()]).unwrap();
    match cli.command {
        Some(crate::Command::Root(crate::commands::root::RootCmd::Restore(cmd))) => cmd,
        other => panic!("not root restore: {other:?}"),
    }
}

/// Restore `dir` on `home`, exchanging through `dial`: the result, and stderr.
async fn restore(home: &Home, dir: &Path, dial: &impl Dial) -> (eyre::Result<()>, String) {
    restore_asking(home, dir, dial, &mut Counting::new([PASS])).await
}

/// [`restore`], answering the prompt from `prompt`.
async fn restore_asking(
    home: &Home,
    dir: &Path,
    dial: &impl Dial,
    prompt: &mut Counting,
) -> (eyre::Result<()>, String) {
    let mut err = Vec::new();
    let result = match restore_cmd(dir).restore(home, prompt).await {
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
    let other = swoosh::credential::short(&TestRoot::seeded(0x31).node_id());
    let short = swoosh::credential::short(&root());
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        format!(
            "this machine keeps root:{short}, and the copy in {} is root:{other}; to restore the copy here, \
             first remove root:{short} from this machine: swoosh root forget --help",
            dir.display()
        )
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
    let refused = restore_cmd(&dir)
        .restore(&home, &mut prompt)
        .await
        .expect_err("refused");
    assert_eq!(
        format!("{refused:#}"),
        "this machine's key was revoked; to restore here, first give this machine a new key: swoosh leave \
         --new-key"
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
        "this machine's key was revoked; to restore here, first give this machine a new key: swoosh leave \
         --new-key"
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
        dial.calls(),
        1,
        "the one exchange with me/laptop, and nothing offered"
    );
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
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        format!(
            "the copy in {} is root:{}, and this machine is a device of root:{}; to restore the copy here, \
             first leave root:{}: swoosh leave",
            dir.display(),
            swoosh::credential::short(&other.node_id()),
            swoosh::credential::short(&root()),
            swoosh::credential::short(&root())
        )
    );
}

/// The name this machine is given when a list has no row for it: the suggested name, the first time.
fn suggested() -> String {
    swoosh::names::suggest().as_str().to_owned()
}

/// Whether `key` is revoked anywhere `home` keeps revocations: its `revoked`, or the list it holds.
fn revoked_at(home: &Home, key: VerifyKey) -> bool {
    swoosh::revoked::open(home).unwrap().is_revoked_key(&key)
        || swoosh::roster::held(home, TestRoot::seeded(ROOT).verify_key())
            .is_some_and(|list| list.is_revoked_key(&key))
}

/// A device that answers above the restore's own cut replaced the list the restore wrote; the restore cuts
/// again on the newer list, with this machine's row, above the fleet, and offers it, under the one prompt.
/// Red when the fold's replacement is taken as final.
#[tokio::test]
async fn a_restore_answered_from_above_its_cut_carries_its_row_above_the_fleet() {
    let home = machine("restore-above", SPARE);
    let dir = stick(&home, &records(1, &[live(LAPTOP, "laptop")], Vec::new()));
    let laptop = sibling(
        &home,
        LAPTOP,
        &records(3, &[live(LAPTOP, "laptop")], Vec::new()),
    )
    .await;
    let dial = Loopback::new(home.clone(), [(node(LAPTOP), laptop.clone())]);
    let mut prompt = Counting::new([PASS]);
    let (result, _) = restore_asking(&home, &dir, &dial, &mut prompt).await;
    result.unwrap();
    assert_eq!(prompt.events(), 1, "no second prompt");
    let here = held(&home);
    assert_eq!(here.epoch(), swoosh::roster::Epoch(4));
    let row = row_for(&home, key(SPARE)).expect("this machine's row");
    assert!(row.until > crate::commands::invite::invite_tests::now());
    let theirs = swoosh::roster::held(&laptop, TestRoot::seeded(ROOT).verify_key()).unwrap();
    assert_eq!(
        theirs.epoch(),
        swoosh::roster::Epoch(4),
        "me/laptop took the cut"
    );
    assert!(
        theirs
            .members()
            .iter()
            .any(|member| member.node == key(SPARE))
    );
}

/// A no-answer restore's row, dropped when a newer list is folded here later (as `serve` would), is carried
/// by the next act that cuts. Red when the next act cuts from the folded list alone.
#[tokio::test]
async fn a_restore_row_dropped_by_a_later_fold_is_carried_by_the_next_cutting_act() {
    let home = machine("restore-dropped", SPARE);
    let dir = stick(&home, &records(1, &[live(LAPTOP, "laptop")], Vec::new()));
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();
    assert!(row_for(&home, key(SPARE)).is_some());

    let fleet = records(3, &[live(LAPTOP, "laptop")], Vec::new());
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&home).await.unwrap(),
        &home,
        &TestRoot::seeded(ROOT).sign_update(&fleet),
    )
    .await
    .unwrap();
    assert!(
        row_for(&home, key(SPARE)).is_none(),
        "the fold dropped the row"
    );

    let laptop = sibling(&home, LAPTOP, &fleet).await;
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
    assert_eq!(committed.number, swoosh::roster::Epoch(4));
    let _ = committed.offer(&dial).await;
    assert!(row_for(&home, key(SPARE)).is_some(), "carried by the cut");
    let theirs = swoosh::roster::held(&laptop, TestRoot::seeded(ROOT).verify_key()).unwrap();
    assert!(
        theirs
            .members()
            .iter()
            .any(|member| member.node == key(SPARE))
    );
}

/// A newer list that gave this machine's suggested name to another key: after the restore, this machine's
/// row has a name fresh against that list, and its key is revoked nowhere. Red when the restore's cut is
/// united with the newer list and the clash revokes this machine.
#[tokio::test]
async fn a_restored_row_whose_name_a_newer_list_took_gets_a_fresh_name() {
    let name = suggested();
    let home = machine("restore-name-taken", SPARE);
    let dir = stick(&home, &records(1, &[live(LAPTOP, "laptop")], Vec::new()));
    let fleet = records(3, &[live(LAPTOP, "laptop"), live(0x44, &name)], Vec::new());
    let laptop = sibling(&home, LAPTOP, &fleet).await;
    let dial = Loopback::new(home.clone(), [(node(LAPTOP), laptop.clone())]);
    restore(&home, &dir, &dial).await.0.unwrap();
    let row = row_for(&home, key(SPARE)).expect("this machine's row");
    assert_ne!(row.label.as_str(), name, "a fresh name");
    assert_eq!(
        row_for(&home, key(0x44)).unwrap().label.as_str(),
        name,
        "the other device keeps its name"
    );
    assert!(!revoked_at(&home, key(SPARE)));
    assert!(!revoked_at(&laptop, key(SPARE)));
}

/// A name clash in a list brought forward never revokes this machine's own key: the act's own sync folds a
/// list holding another key under this machine's name, and this machine's row takes a fresh one. Red when
/// the clash revokes the row's key, as it does any other device's.
#[tokio::test]
async fn a_name_clash_never_revokes_this_machines_own_key() {
    let name = suggested();
    let home = machine("restore-clash", SPARE);
    let dir = stick(&home, &records(1, &[live(LAPTOP, "laptop")], Vec::new()));
    // Nobody answers: the restore's own cut names this machine against the copy's list.
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();
    assert_eq!(row_for(&home, key(SPARE)).unwrap().label.as_str(), name);

    // The next act's sync brings a list that gave that name to another key.
    let fleet = records(3, &[live(LAPTOP, "laptop"), live(0x44, &name)], Vec::new());
    let laptop = sibling(&home, LAPTOP, &fleet).await;
    let dial = Loopback::new(home.clone(), [(node(LAPTOP), laptop.clone())]);
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
    let _ = committed.offer(&dial).await;
    let row = row_for(&home, key(SPARE)).expect("this machine keeps its row");
    assert_ne!(row.label.as_str(), name);
    assert!(!revoked_at(&home, key(SPARE)));
    assert!(!revoked_at(&laptop, key(SPARE)));
}

/// `root restore` takes the reach flags every dialing verb takes. Red when they are dropped.
#[test]
fn restore_takes_the_reach_flags() {
    let cli = Cli::try_parse_from(["swoosh", "root", "restore", "/tmp/copy", "--local"]).unwrap();
    match cli.command {
        Some(crate::Command::Root(crate::commands::root::RootCmd::Restore(cmd))) => {
            assert!(cmd.reach.local);
        }
        other => panic!("not root restore: {other:?}"),
    }
}

/// A prompt that runs `meanwhile` while the restore waits at it, then answers [`PASS`].
struct Meanwhile<F: FnMut()>(F);

impl<F: FnMut()> swoosh::passphrase::Prompt for Meanwhile<F> {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, _asked: swoosh::passphrase::Asked<'_>) -> eyre::Result<Passphrase> {
        (self.0)();
        Ok(Passphrase::try_from(Zeroizing::new(PASS.to_owned())).unwrap())
    }

    fn choose(
        &mut self,
        _asked: swoosh::passphrase::Asked<'_>,
    ) -> eyre::Result<swoosh::passphrase::Choice> {
        eyre::bail!("nothing is chosen here")
    }

    fn say(&mut self, _line: &str) {}
}

/// Fold `list`, signed by the root, into `home` from another thread, as a running `serve` would.
fn fold_from_beside(home: &Home, list: &RosterDoc) {
    let (home, bytes) = (home.clone(), TestRoot::seeded(ROOT).sign_update(list));
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let home_lock = swoosh::home::HomeWrite::take(&home).await.unwrap();
            swoosh::roster::fold(&home_lock, &home, &bytes)
                .await
                .unwrap();
        });
    })
    .join()
    .unwrap();
}

/// A copy is its key and the list beside it: one without its list is refused before the prompt, and
/// nothing is written. Red when the restore signs from no records.
#[tokio::test]
async fn restore_refuses_a_copy_with_no_devices() {
    let home = machine("restore-no-list", SPARE);
    let dir = stick(&home, &records(1, &[live(LAPTOP, "laptop")], Vec::new()));
    std::fs::remove_file(dir.join("devices")).unwrap();
    let before = crate::commands::invite::invite_tests::snapshot(home.dir());
    let mut prompt = Counting::refusing();
    let refused = restore_cmd(&dir)
        .restore(&home, &mut prompt)
        .await
        .expect_err("refused");
    assert_eq!(
        format!("{refused:#}"),
        format!(
            "the copy in {} has no list of your devices beside its key, so it is not a whole copy of your \
             root; use another copy.",
            dir.display()
        )
    );
    assert_eq!(prompt.events(), 0);
    assert!(crate::commands::invite::invite_tests::snapshot(home.dir()) == before);
}

/// The list written is the one verified before the prompt: bytes swapped in while the prompt waits are never
/// read. Red when the file is read again after the prompt.
#[tokio::test]
async fn restore_writes_the_devices_bytes_it_verified() {
    let home = machine("restore-verified-bytes", SPARE);
    let list = records(1, &[live(LAPTOP, "laptop")], Vec::new());
    let dir = stick(&home, &list);
    let verified = std::fs::read(dir.join("devices")).unwrap();
    let devices = dir.join("devices");
    let mut prompt = Meanwhile(|| std::fs::write(&devices, b"not a list").unwrap());
    let sync = restore_cmd(&dir).restore(&home, &mut prompt).await.unwrap();
    sync.finish(&home, &Answering::nobody(), &mut Vec::new())
        .await
        .unwrap();
    let here = held(&home);
    assert!(
        here.members()
            .iter()
            .any(|member| member.node == key(LAPTOP)),
        "the verified list's device is listed"
    );
    assert_eq!(
        swoosh::roster::verify(&verified, TestRoot::seeded(ROOT).verify_key())
            .unwrap()
            .epoch(),
        swoosh::roster::Epoch(1)
    );
}

/// A list newer than the copy, folded here while the restore waits at its prompt, is never written over:
/// the decision is made under the lock. Red when it is made from the read before the prompt.
#[tokio::test]
async fn restore_never_writes_the_copys_list_over_a_newer_one() {
    let home = scratch("restore-never-over");
    let rows = [live(OWN, "desk"), live(LAPTOP, "laptop")];
    device_of(&home, &rows[0]).await;
    crate::commands::invite::invite_tests::held(&home, &records(1, &rows, Vec::new()));
    let dir = stick(&home, &records(2, &rows, Vec::new()));
    let newer = records(3, &rows, Vec::new());
    let mut prompt = Meanwhile(|| fold_from_beside(&home, &newer));
    let sync = restore_cmd(&dir).restore(&home, &mut prompt).await.unwrap();
    sync.finish(&home, &Answering::nobody(), &mut Vec::new())
        .await
        .unwrap();
    assert_eq!(held(&home).epoch(), swoosh::roster::Epoch(3));
}

/// On a device holding a list at the copy's number with other bytes, the copy's list is kept as the
/// conflict and the list held stays. Red when it is written over, or dropped.
#[tokio::test]
async fn restore_on_a_device_keeps_a_copy_at_the_same_number_as_a_fork() {
    let home = scratch("restore-fork");
    let own = live(OWN, "desk");
    device_of(&home, &own).await;
    crate::commands::invite::invite_tests::held(
        &home,
        &records(2, &[own.clone(), live(LAPTOP, "laptop")], Vec::new()),
    );
    let before = std::fs::read(home.devices()).unwrap();
    let dir = stick(&home, &records(2, &[own, live(0x43, "nas")], Vec::new()));
    let copied = std::fs::read(dir.join("devices")).unwrap();
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();
    assert_eq!(std::fs::read(home.devices()).unwrap(), before);
    assert_eq!(std::fs::read(home.devices_conflict()).unwrap(), copied);
}

/// A list revoking this machine, folded here while the restore waits at its prompt, refuses the restore under
/// the lock before `root.key` is written: the check before the prompt is made again where it counts. Red
/// when only the check before the prompt is made.
#[tokio::test]
async fn restore_refuses_when_a_list_revoking_this_machine_lands_during_the_prompt() {
    let home = scratch("restore-revoked-meanwhile");
    let rows = [live(OWN, "desk"), live(LAPTOP, "laptop")];
    device_of(&home, &rows[0]).await;
    crate::commands::invite::invite_tests::held(&home, &records(1, &rows, Vec::new()));
    let dir = stick(&home, &records(2, &rows, Vec::new()));
    let revoking = records(
        3,
        &[live(LAPTOP, "laptop"), revoked(OWN, "desk")],
        Vec::new(),
    );
    let mut asked = 0;
    let mut prompt = Meanwhile(|| {
        asked += 1;
        fold_from_beside(&home, &revoking);
    });
    let refused = restore_cmd(&dir)
        .restore(&home, &mut prompt)
        .await
        .expect_err("refused");
    assert_eq!(
        format!("{refused:#}"),
        "this machine's key was revoked; to restore here, first give this machine a new key: swoosh leave \
         --new-key"
    );
    assert_eq!(asked, 1);
    assert!(!home.root_key().exists(), "the root was never written");
}

/// A fork kept here (`devices.conflict`) that revokes this machine, at the number of the list held, which
/// still lists it, refuses the restore before the prompt: the fork is one of the lists the records are built
/// from. Red when only `devices` is read, which writes `root.key` and then fails signing this machine's row.
#[tokio::test]
async fn restore_refuses_when_a_fork_held_here_revokes_this_machine() {
    let home = scratch("restore-fork-revokes");
    let rows = [live(OWN, "desk"), live(LAPTOP, "laptop")];
    device_of(&home, &rows[0]).await;
    crate::commands::invite::invite_tests::held(&home, &records(2, &rows, Vec::new()));
    fold_from_beside(&home, &fork_revoking_this_machine());
    assert!(home.devices_conflict().exists(), "the fork is kept");
    let dir = stick(&home, &records(2, &rows, Vec::new()));
    let mut prompt = Counting::new([PASS]);
    let refused = restore_cmd(&dir)
        .restore(&home, &mut prompt)
        .await
        .expect_err("refused");
    assert_eq!(
        format!("{refused:#}"),
        "this machine's key was revoked; to restore here, first give this machine a new key: swoosh leave \
         --new-key"
    );
    assert_eq!(prompt.events(), 0, "refused before the prompt");
    assert!(!home.root_key().exists(), "the root was never written");
}

/// The same fork, folded here while the restore waits at its prompt, refuses it under the lock before
/// `root.key` is written. Red when the re-check under the lock reads only `devices`.
#[tokio::test]
async fn restore_refuses_when_a_fork_revoking_this_machine_lands_during_the_prompt() {
    let home = scratch("restore-fork-meanwhile");
    let rows = [live(OWN, "desk"), live(LAPTOP, "laptop")];
    device_of(&home, &rows[0]).await;
    crate::commands::invite::invite_tests::held(&home, &records(2, &rows, Vec::new()));
    let dir = stick(&home, &records(2, &rows, Vec::new()));
    let fork = fork_revoking_this_machine();
    let mut asked = 0;
    let mut prompt = Meanwhile(|| {
        asked += 1;
        fold_from_beside(&home, &fork);
    });
    let refused = restore_cmd(&dir)
        .restore(&home, &mut prompt)
        .await
        .expect_err("refused");
    assert_eq!(
        format!("{refused:#}"),
        "this machine's key was revoked; to restore here, first give this machine a new key: swoosh leave \
         --new-key"
    );
    assert_eq!(asked, 1);
    assert!(home.devices_conflict().exists(), "the fork is kept");
    assert!(!home.root_key().exists(), "the root was never written");
}

/// A list at update 2 that revokes this machine: a fork of the update 2 a test holds, which lists it.
fn fork_revoking_this_machine() -> RosterDoc {
    records(
        2,
        &[
            live(LAPTOP, "laptop"),
            revoked(OWN, "desk"),
            live(0x43, "nas"),
        ],
        Vec::new(),
    )
}

/// A restore whose cut renames this machine, because a fork kept here gave its name to another device, says
/// the new name on its success line. Red when the rename is dropped.
#[tokio::test]
async fn a_restore_with_a_fork_naming_this_machines_name_says_the_new_name() {
    let home = scratch("restore-renamed");
    let own = lapsed(OWN, "desk");
    device_of(&home, &live(OWN, "desk")).await;
    let laptop = live(LAPTOP, "laptop");
    crate::commands::invite::invite_tests::held(
        &home,
        &records(2, &[own.clone(), laptop.clone()], Vec::new()),
    );
    // The copy signed update 2 too, giving the name me/desk to another device: kept here as the fork.
    let dir = stick(
        &home,
        &records(2, &[laptop, live(0x43, "desk")], Vec::new()),
    );
    let (result, err) = restore(&home, &dir, &Answering::nobody()).await;
    result.unwrap();
    assert!(
        home.devices_conflict().exists(),
        "the copy was kept as the fork"
    );
    let renamed = row_for(&home, key(OWN)).expect("this machine's row").label;
    assert_ne!(renamed.as_str(), "desk");
    assert_eq!(
        err.lines().next().unwrap(),
        format!(
            "restored root:{}, your root, on this machine. No device answered: your other devices learn of \
             this machine the next time you use your root. Another device took the name me/desk; this \
             machine is me/{renamed} now.",
            swoosh::credential::short(&root())
        )
    );
}

/// A restore writes the copy's own key bytes, never a new sealing of them, so backing up into the copy it came
/// from keeps that copy's key and says nothing more than the success line. Red when restore seals the key
/// again: every sealing draws a new salt and nonces, and the backup then replaces the copy and warns.
#[tokio::test]
async fn root_backup_after_a_restore_keeps_the_copy() {
    let home = scratch("restore-then-backup");
    let dir = stick(&home, &records(1, &[live(OWN, "desk")], Vec::new()));
    let copied = std::fs::read(dir.join("root.key")).unwrap();
    restore(&home, &dir, &Answering::nobody()).await.0.unwrap();
    assert_eq!(
        std::fs::read(home.root_key()).unwrap(),
        copied,
        "the restored key is the copy's, byte for byte"
    );
    let mut err = Vec::new();
    crate::commands::root::backup::BackupCmd { dir: dir.clone() }
        .backup(&home, &mut err)
        .await
        .unwrap();
    let shown = dir.display();
    assert_eq!(
        String::from_utf8(err).unwrap(),
        format!(
            "copied your root to {shown}. Your root is still on this machine; to take it off: swoosh root \
             forget {shown}\n"
        ),
        "the copy is kept, and no warning prints"
    );
    assert_eq!(std::fs::read(dir.join("root.key")).unwrap(), copied);
}

/// A copy's key that changes while the restore waits at its prompt refuses the restore, and nothing is
/// written: the bytes written are only ever the ones the passphrase opened. Red when the key is not read
/// again after the unlock.
#[tokio::test]
async fn restore_refuses_a_copy_whose_key_changes_during_the_prompt() {
    let home = scratch("restore-key-changed");
    let dir = stick(&home, &records(1, &[live(OWN, "desk")], Vec::new()));
    let key_file = dir.join("root.key");
    let mut prompt = Meanwhile(|| {
        let mut bytes = std::fs::read(&key_file).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&key_file, &bytes).unwrap();
    });
    let refused = restore_cmd(&dir)
        .restore(&home, &mut prompt)
        .await
        .expect_err("refused");
    let shown = dir.display();
    assert_eq!(
        format!("{refused:#}"),
        format!(
            "the copy in {shown} changed while it was read; nothing was restored. Run it again: swoosh root \
             restore {shown}"
        )
    );
    assert!(!home.root_key().exists(), "the root was never written");
}

/// Overwrite `path` with `bytes`, owner-only.
fn overwrite(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The line a restore prints when the copy's `touch-id` lock does not open on this Mac: the line every use
/// of it says, with the check on a fingerprint nobody added before setting it again.
const DEAD_COPY: &str = "touch-id does not open your root on this Mac now; if you did not add a fingerprint, \
     check Touch ID & Password before setting it again: swoosh root lock touch-id";

/// A copy whose `touch-id` lock does not open here is restored byte for byte, and one line says how to use
/// it here; a lock that cannot be checked now gets no line, since it may be live. Red when an unchecked lock
/// is called dead, or the lock is dropped.
#[tokio::test]
async fn restore_keeps_a_dead_touch_id_lock_and_says_once() {
    let list = records(1, &[live(LAPTOP, "laptop")], Vec::new());
    for (tag, health, said) in [
        ("restore-touch-id-dead", keystore::Health::Dead, true),
        (
            "restore-touch-id-unchecked",
            keystore::Health::Unchecked,
            false,
        ),
        ("restore-touch-id-live", keystore::Health::Live, false),
    ] {
        let home = machine(tag, SPARE);
        let dir = stick(&home, &list);
        overwrite(
            &dir.join("root.key"),
            &swoosh::testkit::touch_id::ROOT_PASSPHRASE_AND_TOUCH_ID,
        );
        let mut prompt = Counting::new([PASS]).at_this_mac(health);
        let (result, err) = restore_asking(&home, &dir, &Answering::nobody(), &mut prompt).await;
        result.unwrap();
        assert_eq!(err.lines().any(|line| line == DEAD_COPY), said, "{err}");
        assert_eq!(
            std::fs::read(home.root_key()).unwrap(),
            swoosh::testkit::touch_id::ROOT_PASSPHRASE_AND_TOUCH_ID,
            "the copy's bytes, lock and all"
        );
        assert!(prompt.touches().is_empty(), "a restore asks no touch");
    }
}

/// Restoring onto a machine whose key opens with `touch-id` alone says to give it a passphrase beside the
/// touch, since no verb gives a new key where a root is kept. Red when the line is dropped.
#[tokio::test]
async fn restore_onto_a_touch_id_only_machine_key_names_lock_touch_id() {
    let list = records(1, &[live(LAPTOP, "laptop")], Vec::new());
    let home = machine("restore-onto-touch-id", OWN);
    overwrite(
        &home.key(),
        &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
    );
    let dir = stick(&home, &list);
    let (result, err) = restore(&home, &dir, &Answering::nobody()).await;
    result.unwrap();
    assert!(
        err.lines().any(|line| line
            == "this machine's key opens with touch-id alone, and now keeps your root; give it a \
                passphrase beside the touch: swoosh lock touch-id"),
        "{err}"
    );
}
