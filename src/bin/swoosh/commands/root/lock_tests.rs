//! `swoosh root lock [<dir>]`: the root's passphrase, changed on this machine or in a copy, and nothing else.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use keystore::{KeyFile, Stored, Unlock};
use swoosh::home::Home;
use swoosh::testkit::Counting;

use super::RootLockCmd;
use crate::commands::invite::invite_tests::{
    LAPTOP, OWN, PASS, copy, device_of, holds, live, records, scratch, snapshot,
};

/// A new passphrase the minimum takes.
const FRESH: &str = "a fresh root passphrase";

/// Run `swoosh root lock [<dir>]` on `home`: the result, and stderr.
async fn root_lock(
    home: &Home,
    dir: Option<&Path>,
    prompt: &mut Counting,
) -> (eyre::Result<()>, String) {
    let mut err = Vec::new();
    let result = RootLockCmd {
        dir: dir.map(Path::to_path_buf),
    }
    .lock(home, prompt, &mut err)
    .await;
    (result, String::from_utf8(err).unwrap())
}

/// Every file under `home` but `home.lock`, which taking the lock makes the first time.
fn content(home: &Home) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = snapshot(home.dir());
    files.remove(&home.home_lock());
    files
}

/// Whether the root key at `path` opens under `passphrase`.
fn opens(path: &Path, passphrase: &str) -> bool {
    let Some(Stored::Locked(locked)) = KeyFile::root(path).load().unwrap() else {
        panic!("a sealed root key");
    };
    let passphrase =
        keystore::Passphrase::try_from(zeroize::Zeroizing::new(passphrase.to_owned())).unwrap();
    locked.unlock(Unlock::Passphrase(&passphrase)).is_ok()
}

/// A copy of `ROOT` beside `home`.
fn stick(home: &Home) -> PathBuf {
    let dir = home.dir().with_extension("stick");
    let _ = std::fs::remove_dir_all(&dir);
    copy(&dir, &records(1, &[live(OWN, "desk")], Vec::new()));
    dir
}

/// Only `root.key` changes: the list beside it, and its number, stay. Red when it commits a cut.
#[tokio::test]
async fn root_lock_rewrites_only_the_root_key_and_cuts_nothing() {
    let home = scratch("root-lock-home");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let mut before = content(&home);
    let mut prompt = Counting::new([PASS, FRESH]);
    let (result, err) = root_lock(&home, None, &mut prompt).await;
    result.unwrap();
    assert_eq!(prompt.events(), 2, "the current one, then the new one");
    assert_eq!(
        err,
        "changed your root's passphrase on this machine. Other copies keep the old one.\n"
    );
    assert!(opens(&home.root_key(), FRESH));
    let mut after = content(&home);
    before.remove(&home.root_key());
    after.remove(&home.root_key());
    assert!(after == before, "nothing but root.key changed");
}

/// `root lock <dir>` changes the copy, and leaves the root on this machine as it was. Red when it changes
/// this machine's.
#[tokio::test]
async fn root_lock_in_a_dir_changes_the_copy() {
    let home = scratch("root-lock-dir");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    let kept = std::fs::read(home.root_key()).unwrap();
    let (result, err) = root_lock(&home, Some(&dir), &mut Counting::new([PASS, FRESH])).await;
    result.unwrap();
    assert_eq!(
        err,
        format!(
            "changed your root's passphrase in {}. Other copies keep the old one.\n",
            dir.display()
        )
    );
    assert!(opens(&dir.join("root.key"), FRESH));
    assert_eq!(std::fs::read(home.root_key()).unwrap(), kept);
}

/// No root on this machine, and no `<dir>`: the first invite makes one. Red when the generic refusal prints.
#[tokio::test]
async fn root_lock_with_no_root_and_no_dir_names_invite() {
    let home = scratch("root-lock-none");
    let (result, _) = root_lock(&home, None, &mut Counting::refusing()).await;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "this machine holds no root; your first invite makes one: swoosh invite <name> <key>"
    );
}

/// On a device of a root kept elsewhere, with no `<dir>`: the copy form. Red when the generic refusal
/// prints.
#[tokio::test]
async fn root_lock_on_a_device_names_the_copy_form() {
    let home = scratch("root-lock-device");
    device_of(&home, &live(OWN, "desk")).await;
    let (result, _) = root_lock(&home, None, &mut Counting::refusing()).await;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "your root is not on this machine; to change it in a copy: swoosh root lock <dir>"
    );
}

/// A machine that trusts no root may change a copy's passphrase: nothing is cut. Red when it refuses.
#[tokio::test]
async fn an_unpinned_machine_may_lock_a_presented_copy() {
    let home = scratch("root-lock-unpinned");
    let dir = stick(&home);
    root_lock(&home, Some(&dir), &mut Counting::new([PASS, FRESH]))
        .await
        .0
        .unwrap();
    assert!(opens(&dir.join("root.key"), FRESH));
}

/// A root passphrase under the minimum is refused at the mint and at `root lock`, and nothing is written:
/// the home and the copy are byte for byte as they were. Red when it is accepted, or the prompt moves after
/// a write.
#[tokio::test]
async fn a_root_passphrase_below_the_minimum_is_refused() {
    let short = ["fourteen chars", "fourteen chars", "fourteen chars"];

    // At the mint.
    let home = scratch("root-short-mint");
    let before = content(&home);
    let refused = swoosh::root::Root::mint_to(&home, &mut Counting::new(short), &mut Vec::new())
        .await
        .expect_err("a short root passphrase");
    assert_eq!(refused.to_string(), swoosh::passphrase::TOO_SHORT);
    assert!(content(&home) == before, "no root made");

    // At `root lock`, here and in a copy.
    let home = scratch("root-short-lock");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    let (here, copied) = (content(&home), snapshot(&dir));
    for at in [None, Some(dir.as_path())] {
        let mut prompt = Counting::new([PASS, short[0], short[1], short[2]]);
        let (result, _) = root_lock(&home, at, &mut prompt).await;
        assert_eq!(
            format!("{:#}", result.unwrap_err()),
            swoosh::passphrase::TOO_SHORT
        );
    }
    assert!(content(&home) == here);
    assert!(snapshot(&dir) == copied);
}

/// An act that cuts nothing dials nobody: `root backup <dir>` and `root lock` take no dial at all, and leave
/// no trace of a sync. Red when either syncs as a cutting act's `present` does.
#[tokio::test]
async fn a_non_cutting_act_never_syncs() {
    let home = scratch("root-no-sync");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let dir = home.dir().with_extension("backup");
    let _ = std::fs::remove_dir_all(&dir);
    super::super::backup::BackupCmd { dir }
        .backup(&home, &mut Vec::new())
        .await
        .unwrap();
    root_lock(&home, None, &mut Counting::new([PASS, FRESH]))
        .await
        .0
        .unwrap();
    assert!(!home.synced().exists(), "no exchange ran");
}
