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
        first: None,
        dir: dir.map(Path::to_path_buf),
        remove: false,
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
    assert_eq!(refused.to_string(), swoosh::passphrase::TOO_SHORT_LAST);
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
            swoosh::passphrase::TOO_SHORT_LAST
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

/// `root lock <dir>` where `<dir>` is the home itself changes the root kept here, as `root lock` does: under
/// `home.lock`, and said as "on this machine". Red when the home is treated as a copy.
#[tokio::test]
async fn root_lock_in_the_home_itself_is_root_lock() {
    let home = scratch("root-lock-home-dir");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let (result, err) = root_lock(&home, Some(home.dir()), &mut Counting::new([PASS, FRESH])).await;
    result.unwrap();
    assert_eq!(
        err,
        "changed your root's passphrase on this machine. Other copies keep the old one.\n"
    );
    assert!(opens(&home.root_key(), FRESH));
}

/// Parse `swoosh root lock <args>`.
fn parse(args: &[&str]) -> Result<RootLockCmd, clap::Error> {
    use clap::Parser as _;

    let cli = crate::Cli::try_parse_from(["swoosh", "root", "lock"].iter().chain(args).copied())?;
    match cli.command {
        Some(crate::Command::Root(crate::commands::root::RootCmd::Lock(cmd))) => Ok(cmd),
        other => panic!("not root lock: {other:?}"),
    }
}

/// Run `swoosh root lock touch-id [<dir>] [--remove]` on `home` with `prompt`: the result, and stderr. Built
/// as the parser would build it rather than parsed, so it runs on every build: `touch-id` is a value on a
/// macOS build only, and what it runs ([`swoosh::root::lock_touch_id`]) is the same everywhere.
async fn run(
    home: &Home,
    dir: Option<&Path>,
    remove: bool,
    prompt: &mut Counting,
) -> (eyre::Result<()>, String) {
    let mut err = Vec::new();
    let result = RootLockCmd {
        first: Some(super::First::Method(keystore::Method::TouchId)),
        dir: dir.map(Path::to_path_buf),
        remove,
    }
    .lock(home, prompt, &mut err)
    .await;
    (result, String::from_utf8(err).unwrap())
}

/// The root at `path` under its passphrase and a `touch-id` lock.
fn with_touch_id(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(
        path,
        swoosh::testkit::touch_id::ROOT_PASSPHRASE_AND_TOUCH_ID,
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The methods of the root key's locks at `path`.
fn locks(path: &Path) -> Vec<keystore::Method> {
    let Some(Stored::Locked(locked)) = KeyFile::root(path).load().unwrap() else {
        panic!("a sealed root key");
    };
    locked.methods().collect()
}

/// A prompt at this Mac that answers the passphrase, and whose touch proves the new lock.
fn at_this_mac(touched: swoosh::touch::Touched) -> Counting {
    Counting::new([PASS])
        .at_this_mac(keystore::Health::Live)
        .touching([touched])
}

/// `root lock --remove` is the passphrase, which a root always keeps: a usage error, before anything is read.
#[test]
fn root_lock_remove_of_the_passphrase_is_a_usage_error() {
    let refused = parse(&["--remove"]).unwrap().target().unwrap_err();
    assert_eq!(refused.0, super::KEEPS_PASSPHRASE);
}

/// A lone word is a method or a directory by its shape; one that is neither is refused with the fix, so a
/// mistyped method is never read as a directory. Red when a bare word is taken for a directory.
#[test]
fn a_lone_word_that_is_no_method_and_holds_no_slash_is_refused() {
    let refused = parse(&["backups"]).unwrap_err();
    assert_eq!(refused.exit_code(), 2);
    assert!(
        refused.to_string().contains(
            "backups is not a lock method; a directory needs a /: swoosh root lock ./backups"
        ),
        "{refused}"
    );
    let cmd = parse(&["./backups"]).unwrap();
    assert_eq!(
        cmd.first,
        Some(super::First::Dir(PathBuf::from("./backups")))
    );
    assert_eq!(
        cmd.target().unwrap(),
        (keystore::Method::Passphrase, Some(Path::new("./backups")))
    );
}

/// Two directories are a usage error: the first must be the method.
#[test]
fn two_directories_are_a_usage_error() {
    let refused = parse(&["./a", "./b"]).unwrap().target().unwrap_err();
    assert!(refused.0.contains("name the method first"), "{}", refused.0);
}

/// On a Mac, `touch-id` is a method, before a directory or alone.
#[cfg(target_os = "macos")]
#[test]
fn touch_id_is_a_method_on_a_mac() {
    let cmd = parse(&["touch-id", "./stick"]).unwrap();
    assert_eq!(
        cmd.target().unwrap(),
        (keystore::Method::TouchId, Some(Path::new("./stick")))
    );
    let cmd = parse(&["touch-id", "--remove"]).unwrap();
    assert_eq!(cmd.target().unwrap(), (keystore::Method::TouchId, None));
}

/// Elsewhere `touch-id` is not a method, and is not taken for a directory either: it says it is macOS only.
/// Red when it suggests `./touch-id`.
#[cfg(not(target_os = "macos"))]
#[test]
fn touch_id_is_no_method_off_a_mac() {
    let refused = parse(&["touch-id"]).unwrap_err();
    assert_eq!(refused.exit_code(), 2);
    assert!(
        refused
            .to_string()
            .contains("touch-id is a lock on macOS only"),
        "{refused}"
    );
    assert!(!refused.to_string().contains("./touch-id"), "{refused}");
}

/// `root lock touch-id` says what a new fingerprint does, opens with the passphrase, and proves the new lock
/// with one touch beside it. Red when the passphrase lock is dropped.
#[tokio::test]
async fn root_lock_touch_id_adds_it_beside_the_passphrase() {
    let home = scratch("root-lock-touch-id");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let mut prompt = at_this_mac(swoosh::touch::Touched::Opened(None));
    let (result, err) = run(&home, None, false, &mut prompt).await;
    result.unwrap();
    assert_eq!(
        err,
        "added touch-id to your root on this Mac; its passphrase still opens it.\n"
    );
    assert_eq!(prompt.events(), 1, "the passphrase");
    let [touch] = prompt.touches() else {
        panic!("one touch");
    };
    assert!(matches!(
        touch.act,
        swoosh::touch::TouchAct::BesidePassphrase {
            then: swoosh::touch::Then::Keep,
            ..
        }
    ));
    assert_eq!(touch.reason, swoosh::touch::CHECK_ROOT);
    assert_eq!(touch.file.path(), home.root_key());
    assert_eq!(
        prompt.said(),
        [
            swoosh::touch::ROOT_BESIDE_PASSPHRASE,
            "waiting for touch-id to check it opens your root…"
        ]
    );
    assert_eq!(
        prompt.warned(),
        [swoosh::touch::ROOT_BESIDE_PASSPHRASE],
        "the notice is a warning, and the wait for the touch is not"
    );
}

/// On a copy, the line names the copy.
#[tokio::test]
async fn root_lock_touch_id_on_a_copy_names_the_copy() {
    let home = scratch("root-lock-touch-id-copy");
    device_of(&home, &live(OWN, "desk")).await;
    let dir = stick(&home);
    let mut prompt = at_this_mac(swoosh::touch::Touched::Opened(None));
    let (result, err) = run(&home, Some(&dir), false, &mut prompt).await;
    result.unwrap();
    assert_eq!(
        err,
        format!(
            "added touch-id to the copy of your root in {} on this Mac; its passphrase still opens it.\n",
            swoosh::escape::EscapedPath(&dir)
        )
    );
    assert_eq!(prompt.touches()[0].file.path(), dir.join("root.key"));
}

/// Over ssh it is refused before any prompt, and names the variable.
#[tokio::test]
async fn root_lock_touch_id_over_ssh_is_refused_before_any_prompt() {
    let home = scratch("root-lock-touch-id-ssh");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let before = std::fs::read(home.root_key()).unwrap();
    let mut prompt =
        Counting::new([PASS]).here(swoosh::touch::TouchHere::OverSsh("SSH_CONNECTION"));
    let (result, _) = run(&home, None, false, &mut prompt).await;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "touch-id is set at this Mac's own screen, not over ssh (SSH_CONNECTION is set); run it there: \
         swoosh root lock touch-id"
    );
    assert_eq!(prompt.events(), 0);
    assert_eq!(std::fs::read(home.root_key()).unwrap(), before);
}

/// A touch that does not prove the new lock changes nothing, and says so.
#[tokio::test]
async fn root_lock_touch_id_declined_changes_nothing() {
    let home = scratch("root-lock-touch-id-declined");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let mut prompt = at_this_mac(swoosh::touch::Touched::Declined);
    let (result, err) = run(&home, None, false, &mut prompt).await;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "touch-id did not open your root; nothing changed"
    );
    assert!(err.is_empty());
}

/// A timeout says only that it waited: the write may have finished in the last instant.
#[tokio::test]
async fn root_lock_touch_id_timed_out_never_says_nothing_changed() {
    let home = scratch("root-lock-touch-id-timed-out");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let mut prompt = at_this_mac(swoosh::touch::Touched::TimedOut);
    let (result, _) = run(&home, None, false, &mut prompt).await;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        swoosh::touch::TIMED_OUT
    );
}

/// `--remove` opens with the passphrase, never a touch, and leaves the passphrase the one lock.
#[tokio::test]
async fn root_lock_touch_id_remove_leaves_the_passphrase() {
    let home = scratch("root-lock-touch-id-remove");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    with_touch_id(&home.root_key());
    let mut prompt = Counting::new([PASS]).at_this_mac(keystore::Health::Live);
    let (result, err) = run(&home, None, true, &mut prompt).await;
    result.unwrap();
    assert_eq!(
        err,
        "removed touch-id from your root; its passphrase opens it.\n"
    );
    assert_eq!(locks(&home.root_key()), [keystore::Method::Passphrase]);
    assert!(prompt.touches().is_empty());
}

/// `--remove` on a root with no `touch-id` asks nothing and changes nothing.
#[tokio::test]
async fn root_lock_touch_id_remove_with_none_asks_nothing() {
    let home = scratch("root-lock-touch-id-remove-none");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let mut prompt = Counting::refusing();
    let (result, err) = run(&home, None, true, &mut prompt).await;
    result.unwrap();
    assert_eq!(err, "your root has no touch-id; nothing was changed.\n");
    assert_eq!(prompt.events(), 0);
}

/// Setting a root's `touch-id` lock that does not open here again says first to check for a fingerprint
/// nobody added, as a warning, before the passphrase is asked. Red when the old lock's health is not read.
#[tokio::test]
async fn root_lock_touch_id_over_a_dead_lock_says_to_check_touch_id_first() {
    let home = scratch("root-lock-touch-id-dead");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    with_touch_id(&home.root_key());
    let mut prompt = Counting::new([swoosh::testkit::touch_id::PASSPHRASE])
        .at_this_mac(keystore::Health::Dead)
        .touching([swoosh::touch::Touched::Opened(None)]);
    let (result, _) = run(&home, None, false, &mut prompt).await;
    result.unwrap();
    assert_eq!(
        prompt.warned(),
        [
            swoosh::touch::ROOT_BESIDE_PASSPHRASE,
            "warning: touch-id does not open your root on this Mac now; if you did not add a fingerprint, \
             check Touch ID & Password before setting it again: swoosh root lock touch-id"
        ]
    );
}

/// A usage error found once `root lock`'s arguments are read together prints `root lock`'s own usage,
/// never its parent's. Red when the walk stops at `root`.
#[test]
fn a_root_lock_usage_error_prints_root_locks_usage() {
    let rendered = crate::usage(&["root", "lock"], "x").render().to_string();
    assert!(rendered.contains("swoosh root lock"), "{rendered}");
    let rendered = crate::usage(&["revoke"], "x").render().to_string();
    assert!(rendered.contains("swoosh revoke"), "{rendered}");
}
