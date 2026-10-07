//! `swoosh lock`: the passphrase on this machine's key, set, changed and removed, and the shape of the verb.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use clap::{CommandFactory as _, Parser as _, ValueEnum as _};
use keystore::{KeyFile, Method, Stored};
use swoosh::home::Home;
use swoosh::testkit::Counting;

use super::{LockCmd, LockMethod};
use crate::Cli;
use crate::commands::invite::invite_tests::{scratch, snapshot};

/// A passphrase the minimum takes.
const LONG: &str = "a passphrase long enough";
/// Another.
const OTHER: &str = "another passphrase long enough";

/// Parse `swoosh lock <args>`.
fn parse(args: &[&str]) -> Result<LockCmd, clap::Error> {
    let cli = Cli::try_parse_from(["swoosh", "lock"].iter().chain(args).copied())?;
    match cli.command {
        Some(crate::Command::Lock(cmd)) => Ok(cmd),
        other => panic!("not lock: {other:?}"),
    }
}

/// Run `swoosh lock <args>` on `home` with `prompt`: the result, and stderr.
async fn lock(home: &Home, args: &[&str], prompt: &mut Counting) -> (eyre::Result<()>, String) {
    let mut err = Vec::new();
    let result = parse(args).unwrap().lock(home, prompt, &mut err).await;
    (result, String::from_utf8(err).unwrap())
}

/// The locks on this machine's key file: none for a plain one.
fn locks(home: &Home) -> Vec<Method> {
    match KeyFile::device(home.key()).load().unwrap().unwrap() {
        Stored::Plain(_) => Vec::new(),
        Stored::Locked(locked) => locked.methods().collect(),
    }
}

/// `none`, `plain` and `off` are not methods: no value means no lock, and that is `--remove`. Red when a
/// `none` value is added.
#[test]
fn lock_with_none_or_plain_is_a_usage_error() {
    for value in ["none", "plain", "off"] {
        let refused = parse(&[value]).expect_err(value);
        assert_eq!(refused.exit_code(), 2, "{value}: {refused}");
    }
}

/// The methods `lock` offers on this build: `touch-id` on a Mac only, where there is an enclave to make it.
#[cfg(target_os = "macos")]
const OFFERED: [&str; 2] = ["passphrase", "touch-id"];
#[cfg(not(target_os = "macos"))]
const OFFERED: [&str; 1] = ["passphrase"];

/// `--help` offers exactly the methods `LockMethod` has on this build, each mapped to the key store's. A value
/// with no method arm fails to compile at `From<LockMethod> for Method`. Red when `touch-id` is offered off a
/// Mac.
#[test]
fn lock_help_lists_exactly_the_lockmethod_values() {
    let values: Vec<String> = LockMethod::value_variants()
        .iter()
        .map(|value| value.to_possible_value().unwrap().get_name().to_owned())
        .collect();
    assert_eq!(values, OFFERED);
    assert_eq!(Method::from(LockMethod::Passphrase), Method::Passphrase);
    #[cfg(target_os = "macos")]
    assert_eq!(Method::from(LockMethod::TouchId), Method::TouchId);
    let mut cli = Cli::command();
    let help = cli
        .find_subcommand_mut("lock")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(help.contains("passphrase"), "{help}");
    assert!(!help.contains("plain"), "{help}");
    // The short form: one line per argument, the values inline, never a block per value.
    assert!(!help.contains("Possible values:"), "{help}");
    assert!(
        help.contains(&format!("[possible values: {}]", OFFERED.join(", "))),
        "{help}"
    );
}

/// A plain key gets a passphrase: the header is sealed, and the first time says `serve` asks at each start.
/// Red when either is skipped.
#[tokio::test]
async fn lock_sets_one_and_warns_about_restart() {
    let home = scratch("lock-sets");
    let key = swoosh::testkit::stored_key(&KeyFile::device(home.key()));
    let (result, err) = lock(&home, &[], &mut Counting::new([LONG])).await;
    result.unwrap();
    assert_eq!(locks(&home), [Method::Passphrase]);
    assert_eq!(
        swoosh::testkit::stored_key(&KeyFile::device(home.key())),
        key,
        "lock never changes the key"
    );
    assert_eq!(
        err,
        "set a passphrase on this machine's key.\n\
         every command that acts as this machine now asks for it, so swoosh serve cannot start with nobody \
         at a terminal.\n"
    );
}

/// Changing a passphrase asks the current one first; a wrong one, three times, changes nothing. Red when the
/// current one is not checked.
#[tokio::test]
async fn lock_changes_an_existing_one_after_the_current_one() {
    let home = scratch("lock-changes");
    lock(&home, &[], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    let before = snapshot(home.dir());

    let mut prompt = Counting::new(["wrong one", "wrong two", "wrong three", OTHER]);
    let (refused, _) = lock(&home, &[], &mut prompt).await;
    let refusal = format!("{:#}", refused.unwrap_err());
    assert_eq!(refusal, "that passphrase does not open this machine's key.");
    assert_eq!(prompt.events(), 3, "no new passphrase is asked");
    assert!(snapshot(home.dir()) == before, "nothing changed");

    let (result, err) = lock(&home, &[], &mut Counting::new([LONG, OTHER])).await;
    result.unwrap();
    assert_eq!(
        err, "changed the passphrase on this machine's key.\n",
        "no warning the second time"
    );
    let mut opens = Counting::new([OTHER]);
    swoosh::identity::resolve_with(swoosh::identity::Identity::Persisted, &home, &mut opens)
        .expect("the new passphrase opens it");
}

/// Removing the passphrase needs the current one; a wrong one removes nothing. Red when the file is written
/// without unlocking.
#[tokio::test]
async fn lock_remove_needs_the_current_one() {
    let home = scratch("lock-remove");
    lock(&home, &[], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    let before = snapshot(home.dir());
    let (refused, _) = lock(
        &home,
        &["--remove"],
        &mut Counting::new(["no", "nope", "never"]),
    )
    .await;
    assert!(refused.is_err());
    assert!(snapshot(home.dir()) == before, "nothing removed");

    let (result, err) = lock(&home, &["--remove"], &mut Counting::new([LONG])).await;
    result.unwrap();
    assert!(locks(&home).is_empty(), "plain now");
    assert_eq!(
        err,
        "removed the passphrase from this machine's key, which now has no lock.\n\
         anyone with a copy of its key file can act as this machine.\n"
    );
}

/// `--remove` on a key with no passphrase says so and succeeds, asking nothing. Red when it exits 1.
#[tokio::test]
async fn lock_remove_on_an_unlocked_key_says_so_and_exits_0() {
    let home = scratch("lock-remove-plain");
    let mut prompt = Counting::refusing();
    let (result, err) = lock(&home, &["--remove"], &mut prompt).await;
    result.unwrap();
    assert_eq!(
        err,
        "this machine's key has no passphrase; nothing was changed.\n"
    );
    assert_eq!(prompt.events(), 0);
}

/// A bare `lock` is `lock passphrase`. Red when a method is required.
#[test]
fn lock_with_no_method_uses_passphrase() {
    let bare = parse(&[]).unwrap();
    assert!(matches!(bare.method, LockMethod::Passphrase));
    assert!(!bare.remove);
}

/// `lock` is this machine's key only: `--root` is a usage error. Red when `lock` keeps a `--root`.
#[test]
fn lock_takes_no_root_flag() {
    let refused = parse(&["--root", "/tmp/copy"]).expect_err("no --root");
    assert_eq!(refused.exit_code(), 2, "{refused}");
}

/// A passphrase under the minimum, for this machine's key, is refused and the key is left as it was. Red
/// when the floor is skipped for `lock`.
#[tokio::test]
async fn lock_refuses_a_passphrase_below_the_minimum() {
    let home = scratch("lock-short");
    let before = snapshot(home.dir());
    let mut prompt = Counting::new(["fourteen chars", "short", "tiny"]);
    let (refused, _) = lock(&home, &[], &mut prompt).await;
    assert_eq!(
        format!("{:#}", refused.unwrap_err()),
        swoosh::passphrase::TOO_SHORT_LAST
    );
    assert!(snapshot(home.dir()) == before, "nothing written");
}

/// No prompt and no passphrase refusal names a file in the home: a prompt says which key, never where it is
/// kept. Red when a line prints `passphrase for <path>:` or the key store's `could not unlock the key file
/// <path>`.
#[tokio::test]
async fn no_prompt_or_passphrase_refusal_names_a_key_file() {
    let home = scratch("lock-no-path");
    lock(&home, &[], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    let home_dir = home.dir().to_str().unwrap().to_owned();
    for args in [&[][..], &["--remove"][..]] {
        let (refused, err) = lock(&home, args, &mut Counting::new(["a", "b", "c"])).await;
        let refusal = format!("{:#}", refused.unwrap_err());
        assert!(!refusal.contains(&home_dir), "{refusal}");
        assert!(!refusal.contains("key file"), "{refusal}");
        assert!(!err.contains(&home_dir), "{err}");
    }
    let resolved = swoosh::identity::resolve_with(
        swoosh::identity::Identity::Persisted,
        &home,
        &mut Counting::new(["a", "b", "c"]),
    );
    let refusal = format!("{:#}", resolved.err().expect("three wrong ones refuse"));
    assert!(!refusal.contains(&home_dir), "{refusal}");
    assert_eq!(refusal, "that passphrase does not open this machine's key.");
}

/// A prompt with nobody at a terminal.
struct NoTerminal;

impl swoosh::passphrase::Prompt for NoTerminal {
    fn terminal(&self) -> bool {
        false
    }

    fn unlock(
        &mut self,
        _asked: swoosh::passphrase::Asked<'_>,
    ) -> eyre::Result<keystore::Passphrase> {
        eyre::bail!("no terminal")
    }

    fn choose(
        &mut self,
        _asked: swoosh::passphrase::Asked<'_>,
    ) -> eyre::Result<swoosh::passphrase::Choice> {
        eyre::bail!("no terminal")
    }

    fn say(&mut self, _line: &str) {}
}

/// At no terminal, `lock` says it needs one and how to get one over ssh; changing or removing never names
/// `lock --remove`, the command just run. Red when the line for using the key prints here.
#[tokio::test]
async fn lock_at_no_terminal_says_it_needs_one() {
    let home = scratch("lock-no-tty");
    let mut err = Vec::new();
    let set = parse(&[])
        .unwrap()
        .lock(&home, &mut NoTerminal, &mut err)
        .await;
    assert_eq!(
        format!("{:#}", set.unwrap_err()),
        "setting a passphrase on this machine's key needs a terminal: over swoosh ssh, add -t after --"
    );
    lock(&home, &[], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    for args in [&[][..], &["--remove"][..]] {
        let refused = parse(args)
            .unwrap()
            .lock(&home, &mut NoTerminal, &mut Vec::new())
            .await;
        let refusal = format!("{:#}", refused.unwrap_err());
        assert_eq!(
            refusal,
            "changing or removing the passphrase on this machine's key needs a terminal: over swoosh ssh, add \
             -t after --"
        );
        assert!(!refusal.contains("lock --remove"));
    }
}

/// `lock touch-id` on a key under `touch-id` alone where no root is kept, whose lock reads live here, says it
/// already has that one lock, and asks nothing. On a Mac only, where `touch-id` is a value; the decision itself is the library's, tested
/// on every build.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn lock_touch_id_on_a_touch_id_only_key_says_nothing_changed() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = scratch("lock-touch-id-has");
    swoosh::identity::make_machine_dir(&home).unwrap();
    std::fs::write(home.key(), swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE).unwrap();
    std::fs::set_permissions(home.key(), std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut prompt = Counting::refusing().at_this_mac(keystore::Health::Live);
    let (result, err) = lock(&home, &["touch-id"], &mut prompt).await;
    result.unwrap();
    assert_eq!(
        err,
        "this machine's key already has touch-id as its only lock; nothing was changed.\n"
    );
    assert_eq!(prompt.events(), 0);
    assert!(prompt.touches().is_empty());
}

/// A passphrase put on a key under `touch-id` alone beside a kept root goes beside the touch, and the done
/// line says so. Red when it reads as a first passphrase, which would say every command now asks for it.
#[tokio::test]
async fn lock_passphrase_beside_touch_id_says_it_went_beside() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = scratch("lock-passphrase-beside-touch-id");
    swoosh::identity::make_machine_dir(&home).unwrap();
    std::fs::write(home.key(), swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE).unwrap();
    std::fs::set_permissions(home.key(), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(home.root_key(), b"a root kept here").unwrap();
    let mut prompt = Counting::new([LONG])
        .at_this_mac(keystore::Health::Live)
        .touching([swoosh::touch::Touched::Opened(None)]);
    let (result, err) = lock(&home, &["passphrase"], &mut prompt).await;
    result.unwrap();
    assert_eq!(
        err,
        "added a passphrase to this machine's key, beside touch-id.\n"
    );
}

/// `lock --remove`'s help says it removes the lock named, whichever that is.
#[test]
fn lock_remove_help_names_this_lock() {
    let mut cli = Cli::command();
    cli.build();
    let help = cli
        .find_subcommand_mut("lock")
        .unwrap()
        .render_help()
        .to_string();
    assert!(help.contains("remove this lock instead"), "{help}");
}
