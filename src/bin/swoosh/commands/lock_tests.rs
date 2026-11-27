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

/// Run `swoosh lock <args>` on `home` with `prompt`: the result, and stderr. An act prints nothing on
/// stdout, which is the read's.
async fn lock(home: &Home, args: &[&str], prompt: &mut Counting) -> (eyre::Result<()>, String) {
    let (result, out, err) = run(home, args, prompt).await;
    assert_eq!(out, "", "an act prints nothing on stdout");
    (result, err)
}

/// Run `swoosh lock <args>` on `home` with `prompt`: the result, stdout and stderr.
async fn run(
    home: &Home,
    args: &[&str],
    prompt: &mut Counting,
) -> (eyre::Result<()>, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = parse(args)
        .unwrap()
        .lock(home, prompt, &mut out, &mut err)
        .await;
    (
        result,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// The locks on this machine's key file: none for a plain one.
fn locks(home: &Home) -> Vec<Method> {
    match KeyFile::new(home.key()).load().unwrap().unwrap() {
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

/// A plain key gets a passphrase: the header is sealed, and the result says what it opens with now. Red when
/// either is skipped.
#[tokio::test]
async fn lock_puts_a_passphrase_on_a_plain_key() {
    let home = scratch("lock-sets");
    let key = swoosh::testkit::stored_key(&KeyFile::new(home.key()));
    let (result, err) = lock(&home, &["passphrase"], &mut Counting::new([LONG])).await;
    result.unwrap();
    assert_eq!(locks(&home), [Method::Passphrase]);
    assert_eq!(
        swoosh::testkit::stored_key(&KeyFile::new(home.key())),
        key,
        "lock never changes the key"
    );
    assert_eq!(
        err,
        "Added a passphrase to this machine's key.\n\
         It now opens with the passphrase.\n"
    );
}

/// Changing a passphrase asks the current one first; a wrong one, three times, changes nothing. Red when the
/// current one is not checked.
#[tokio::test]
async fn lock_changes_an_existing_one_after_the_current_one() {
    let home = scratch("lock-changes");
    lock(&home, &["passphrase"], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    let before = snapshot(home.dir());

    let mut prompt = Counting::new(["wrong one", "wrong two", "wrong three", OTHER]);
    let (refused, _) = lock(&home, &["passphrase"], &mut prompt).await;
    let refusal = format!("{:#}", refused.unwrap_err());
    assert_eq!(refusal, "that passphrase does not open this machine's key.");
    assert_eq!(prompt.events(), 3, "no new passphrase is asked");
    assert!(snapshot(home.dir()) == before, "nothing changed");

    let (result, err) = lock(&home, &["passphrase"], &mut Counting::new([LONG, OTHER])).await;
    result.unwrap();
    assert_eq!(
        err,
        "Changed the passphrase on this machine's key.\n\
         A copy made earlier still opens with the old passphrase.\n",
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
    lock(&home, &["passphrase"], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    let before = snapshot(home.dir());
    let (refused, _) = lock(
        &home,
        &["passphrase", "--remove"],
        &mut Counting::new(["no", "nope", "never"]),
    )
    .await;
    assert!(refused.is_err());
    assert!(snapshot(home.dir()) == before, "nothing removed");

    let (result, err) = lock(
        &home,
        &["passphrase", "--remove"],
        &mut Counting::new([LONG]),
    )
    .await;
    result.unwrap();
    assert!(locks(&home).is_empty(), "plain now");
    assert_eq!(
        err,
        "Removed the passphrase from this machine's key.\n\
         It now has no lock.\n"
    );
}

/// `--remove` on a key with no passphrase says so and succeeds, asking nothing. Red when it exits 1.
#[tokio::test]
async fn lock_remove_on_an_unlocked_key_says_so_and_exits_0() {
    let home = scratch("lock-remove-plain");
    let mut prompt = Counting::refusing();
    let (result, err) = lock(&home, &["passphrase", "--remove"], &mut prompt).await;
    result.unwrap();
    assert_eq!(
        err,
        "This machine's key has no lock, so nothing was changed.\n"
    );
    assert_eq!(prompt.events(), 0);
}

/// A bare `lock` names no method, and so is the read; a bare `lock --remove` names no lock to take off, so it
/// is clap's own usage error, exit 2, never a guess. Red when it parses, or picks a method.
#[test]
fn lock_remove_needs_a_method() {
    let bare = parse(&[]).unwrap();
    assert!(bare.method.is_none() && !bare.remove);
    let refused = parse(&["--remove"]).expect_err("--remove names no lock");
    assert_eq!(refused.exit_code(), 2, "{refused}");
    assert_eq!(
        refused.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
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
    let (refused, _) = lock(&home, &["passphrase"], &mut prompt).await;
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
    lock(&home, &["passphrase"], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    let home_dir = home.dir().to_str().unwrap().to_owned();
    for args in [&["passphrase"][..], &["passphrase", "--remove"][..]] {
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
    let set = parse(&["passphrase"])
        .unwrap()
        .lock(&home, &mut NoTerminal, &mut Vec::new(), &mut err)
        .await;
    assert_eq!(
        format!("{:#}", set.unwrap_err()),
        "setting a passphrase on this machine's key needs a terminal: over swoosh ssh, add -t after --"
    );
    lock(&home, &["passphrase"], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    for args in [&["passphrase"][..], &["passphrase", "--remove"][..]] {
        let refused = parse(args)
            .unwrap()
            .lock(&home, &mut NoTerminal, &mut Vec::new(), &mut Vec::new())
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
        "This machine's key already opens with Touch ID alone, so nothing was changed.\n"
    );
    assert_eq!(prompt.events(), 0);
    assert!(prompt.touches().is_empty());
}

/// `bytes` as this machine's key in `home`, owner-only, with a root kept beside it when `root_kept`.
fn placed(home: &Home, bytes: &[u8], root_kept: bool) {
    use std::os::unix::fs::PermissionsExt as _;

    swoosh::identity::make_machine_dir(home).unwrap();
    std::fs::write(home.key(), bytes).unwrap();
    std::fs::set_permissions(home.key(), std::fs::Permissions::from_mode(0o600)).unwrap();
    if root_kept {
        std::fs::write(home.root_key(), b"a root kept here").unwrap();
    }
}

/// At this Mac, the touch scripted to open, leaving the file under the passphrase and Touch ID as the key
/// store's act would: a scripted touch writes nothing itself.
fn proving(answers: impl IntoIterator<Item = &'static str>) -> Counting {
    Counting::new(answers)
        .at_this_mac(keystore::Health::Live)
        .touching([swoosh::touch::Touched::Opened(None)])
        .publishing(|touch| {
            let public = match touch.file.load().unwrap() {
                Some(Stored::Locked(locked)) => locked.public_key(),
                other => panic!("an add on a sealed key: {other:?}"),
            };
            let both = swoosh::testkit::touch_id::claiming(
                &swoosh::testkit::touch_id::DEVICE_PASSPHRASE_AND_TOUCH_ID,
                &public,
            );
            std::fs::write(touch.file.path(), both).unwrap();
        })
}

/// What an added passphrase prints where no root is kept: the step back to Touch ID alone.
const ADDED_PASSPHRASE: &str = "\
Added a passphrase to this machine's key.
It now opens with Touch ID or the passphrase.

To go back to Touch ID alone:
  swoosh lock passphrase --remove
";

/// What an added Touch ID prints where no root is kept: the step to Touch ID alone.
#[cfg(target_os = "macos")]
const ADDED_TOUCH_ID: &str = "\
Added Touch ID to this machine's key.
It now opens with Touch ID or the passphrase.

To make Touch ID its only lock:
  swoosh lock passphrase --remove
";

/// Each add that leaves both locks prints its screen, byte for byte, through the screen law. Where a root is
/// kept, the passphrase cannot come off beside Touch ID, so no step offers it. Red when a byte differs, the
/// step is a bare `swoosh lock --remove`, or a step that would be refused is printed.
#[tokio::test]
async fn an_added_lock_prints_its_result_screen() {
    for root_kept in [false, true] {
        let home = scratch(&format!("lock-added-passphrase-{root_kept}"));
        placed(
            &home,
            &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
            root_kept,
        );
        let (result, err) = lock(&home, &["passphrase"], &mut proving([LONG])).await;
        result.unwrap();
        let expected = if root_kept {
            "Added a passphrase to this machine's key.\n\
             It now opens with Touch ID or the passphrase.\n"
        } else {
            ADDED_PASSPHRASE
        };
        assert_eq!(err, expected, "root kept {root_kept}");
    }
    #[cfg(target_os = "macos")]
    for root_kept in [false, true] {
        let home = scratch(&format!("lock-added-touch-id-{root_kept}"));
        lock(&home, &["passphrase"], &mut Counting::new([LONG]))
            .await
            .0
            .unwrap();
        if root_kept {
            std::fs::write(home.root_key(), b"a root kept here").unwrap();
        }
        let (result, err) = lock(&home, &["touch-id"], &mut proving([LONG])).await;
        result.unwrap();
        let expected = if root_kept {
            "Added Touch ID to this machine's key.\n\
             It now opens with Touch ID or the passphrase.\n"
        } else {
            ADDED_TOUCH_ID
        };
        assert_eq!(err, expected, "root kept {root_kept}");
    }
    #[cfg(target_os = "macos")]
    {
        let home = scratch("lock-changed-touch-id");
        placed(
            &home,
            &swoosh::testkit::touch_id::DEVICE_PASSPHRASE_AND_TOUCH_ID,
            false,
        );
        let mut prompt = proving([swoosh::testkit::touch_id::PASSPHRASE]);
        let (result, err) = lock(&home, &["touch-id"], &mut prompt).await;
        result.unwrap();
        assert_eq!(err, "Changed Touch ID on this machine's key.\n");
    }
}

/// `lock touch-id` on a key under Touch ID alone beside a kept root changes nothing and exits 0, but never
/// reads as all clear: it says the key needs a passphrase there, and names the command that adds it. Red when
/// it says the key already has the one lock asked for, or names no command.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn touch_id_alone_beside_a_root_names_the_passphrase_command() {
    let home = scratch("lock-touch-id-beside-root");
    placed(
        &home,
        &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
        true,
    );
    let before = snapshot(home.dir());
    let mut prompt = Counting::refusing().at_this_mac(keystore::Health::Live);
    let (result, err) = lock(&home, &["touch-id"], &mut prompt).await;
    result.unwrap();
    assert_eq!(
        err,
        "Your root is on this machine, so its key needs a passphrase beside Touch ID.\n\
         Nothing was changed.\n\
         To add the passphrase:\n  \
         swoosh lock passphrase\n"
    );
    assert_eq!(prompt.events(), 0);
    assert!(prompt.touches().is_empty());
    assert!(snapshot(home.dir()) == before, "nothing written");
}

/// `lock --remove`'s help says it takes off the lock named, whichever that is.
#[test]
fn lock_remove_help_names_this_lock() {
    let mut cli = Cli::command();
    cli.build();
    let help = cli
        .find_subcommand_mut("lock")
        .unwrap()
        .render_help()
        .to_string();
    assert!(help.contains("take this lock off"), "{help}");
    assert!(
        help.contains("the lock to add or, with --remove, take off; omit to show the locks"),
        "{help}"
    );
}

/// What a write that landed and could not be read back prints, under the act's own first line at `{act}`.
const UNREAD: &str = "\
{act}
warning: this command could not confirm the key file
  swoosh status shows what is there.
  file   /h/machine/key
  read   could not access the key file /h/machine/key: denied
";

/// Every outcome `lock` can have prints its own lines, byte for byte, through the screen law: a made key alone
/// on its line at indent two, what the key opens with now from the set read back, a step only where it would
/// not be refused, and the copy line wherever a lock is taken off and another stays. Red when any byte
/// differs from the ruled words.
#[test]
fn each_result_prints_its_ruled_lines() {
    use keystore::Health::{Dead, Live};
    use swoosh::identity::{Locked, Locks, Methods, Now, Root, Unread, Why};

    let key = swoosh::testkit::TestNode::seeded(0x11).node_id();
    let made = |now| Locked::Made {
        key,
        now,
        failed: None,
    };
    let added = |method, now, root| Locked::Added {
        method,
        now: Now::Read(now),
        root,
        failed: None,
    };
    let unread = || {
        Now::Unread(Unread {
            path: "/h/machine/key".to_owned(),
            read: "could not access the key file /h/machine/key: denied".to_owned(),
        })
    };
    let rows: Vec<(Locked, String)> = vec![
        (made(Methods::Passphrase), format!("Made this machine's key, locked with a passphrase:\n  {key}\n")),
        (made(Methods::TouchId), format!("Made this machine's key, locked with Touch ID:\n  {key}\n")),
        (made(Methods::Both), format!("Made this machine's key, locked with Touch ID or a passphrase:\n  {key}\n")),
        (added(Methods::Passphrase, Locks::Both(Some(Live)), Root::NotKept), ADDED_PASSPHRASE.to_owned()),
        (
            added(Methods::Passphrase, Locks::Both(Some(Live)), Root::Kept),
            "Added a passphrase to this machine's key.\nIt now opens with Touch ID or the passphrase.\n".to_owned(),
        ),
        (
            added(Methods::TouchId, Locks::Both(Some(Live)), Root::NotKept),
            "Added Touch ID to this machine's key.\n\
             It now opens with Touch ID or the passphrase.\n\
             \n\
             To make Touch ID its only lock:\n  \
             swoosh lock passphrase --remove\n"
                .to_owned(),
        ),
        (
            added(Methods::TouchId, Locks::Both(Some(Live)), Root::Kept),
            "Added Touch ID to this machine's key.\nIt now opens with Touch ID or the passphrase.\n".to_owned(),
        ),
        (
            added(Methods::Passphrase, Locks::Passphrase, Root::NotKept),
            "Added a passphrase to this machine's key.\nIt now opens with the passphrase.\n".to_owned(),
        ),
        (
            added(Methods::TouchId, Locks::TouchId(Some(Live)), Root::NotKept),
            "Added Touch ID to this machine's key.\nIt now opens with Touch ID, on this Mac only.\n".to_owned(),
        ),
        (
            added(Methods::Both, Locks::Both(Some(Live)), Root::Kept),
            "Added Touch ID and a passphrase to this machine's key.\n\
             It now opens with Touch ID or the passphrase.\n"
                .to_owned(),
        ),
        (
            Locked::Changed { method: Method::Passphrase, now: Now::Read(Locks::Both(Some(Live))), failed: None },
            "Changed the passphrase on this machine's key.\n\
             A copy made earlier still opens with the old passphrase.\n"
                .to_owned(),
        ),
        (Locked::Changed { method: Method::TouchId, now: Now::Read(Locks::Both(Some(Live))), failed: None }, "Changed Touch ID on this machine's key.\n".to_owned()),
        (
            Locked::Removed { method: Method::Passphrase, now: Now::Read(Locks::TouchId(Some(Live))), failed: None },
            "Removed the passphrase from this machine's key.\n\
             It now opens with Touch ID, on this Mac only.\n\
             A copy made earlier still opens with the passphrase.\n"
                .to_owned(),
        ),
        (
            Locked::Removed { method: Method::TouchId, now: Now::Read(Locks::Passphrase), failed: None },
            "Removed Touch ID from this machine's key.\n\
             It now opens with the passphrase.\n\
             A copy made earlier still opens with Touch ID on this Mac.\n"
                .to_owned(),
        ),
        (
            Locked::Removed { method: Method::Passphrase, now: Now::Read(Locks::None), failed: None },
            "Removed the passphrase from this machine's key.\nIt now has no lock.\n".to_owned(),
        ),
        (
            Locked::Removed { method: Method::TouchId, now: Now::Read(Locks::None), failed: None },
            "Removed Touch ID from this machine's key.\nIt now has no lock.\n".to_owned(),
        ),
        // A key made with a failure after it in place says so under the key.
        (
            Locked::Made { key, now: Methods::TouchId, failed: Some("the directory could not be synced".to_owned()) },
            format!(
                "Made this machine's key, locked with Touch ID:\n  {key}\n\n\
                 warning: the key file was written, but a step after it failed\n  \
                 failure   the directory could not be synced\n"
            ),
        ),
        // Every other written result with a failure after it says so after what was done, before any step.
        (
            Locked::Added { method: Methods::TouchId, now: Now::Read(Locks::Both(Some(Live))), root: Root::NotKept, failed: Some("the directory could not be synced".to_owned()) },
            "Added Touch ID to this machine's key.\n\
             It now opens with Touch ID or the passphrase.\n\
             \n\
             warning: the key file was written, but a step after it failed\n  \
             failure   the directory could not be synced\n\
             \n\
             To make Touch ID its only lock:\n  \
             swoosh lock passphrase --remove\n"
                .to_owned(),
        ),
        (
            Locked::Changed { method: Method::Passphrase, now: Now::Read(Locks::Passphrase), failed: Some("the directory could not be synced".to_owned()) },
            "Changed the passphrase on this machine's key.\n\
             A copy made earlier still opens with the old passphrase.\n\
             \n\
             warning: the key file was written, but a step after it failed\n  \
             failure   the directory could not be synced\n"
                .to_owned(),
        ),
        (
            Locked::Removed { method: Method::TouchId, now: Now::Read(Locks::None), failed: Some("the directory could not be synced".to_owned()) },
            "Removed Touch ID from this machine's key.\n\
             It now has no lock.\n\
             \n\
             warning: the key file was written, but a step after it failed\n  \
             failure   the directory could not be synced\n"
                .to_owned(),
        ),
        // Over a Touch ID lock that reads dead, no step offers the removal the key store would refuse.
        (
            added(Methods::Passphrase, Locks::Both(Some(Dead)), Root::NotKept),
            "Added a passphrase to this machine's key.\n\
             It opens with the passphrase; Touch ID does not open on this Mac now.\n"
                .to_owned(),
        ),
        // A Touch ID lock that reads dead is said as such, beside the passphrase or alone.
        (
            added(Methods::Passphrase, Locks::Both(Some(Dead)), Root::Kept),
            "Added a passphrase to this machine's key.\n\
             It opens with the passphrase; Touch ID does not open on this Mac now.\n"
                .to_owned(),
        ),
        (
            Locked::Removed { method: Method::Passphrase, now: Now::Read(Locks::TouchId(Some(Dead))), failed: None },
            "Removed the passphrase from this machine's key.\n\
             Touch ID does not open on this Mac now, so nothing opens this machine's key.\n\
             A copy made earlier still opens with the passphrase.\n"
                .to_owned(),
        ),
        // A write that landed and could not be read back says the act, then that it could not confirm it.
        (
            Locked::Added { method: Methods::TouchId, now: unread(), root: Root::NotKept, failed: None },
            UNREAD.replace("{act}", "Added Touch ID to this machine's key."),
        ),
        (
            Locked::Changed { method: Method::Passphrase, now: unread(), failed: None },
            UNREAD.replace("{act}", "Changed the passphrase on this machine's key."),
        ),
        (
            Locked::Removed { method: Method::TouchId, now: unread(), failed: None },
            UNREAD.replace("{act}", "Removed Touch ID from this machine's key."),
        ),
        (
            Locked::Unchanged(Why::NoKey),
            "This machine has no key yet, so nothing was changed.\n".to_owned(),
        ),
        (
            Locked::Unchanged(Why::NoLock),
            "This machine's key has no lock, so nothing was changed.\n".to_owned(),
        ),
        (
            Locked::Unchanged(Why::NoSuchLock(Method::Passphrase)),
            "This machine's key has no passphrase, so nothing was changed.\n".to_owned(),
        ),
        (
            Locked::Unchanged(Why::NoSuchLock(Method::TouchId)),
            "This machine's key has no Touch ID lock, so nothing was changed.\n".to_owned(),
        ),
        (
            Locked::Unchanged(Why::TouchIdAlone),
            "This machine's key already opens with Touch ID alone, so nothing was changed.\n".to_owned(),
        ),
        (
            Locked::Unchanged(Why::NeedsPassphrase),
            "Your root is on this machine, so its key needs a passphrase beside Touch ID.\n\
             Nothing was changed.\n\
             To add the passphrase:\n  \
             swoosh lock passphrase\n"
                .to_owned(),
        ),
    ];
    for (locked, expected) in rows {
        let text = match &locked {
            Locked::Made { key, .. } => key.to_string(),
            _ => String::new(),
        };
        let mut err = Vec::new();
        super::result(&locked, &text).write(&mut err).unwrap();
        assert_eq!(String::from_utf8(err).unwrap(), expected, "{locked:?}");
    }
}

/// Taking off a key's last lock says it has none now, and never lists `none` as one lock among others. Red
/// when the line names `none`, or a copy line follows a key left with no lock.
#[tokio::test]
async fn a_removal_down_to_no_lock_says_so() {
    let home = scratch("lock-remove-last-passphrase");
    lock(&home, &["passphrase"], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    let (result, err) = lock(
        &home,
        &["passphrase", "--remove"],
        &mut Counting::new([LONG]),
    )
    .await;
    result.unwrap();
    assert_eq!(
        err,
        "Removed the passphrase from this machine's key.\nIt now has no lock.\n"
    );
    assert!(!err.contains("none"), "{err}");

    #[cfg(target_os = "macos")]
    {
        let home = scratch("lock-remove-last-touch-id");
        placed(
            &home,
            &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
            false,
        );
        let mut prompt = Counting::new([])
            .at_this_mac(keystore::Health::Live)
            .touching([swoosh::touch::Touched::Opened(None)])
            .publishing(|touch| std::fs::write(touch.file.path(), [0x11; 32]).unwrap());
        let (result, err) = lock(&home, &["touch-id", "--remove"], &mut prompt).await;
        result.unwrap();
        assert!(locks(&home).is_empty(), "plain now");
        assert_eq!(
            err,
            "Removed Touch ID from this machine's key.\nIt now has no lock.\n"
        );
    }
}

/// At the command line, a cancelled `lock touch-id` on an empty home made no key and says so, and the `lock
/// passphrase` after it makes one and shows it. Red when the second reads as an add, or no key is on its
/// screen.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn lock_after_a_missed_make_shows_the_made_key() {
    let dir = std::env::temp_dir().join(format!("swoosh-lock-missed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir.clone())).unwrap();
    let mut cancelled = Counting::new([])
        .at_this_mac(keystore::Health::Live)
        .touching([swoosh::touch::Touched::Declined]);
    let (refused, _) = lock(&home, &["touch-id"], &mut cancelled).await;
    assert_eq!(
        format!("{:#}", refused.unwrap_err()),
        "Touch ID was cancelled\n  This command made no key."
    );
    let (result, err) = lock(&home, &["passphrase"], &mut Counting::new([LONG])).await;
    result.unwrap();
    let key = swoosh::testkit::stored_key(&KeyFile::new(home.key()));
    assert_eq!(
        err,
        format!("Made this machine's key, locked with a passphrase:\n  {key}\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A key file this command could not confirm, or that is gone, refuses as a screen through the law, with its
/// path and the read's error as rows where a read failed, and exits 1 without `main` printing it again; any
/// other refusal is `main`'s to print. Red when a row is missing, a `read` row prints with no read error, or
/// the refusal is printed twice. A first key beside a root whose touch never ran shows the key, the failure,
/// and how to add Touch ID, and still exits 1.
#[test]
fn a_file_this_command_cannot_confirm_refuses_as_a_screen() {
    use swoosh::identity::{Gone, TouchIdNotAdded, Unconfirmed};

    let path = std::path::PathBuf::from("/h/machine/key");
    let key = swoosh::testkit::TestNode::seeded(0x11).node_id();
    for (report, expected) in [
        (
            eyre::Report::new(Unconfirmed {
                path: path.clone(),
                read: Some(keystore::Error::Absent { path: path.clone() }),
            }),
            "error: this command could not confirm the key file\n  \
             swoosh status shows what is there.\n  \
             file   /h/machine/key\n  \
             read   there is no key file at /h/machine/key\n"
                .to_owned(),
        ),
        (
            eyre::Report::new(Unconfirmed {
                path: path.clone(),
                read: None,
            }),
            "error: this command could not confirm the key file\n  \
             swoosh status shows what is there.\n  \
             file   /h/machine/key\n"
                .to_owned(),
        ),
        (
            eyre::Report::new(Gone { path: path.clone() }),
            "error: the key file this command wrote is gone\n  \
             swoosh status shows what is there.\n"
                .to_owned(),
        ),
        // A first key beside a root, made under the passphrase, whose touch never ran.
        (
            eyre::Report::new(TouchIdNotAdded {
                key,
                failed: "the directory could not be synced".to_owned(),
            }),
            format!(
                "Made this machine's key, locked with a passphrase:\n  {key}\n\n\
                 warning: the key file was written, but a step after it failed\n  \
                 failure   the directory could not be synced\n\n\
                 Touch ID was not added.\n\
                 To add it:\n  \
                 swoosh lock touch-id\n"
            ),
        ),
    ] {
        let mut err = Vec::new();
        let refused = super::refused(report, &mut err);
        assert!(
            refused.is::<crate::commands::through_serve::Reported>(),
            "{refused:#}"
        );
        assert_eq!(String::from_utf8(err).unwrap(), expected);
    }
    let mut err = Vec::new();
    let passed = super::refused(eyre::eyre!("another refusal"), &mut err);
    assert_eq!(format!("{passed:#}"), "another refusal");
    assert!(err.is_empty(), "main prints it");
}

// --- the bare read ---

/// The read's `locks` rows for a key with no lock: both methods off.
const ROWS_OFF: &str = "\
locks
  touch-id     off   a touch on this Mac's sensor; opens on this Mac only
  passphrase   off   typed at each use; a copy opens on any machine
";

/// What the read prints on a home with no key, on a build with an enclave.
const NO_KEY: &str = "\
This machine has no key yet.

locks
  touch-id     a touch on this Mac's sensor; opens on this Mac only
  passphrase   typed at each use; a copy opens on any machine

To make the key with one of them:
  swoosh lock touch-id
  swoosh lock passphrase
";

/// What the read prints on a home with no key, on a build with no enclave.
const NO_KEY_ABSENT: &str = "\
This machine has no key yet.

locks
  passphrase   typed at each use; a copy opens on any machine

To make the key with a passphrase:
  swoosh lock passphrase
";

/// What the read prints on a home with no key, on this build.
#[cfg(target_os = "macos")]
const NO_KEY_BUILT: &str = NO_KEY;
#[cfg(not(target_os = "macos"))]
const NO_KEY_BUILT: &str = NO_KEY_ABSENT;

/// The read's every state, byte for byte, through the screen law: the key's locks as `locks` and a kept root
/// as `root`, on a build with and without an enclave. Every step is a command the state would not refuse.
/// Red when a byte differs from the ruled words, or a `--remove` or `lock passphrase` that refuses is offered.
#[test]
fn bare_lock_reads_each_state() {
    use keystore::Health::{Dead, Live, Unchecked};
    use swoosh::identity::{Locks, Root};

    use super::Enclave::{Absent, Here};

    let plain = format!(
        "This machine's key has no lock.\n\n{ROWS_OFF}\n\
         To lock it with one of them:\n  swoosh lock touch-id\n  swoosh lock passphrase\n"
    );
    let passphrase = "This machine's key opens with a passphrase.\n\n\
                      locks\n  \
                      touch-id     off   a touch on this Mac's sensor; opens on this Mac only\n  \
                      passphrase   on    typed at each use; a copy opens on any machine\n\n\
                      To add Touch ID beside the passphrase:\n  swoosh lock touch-id\n";
    let alone = |title: &str, state: &str, step: &str| {
        format!(
            "{title}\n\nlocks\n  touch-id     on    {state}\n  \
             passphrase   off   typed at each use; a copy opens on any machine\n{step}"
        )
    };
    let both = |title: &str, state: &str, step: &str| {
        format!(
            "{title}\n\nlocks\n  touch-id     on    {state}\n  \
             passphrase   on    typed at each use; a copy opens on any machine\n\n{step}"
        )
    };
    let gloss = "a touch on this Mac's sensor; opens on this Mac only";
    let either = "This machine's key opens with Touch ID or a passphrase.";
    let a_passphrase = "This machine's key opens with a passphrase.";
    let take_one =
        "To take one off:\n  swoosh lock touch-id --remove\n  swoosh lock passphrase --remove\n";
    let take_touch_id = "To take Touch ID off:\n  swoosh lock touch-id --remove\n";
    let change = "To change the passphrase:\n  swoosh lock passphrase\n";
    let cases: Vec<(Option<Locks>, Root, super::Enclave, String)> = vec![
        (None, Root::NotKept, Here, NO_KEY.to_owned()),
        (None, Root::Kept, Here, NO_KEY.to_owned()),
        (None, Root::NotKept, Absent, NO_KEY_ABSENT.to_owned()),
        (Some(Locks::None), Root::NotKept, Here, plain),
        (
            Some(Locks::None),
            Root::NotKept,
            Absent,
            "This machine's key has no lock.\n\n\
             locks\n  passphrase   off   typed at each use; a copy opens on any machine\n\n\
             To lock it with a passphrase:\n  swoosh lock passphrase\n"
                .to_owned(),
        ),
        (
            Some(Locks::Passphrase),
            Root::NotKept,
            Here,
            passphrase.to_owned(),
        ),
        (
            Some(Locks::Passphrase),
            Root::Kept,
            Here,
            passphrase.to_owned(),
        ),
        (
            Some(Locks::Passphrase),
            Root::NotKept,
            Absent,
            format!(
                "{a_passphrase}\n\n\
                 locks\n  passphrase   on    typed at each use; a copy opens on any machine\n\n{change}"
            ),
        ),
        (
            Some(Locks::TouchId(Some(Live))),
            Root::NotKept,
            Here,
            alone(
                "This machine's key opens with Touch ID, on this Mac only.",
                gloss,
                "\nTo add a passphrase beside Touch ID:\n  swoosh lock passphrase\n",
            ),
        ),
        (
            Some(Locks::TouchId(Some(Live))),
            Root::Kept,
            Here,
            alone(
                "This machine's key opens with Touch ID, on this Mac only.",
                gloss,
                "\nTo add a passphrase beside Touch ID:\n  swoosh lock passphrase\n",
            ),
        ),
        (
            Some(Locks::TouchId(Some(Dead))),
            Root::NotKept,
            Here,
            alone(
                "This machine's key does not open on this Mac now.",
                "does not open on this Mac now",
                "\nswoosh status says how to mend it.\n",
            ),
        ),
        (
            Some(Locks::TouchId(Some(Unchecked))),
            Root::NotKept,
            Here,
            alone(
                "Touch ID on this machine's key cannot be checked now.",
                "cannot be checked now",
                "",
            ),
        ),
        (
            Some(Locks::TouchId(None)),
            Root::NotKept,
            Absent,
            alone(
                "Touch ID opens this machine's key only on the Mac that set it.",
                "opens only on the Mac that set it",
                "",
            ),
        ),
        (
            Some(Locks::Both(Some(Live))),
            Root::NotKept,
            Here,
            both(either, gloss, take_one),
        ),
        (
            Some(Locks::Both(Some(Live))),
            Root::Kept,
            Here,
            both(either, gloss, take_touch_id),
        ),
        (
            Some(Locks::Both(Some(Dead))),
            Root::NotKept,
            Here,
            both(a_passphrase, "does not open on this Mac now", take_touch_id),
        ),
        (
            Some(Locks::Both(Some(Unchecked))),
            Root::NotKept,
            Here,
            both(a_passphrase, "cannot be checked now", take_touch_id),
        ),
        (
            Some(Locks::Both(None)),
            Root::NotKept,
            Absent,
            both(a_passphrase, "opens only on the Mac that set it", change),
        ),
    ];
    for (locks, root, enclave, expected) in cases {
        let mut out = Vec::new();
        super::read(locks, root, enclave).write(&mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out, expected, "{locks:?} {root:?} {enclave:?}");
        if enclave == Absent {
            assert!(!out.contains("swoosh lock touch-id"), "{out}");
        }
    }
}

/// The read's row names are the values `lock` takes, and the key store's spelling of each method, which names
/// the Touch ID row on a build that takes no such value, is the same word. Red when the two part.
#[test]
fn the_read_names_each_lock_as_it_is_typed() {
    for value in LockMethod::value_variants() {
        let typed = value.to_possible_value().unwrap();
        assert_eq!(super::name(Method::from(*value)), typed.get_name());
        assert_eq!(Method::from(*value).to_string(), typed.get_name());
    }
    assert_eq!(super::name(Method::TouchId), Method::TouchId.to_string());
}

/// `RISK` marks where nothing opens the key (Touch ID dead, or alone where it cannot open) or anyone with a
/// copy opens it (plain), and a dead row; never a lock that could not be checked, nor a live one. Red when
/// the style moves, or lands on `Unchecked`.
#[test]
fn the_read_paints_risk_only_where_the_key_is_at_risk() {
    use anstream::AutoStream;
    use keystore::Health::{Dead, Live, Unchecked};
    use swoosh::identity::{Locks, Root};

    use super::Enclave::{Absent, Here};

    let risk = crate::screen::Style::RISK.paint("x", &AutoStream::always(Vec::new()));
    let open = risk.to_string().split('x').next().unwrap().to_owned();
    let painted = |locks, enclave| {
        let mut out = AutoStream::always(Vec::new());
        super::read(Some(locks), Root::NotKept, enclave)
            .write(&mut out)
            .unwrap();
        let out = String::from_utf8(out.into_inner()).unwrap();
        out.lines()
            .filter(|line| line.contains(&open))
            .map(|line| anstream::adapter::strip_str(line).to_string())
            .collect::<Vec<_>>()
    };
    let dead_row = "  touch-id     on    does not open on this Mac now";
    assert_eq!(
        painted(Locks::None, Here),
        ["This machine's key has no lock."]
    );
    assert_eq!(
        painted(Locks::TouchId(Some(Dead)), Here),
        [
            "This machine's key does not open on this Mac now.",
            dead_row
        ]
    );
    assert_eq!(
        painted(Locks::TouchId(None), Absent),
        [
            "Touch ID opens this machine's key only on the Mac that set it.",
            "  touch-id     on    opens only on the Mac that set it"
        ]
    );
    assert_eq!(painted(Locks::Both(Some(Dead)), Here), [dead_row]);
    for calm in [
        Locks::Passphrase,
        Locks::TouchId(Some(Live)),
        Locks::TouchId(Some(Unchecked)),
        Locks::Both(Some(Live)),
        Locks::Both(Some(Unchecked)),
        Locks::Both(None),
    ] {
        assert!(painted(calm, Absent).is_empty(), "{calm:?}");
    }
}

/// Bare `lock` on real homes, the wiring: the key's header, Touch ID's health as the prompt reads it, and a
/// root kept beside it, or one that cannot be told kept, which drops the passphrase's `--remove`. Red when the
/// read takes its state from anywhere else.
#[tokio::test]
async fn bare_lock_reads_the_home() {
    let home = scratch("lock-read-none");
    std::fs::remove_file(home.key()).unwrap();
    let (result, out, err) = run(&home, &[], &mut Counting::refusing()).await;
    result.unwrap();
    assert_eq!((out.as_str(), err.as_str()), (NO_KEY_BUILT, ""));

    let home = scratch("lock-read-plain");
    let (_, out, _) = run(&home, &[], &mut Counting::refusing()).await;
    assert!(
        out.starts_with("This machine's key has no lock.\n"),
        "{out}"
    );

    let home = scratch("lock-read-dead");
    placed(
        &home,
        &swoosh::testkit::touch_id::DEVICE_TOUCH_ID_ALONE,
        false,
    );
    let mut prompt = Counting::refusing().at_this_mac(keystore::Health::Dead);
    let (_, out, _) = run(&home, &[], &mut prompt).await;
    assert!(
        out.ends_with("\nswoosh status says how to mend it.\n"),
        "{out}"
    );

    let take_one =
        "To take one off:\n  swoosh lock touch-id --remove\n  swoosh lock passphrase --remove\n";
    let take_touch_id = "To take Touch ID off:\n  swoosh lock touch-id --remove\n";
    for (root, step) in [
        ("none", take_one),
        ("kept", take_touch_id),
        ("unknown", take_touch_id),
    ] {
        let home = scratch(&format!("lock-read-both-{root}"));
        placed(
            &home,
            &swoosh::testkit::touch_id::DEVICE_PASSPHRASE_AND_TOUCH_ID,
            root == "kept",
        );
        if root == "unknown" {
            // A link to itself: whether a root is there cannot be told.
            std::os::unix::fs::symlink(home.root_key(), home.root_key()).unwrap();
            assert!(home.keeps_root().is_err());
        }
        let mut prompt = Counting::refusing().at_this_mac(keystore::Health::Live);
        let (_, out, _) = run(&home, &[], &mut prompt).await;
        assert!(
            out.starts_with("This machine's key opens with Touch ID or a passphrase.\n"),
            "{out}"
        );
        assert!(out.ends_with(&format!("\n\n{step}")), "{root}: {out}");
    }
}

/// Bare `lock` asks, touches and writes nothing: on a home never made, the home, `home.lock` and
/// `serve.lock` are all still absent after it; on a home with a key, under a passphrase or Touch ID, every
/// file is byte for byte as it was. Red when the read mints, opens, locks the home, or asks.
#[tokio::test]
async fn bare_lock_writes_and_asks_nothing() {
    let dir = std::env::temp_dir().join(format!("swoosh-lock-read-unmade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = Home::resolve(Some(dir.clone())).unwrap();
    let mut prompt = Counting::refusing();
    let (result, out, _) = run(&home, &[], &mut prompt).await;
    result.unwrap();
    assert_eq!(out, NO_KEY_BUILT);
    for path in [dir.clone(), dir.join("home.lock"), dir.join("serve.lock")] {
        assert!(!path.exists(), "{} was made", path.display());
    }
    assert_eq!(prompt.events(), 0);
    assert!(prompt.touches().is_empty());

    let sealed = scratch("lock-read-sealed");
    lock(&sealed, &["passphrase"], &mut Counting::new([LONG]))
        .await
        .0
        .unwrap();
    let touch_id = scratch("lock-read-touch-id");
    placed(
        &touch_id,
        &swoosh::testkit::touch_id::DEVICE_PASSPHRASE_AND_TOUCH_ID,
        false,
    );
    for home in [sealed, touch_id] {
        let before = snapshot(home.dir());
        let mut prompt = Counting::refusing().at_this_mac(keystore::Health::Live);
        run(&home, &[], &mut prompt).await.0.unwrap();
        assert!(snapshot(home.dir()) == before, "nothing written");
        assert_eq!(prompt.events(), 0);
        assert!(prompt.touches().is_empty());
    }
}

/// A key file the read cannot read refuses on stderr, exit 1, naming the file and the read's own error, and
/// no command to look with, since `status` reads the same file. Red when it names `swoosh status`, or prints
/// a screen of locks.
#[tokio::test]
async fn bare_lock_on_an_unreadable_key_file_refuses() {
    let home = scratch("lock-read-unreadable");
    std::fs::write(home.key(), b"not a key file").unwrap();
    let error = KeyFile::new(home.key()).load().unwrap_err();
    let (result, out, err) = run(&home, &[], &mut Counting::refusing()).await;
    assert!(
        result
            .unwrap_err()
            .is::<crate::commands::through_serve::Reported>()
    );
    assert_eq!(out, "");
    // A row stacks where its value does not fit beside its label, as a long temporary path does here.
    let row = |label: &str, value: &str| {
        let line = format!("  {label}   {value}\n");
        if line.chars().count() <= 81 {
            line
        } else {
            format!("  {label}\n    {value}\n")
        }
    };
    let expected = format!(
        "error: this command could not read the key file\n{}{}",
        row("file", &home.key().display().to_string()),
        row("read", &swoosh::escape::causes(&error))
    );
    assert_eq!(err, expected);
    assert!(!err.contains("swoosh status"), "{err}");
}
