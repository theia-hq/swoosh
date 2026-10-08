//! How a key file with a `touch-id` lock opens: the gates before any dialog, the fall to the passphrase or
//! the refusal after one, the wait, and the lines each says. The touch itself is the script's; the
//! files are the testkit's fixtures, so every lock list and passphrase here is real.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::ffi::OsString;
use std::path::PathBuf;

use keystore::{Health, KeyFile, Method, Stored};

// The touch itself is built only by the hardware tests, which run on a Mac.
#[cfg(target_os = "macos")]
use super::Touch;
use super::{
    Lines, Route, SSH_VARIABLES, Stopped, TIMED_OUT, TOUCH_WAIT, TouchAct, TouchHere, Touched,
    USE_ROOT, changed, open, over_ssh, route,
};
use crate::passphrase::Asked;
use crate::testkit::Counting;
use crate::testkit::touch_id::{
    DEVICE_PASSPHRASE_AND_TOUCH_ID, DEVICE_TOUCH_ID_ALONE, PASSPHRASE, ROOT_PASSPHRASE_AND_TOUCH_ID,
};

/// A home under the temp dir, empty, unique to this test.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-touch-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("machine")).unwrap();
    dir
}

/// `bytes` written owner-only at `path`, as the key store requires.
fn private(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The root fixture, kept in a home: its key file and its locked form.
fn root(tag: &str) -> (KeyFile, keystore::Locked) {
    let path = scratch(tag).join("root.key");
    private(&path, &ROOT_PASSPHRASE_AND_TOUCH_ID);
    loaded(KeyFile::root(path))
}

/// `bytes` as this machine's key in a home, beside a root when `root_kept`.
fn machine(tag: &str, bytes: &[u8], root_kept: bool) -> (KeyFile, keystore::Locked) {
    let home = scratch(tag);
    if root_kept {
        private(&home.join("root.key"), b"a root kept here");
    }
    let path = home.join("machine").join("key");
    private(&path, bytes);
    loaded(KeyFile::device(path))
}

fn loaded(file: KeyFile) -> (KeyFile, keystore::Locked) {
    let Some(Stored::Locked(locked)) = file.load().unwrap() else {
        panic!("a sealed key file");
    };
    (file, locked)
}

/// The key a fixture's seed makes.
fn secret(seed: u8) -> keystore::Secret {
    keystore::Secret::take(&mut [seed; 32])
}

/// Open `locked` as `asked` with `prompt`, by the product's routine.
fn opened(
    prompt: &mut Counting,
    file: &KeyFile,
    locked: &keystore::Locked,
    asked: Asked<'_>,
) -> eyre::Result<keystore::PublicKey> {
    open(prompt, file, locked, asked, USE_ROOT).map(|secret| secret.public_key())
}

/// No ssh variable set reads as no ssh session.
#[test]
fn no_ssh_variable_is_no_ssh_session() {
    assert_eq!(over_ssh(|_| None), None);
}

/// Each variable alone reads as an ssh session, and names itself. Red when one is dropped from the list.
#[test]
fn each_ssh_variable_alone_names_itself() {
    for variable in SSH_VARIABLES {
        let found = over_ssh(|name| (name == variable).then(|| OsString::from("10.0.0.1 22")));
        assert_eq!(found, Some(variable));
    }
}

/// The three variables an ssh session sets are the ones read, by name, so dropping one from the list is
/// caught here. Red when one is missing.
#[test]
fn the_three_ssh_variables_are_read_by_name() {
    for variable in ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"] {
        let found = over_ssh(|name| (name == variable).then(|| OsString::from("x")));
        assert_eq!(found, Some(variable));
    }
}

/// A variable set but empty is not a session: a shell that cleared it with `SSH_TTY=` has none. Red when
/// presence alone counts.
#[test]
fn an_empty_ssh_variable_is_no_ssh_session() {
    assert_eq!(over_ssh(|_| Some(OsString::new())), None);
}

/// With several set, the first of the list is the one named. Red when the order is not the list's.
#[test]
fn several_ssh_variables_name_the_first_of_the_list() {
    assert_eq!(
        over_ssh(|_| Some(OsString::from("x"))),
        Some("SSH_CONNECTION")
    );
}

/// Every act shows one dialog, waited a minute, and the timeout's line says the wait it did. Red when the
/// line and the bound part.
#[test]
fn the_wait_is_a_minute_and_the_timeout_says_so() {
    assert_eq!(TOUCH_WAIT, Duration::from_secs(60));
    assert!(
        TIMED_OUT.contains(&format!("waited {} seconds", TOUCH_WAIT.as_secs())),
        "{TIMED_OUT}"
    );
}

/// A build with no enclave reads as a lock that does not open, and any other refusal of the key store as
/// a failure, never a cancel. Red when a failure reads as a cancel, which would let it fall silently.
#[test]
fn the_key_stores_refusals_read_as_a_touch_ends() {
    let unavailable = keystore::Error::TouchId {
        path: PathBuf::from("key"),
        source: keystore::TouchIdError::Unavailable,
    };
    assert!(matches!(
        Touched::from(Err(Stopped::Touch(unavailable))),
        Touched::NotHere
    ));
    let unlock = keystore::Error::Unlock {
        path: PathBuf::from("key"),
        method: Method::TouchId,
    };
    assert!(matches!(
        Touched::from(Err(Stopped::Touch(unlock))),
        Touched::Failed(_)
    ));
    assert!(matches!(Touched::from(Ok(None)), Touched::Opened(None)));
}

/// A refusal after the new lock went on reads as half done, never as a touch that did not open, and names
/// the lock left on and the command that takes it off. Red when the second write's failure is mapped as the
/// touch's, or the lock left on is not carried.
#[test]
fn a_refusal_after_the_new_lock_reads_as_half_done() {
    let (file, _) = machine("half-done", &DEVICE_PASSPHRASE_AND_TOUCH_ID, false);
    let lines = Lines::of(Asked::MachineKey, &file, true);
    for (left, line_1, line_2) in [
        (
            Method::Passphrase,
            "this machine's key has its new touch-id lock, but its passphrase did not come off: ",
            "to take it off: swoosh lock --remove",
        ),
        (
            Method::TouchId,
            "this machine's key has its new passphrase, but its touch-id lock did not come off: ",
            "to take it off: swoosh lock touch-id --remove",
        ),
    ] {
        let unlock = keystore::Error::Unlock {
            path: PathBuf::from("key"),
            method: Method::Passphrase,
        };
        let touched = Touched::from(Err(Stopped::After(left, unlock)));
        assert!(
            matches!(&touched, Touched::HalfDone { left: kept, .. } if *kept == left),
            "{touched:?}"
        );
        let refused = format!("{:#}", changed(touched, &lines).unwrap_err());
        let lines: Vec<&str> = refused.lines().collect();
        assert_eq!(lines.len(), 2, "{refused}");
        assert!(lines[0].starts_with(line_1), "{refused}");
        assert_eq!(lines[1], line_2, "{refused}");
    }
}

/// A live lock at this Mac is touched, and the key it opens is the answer: no passphrase is asked.
#[test]
fn a_live_lock_opens_by_one_touch_and_asks_no_passphrase() {
    let (file, locked) = root("live");
    let mut prompt = Counting::refusing()
        .at_this_mac(Health::Live)
        .touching([Touched::Opened(Some(secret(0x21)))]);
    let key = opened(&mut prompt, &file, &locked, Asked::Root).unwrap();
    assert_eq!(key, locked.public_key());
    assert_eq!(prompt.events(), 0, "no passphrase asked");
    assert_eq!(prompt.touches().len(), 1);
    assert!(matches!(prompt.touches()[0].act, TouchAct::Open));
    assert_eq!(prompt.touches()[0].reason, USE_ROOT);
    assert_eq!(prompt.said(), ["waiting for touch-id to use your root…"]);
    assert!(prompt.warned().is_empty(), "the wait attends the touch");
}

/// A touch that opens a key other than the one the header named, which the caller checked, is refused:
/// the file was replaced between the two reads. No passphrase is asked, and the key is not handed back.
/// Red when the touched key is not compared, which returns the wrong key.
#[test]
fn a_touch_that_opens_another_key_is_refused() {
    let (file, locked) = root("another-key");
    let mut prompt = Counting::new([PASSPHRASE])
        .at_this_mac(Health::Live)
        .touching([Touched::Opened(Some(secret(0x11)))]);
    let refused = opened(&mut prompt, &file, &locked, Asked::Root).unwrap_err();
    assert_eq!(
        format!("{refused:#}"),
        "the file holding your root was replaced while this ran; run this again."
    );
    assert_eq!(prompt.events(), 0, "no passphrase after another key");
}

/// A cancel falls to the passphrase with no line of its own, and never to a second touch. Red when a
/// declined touch is asked again.
#[test]
fn a_declined_touch_falls_to_the_passphrase_once() {
    let (file, locked) = root("declined");
    let mut prompt = Counting::new([PASSPHRASE])
        .at_this_mac(Health::Live)
        .touching([Touched::Declined, Touched::Declined]);
    let key = opened(&mut prompt, &file, &locked, Asked::Root).unwrap();
    assert_eq!(key, locked.public_key());
    assert_eq!(prompt.touches().len(), 1, "one touch per key");
    assert_eq!(prompt.events(), 1);
    assert_eq!(prompt.said(), ["waiting for touch-id to use your root…"]);
}

/// A lock that turns out dead after the dialog says so, then asks the passphrase.
#[test]
fn a_touch_that_does_not_open_here_warns_then_asks_the_passphrase() {
    let (file, locked) = root("not-here");
    let mut prompt = Counting::new([PASSPHRASE])
        .at_this_mac(Health::Live)
        .touching([Touched::NotHere]);
    opened(&mut prompt, &file, &locked, Asked::Root).unwrap();
    assert_eq!(prompt.touches().len(), 1);
    assert_eq!(prompt.events(), 1);
    assert!(
        prompt.said()[1].starts_with("warning: touch-id does not open your root on this Mac now"),
        "{:?}",
        prompt.said()
    );
}

/// A touch that fails (a lock someone else made with this Mac's enclave reads live, then fails at the
/// unwrap) says so, then asks the passphrase, and never a second touch.
#[test]
fn a_failed_touch_says_so_then_asks_the_passphrase() {
    let (file, locked) = root("failed");
    let mut prompt = Counting::new([PASSPHRASE])
        .at_this_mac(Health::Live)
        .touching([Touched::Failed(eyre::eyre!("the unwrap refused"))]);
    opened(&mut prompt, &file, &locked, Asked::Root).unwrap();
    assert_eq!(prompt.touches().len(), 1);
    assert_eq!(prompt.events(), 1);
    assert_eq!(
        prompt.said()[1],
        "touch-id did not open your root: the unwrap refused"
    );
}

/// A timeout ends the command and never falls to the passphrase: the dialog may still be up. Red when it
/// falls through.
#[test]
fn a_timed_out_touch_ends_and_asks_no_passphrase() {
    let (file, locked) = root("timed-out");
    let mut prompt = Counting::new([PASSPHRASE])
        .at_this_mac(Health::Live)
        .touching([Touched::TimedOut]);
    let refused = opened(&mut prompt, &file, &locked, Asked::Root).unwrap_err();
    assert_eq!(format!("{refused:#}"), TIMED_OUT);
    assert_eq!(prompt.events(), 0, "no passphrase after a timeout");
}

/// A lock the enclave reads dead shows no dialog: the root's line leads with setting it again, after the
/// check on a fingerprint nobody added, and names no finger to remove. Red when a dead lock is touched.
#[test]
fn a_dead_root_lock_shows_no_dialog_and_leads_with_setting_it_again() {
    let (file, locked) = root("dead");
    let mut prompt = Counting::new([PASSPHRASE]).at_this_mac(Health::Dead);
    opened(&mut prompt, &file, &locked, Asked::Root).unwrap();
    assert!(prompt.touches().is_empty(), "no dialog for a dead lock");
    assert_eq!(
        prompt.warned(),
        [
            "warning: touch-id does not open your root on this Mac now.\n\
             check Touch ID & Password for a fingerprint you did not add, then set touch-id again: swoosh \
             root lock touch-id"
        ]
    );
}

/// A copy's dead line names the copy's directory in the command that sets it again.
#[test]
fn a_dead_lock_on_a_copy_names_the_copy() {
    let (file, locked) = root("dead-copy");
    let dir = PathBuf::from("/Volumes/key/swoosh-root");
    let mut prompt = Counting::new([PASSPHRASE]).at_this_mac(Health::Dead);
    opened(&mut prompt, &file, &locked, Asked::Copy(&dir)).unwrap();
    assert!(
        prompt.said()[0].ends_with("swoosh root lock touch-id /Volumes/key/swoosh-root"),
        "{:?}",
        prompt.said()
    );
}

/// A lock that cannot be checked now shows no dialog, never reads as dead, and asks the passphrase. Red
/// when an unchecked lock says it does not open.
#[test]
fn an_unchecked_lock_is_never_called_dead() {
    let (file, locked) = root("unchecked");
    let mut prompt = Counting::new([PASSPHRASE]).at_this_mac(Health::Unchecked);
    opened(&mut prompt, &file, &locked, Asked::Root).unwrap();
    assert!(prompt.touches().is_empty());
    assert_eq!(prompt.said().len(), 1);
    assert!(prompt.said()[0].starts_with("touch-id cannot be checked now"));
    assert!(!prompt.said()[0].contains("does not open"));
}

/// Over ssh no touch is asked, and the line names the variable that said so. Red when the variable is not
/// named, or a touch is asked.
#[test]
fn over_ssh_no_touch_is_asked_and_the_variable_is_named() {
    let (file, locked) = root("ssh");
    let mut prompt = Counting::new([PASSPHRASE])
        .here(TouchHere::OverSsh("SSH_TTY"))
        .touching([Touched::Opened(Some(secret(0x21)))]);
    opened(&mut prompt, &file, &locked, Asked::Root).unwrap();
    assert!(prompt.touches().is_empty());
    assert_eq!(
        prompt.said(),
        ["touch-id is not asked over ssh (SSH_TTY is set)."]
    );
}

/// With no terminal, nothing is touched; the passphrase prompt that follows refuses for want of one.
#[test]
fn with_no_terminal_no_touch_is_asked() {
    let (file, locked) = root("no-terminal");
    let prompt = Counting::refusing().here(TouchHere::NoTerminal);
    assert_eq!(
        route(&prompt, &file, &locked, Asked::Root),
        Route::Passphrase(None)
    );
}

/// A build with no enclave never names `touch-id` on the way to the passphrase.
#[test]
fn a_build_with_no_enclave_says_nothing_of_touch_id() {
    let (file, locked) = root("no-enclave");
    let prompt = Counting::refusing();
    assert_eq!(
        route(&prompt, &file, &locked, Asked::Root),
        Route::Passphrase(None)
    );
}

/// A file with no `touch-id` lock goes straight to its passphrase, whatever the Mac says.
#[test]
fn a_file_with_no_touch_id_lock_asks_its_passphrase() {
    let path = scratch("passphrase-only").join("machine").join("key");
    let file = KeyFile::device(&path);
    let under =
        keystore::Passphrase::try_from(zeroize::Zeroizing::new(PASSPHRASE.to_owned())).unwrap();
    file.write(&secret(0x11), keystore::Protection::Passphrase(&under))
        .unwrap();
    let (file, locked) = loaded(file);
    let prompt = Counting::refusing().at_this_mac(Health::Live);
    assert_eq!(
        route(&prompt, &file, &locked, Asked::MachineKey),
        Route::Passphrase(None)
    );
}

/// This machine's key under `touch-id` alone opens by the touch.
#[test]
fn a_machine_key_under_touch_id_alone_opens_by_the_touch() {
    let (file, locked) = machine("alone-live", &DEVICE_TOUCH_ID_ALONE, false);
    let mut prompt = Counting::refusing()
        .at_this_mac(Health::Live)
        .touching([Touched::Opened(Some(secret(0x11)))]);
    let key = opened(&mut prompt, &file, &locked, Asked::MachineKey).unwrap();
    assert_eq!(key, locked.public_key());
    assert_eq!(
        prompt.said(),
        ["waiting for touch-id to use this machine's key…"]
    );
}

/// With no passphrase to fall to, a cancel refuses, and nothing more is asked. Red when it routes by the
/// key's kind rather than its locks.
#[test]
fn a_touch_id_only_key_refuses_a_cancel() {
    let (file, locked) = machine("alone-declined", &DEVICE_TOUCH_ID_ALONE, false);
    let mut prompt = Counting::new([PASSPHRASE])
        .at_this_mac(Health::Live)
        .touching([Touched::Declined]);
    let refused = opened(&mut prompt, &file, &locked, Asked::MachineKey).unwrap_err();
    assert_eq!(
        format!("{refused:#}"),
        "touch-id was cancelled; this machine's key was not opened"
    );
    assert_eq!(prompt.events(), 0);
    assert_eq!(prompt.touches().len(), 1);
}

/// Where no root is kept, a dead one-lock key leads with removing the added finger, then a new key, which
/// `leave --new-key` gives.
#[test]
fn a_dead_touch_id_only_key_names_the_finger_then_a_new_key() {
    let (file, locked) = machine("alone-dead", &DEVICE_TOUCH_ID_ALONE, false);
    let mut prompt = Counting::refusing().at_this_mac(Health::Dead);
    let refused = opened(&mut prompt, &file, &locked, Asked::MachineKey).unwrap_err();
    assert_eq!(
        format!("{refused:#}"),
        "touch-id does not open this machine's key on this Mac now.\n\
         if you added a fingerprint, removing it lets touch-id open the key again.\n\
         otherwise, give this machine a new key and join again: swoosh leave --new-key"
    );
    assert!(prompt.touches().is_empty());
}

/// Beside a root kept here, `leave` refuses, so the dead line names the finger and no command. Red when it
/// names `leave`.
#[test]
fn a_dead_touch_id_only_key_beside_a_root_names_no_command() {
    let (file, locked) = machine("alone-dead-root", &DEVICE_TOUCH_ID_ALONE, true);
    let mut prompt = Counting::refusing().at_this_mac(Health::Dead);
    let refused = opened(&mut prompt, &file, &locked, Asked::MachineKey).unwrap_err();
    let refused = format!("{refused:#}");
    assert!(!refused.contains("swoosh"), "{refused}");
    assert!(refused.contains("removing it"), "{refused}");
}

/// Over ssh, a key with no passphrase refuses and names the variable.
#[test]
fn over_ssh_a_touch_id_only_key_refuses_naming_the_variable() {
    let (file, locked) = machine("alone-ssh", &DEVICE_TOUCH_ID_ALONE, false);
    let mut prompt = Counting::refusing().here(TouchHere::OverSsh("SSH_CONNECTION"));
    let refused = opened(&mut prompt, &file, &locked, Asked::MachineKey).unwrap_err();
    assert!(
        format!("{refused:#}").contains("(SSH_CONNECTION is set)"),
        "{refused:#}"
    );
}

/// With no terminal (a service manager), a key with no passphrase refuses, and no touch is asked.
#[test]
fn with_no_terminal_a_touch_id_only_key_refuses() {
    let (file, locked) = machine("alone-no-terminal", &DEVICE_TOUCH_ID_ALONE, false);
    let mut prompt = Counting::refusing().here(TouchHere::NoTerminal);
    let refused = opened(&mut prompt, &file, &locked, Asked::MachineKey).unwrap_err();
    assert!(
        format!("{refused:#}").contains("needs a person at a terminal"),
        "{refused:#}"
    );
    assert!(prompt.touches().is_empty());
}

/// A machine key with a passphrase beside the touch takes the root's path: a dead lock falls to the
/// passphrase, with the line naming `lock touch-id`. Red when it routes by kind and refuses.
#[test]
fn a_two_lock_machine_key_falls_to_its_passphrase() {
    let (file, locked) = machine("two-dead", &DEVICE_PASSPHRASE_AND_TOUCH_ID, true);
    let mut prompt = Counting::new([PASSPHRASE]).at_this_mac(Health::Dead);
    let key = opened(&mut prompt, &file, &locked, Asked::MachineKey).unwrap();
    assert_eq!(key, locked.public_key());
    assert!(
        prompt.said()[0].ends_with("then set touch-id again: swoosh lock touch-id"),
        "{:?}",
        prompt.said()
    );
}

/// The real enclave, through the product's own wait: a key locked by a touch, then opened by another, each
/// its own dialog. Run on an unlocked Mac with Touch ID, touching each dialog:
/// `cargo test --lib -- --ignored the_terminal_touch`.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs a finger on this Mac's Touch ID sensor"]
fn the_terminal_touch_locks_then_opens_a_key() {
    use crate::passphrase::{Prompt as _, Terminal};

    let file = KeyFile::device(scratch("hardware-opens").join("machine").join("key"));
    let made = Touch {
        file: file.clone(),
        reason: "make a test key (touch to allow)",
        act: TouchAct::Write(secret(0x51)),
    };
    assert!(matches!(Terminal.touch(made), Touched::Opened(None)));
    let (file, locked) = loaded(file);
    assert_eq!(Terminal.health(&locked), Some(Health::Live));
    let open = Touch {
        file,
        reason: "open the test key (touch to allow)",
        act: TouchAct::Open,
    };
    let Touched::Opened(Some(opened)) = Terminal.touch(open) else {
        panic!("the touch did not open the key");
    };
    assert_eq!(opened.public_key(), locked.public_key());
}

/// The real enclave: a cancelled dialog reads as a cancel, never a failure, so it falls to the passphrase.
/// Run as above, pressing Cancel on the second dialog.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs a person at this Mac to cancel the dialog"]
fn the_terminal_touch_reads_a_cancel_as_declined() {
    use crate::passphrase::{Prompt as _, Terminal};

    let file = KeyFile::device(scratch("hardware-cancel").join("machine").join("key"));
    let made = Touch {
        file: file.clone(),
        reason: "make a test key (touch to allow)",
        act: TouchAct::Write(secret(0x52)),
    };
    assert!(matches!(Terminal.touch(made), Touched::Opened(None)));
    let open = Touch {
        file,
        reason: "open the test key (press Cancel)",
        act: TouchAct::Open,
    };
    assert!(matches!(Terminal.touch(open), Touched::Declined));
}

/// The real enclave: a dialog left untouched for a minute ends the wait as a timeout, through the key
/// store's own refusal and [`Touched::from`]. Run as above and touch nothing on the second dialog; the
/// dialog must close by itself at the minute, before the test ends.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "needs a person at this Mac to leave the dialog for a minute"]
fn the_terminal_touch_times_out_after_a_minute() {
    use crate::passphrase::{Prompt as _, Terminal};

    let file = KeyFile::device(scratch("hardware-timeout").join("machine").join("key"));
    let made = Touch {
        file: file.clone(),
        reason: "make a test key (touch to allow)",
        act: TouchAct::Write(secret(0x53)),
    };
    assert!(matches!(Terminal.touch(made), Touched::Opened(None)));
    let started = std::time::Instant::now();
    let open = Touch {
        file,
        reason: "open the test key (touch nothing)",
        act: TouchAct::Open,
    };
    assert!(matches!(Terminal.touch(open), Touched::TimedOut));
    assert!(started.elapsed() >= TOUCH_WAIT);
}

/// Each lock-changing act against the real enclave, through the product's own wait: the lock list after
/// is the one the act is for. Run on an unlocked Mac with Touch ID, touching every dialog:
/// `cargo test --lib -- --ignored the_terminal_act`.
#[cfg(target_os = "macos")]
mod hardware_acts {
    use keystore::{KeyFile, Method, Protection, Stored};

    use super::{PASSPHRASE, Touch, TouchAct, Touched, scratch, secret};
    use crate::passphrase::{Prompt as _, Terminal};
    use crate::touch::Then;

    fn passphrase(text: &str) -> keystore::Passphrase {
        keystore::Passphrase::try_from(zeroize::Zeroizing::new(text.to_owned())).unwrap()
    }

    /// A machine key in a fresh home, written under `protection`.
    fn written(tag: &str, protection: Protection<'_>) -> KeyFile {
        let file = KeyFile::device(scratch(tag).join("machine").join("key"));
        file.write(&secret(0x61), protection).unwrap();
        file
    }

    /// A machine key in a fresh home, sealed by a first touch under `touch-id` alone.
    fn touched(tag: &str) -> KeyFile {
        let file = KeyFile::device(scratch(tag).join("machine").join("key"));
        let made = Touch {
            file: file.clone(),
            reason: "make a test key (touch to allow)",
            act: TouchAct::Write(secret(0x61)),
        };
        assert!(matches!(Terminal.touch(made), Touched::Opened(None)));
        file
    }

    /// Run `act` on `file` by one real touch, and read the lock list after.
    fn after(file: &KeyFile, act: TouchAct) -> Vec<Method> {
        let touch = Touch {
            file: file.clone(),
            reason: "change the test key's locks (touch to allow)",
            act,
        };
        let touched = Terminal.touch(touch);
        assert!(matches!(touched, Touched::Opened(None)), "{touched:?}");
        match file.load().unwrap() {
            Some(Stored::Locked(locked)) => locked.methods().collect(),
            Some(Stored::Plain(_)) => Vec::new(),
            None => panic!("the key is gone"),
        }
    }

    #[test]
    #[ignore = "needs a finger on this Mac's Touch ID sensor"]
    fn the_terminal_act_seals_a_plain_key() {
        let file = written("hardware-seal-plain", Protection::Plain);
        assert_eq!(after(&file, TouchAct::SealPlain), [Method::TouchId]);
    }

    #[test]
    #[ignore = "needs a finger on this Mac's Touch ID sensor"]
    fn the_terminal_act_puts_touch_id_beside_the_passphrase() {
        let under = passphrase(PASSPHRASE);
        let file = written("hardware-beside-keep", Protection::Passphrase(&under));
        let act = TouchAct::BesidePassphrase {
            current: passphrase(PASSPHRASE),
            then: Then::Keep,
        };
        assert_eq!(after(&file, act), [Method::Passphrase, Method::TouchId]);
    }

    #[test]
    #[ignore = "needs a finger on this Mac's Touch ID sensor"]
    fn the_terminal_act_replaces_the_passphrase_with_touch_id() {
        let under = passphrase(PASSPHRASE);
        let file = written("hardware-beside-drop", Protection::Passphrase(&under));
        let act = TouchAct::BesidePassphrase {
            current: passphrase(PASSPHRASE),
            then: Then::Drop,
        };
        assert_eq!(after(&file, act), [Method::TouchId]);
    }

    #[test]
    #[ignore = "needs a finger on this Mac's Touch ID sensor"]
    fn the_terminal_act_adds_a_passphrase_beside_touch_id() {
        let file = touched("hardware-add-keep");
        let act = TouchAct::AddPassphrase {
            new: passphrase(PASSPHRASE),
            then: Then::Keep,
        };
        assert_eq!(after(&file, act), [Method::TouchId, Method::Passphrase]);
    }

    #[test]
    #[ignore = "needs a finger on this Mac's Touch ID sensor"]
    fn the_terminal_act_replaces_touch_id_with_a_passphrase() {
        let file = touched("hardware-add-drop");
        let act = TouchAct::AddPassphrase {
            new: passphrase(PASSPHRASE),
            then: Then::Drop,
        };
        assert_eq!(after(&file, act), [Method::Passphrase]);
    }

    #[test]
    #[ignore = "needs a finger on this Mac's Touch ID sensor"]
    fn the_terminal_act_removes_touch_id() {
        let file = touched("hardware-remove");
        assert_eq!(after(&file, TouchAct::RemoveTouchId), Vec::<Method>::new());
    }
}
