//! How a key file with a `touch-id` lock opens: the gates before any dialog, the fall to the passphrase or
//! the refusal after one, the wait, and the lines each says. The touch itself is the script's; the
//! files are the testkit's fixtures, so every lock list and passphrase here is real.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::ffi::OsString;
use std::path::PathBuf;

use keystore::{Health, Method, Stored};

// The touch itself is built only by the hardware tests, which run on a Mac.
#[cfg(target_os = "macos")]
use super::Touch;
use super::{
    Reason, Route, SSH_VARIABLES, TIMED_OUT, TOUCH_WAIT, TouchAct, TouchHere, Touched,
    USE_MACHINE_KEY, USE_ROOT, open, over_ssh, route,
};
use crate::home::Home;
use crate::key_file::KeyFile;
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

/// The home at `dir`.
fn home_at(dir: PathBuf) -> Home {
    Home::resolve(Some(dir)).unwrap()
}

/// `bytes` written owner-only at `path`, as the key store requires.
fn private(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// The root fixture, kept in a home: its key file and its locked form.
fn root(tag: &str) -> (KeyFile, keystore::Locked) {
    let dir = scratch(tag);
    private(&dir.join("root.key"), &ROOT_PASSPHRASE_AND_TOUCH_ID);
    loaded(KeyFile::root(&home_at(dir)))
}

/// `bytes` as this machine's key in a home, beside a root when `root_kept`.
fn machine(tag: &str, bytes: &[u8], root_kept: bool) -> (KeyFile, keystore::Locked) {
    let home = scratch(tag);
    if root_kept {
        private(&home.join("root.key"), b"a root kept here");
    }
    private(&home.join("machine").join("key"), bytes);
    loaded(KeyFile::machine(&home_at(home)))
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
    open(prompt, file, locked, asked, Reason::to_use(USE_ROOT)).map(|secret| secret.public_key())
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
        Touched::from(Err(any_file().refuse(unavailable))),
        Touched::NotHere
    ));
    let unlock = keystore::Error::Unlock {
        path: PathBuf::from("key"),
        method: Method::TouchId,
    };
    assert!(matches!(
        Touched::from(Err(any_file().refuse(unlock))),
        Touched::Failed(_)
    ));
    assert!(matches!(Touched::from(Ok(None)), Touched::Opened(None)));
}

/// The key store's touch-id refusal `source`, carried as the call that asks the touch stopped, read as a
/// touch's end. Each refusal below carries what the enclave said, built here as the key store lets a
/// dependent build it, so every arm of the mapping is guarded off a Mac and without a finger.
fn refused(source: keystore::TouchIdError) -> Touched {
    Touched::from(Err(any_file().refuse(keystore::Error::TouchId {
        path: PathBuf::from("key"),
        source,
    })))
}

/// A machine key file in a home nothing writes, for a refusal built by hand.
fn any_file() -> KeyFile {
    KeyFile::machine(&home_at(std::env::temp_dir().join("swoosh-touch-any")))
}

/// What the enclave said, for a refusal that must carry it.
fn enclave(said: &str) -> keystore::EnclaveError {
    keystore::EnclaveError::new(std::io::Error::other(said.to_owned()))
}

/// No touch in time reads as a timeout, never a cancel or a failure: a failure falls to the passphrase,
/// and nobody who let the dialog run out is there to type one. Red when the timeout's arm is dropped to
/// the catch-all or mapped to any other end.
#[test]
fn no_touch_in_time_reads_as_a_timeout() {
    let touched = refused(keystore::TouchIdError::TimedOut(enclave("no touch")));
    assert!(matches!(touched, Touched::TimedOut), "{touched:?}");
}

/// A cancel or a touch that did not match reads as declined. Red when it reads as a failure, which would
/// say the touch failed when the person only said no.
#[test]
fn a_cancel_reads_as_declined() {
    let touched = refused(keystore::TouchIdError::Declined(enclave("cancelled")));
    assert!(matches!(touched, Touched::Declined), "{touched:?}");
}

/// A lock the enclave turned down after the dialog reads as one that does not open on this Mac, never a
/// cancel. Red when it reads as declined or as a failure.
#[test]
fn a_lock_the_enclave_turns_down_reads_as_not_here() {
    let touched = refused(keystore::TouchIdError::NotHere(enclave("not this Mac")));
    assert!(matches!(touched, Touched::NotHere), "{touched:?}");
}

/// The enclave's own failure reads as a failure, in swoosh's words alone: what the enclave said stays at
/// `debug`. Red when it reads as a refusal a person made, or the enclave's text reaches the line.
#[test]
fn an_enclave_failure_reads_as_a_failure_in_swooshs_words() {
    let touched = refused(keystore::TouchIdError::Enclave(enclave("it broke")));
    let Touched::Failed(why) = touched else {
        panic!("{touched:?}");
    };
    assert_eq!(
        format!("{why:#}"),
        "Touch ID could not open this machine's key"
    );
}

/// A change whose touch ended in a refusal of the key file, not of the touch, says that refusal in its own
/// words: Touch ID is named only where the touch itself failed. Red when a key file refusal reads as a touch
/// that did not open, or prints the key store's text.
#[test]
fn a_change_refused_by_its_key_file_says_the_files_words() {
    let file = any_file();
    let lines = super::Lines::of(Asked::MachineKey, &file, true);
    let io = keystore::Error::Io {
        path: PathBuf::from("/elsewhere/key"),
        source: std::io::Error::other("the disk went away"),
    };
    let refused =
        super::changed(Touched::Failed(eyre::Report::new(file.refuse(io))), &lines).unwrap_err();
    assert_eq!(
        format!("{refused:#}"),
        format!(
            "could not access this machine's key file\n  file   {}",
            crate::escape::peer_cell(
                &file.path().to_string_lossy(),
                crate::escape::room("  file   ".len())
            )
        )
    );
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
    // The act, not the command: the command is a process's, set or not by whatever ran first.
    assert!(matches!(
        prompt.touches()[0].reason,
        Reason::Use { act: USE_ROOT, .. }
    ));
    assert_eq!(prompt.said(), ["Touch the sensor to use your root…"]);
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
    assert_eq!(prompt.said(), ["Touch the sensor to use your root…"]);
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
        prompt.said()[1].starts_with("warning: Touch ID does not open your root on this Mac now"),
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
        "Touch ID did not open your root\n  failure   the unwrap refused"
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
            "warning: Touch ID does not open your root on this Mac now.\n\
             check Touch ID & Password for a fingerprint you did not add, then set Touch ID again: swoosh \
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
    assert!(prompt.said()[0].starts_with("Touch ID cannot be checked now"));
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
        ["Touch ID is not asked over ssh (SSH_TTY is set)."]
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
    let file = KeyFile::machine(&home_at(scratch("passphrase-only")));
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
        ["Touch the sensor to use this machine's key…"]
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
        "Touch ID was cancelled; this machine's key was not opened"
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
        "Touch ID does not open this machine's key on this Mac now.\n\
         if you added a fingerprint, removing it lets Touch ID open the key again.\n\
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
        prompt.said()[0].ends_with("then set Touch ID again: swoosh lock touch-id"),
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

    let file = KeyFile::machine(&home_at(scratch("hardware-opens")));
    let made = Touch {
        file: file.clone(),
        reason: Reason::Change("make a test key (touch to allow)"),
        act: TouchAct::Write(secret(0x51)),
    };
    assert!(matches!(Terminal.touch(made), Touched::Opened(None)));
    let (file, locked) = loaded(file);
    assert_eq!(Terminal.health(&locked), Some(Health::Live));
    let open = Touch {
        file,
        reason: Reason::Change("open the test key (touch to allow)"),
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

    let file = KeyFile::machine(&home_at(scratch("hardware-cancel")));
    let made = Touch {
        file: file.clone(),
        reason: Reason::Change("make a test key (touch to allow)"),
        act: TouchAct::Write(secret(0x52)),
    };
    assert!(matches!(Terminal.touch(made), Touched::Opened(None)));
    let open = Touch {
        file,
        reason: Reason::Change("open the test key (press Cancel)"),
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

    let file = KeyFile::machine(&home_at(scratch("hardware-timeout")));
    let made = Touch {
        file: file.clone(),
        reason: Reason::Change("make a test key (touch to allow)"),
        act: TouchAct::Write(secret(0x53)),
    };
    assert!(matches!(Terminal.touch(made), Touched::Opened(None)));
    let started = std::time::Instant::now();
    let open = Touch {
        file,
        reason: Reason::Change("open the test key (touch nothing)"),
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
    use keystore::{Method, Protection, Stored};

    use super::{PASSPHRASE, Reason, Touch, TouchAct, Touched, home_at, scratch, secret};
    use crate::key_file::KeyFile;
    use crate::passphrase::{Prompt as _, Terminal};

    fn passphrase(text: &str) -> keystore::Passphrase {
        keystore::Passphrase::try_from(zeroize::Zeroizing::new(text.to_owned())).unwrap()
    }

    /// A machine key in a fresh home, written under `protection`.
    fn written(tag: &str, protection: Protection<'_>) -> KeyFile {
        let file = KeyFile::machine(&home_at(scratch(tag)));
        file.write(&secret(0x61), protection).unwrap();
        file
    }

    /// A machine key in a fresh home, sealed by a first touch under `touch-id` alone.
    fn touched(tag: &str) -> KeyFile {
        let file = KeyFile::machine(&home_at(scratch(tag)));
        let made = Touch {
            file: file.clone(),
            reason: Reason::Change("make a test key (touch to allow)"),
            act: TouchAct::Write(secret(0x61)),
        };
        assert!(matches!(Terminal.touch(made), Touched::Opened(None)));
        file
    }

    /// Run `act` on `file` by one real touch, and read the lock list after.
    fn after(file: &KeyFile, act: TouchAct) -> Vec<Method> {
        let touch = Touch {
            file: file.clone(),
            reason: Reason::Change("change the test key's locks (touch to allow)"),
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
        };
        assert_eq!(after(&file, act), [Method::Passphrase, Method::TouchId]);
    }

    #[test]
    #[ignore = "needs a finger on this Mac's Touch ID sensor"]
    fn the_terminal_act_adds_a_passphrase_beside_touch_id() {
        let file = touched("hardware-add-keep");
        let act = TouchAct::AddPassphrase {
            new: passphrase(PASSPHRASE),
        };
        assert_eq!(after(&file, act), [Method::TouchId, Method::Passphrase]);
    }

    #[test]
    #[ignore = "needs a finger on this Mac's Touch ID sensor"]
    fn the_terminal_act_removes_touch_id() {
        let file = touched("hardware-remove");
        assert_eq!(after(&file, TouchAct::RemoveTouchId), Vec::<Method>::new());
    }
}

/// Each act's waiting line and its dialog's reason name the same change, by the same verb, for every act a
/// touch is asked for: the line from [`Lines::waiting`](super::Lines::waiting), the reason from the touch built
/// for the act, both from one act. Red when `use` waits over an `add` or `remove` dialog, or a line or a reason
/// moves off its words.
#[test]
fn the_waiting_line_names_the_dialogs_act() {
    let passphrase =
        || keystore::Passphrase::try_from(zeroize::Zeroizing::new(PASSPHRASE.to_owned())).unwrap();
    let file = KeyFile::machine(&home_at(scratch("waiting-line")));
    let lines = super::Lines::of(Asked::MachineKey, &file, false);
    let root = super::Lines::of(Asked::Root, &file, true);
    let acts = [
        TouchAct::Open,
        TouchAct::Write(keystore::Secret::generate().unwrap()),
        TouchAct::SealPlain,
        TouchAct::BesidePassphrase {
            current: passphrase(),
        },
        TouchAct::AddPassphrase { new: passphrase() },
        TouchAct::RemoveTouchId,
    ];
    for act in acts {
        // Exhaustive, so an act with no row fails to compile here.
        let (waiting, reason) = match &act {
            TouchAct::Open => (
                "Touch the sensor to use this machine's key…",
                "use this machine's key",
            ),
            TouchAct::Write(_) => (
                "Touch the sensor to make this machine's key…",
                "make this machine's key",
            ),
            TouchAct::SealPlain | TouchAct::BesidePassphrase { .. } => (
                "Touch the sensor to add Touch ID…",
                "add Touch ID to this machine's key",
            ),
            TouchAct::AddPassphrase { .. } => (
                "Touch the sensor to add the passphrase…",
                "add a passphrase to this machine's key",
            ),
            TouchAct::RemoveTouchId => (
                "Touch the sensor to remove Touch ID…",
                "remove Touch ID from this machine's key",
            ),
        };
        assert_eq!(lines.waiting(act.act()), waiting);
        let verb = reason.split(' ').next().unwrap();
        assert!(
            waiting.starts_with(&format!("Touch the sensor to {verb} ")),
            "{waiting}"
        );
        // Only opening the key to use it may name a command; a change names itself alone.
        let opens = matches!(act, TouchAct::Open);
        // The act's words, read apart from any command this process may have named.
        let (words, uses) = match super::Touch::on_machine_key(file.clone(), act).reason {
            Reason::Change(words) => (words, false),
            Reason::Use { act, .. } => (act, true),
        };
        assert_eq!(words, reason);
        assert_eq!(uses, opens, "{reason}");
    }
    // Your root is used and gets Touch ID, by the reasons its callers name.
    assert_eq!(
        root.waiting(super::Act::Use),
        "Touch the sensor to use your root…"
    );
    assert_eq!(USE_ROOT, "use your root");
    assert_eq!(
        root.waiting(super::Act::Add),
        "Touch the sensor to add Touch ID…"
    );
    assert_eq!(super::CHECK_ROOT, "add Touch ID to your root");
}

/// A dialog that opens a key to use it names the command that asked, by its path, and only then: unnamed (a
/// library caller, a test) it says the bare act, and a change never carries a path. Red when the path is
/// dropped or moves off its words.
#[test]
fn the_use_reasons_name_the_command() {
    let named = |act, command| Reason::Use {
        act,
        command: Some(command),
    };
    assert_eq!(
        named(USE_MACHINE_KEY, "serve").to_string(),
        "use this machine's key for swoosh serve"
    );
    assert_eq!(
        named(USE_ROOT, "root restore").to_string(),
        "use your root for swoosh root restore"
    );
    // Unnamed, the bare act. Built whole rather than read from this process, so no other test can set it.
    let unnamed = |act| Reason::Use { act, command: None };
    assert_eq!(
        unnamed(USE_MACHINE_KEY).to_string(),
        "use this machine's key"
    );
    assert_eq!(unnamed(USE_ROOT).to_string(), "use your root");
    assert_eq!(
        Reason::Change(super::CHECK_ROOT).to_string(),
        "add Touch ID to your root"
    );
}

/// The lines said before a lock act, byte for byte: each is the ruled words, so a constant that drifts from
/// them goes red here, where the tests that place it would follow it. Red when any byte moves.
#[test]
fn the_lines_before_a_lock_act_are_the_ruled_words() {
    const EVERY: &str = "Every fingerprint in Touch ID & Password opens it.";
    const LATER: &str =
        "A fingerprint added later stops Touch ID opening this key until it is removed.";
    const ROOT: &str = "Your root is on this machine, so the key keeps a passphrase.\n\
                        A copy of the key file opens with the passphrase on any machine.";
    for (said, ruled) in [
        (
            super::BESIDE_TOUCH_ID,
            "This adds a passphrase beside Touch ID; either will open this machine's key.\n\
             A copy of the key file would then open with the passphrase on any machine."
                .to_owned(),
        ),
        (
            super::TOUCH_ID_BESIDE,
            format!(
                "This adds Touch ID beside the passphrase; either will open this machine's key.\n\
                 A copy of the key file still opens with the passphrase on any machine.\n{EVERY}"
            ),
        ),
        (
            super::CHANGES_TOUCH_ID,
            "This changes Touch ID on this machine's key.\nOnce changed, either lock will open it.\n\
             A copy of the key file still opens with the passphrase on any machine."
                .to_owned(),
        ),
        (
            super::MAKES_UNDER_PASSPHRASE,
            "This machine has no key yet.\nThis makes one that opens with a passphrase.".to_owned(),
        ),
        (
            super::MAKES_UNDER_TOUCH_ID,
            format!(
                "This machine has no key yet.\nThis makes one that only Touch ID on this Mac opens.\n\
                 {EVERY}\n{LATER}"
            ),
        ),
        (
            super::MAKES_BESIDE_ROOT,
            format!(
                "This machine has no key yet.\n\
                 This makes one that opens with Touch ID or a passphrase.\n{ROOT}\n{EVERY}"
            ),
        ),
        (
            super::SEALS_UNDER_PASSPHRASE,
            "This machine's key has no lock.\nThis adds a passphrase.".to_owned(),
        ),
        (
            super::SEALS_UNDER_TOUCH_ID,
            format!(
                "This machine's key has no lock.\n\
                 This adds Touch ID, so only Touch ID on this Mac opens it.\n{EVERY}\n{LATER}"
            ),
        ),
        (
            super::SEALS_BESIDE_ROOT,
            format!(
                "This machine's key has no lock.\nThis adds Touch ID and a passphrase.\n{ROOT}\n{EVERY}"
            ),
        ),
        (
            super::TAKES_PASSPHRASE_OFF,
            format!(
                "This takes the passphrase off.\n\
                 Only Touch ID on this Mac will then open this machine's key.\n{LATER}"
            ),
        ),
        (
            super::TAKES_TOUCH_ID_OFF,
            "This takes Touch ID off.\nOnly the passphrase will then open this machine's key."
                .to_owned(),
        ),
        (
            super::TAKES_LAST_LOCK_OFF,
            "This takes the last lock off this machine's key.\n\
             Anyone with a copy of its key file could then act as this machine."
                .to_owned(),
        ),
        (
            super::ROOT_BESIDE_PASSPHRASE,
            format!("Your root will open with Touch ID or its passphrase.\n{EVERY}"),
        ),
        (
            super::SHARED_FINGER,
            "Your root and this machine's key will both open with Touch ID on this Mac.\n\
             Any program running as you can ask for a touch with any words in the dialog,\n  \
             so touch it only for a command you just ran."
                .to_owned(),
        ),
        (
            crate::identity::TOUCH_ID_ALONE_BESIDE_ROOT,
            "this machine's key needs a passphrase beside Touch ID while your root is here:\n  \
             swoosh lock passphrase"
                .to_owned(),
        ),
        (
            crate::passphrase::NO_TERMINAL_FOR_KEY,
            "this machine's key has a passphrase and there is no terminal to type it at; start this from a \
             terminal"
                .to_owned(),
        ),
        (
            super::PASSPHRASE_STAYS_OFF_THE_MAC,
            "the passphrase stays: Touch ID opens this key only on the Mac that set it".to_owned(),
        ),
    ] {
        assert_eq!(said, ruled);
    }
}
