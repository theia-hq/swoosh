//! `swoosh root backup <dir>`: two files, locked as stored, into a directory of their own.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use swoosh::home::Home;

use super::BackupCmd;
use crate::commands::invite::invite_tests::{
    LAPTOP, OWN, held, holds, live, records, scratch, snapshot,
};

/// Run `swoosh root backup <dir>` on `home`: the result, and stderr.
async fn backup(home: &Home, dir: &Path) -> (eyre::Result<()>, String) {
    let mut err = Vec::new();
    let result = BackupCmd {
        dir: dir.to_path_buf(),
    }
    .backup(home, &mut err)
    .await;
    (result, String::from_utf8(err).unwrap())
}

/// A directory beside `home` that does not exist yet.
fn stick(home: &Home) -> PathBuf {
    let dir = home.dir().with_extension("stick");
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A backup is `root.key` and `devices`, owner-only, in a new owner-only directory, and nothing else. Red
/// when it copies `links`, `root/` or any other file.
#[tokio::test]
async fn root_backup_writes_root_key_and_devices_only() {
    let home = scratch("backup-two");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    std::fs::write(home.links(), "a link").unwrap();
    let dir = stick(&home);
    let (result, err) = backup(&home, &dir).await;
    result.unwrap();
    assert_eq!(names(&dir), ["devices", "root.key"]);
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("root.key")), 0o600);
    assert_eq!(mode(&dir.join("devices")), 0o600);
    assert_eq!(
        std::fs::read(dir.join("devices")).unwrap(),
        std::fs::read(home.devices()).unwrap()
    );
    let shown = dir.display();
    assert_eq!(
        err,
        format!(
            "copied your root to {shown}. Your root is still on this machine; to take it off: swoosh root \
             forget {shown}\n"
        )
    );
    assert!(home.root_key().exists(), "the root stays on this machine");
}

/// A directory holding anything else is refused and left as it was; one holding a copy of this same root is
/// brought up to date. Red when a backup writes over another directory.
#[tokio::test]
async fn root_backup_refuses_a_directory_that_is_not_empty() {
    let home = scratch("backup-full");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    swoosh::config::create_store_dir(&dir).unwrap();
    std::fs::write(dir.join("notes.txt"), "mine").unwrap();
    let before = snapshot(&dir);
    let (refused, _) = backup(&home, &dir).await;
    let shown = dir.display();
    assert_eq!(
        format!("{:#}", refused.unwrap_err()),
        format!(
            "{shown} is not empty; name a new directory: swoosh root backup {shown}/swoosh-root"
        )
    );
    assert!(snapshot(&dir) == before, "the directory is left as it was");

    // A copy of this root, behind this machine: brought up to date.
    let dir = stick(&home);
    backup(&home, &dir).await.0.unwrap();
    held(
        &home,
        &records(2, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new()),
    );
    backup(&home, &dir).await.0.unwrap();
    assert_eq!(
        std::fs::read(dir.join("devices")).unwrap(),
        std::fs::read(home.devices()).unwrap(),
        "the copy's list is this machine's"
    );
}

/// A run killed after `devices` and before `root.key` leaves a directory the next run finishes. Red when
/// that directory is refused as not empty.
#[tokio::test]
async fn root_backup_killed_before_the_key_is_finished_by_running_it_again() {
    let home = scratch("backup-killed");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    swoosh::config::create_store_dir(&dir).unwrap();
    std::fs::copy(home.devices(), dir.join("devices")).unwrap();
    backup(&home, &dir).await.0.unwrap();
    assert_eq!(names(&dir), ["devices", "root.key"]);
}

/// A backup asks for nothing and unlocks nothing: the key is copied as it is stored, byte for byte. Red when
/// the root is presented (a prompt) or sealed again.
#[tokio::test]
async fn root_backup_asks_no_passphrase() {
    let home = scratch("backup-no-prompt");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    // `BackupCmd::backup` takes no prompt: there is no way to ask. The key's bytes show nothing was sealed.
    backup(&home, &dir).await.0.unwrap();
    assert_eq!(
        std::fs::read(dir.join("root.key")).unwrap(),
        std::fs::read(home.root_key()).unwrap()
    );
}

/// On a machine with no root, the refusal says a device is replaced, not restored. Red when the generic
/// refusal prints.
#[tokio::test]
async fn root_backup_with_no_root_here_names_invite() {
    let home = scratch("backup-device");
    let (refused, _) = backup(&home, &stick(&home)).await;
    assert_eq!(
        format!("{:#}", refused.unwrap_err()),
        "this machine holds no root, so there is nothing to back up. A lost device is replaced, not \
         restored: invite a new one."
    );

    // On a device of a root kept elsewhere: back it up where it is kept.
    crate::commands::invite::invite_tests::device_of(&home, &live(OWN, "desk")).await;
    let (refused, _) = backup(&home, &stick(&home)).await;
    assert_eq!(
        format!("{:#}", refused.unwrap_err()),
        "your root is not on this machine; back it up on the machine that keeps it."
    );
}

/// A run killed during its first write leaves only its temp: the next run finishes, and removes the temp.
/// Red when a directory of temps is refused as not empty.
#[tokio::test]
async fn root_backup_killed_during_its_first_write_is_finished_by_running_it_again() {
    let home = scratch("backup-killed-first");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    swoosh::config::create_store_dir(&dir).unwrap();
    std::fs::write(dir.join("devices.tmp.1.0"), b"half a list").unwrap();
    backup(&home, &dir).await.0.unwrap();
    assert_eq!(names(&dir), ["devices", "root.key"], "the temp is gone");
}

/// A copy whose `root.key` names this root but is not this machine's key, byte for byte, is replaced, never
/// kept and reported as copied. Red when the header alone decides.
#[tokio::test]
async fn root_backup_replaces_a_copy_key_that_differs() {
    let home = scratch("backup-key-differs");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    backup(&home, &dir).await.0.unwrap();
    // Flip a byte past the header: the header still names the root, and the key no longer opens.
    let mut bytes = std::fs::read(dir.join("root.key")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(dir.join("root.key"), &bytes).unwrap();
    backup(&home, &dir).await.0.unwrap();
    assert_eq!(
        std::fs::read(dir.join("root.key")).unwrap(),
        std::fs::read(home.root_key()).unwrap()
    );
}

/// An empty directory the backup adopts is made owner-only, as one it makes is. Red when its mode is kept.
#[tokio::test]
async fn root_backup_into_an_empty_directory_makes_it_owner_only() {
    let home = scratch("backup-empty-dir");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    backup(&home, &dir).await.0.unwrap();
    assert_eq!(mode(&dir), 0o700);
}

/// A planted pipe named `devices` is refused without blocking: the read checks the file's type first, and
/// nothing holds `home.lock` while it is judged. Red when the read blocks on the pipe.
#[tokio::test]
async fn root_backup_refuses_a_planted_pipe_without_blocking() {
    let home = scratch("backup-fifo");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    swoosh::config::create_store_dir(&dir).unwrap();
    let fifo = std::ffi::CString::new(dir.join("devices").to_str().unwrap()).unwrap();
    // SAFETY: `fifo` is a live NUL-terminated path for the length of the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    // On a thread of its own, so a blocking open stalls that thread and never the one that waits here: the
    // wait then runs out and the test fails, rather than hanging with the timer it would wait on.
    let (sent, got) = std::sync::mpsc::channel();
    let (blocked, at) = (home.clone(), dir.clone());
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = sent.send(runtime.block_on(backup(&blocked, &at)).0);
    });
    let refused = got
        .recv_timeout(core::time::Duration::from_secs(5))
        .expect("the backup does not block");
    assert!(
        format!("{:#}", refused.unwrap_err()).contains("is not empty"),
        "a pipe is no list"
    );
}

/// A directory that cannot be read says why once. Red when the reason prints twice.
#[tokio::test]
async fn root_backup_into_an_unreadable_directory_says_why_once() {
    let home = scratch("backup-unreadable");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let dir = stick(&home);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (result, _) = backup(&home, &dir).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        format!(
            "could not read {}: {}",
            dir.display(),
            std::io::Error::from_raw_os_error(libc::EACCES)
        )
    );
}
