//! Unit tests for the home's two locks.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::path::PathBuf;

use super::{HomeWrite, ServeLock, ServeLockError};
use crate::home::Home;
use crate::testkit::TestRoot;

/// A fresh scratch home, removed by the caller.
fn scratch(name: &str) -> (Home, PathBuf) {
    let dir = std::env::temp_dir().join(format!("sw-homelock-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    (Home::resolve(Some(dir.clone())).unwrap(), dir)
}

/// A second taker of `home.lock` in this process waits for the first to let it go: the lock is per open
/// file, so the guard is what a caller passes down rather than taking it again.
#[tokio::test]
async fn a_second_taker_waits_for_the_first() {
    let (home, dir) = scratch("wait");
    let first = HomeWrite::take(&home).await.unwrap();
    let second = tokio::time::timeout(Duration::from_millis(200), HomeWrite::take(&home)).await;
    assert!(
        second.is_err(),
        "the second taker waits while the first holds it"
    );
    drop(first);
    let second = tokio::time::timeout(Duration::from_secs(5), HomeWrite::take(&home)).await;
    assert!(second.is_ok(), "and goes on once it is let go");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `serve.lock` has one holder at a time, records the running serve's pid and admitted root, and is
/// emptied when its holder lets it go.
#[tokio::test]
async fn serve_lock_has_one_holder_and_records_it() {
    let (home, dir) = scratch("serve");
    let root = TestRoot::seeded(0x41).node_id();
    let home_lock = HomeWrite::take(&home).await.unwrap();
    let held = ServeLock::take(&home_lock, &home).unwrap();
    held.record(&home_lock, Some(root)).unwrap();
    let second = ServeLock::take(&home_lock, &home);
    assert!(
        matches!(second, Err(ServeLockError::Held)),
        "a second taker is refused as held: {second:?}"
    );
    assert_eq!(ServeLock::admitting(&home_lock, &home).unwrap(), Some(root));
    let recorded = ServeLock::recorded(&home);
    assert_eq!(recorded.pid, Some(std::process::id()));
    assert_eq!(recorded.admit, Some(root));

    drop(held);
    assert_eq!(ServeLock::admitting(&home_lock, &home).unwrap(), None);
    assert_eq!(ServeLock::recorded(&home), super::Recorded::default());
    // flock belongs to the open file description, so a child a sibling test forks while `held` is open
    // shares the lock until its exec closes the O_CLOEXEC copy. A drop inside that window leaves the lock
    // held for a moment by no one this test owns, so the later take waits on a condition with a bound: a
    // drop that never let the lock go still fails here.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let again = loop {
        match ServeLock::take(&home_lock, &home) {
            Err(ServeLockError::Held) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            taken => break taken,
        }
    };
    assert!(again.is_ok(), "a later serve takes it: {again:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// What a serve that is no longer running left in `serve.lock` admits nothing.
#[tokio::test]
async fn a_root_left_by_a_stopped_serve_admits_nothing() {
    let (home, dir) = scratch("left");
    let root = TestRoot::seeded(0x42).node_id();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(home.serve_lock(), format!("1\n{root}\n")).unwrap();
    let home_lock = HomeWrite::take(&home).await.unwrap();
    assert_eq!(ServeLock::admitting(&home_lock, &home).unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn presence_uses_the_flock_without_mutating_or_retaining_it() {
    let (home, dir) = scratch("presence");
    let guard = HomeWrite::take(&home).await.unwrap();
    assert_eq!(
        ServeLock::presence(&guard, &home).unwrap(),
        super::ResidentPresence::Free
    );
    assert!(
        !home.serve_lock().exists(),
        "absence must not create a record"
    );
    for text in [
        String::new(),
        format!("{}\n", std::process::id()),
        "damaged\n".to_owned(),
    ] {
        std::fs::write(home.serve_lock(), &text).unwrap();
        assert_eq!(
            ServeLock::presence(&guard, &home).unwrap(),
            super::ResidentPresence::Free
        );
        assert_eq!(std::fs::read_to_string(home.serve_lock()).unwrap(), text);
        let held = ServeLock::take(&guard, &home).unwrap();
        // Empty/startup, PID-only and damaged records all remain held. No admitted root
        // or valid PID is required to exclude another holder.
        std::fs::write(home.serve_lock(), &text).unwrap();
        assert_eq!(
            ServeLock::presence(&guard, &home).unwrap(),
            super::ResidentPresence::Held
        );
        assert_eq!(std::fs::read_to_string(home.serve_lock()).unwrap(), text);
        drop(held);
    }
    let held = ServeLock::take(&guard, &home).unwrap();
    held.record(&guard, Some(TestRoot::seeded(0x43).node_id()))
        .unwrap();
    assert_eq!(
        ServeLock::presence(&guard, &home).unwrap(),
        super::ResidentPresence::Held
    );
    drop(held);
    drop(guard);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn presence_releases_both_locks_before_the_callers_next_wait() {
    let (home, dir) = scratch("released");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(home.serve_lock(), b"42\n").unwrap();
    let presence = home.resident_presence().await.unwrap();
    assert_eq!(presence, super::ResidentPresence::Free);
    let guard = tokio::time::timeout(Duration::from_secs(1), HomeWrite::take(&home))
        .await
        .unwrap()
        .unwrap();
    let held = ServeLock::take(&guard, &home).unwrap();
    // A later serve can start while the classification remains alive: it is no reservation.
    assert_eq!(presence, super::ResidentPresence::Free);
    drop(held);
    drop(guard);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn presence_and_checked_pid_fail_closed_on_nonregular_names() {
    let (home, dir) = scratch("names");
    let guard = HomeWrite::take(&home).await.unwrap();
    let path = home.serve_lock();
    std::fs::create_dir(&path).unwrap();
    assert!(ServeLock::presence(&guard, &home).is_err());
    assert!(ServeLock::checked_pid(&home).is_err());
    std::fs::remove_dir(&path).unwrap();
    for target in [home.home_lock(), dir.join("missing")] {
        std::os::unix::fs::symlink(target, &path).unwrap();
        assert!(ServeLock::presence(&guard, &home).is_err());
        assert!(ServeLock::checked_pid(&home).is_err());
        std::fs::remove_file(&path).unwrap();
    }
    let cpath =
        std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str())).unwrap();
    // SAFETY: cpath is a valid NUL-terminated synthetic path; mkfifo retains no pointer.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert!(
        ServeLock::presence(&guard, &home).is_err(),
        "a FIFO must not block open"
    );
    assert!(ServeLock::checked_pid(&home).is_err());
    drop(guard);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn checked_pid_rejects_missing_invalid_and_unreadable_records() {
    let (home, dir) = scratch("pid");
    std::fs::create_dir_all(&dir).unwrap();
    assert!(ServeLock::checked_pid(&home).is_err());
    for text in [
        "",
        "0\n",
        "-1\n",
        "+1\n",
        "2147483648\n",
        "4294967296\n",
        "bad\n",
        " 1\n",
    ] {
        std::fs::write(home.serve_lock(), text).unwrap();
        assert!(ServeLock::checked_pid(&home).is_err(), "{text:?}");
    }
    for bytes in [vec![255], vec![b'1'; 257]] {
        std::fs::write(home.serve_lock(), bytes).unwrap();
        assert!(ServeLock::checked_pid(&home).is_err());
    }
    std::fs::write(home.serve_lock(), b"42\n").unwrap();
    assert_eq!(ServeLock::checked_pid(&home).unwrap().get(), 42);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn process_id_parses_strictly_and_renders_the_checked_numeric_domain() {
    for raw in [0, i32::MAX as u32 + 1, u32::MAX] {
        assert!(super::ProcessId::try_from(raw).is_err(), "{raw}");
    }
    for text in [
        "",
        "0",
        "-1",
        "+1",
        " 1",
        "1 ",
        "1\n",
        "2147483648",
        "4294967296",
    ] {
        assert!(text.parse::<super::ProcessId>().is_err(), "{text:?}");
    }
    for raw in [1, 42, i32::MAX as u32] {
        let pid = super::ProcessId::try_from(raw).unwrap();
        assert_eq!(pid.get(), raw);
        assert_eq!(pid.to_string(), raw.to_string());
        assert_eq!(pid.to_string().parse::<super::ProcessId>().unwrap(), pid);
    }
    assert_eq!("00042".parse::<super::ProcessId>().unwrap().get(), 42);
}

#[test]
fn checked_pid_preserves_record_bytes_and_the_signed_pid_range() {
    let (home, dir) = scratch("pid-range");
    std::fs::create_dir_all(&dir).unwrap();
    for (text, raw) in [
        ("1\n", 1),
        ("00042\r\n", 42),
        ("2147483647\n", i32::MAX as u32),
    ] {
        std::fs::write(home.serve_lock(), text).unwrap();
        assert_eq!(ServeLock::checked_pid(&home).unwrap().get(), raw);
        assert_eq!(std::fs::read(home.serve_lock()).unwrap(), text.as_bytes());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// A lock that cannot be taken says so in swoosh's words, naming the file, and its reason follows once,
/// as the cause.
#[tokio::test]
async fn a_lock_that_cannot_be_taken_names_its_reason_once() {
    let (home, dir) = scratch("refused");
    std::fs::create_dir_all(home.home_lock()).unwrap();
    let error = HomeWrite::take(&home).await.unwrap_err();
    let reason = std::io::Error::from_raw_os_error(libc::EISDIR).to_string();
    let line = format!("{:#}", eyre::Report::new(error));
    assert_eq!(
        line,
        format!(
            "could not lock {}: {reason}",
            crate::escape::EscapedPath(&home.home_lock())
        )
    );
    let _ = std::fs::remove_dir_all(&dir);
}
