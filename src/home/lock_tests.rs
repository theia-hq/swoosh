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
    assert!(matches!(
        ServeLock::take(&home_lock, &home),
        Err(ServeLockError::Held)
    ));
    assert_eq!(ServeLock::admitting(&home_lock, &home).unwrap(), Some(root));
    let recorded = ServeLock::recorded(&home);
    assert_eq!(recorded.pid, Some(std::process::id()));
    assert_eq!(recorded.admit, Some(root));

    drop(held);
    assert_eq!(ServeLock::admitting(&home_lock, &home).unwrap(), None);
    assert_eq!(ServeLock::recorded(&home), super::Recorded::default());
    let again = ServeLock::take(&home_lock, &home);
    assert!(again.is_ok(), "a later serve takes it");
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
