//! `root forget`'s syncs under `home.lock`: a file of the copy swapped for a pipe never blocks them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::path::{Path, PathBuf};

use super::{ForgetError, sync_dir, sync_list};

/// A directory of its own for `tag`, made empty.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("swoosh-forget-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A pipe at `path`.
fn pipe(path: &Path) {
    let fifo = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: `fifo` is a live NUL-terminated path for the length of the call.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
}

/// Run `sync` on a thread of its own, so a blocking open stalls that thread and never the one that waits
/// here: the wait then runs out and the test fails, rather than hanging.
fn bounded<T: Send + 'static>(sync: impl FnOnce() -> T + Send + 'static) -> T {
    let (sent, got) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(sync());
    });
    got.recv_timeout(Duration::from_secs(60))
        .expect("the sync does not block on the pipe")
}

/// A pipe renamed over the copy's `devices` after step 6 read it is opened without blocking and refused as
/// the copy changed, so forget never waits on it holding `home.lock`. Red when the list is opened blocking,
/// which waits for a writer that never comes.
#[test]
fn the_lists_sync_never_blocks_on_a_pipe_renamed_over_it() {
    let dir = scratch("list-pipe");
    let list = dir.join("devices");
    std::fs::write(&list, b"a list").unwrap();
    let aside = dir.join("devices.pipe");
    pipe(&aside);
    std::fs::rename(&aside, &list).unwrap();
    let (at_list, at_dir) = (list.clone(), dir.clone());
    let synced = bounded(move || sync_list(&at_list, &at_dir));
    assert!(
        matches!(synced, Err(ForgetError::Changed { dir: changed }) if changed == dir),
        "the pipe is refused as a change"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pipe where the copy's directory was fails the directory's sync at once. Red when the directory is opened
/// without `O_DIRECTORY`, which blocks on the pipe.
#[test]
fn the_directorys_sync_never_blocks_on_a_pipe() {
    let dir = scratch("dir-pipe");
    let at = dir.join("copy");
    pipe(&at);
    let synced = bounded(move || sync_dir(&at).is_err());
    assert!(synced, "a pipe is no directory");
    let _ = std::fs::remove_dir_all(&dir);
}
