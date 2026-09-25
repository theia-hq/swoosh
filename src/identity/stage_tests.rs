//! Publishing a sealed file: no clobber even where there are no hard links, no replace of a file that
//! changed since it was compared, and no stray stage left from a killed run.

use std::io;
use std::path::PathBuf;

use super::{Seen, Stage};

/// A fresh scratch dir for one test.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("swoosh-stage-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A link that fails the way FAT and exFAT fail one.
fn no_links(_: &std::path::Path, _: &std::path::Path) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOTSUP))
}

/// With no hard links, a publish into absence still lands the bytes, and the stage is gone.
#[test]
fn a_filesystem_without_hard_links_still_publishes() {
    let dir = scratch("nolink");
    let target = dir.join("backup.key");

    let stage = Stage::write(&target, b"sealed bytes").expect("stage");
    stage
        .publish_new_with(&target, b"sealed bytes", no_links)
        .expect("publish without a hard link");
    assert_eq!(std::fs::read(&target).expect("read"), b"sealed bytes");
    assert_eq!(
        std::fs::read_dir(&dir).expect("list").count(),
        1,
        "only the published file is left"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Without hard links, a file that appears at the target is still never overwritten: the exclusive
/// create refuses it. The survival assertion comes first.
#[test]
fn a_filesystem_without_hard_links_still_never_clobbers() {
    let dir = scratch("noclobber");
    let target = dir.join("backup.key");

    let stage = Stage::write(&target, b"new").expect("stage");
    std::fs::write(&target, b"someone else's").expect("a file appears");
    let refused = stage.publish_new_with(&target, b"new", no_links);
    assert_eq!(std::fs::read(&target).expect("read"), b"someone else's");
    assert!(refused.is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A target that changed after it was compared is left as it now is.
#[test]
fn a_target_that_changed_is_not_replaced() {
    let dir = scratch("changed");
    let target = dir.join("key");
    std::fs::write(&target, b"compared").expect("the compared file");
    let seen = Seen::of(&target).expect("see it");
    // Replaced meanwhile, the way a racing write replaces a key file.
    std::fs::remove_file(&target).expect("remove");
    std::fs::write(&target, b"replaced meanwhile").expect("a new file");

    let stage = Stage::write(&target, b"restored").expect("stage");
    let refused = stage.publish_over(&target, seen);
    assert_eq!(std::fs::read(&target).expect("read"), b"replaced meanwhile");
    assert!(refused.is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A stage a killed run left beside the target is swept by the next one; a lookalike name is not.
#[test]
fn a_stray_stage_is_swept_and_a_lookalike_is_not() {
    let dir = scratch("sweep");
    let target = dir.join("key");
    let stray = dir.join("key.swoosh.4242.00000000deadbeef");
    let lookalike = dir.join("key.swoosh.notapid.00000000deadbeef");
    std::fs::write(&stray, b"sealed under an old passphrase").expect("stray");
    std::fs::write(&lookalike, b"not ours").expect("lookalike");

    drop(Stage::write(&target, b"x").expect("stage"));
    assert!(!stray.exists(), "the stray stage is swept");
    assert!(lookalike.exists(), "only the exact stage shape is swept");

    let _ = std::fs::remove_dir_all(&dir);
}
