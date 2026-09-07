//! The store's private posture on disk: a trust file (`signet`, `badge`) written beside the identity is
//! created owner-only (`0600`) and the store dir owner-only (`0700`), so a co-tenant local user cannot read
//! this node's trust graph. The bug this guards: bare `write`/`create_dir_all` left these `0644` in a
//! likely-`0755` dir whenever the mint-log did not happen to create the dir first.

use std::path::PathBuf;

use crate::home::Home;

/// A unique store dir under the temp dir, resolved as an explicit [`Home`] (so its trust files derive from
/// that dir). Returns `(home, store_dir)`; the store dir does not exist yet, so a write under it exercises
/// the `0700` create.
fn store(tag: &str) -> (Home, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-config-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let home = Home::resolve(Some(dir.clone())).expect("resolve an explicit home");
    (home, dir)
}

#[cfg(unix)]
#[tokio::test]
async fn a_written_badge_is_owner_only_in_an_owner_only_store() {
    use std::os::unix::fs::PermissionsExt as _;

    let (home, dir) = store("badge-perms");
    super::write_badge(&home, "sheer:example-badge-link")
        .await
        .expect("write the badge into a fresh store");

    let dir_mode = std::fs::metadata(&dir)
        .expect("stat the store dir")
        .permissions()
        .mode();
    assert_eq!(
        dir_mode & 0o777,
        0o700,
        "the store dir is created 0700 (owner-only), not left group/world-traversable"
    );

    let file_mode = std::fs::metadata(home.badge())
        .expect("stat the badge")
        .permissions()
        .mode();
    assert_eq!(
        file_mode & 0o777,
        0o600,
        "the badge is written 0600 (owner read/write only), never world-readable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[tokio::test]
async fn a_loosened_trust_file_is_retightened_on_rewrite() {
    use std::os::unix::fs::PermissionsExt as _;

    let (home, dir) = store("badge-retighten");
    super::write_badge(&home, "sheer:first")
        .await
        .expect("first badge write");
    let badge = home.badge();
    // Simulate a file loosened after an earlier write; the next write must reassert 0600.
    std::fs::set_permissions(&badge, std::fs::Permissions::from_mode(0o644))
        .expect("loosen the badge");
    super::write_badge(&home, "sheer:second")
        .await
        .expect("second badge write");

    let mode = std::fs::metadata(&badge)
        .expect("stat the badge")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "a rewrite reasserts 0600 even on a pre-existing, loosened file"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
