//! The persisted identity file's failure modes: a corrupt or too-open `identity.key` is refused, never
//! silently replaced, and a write is atomic (a failed write leaves the old key intact).

use std::path::PathBuf;

use crate::home::Home;

/// A unique home under the temp dir, created empty on entry. Returns `(home, dir)`.
fn home(tag: &str) -> (Home, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-identity-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch home");
    let home = Home::resolve(Some(dir.clone())).expect("resolve an explicit home");
    (home, dir)
}

/// A wrong-size `identity.key` is corrupt or foreign: reading it fails closed with the size named, and
/// `Persisted` never mints a fresh key over the file (the old silent-overwrite bug this guards).
#[tokio::test]
async fn a_wrong_size_key_file_refuses_and_is_never_overwritten() {
    let (home, dir) = home("wrong-size");
    let path = home.identity_key();
    let corrupt = [7u8; 16];
    std::fs::write(&path, corrupt).expect("seed a wrong-size key file");
    // The mode guard reads before the size check, so lock the corrupt file owner-only: this test is about
    // the SIZE refusal, and a 0644 file would refuse for the other, equally-closed reason.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }

    let error = super::resolve(super::Identity::Persisted, &home)
        .await
        .err()
        .expect("a 16-byte key file must be refused, not replaced");
    let message = format!("{error:#}");
    assert!(
        message.contains("16 bytes") && message.contains("32"),
        "the refusal names the actual and expected sizes: {message}"
    );
    assert_eq!(
        std::fs::read(&path).expect("the corrupt file is still there"),
        corrupt,
        "a refused load must never overwrite the file it refused"
    );

    let error = super::resolve(super::Identity::PersistedIfPresent, &home)
        .await
        .err()
        .expect("an outward dial must refuse a corrupt key file too, not dial ephemerally");
    assert!(
        format!("{error:#}").contains("16 bytes"),
        "the read-only path names the size too: {error:#}"
    );
    assert_eq!(
        std::fs::read(&path).expect("the corrupt file survives the read-only path"),
        corrupt,
        "PersistedIfPresent never writes at all"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A write lands atomically and owner-only: the new seed replaces the old one, no temp sibling survives,
/// and the key is 0600.
#[tokio::test]
async fn a_write_replaces_the_key_atomically_owner_only() {
    let (home, dir) = home("atomic");
    let path = home.identity_key();

    super::write(&[1u8; 32], &home).await.expect("first write");
    super::write(&[2u8; 32], &home).await.expect("second write");
    assert_eq!(
        std::fs::read(&path).expect("the key reads"),
        [2u8; 32],
        "the rename replaced the old key with the new seed"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("stat the key")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the key lands owner-only");
    }

    let entries: Vec<String> = std::fs::read_dir(&dir)
        .expect("read the home dir")
        .map(|entry| {
            entry
                .expect("a dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        entries,
        vec!["identity.key".to_owned()],
        "the atomic write leaves no temp sibling behind: {entries:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed write leaves the previous key byte-identical: the temp sibling cannot be created, so the
/// rename never happens (the atomicity guarantee, exercised rather than argued).
#[cfg(unix)]
#[tokio::test]
async fn a_failed_write_leaves_the_old_key_intact() {
    use std::os::unix::fs::PermissionsExt as _;

    let (home, dir) = home("failed-write");
    let path = home.identity_key();
    let old = [3u8; 32];
    super::write(&old, &home).await.expect("seed the old key");

    // Drop write permission on the store dir: the next write cannot create its temp sibling.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500))
        .expect("make the store dir read-only");
    let result = super::write(&[4u8; 32], &home).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore the store dir");

    assert!(result.is_err(), "the write into a read-only dir must fail");
    assert_eq!(
        std::fs::read(&path).expect("the old key is still there"),
        old,
        "a failed write must leave the old key intact"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A group- or world-readable key is refused with a chmod hint, mirroring the `@<path>` secret reader:
/// the key is a full device identity, so silently reading a file others can read defeats the point.
#[cfg(unix)]
#[tokio::test]
async fn a_group_or_world_readable_key_is_refused_with_a_chmod_hint() {
    use std::os::unix::fs::PermissionsExt as _;

    let (home, dir) = home("too-open");
    let path = home.identity_key();
    let seed = [5u8; 32];
    std::fs::write(&path, seed).expect("seed the key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let error = super::resolve(super::Identity::Persisted, &home)
        .await
        .err()
        .expect("a group/world-readable key must be refused");
    let message = format!("{error:#}");
    assert!(
        message.contains("too open"),
        "the refusal explains why: {message}"
    );
    assert!(
        message.contains(&format!("chmod 600 {}", path.display())),
        "the refusal hints the fix: {message}"
    );
    assert_eq!(
        std::fs::read(&path).expect("the too-open key is untouched"),
        seed,
        "a refused load never rewrites or replaces the key"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
