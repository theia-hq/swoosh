//! The persisted identity file's failure modes: a corrupt, too-open, or ALREADY-PROVISIONED
//! `identity.key` is refused, never silently replaced, and a write is atomic (a failed one leaves the
//! store exactly as it was).

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

/// A write lands atomically and owner-only: the seed is on disk, no temp sibling survives, and the key
/// is 0600.
#[tokio::test]
async fn a_write_lands_the_key_atomically_owner_only() {
    let (home, dir) = home("atomic");
    let path = home.identity_key();

    super::write(&[1u8; 32], &home).await.expect("first write");
    assert_eq!(
        std::fs::read(&path).expect("the key reads"),
        [1u8; 32],
        "the rename landed the seed"
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

/// The signet guard: a home that already holds a key is REFUSED, not re-identified. The key is the one
/// file in the store nothing can re-issue, so `adopt`ing a derived invite onto a provisioned machine
/// must leave it exactly as found and say what was at stake. Re-writing the seed already on disk is not
/// a replacement, so a re-adopt of the same invite stays a silent no-op.
///
/// The file-survives assertion comes FIRST: with the guard deleted the write succeeds, and that
/// assertion is the one that then fails, naming the protection rather than tripping on a missing error.
#[tokio::test]
async fn a_write_refuses_a_home_that_already_holds_a_different_key() {
    let (home, dir) = home("already-provisioned");
    let path = home.identity_key();
    let provisioned = [9u8; 32];
    super::write(&provisioned, &home)
        .await
        .expect("provision an empty home");

    let result = super::write(&[8u8; 32], &home).await;
    assert_eq!(
        std::fs::read(&path).expect("the key is still there"),
        provisioned,
        "a refused write must leave the existing key byte-identical: it is the one file nothing can \
         re-issue"
    );
    let error = result.expect_err("a different seed over a provisioned home must be refused");
    let message = format!("{error:#}");
    let held = bifrost::NodeId::from_ed25519_secret(&provisioned).to_string();
    assert!(
        message.contains(&held),
        "the refusal names the identity this machine already has: {message}"
    );
    assert!(
        message.contains(&path.display().to_string()),
        "the refusal names the file to move aside: {message}"
    );

    // The same seed is not a replacement: re-adopting an invite this machine already adopted writes
    // nothing and says nothing, so idempotence survives the guard.
    super::write(&provisioned, &home)
        .await
        .expect("re-writing the key already on disk is a no-op, not a refusal");
    assert_eq!(
        std::fs::read(&path).expect("the key is still there"),
        provisioned
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed write leaves the store exactly as it was: the temp sibling cannot be created, so the rename
/// never happens and no key (and no litter) appears. The atomicity guarantee, exercised rather than
/// argued; the already-provisioned case is the guard above, which never reaches a write at all.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_write_leaves_the_store_untouched() {
    use std::os::unix::fs::PermissionsExt as _;

    let (home, dir) = home("failed-write");
    let path = home.identity_key();

    // Drop write permission on the store dir: the write cannot create its temp sibling.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500))
        .expect("make the store dir read-only");
    let result = super::write(&[4u8; 32], &home).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore the store dir");

    assert!(result.is_err(), "the write into a read-only dir must fail");
    assert!(
        !path.exists(),
        "a failed write leaves no key behind, and no temp sibling either"
    );
    let entries = std::fs::read_dir(&dir).expect("read the home dir").count();
    assert_eq!(entries, 0, "the store is exactly as it was found");

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

/// An outward dial never CREATES the key, and an explicit home does not change that: `--home`/`SWOOSH_HOME`
/// says where this node's files live, not that a dial should provision one. The home a caller names for
/// one `swoosh reach` is left exactly as it was found, because the key that would appear there is the
/// root a later `serve` gates its whole fleet on. The loading half still holds: once a key exists, the
/// same outward dial binds it, which is what makes a member's badge admit at their own node.
#[tokio::test]
async fn an_outward_dial_never_creates_the_key_under_an_explicit_home() {
    let (home, dir) = home("outward-no-create");
    let path = home.identity_key();

    let dialed = super::resolve(super::Identity::PersistedIfPresent, &home)
        .await
        .expect("an outward dial resolves against a home with no key");
    assert!(
        !path.exists(),
        "an outward dial must write nothing, whatever home it was pointed at"
    );

    let served = super::resolve(super::Identity::Persisted, &home)
        .await
        .expect("a serving verb provisions the key");
    assert!(path.exists(), "only a persisting intent writes the key");
    assert_ne!(
        dialed.node_id(),
        served.node_id(),
        "the throwaway the dial minted was never the key on disk"
    );

    let reached = super::resolve(super::Identity::PersistedIfPresent, &home)
        .await
        .expect("an outward dial resolves against a provisioned home");
    assert_eq!(
        reached.node_id(),
        served.node_id(),
        "with a key on disk the outward dial binds it, so the badge it presents roots there"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
