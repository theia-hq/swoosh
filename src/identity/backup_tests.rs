//! `export` and `restore`: a backup is always sealed and written only as a file; a restore unlocks the
//! backup before it touches the home, and never replaces a different identity unasked.

use std::path::Path;

use keystore::{KeyFile, Method, Stored};

use super::{Existing, export, restore};
use crate::identity::identity_tests::{home, sealed};
use crate::identity::{HomeLock, Identity, inspect, resolve_with};
use crate::passphrase::Scripted;

/// The node a sealed file at `path` opens as under `passphrase`.
fn opens_as(path: &Path, passphrase: &'static str) -> bifrost::NodeId {
    let Some(Stored::Locked(locked)) = KeyFile::device(path).load().expect("load") else {
        panic!("{} is not sealed", path.display());
    };
    let passphrase =
        keystore::Passphrase::new(zeroize::Zeroizing::new(passphrase.into())).expect("non-empty");
    locked.unlock(&passphrase).expect("it opens").node_id()
}

/// A plain home exports a SEALED backup under a passphrase chosen then, and the home itself stays plain.
#[test]
fn a_plain_home_exports_a_sealed_backup() {
    let (home, dir) = home("export-plain");
    let node = resolve_with(Identity::Persisted, &home, &mut Scripted::new([]))
        .expect("mint")
        .node_id();
    let to = dir.join("backup.key");

    let exported = export(
        &home,
        &to,
        Existing::Refuse,
        &mut Scripted::new(["backup pass"]),
    )
    .expect("export");
    assert_eq!(exported, node);
    assert_eq!(opens_as(&to, "backup pass"), node, "the backup is sealed");
    assert_eq!(
        inspect(&home).expect("inspect").into_stored().method(),
        Method::Plain
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A sealed home is unlocked, and its backup gets a passphrase of its own: the medium most likely to be
/// lost never carries the passphrase typed every day.
#[test]
fn a_sealed_home_exports_under_a_passphrase_of_its_own() {
    let (home, dir) = home("export-sealed");
    let node = sealed(&home, "home pass");
    let to = dir.join("backup.key");

    export(
        &home,
        &to,
        Existing::Refuse,
        &mut Scripted::new(["home pass", "backup pass"]),
    )
    .expect("export");
    assert_eq!(opens_as(&to, "backup pass"), node);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A home with no key exports nothing and mints nothing: a backup of a key made just for it would be a
/// backup of nobody.
#[test]
fn an_empty_home_exports_nothing_and_mints_nothing() {
    let (home, dir) = home("export-empty");
    let to = dir.join("backup.key");

    assert!(export(&home, &to, Existing::Refuse, &mut Scripted::new([])).is_err());
    assert!(!to.exists(), "no backup is written");
    assert!(!home.key().exists(), "no key is minted");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A file already at the destination may be the only other backup: refused, and left byte for byte,
/// unless the caller says to replace it. The survival assertion comes first.
#[test]
fn an_existing_backup_is_replaced_only_when_asked() {
    let (home, dir) = home("export-existing");
    let node = sealed(&home, "home pass");
    let to = dir.join("backup.key");
    std::fs::write(&to, b"an older backup").expect("plant a file");

    let refused = export(
        &home,
        &to,
        Existing::Refuse,
        &mut Scripted::new(["home pass"]),
    );
    assert_eq!(
        std::fs::read(&to).expect("read it back"),
        b"an older backup",
        "the file at the destination survives"
    );
    assert!(refused.is_err());

    export(
        &home,
        &to,
        Existing::Replace,
        &mut Scripted::new(["home pass", "home pass"]),
    )
    .expect("replace");
    assert_eq!(opens_as(&to, "home pass"), node);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A backup is only ever a file: `-` is refused rather than written as a file named `-`, and the home's
/// own key is not a destination even when replacing is allowed.
#[test]
fn a_backup_is_only_ever_a_separate_file() {
    let (home, dir) = home("export-file-only");
    sealed(&home, "home pass");
    let before = std::fs::read(home.key()).expect("read the key");

    assert!(
        export(
            &home,
            Path::new("-"),
            Existing::Replace,
            &mut Scripted::new(["home pass"])
        )
        .is_err()
    );
    assert!(!Path::new("-").exists(), "no file named `-` was written");
    let own = export(
        &home,
        &home.key(),
        Existing::Replace,
        &mut Scripted::new(["home pass"]),
    );
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        before,
        "the home's key is untouched"
    );
    assert!(own.is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A restore into an empty home installs the backup's key, sealed under the backup's passphrase.
#[test]
fn a_backup_restores_into_an_empty_home_sealed() {
    let (source, source_dir) = home("restore-source");
    let node = sealed(&source, "pass");
    let backup = source_dir.join("backup.key");
    export(
        &source,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass", "pass"]),
    )
    .expect("export");

    let (fresh, fresh_dir) = home("restore-fresh");
    let restored = restore(
        &fresh,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass"]),
    )
    .expect("restore");
    assert_eq!(restored.node, node);
    assert_eq!(opens_as(&fresh.key(), "pass"), node);

    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&fresh_dir);
}

/// A wrong passphrase for the backup changes nothing at home, even when replacing was allowed: the
/// backup is unlocked before the home is touched.
#[test]
fn a_wrong_backup_passphrase_leaves_the_home_untouched() {
    let (home, dir) = home("restore-wrong");
    let backup = dir.join("backup.key");
    sealed(&home, "pass");
    export(
        &home,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass", "pass"]),
    )
    .expect("export");
    std::fs::remove_file(home.key()).expect("lose the key");
    resolve_with(Identity::Persisted, &home, &mut Scripted::new([])).expect("a different key");
    let before = std::fs::read(home.key()).expect("read the key");

    let refused = restore(
        &home,
        &backup,
        Existing::Replace,
        &mut Scripted::new(["nope"]),
    );
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        before,
        "the home's key is untouched"
    );
    assert!(refused.is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A home holding a DIFFERENT key keeps it unless replacing is asked for: that key may be the only copy
/// of its identity. The survival assertion comes first, so with the check removed it is the one that
/// fails.
#[test]
fn a_different_identity_is_replaced_only_when_asked() {
    let (source, source_dir) = home("restore-other-source");
    let node = sealed(&source, "pass");
    let backup = source_dir.join("backup.key");
    export(
        &source,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass", "pass"]),
    )
    .expect("export");

    let (home, dir) = home("restore-other-home");
    resolve_with(Identity::Persisted, &home, &mut Scripted::new([])).expect("its own key");
    let before = std::fs::read(home.key()).expect("read the key");

    let refused = restore(
        &home,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass"]),
    );
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        before,
        "the different key survives"
    );
    let Err(error) = refused else {
        panic!("refused");
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("--force"),
        "the refusal names the way past it: {message}"
    );

    let restored = restore(
        &home,
        &backup,
        Existing::Replace,
        &mut Scripted::new(["pass"]),
    )
    .expect("replace");
    assert_eq!(restored.node, node);
    assert_eq!(opens_as(&home.key(), "pass"), node);

    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plain key file is not a backup: a restore from one is refused, so no restore installs a key that
/// was never sealed.
#[test]
fn a_plain_key_file_is_not_a_backup() {
    let (source, source_dir) = home("restore-plain-source");
    resolve_with(Identity::Persisted, &source, &mut Scripted::new([])).expect("a plain key");
    let (home, dir) = home("restore-plain-home");

    assert!(
        restore(
            &home,
            &source.key(),
            Existing::Replace,
            &mut Scripted::new([])
        )
        .is_err()
    );
    assert!(!home.key().exists(), "nothing was installed");

    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A key file at home that cannot be read cannot be compared with the backup, so it is replaced only
/// when asked, exactly like a different key.
#[test]
fn an_unreadable_home_key_is_replaced_only_when_asked() {
    use std::os::unix::fs::PermissionsExt as _;

    let (source, source_dir) = home("restore-unreadable-source");
    let node = sealed(&source, "pass");
    let backup = source_dir.join("backup.key");
    export(
        &source,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass", "pass"]),
    )
    .expect("export");

    let (home, dir) = home("restore-unreadable-home");
    std::fs::write(home.key(), [7u8; 16]).expect("a truncated key");
    std::fs::set_permissions(home.key(), std::fs::Permissions::from_mode(0o600))
        .expect("owner-only");

    let refused = restore(
        &home,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass"]),
    );
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        [7u8; 16],
        "the unreadable file survives"
    );
    assert!(refused.is_err());

    restore(
        &home,
        &backup,
        Existing::Replace,
        &mut Scripted::new(["pass"]),
    )
    .expect("replace");
    assert_eq!(opens_as(&home.key(), "pass"), node);

    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A backup readable by all, as every file on a FAT or exFAT stick reads, is restored: it is sealed, so its
/// passphrase protects it. The loose mode is reported, and the home key it becomes is owner-only.
#[test]
fn a_backup_readable_by_all_is_restored_and_reported() {
    use std::os::unix::fs::PermissionsExt as _;

    let (source, source_dir) = home("restore-loose-source");
    let node = sealed(&source, "pass");
    let backup = source_dir.join("backup.key");
    export(
        &source,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass", "pass"]),
    )
    .expect("export");
    std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let (home, dir) = home("restore-loose-home");
    let restored = restore(
        &home,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass"]),
    )
    .expect("restore");
    assert_eq!(restored.node, node);
    assert_eq!(restored.loose, Some(0o644));
    let mode = std::fs::metadata(home.key())
        .expect("stat")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the home key is owner-only");

    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A restore never runs while a node serves the home: it is refused before anything is read or asked,
/// and the home key is untouched even with --force.
#[test]
fn a_restore_is_refused_while_a_node_serves_the_home() {
    let (source, source_dir) = home("restore-served-source");
    sealed(&source, "pass");
    let backup = source_dir.join("backup.key");
    export(
        &source,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass", "pass"]),
    )
    .expect("export");

    let (home, dir) = home("restore-served-home");
    resolve_with(Identity::Persisted, &home, &mut Scripted::new([])).expect("its own key");
    let before = std::fs::read(home.key()).expect("read the key");
    let serving = HomeLock::serving(&home).expect("a node serves the home");

    let refused = restore(
        &home,
        &backup,
        Existing::Replace,
        &mut Scripted::new(["pass"]),
    );
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        before,
        "the served key is untouched"
    );
    let Err(error) = refused else {
        panic!("a restore under a serving node is refused");
    };
    assert!(
        format!("{error:#}").contains("a node is running"),
        "the refusal names why: {error:#}"
    );
    drop(serving);

    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sealed home that CLAIMS the backup's node is still replaced only when asked: its header is not proof,
/// and anyone who can write the file can make it claim any node.
#[test]
fn a_sealed_home_claiming_the_same_node_is_replaced_only_when_asked() {
    let (home, dir) = home("restore-same-claim");
    let node = sealed(&home, "home pass");
    let backup = dir.join("backup.key");
    export(
        &home,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["home pass", "backup pass"]),
    )
    .expect("export");
    let before = std::fs::read(home.key()).expect("read the key");

    let refused = restore(
        &home,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["backup pass"]),
    );
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        before,
        "the sealed home survives"
    );
    assert!(refused.is_err());

    let restored = restore(
        &home,
        &backup,
        Existing::Replace,
        &mut Scripted::new(["backup pass"]),
    )
    .expect("replace");
    assert_eq!(restored.node, node);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The refusal to replace a different key says how to keep it first.
#[test]
fn replacing_a_different_key_is_refused_with_the_way_to_keep_it() {
    let (source, source_dir) = home("restore-advice-source");
    sealed(&source, "pass");
    let backup = source_dir.join("backup.key");
    export(
        &source,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass", "pass"]),
    )
    .expect("export");
    let (home, dir) = home("restore-advice-home");
    resolve_with(Identity::Persisted, &home, &mut Scripted::new([])).expect("its own key");

    let Err(error) = restore(
        &home,
        &backup,
        Existing::Refuse,
        &mut Scripted::new(["pass"]),
    ) else {
        panic!("a different key is refused");
    };
    assert!(
        format!("{error:#}").contains("swoosh identity export"),
        "the refusal names the backup to take first: {error:#}"
    );

    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&dir);
}
