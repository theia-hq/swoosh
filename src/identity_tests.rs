//! The persisted identity file's failure modes: a corrupt, too-open, or ALREADY-PROVISIONED
//! `key` is refused, never silently replaced, a write is atomic (a failed one leaves the store
//! exactly as it was), and a sealed key opens only under its passphrase and never becomes a new identity.

use std::path::PathBuf;

use keystore::{Method, Stored};

use crate::home::Home;
use crate::passphrase::Scripted;
use crate::testkit::Counting;
use crate::testkit::touch_id::{DEVICE_PASSPHRASE_AND_TOUCH_ID, DEVICE_TOUCH_ID_ALONE, PASSPHRASE};
use crate::touch::{Then, TouchAct, TouchHere, Touched};

/// A unique home under the temp dir, created empty on entry. Returns `(home, dir)`. Shared with the
/// `backup` and `protect` tests beneath this module.
pub(super) fn home(tag: &str) -> (Home, PathBuf) {
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

/// A wrong-size `key` is corrupt or foreign: reading it fails closed with the size named, and
/// `Persisted` never mints a fresh key over the file (the old silent-overwrite bug this guards).
#[tokio::test]
async fn a_wrong_size_key_file_refuses_and_is_never_overwritten() {
    let (home, dir) = home("wrong-size");
    let path = home.key();
    super::make_machine_dir(&home).expect("the key's dir");
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
    let path = home.key();

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

    let entries: Vec<String> = std::fs::read_dir(home.machine())
        .expect("read the key's dir")
        .map(|entry| {
            entry
                .expect("a dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name != "CACHEDIR.TAG")
        .collect();
    assert_eq!(
        entries,
        vec!["key".to_owned()],
        "the atomic write leaves no temp sibling behind: {entries:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The signet guard: a home that already holds a key is REFUSED, not re-identified. The key is the one
/// file in the store nothing can re-issue, so joining an invite that carries a key onto a provisioned machine
/// must leave it exactly as found and say what was at stake. Re-writing the seed already on disk is not
/// a replacement, so a second join of the same invite stays a silent no-op.
///
/// The file-survives assertion comes FIRST: with the guard deleted the write succeeds, and that
/// assertion is the one that then fails, naming the protection rather than tripping on a missing error.
#[tokio::test]
async fn a_write_refuses_a_home_that_already_holds_a_different_key() {
    let (home, dir) = home("already-provisioned");
    let path = home.key();
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

    // The same seed is not a replacement: joining an invite this machine already joined writes
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
    let path = home.key();

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
    let path = home.key();
    super::make_machine_dir(&home).expect("the key's dir");
    let seed = [5u8; 32];
    std::fs::write(&path, seed).expect("seed the key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let error = super::resolve(super::Identity::Persisted, &home)
        .await
        .err()
        .expect("a group/world-readable key must be refused");
    let message = format!("{error:#}");
    assert!(
        message.contains("group or other"),
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
    let path = home.key();

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

/// Seal a fresh key into `home` under `passphrase`, the way `lock` makes a home's first key.
pub(super) async fn sealed(home: &Home, passphrase: &'static str) -> bifrost::NodeId {
    let locked = super::lock(
        home,
        Method::Passphrase,
        false,
        &mut Scripted::new([passphrase]),
    )
    .await
    .expect("seal a fresh key");
    assert_eq!(locked, super::Locked::Set { first: true });
    crate::testkit::stored_key(&keystore::KeyFile::device(home.key()))
}

/// A sealed key opens under its passphrase, for a serving verb and an outward dial alike, as the node it
/// was sealed as.
#[tokio::test]
async fn a_sealed_key_opens_under_its_passphrase() {
    let (home, dir) = home("sealed-opens");
    let node = sealed(&home, "correct horse battery").await;

    for intent in [
        super::Identity::Persisted,
        super::Identity::PersistedIfPresent,
    ] {
        let secret =
            super::resolve_with(intent, &home, &mut Scripted::new(["correct horse battery"]))
                .expect("the passphrase opens it");
        assert_eq!(secret.node_id(), node, "{intent:?} binds the sealed key");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A wrong passphrase is an error, never a new identity: not a fresh key minted over the sealed one for a
/// serving verb, and not a throwaway for an outward dial. The file survives byte for byte.
#[tokio::test]
async fn a_wrong_passphrase_is_never_a_new_identity() {
    let (home, dir) = home("sealed-wrong");
    sealed(&home, "correct horse battery").await;
    let before = std::fs::read(home.key()).expect("read the sealed key");

    for intent in [
        super::Identity::Persisted,
        super::Identity::PersistedIfPresent,
    ] {
        let mut wrong = Scripted::new(["battery staple", "battery staple", "battery staple"]);
        let refused = super::resolve_with(intent, &home, &mut wrong);
        let Err(error) = refused else {
            panic!("a wrong passphrase refuses");
        };
        let message = format!("{error:#}");
        assert!(
            message.contains("that passphrase does not open this machine's key"),
            "{intent:?} names the refusal: {message}"
        );
    }
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        before,
        "the sealed key survives a failed unlock untouched"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Printing an identity never asks for a passphrase: a sealed file names its node and its protection
/// in its header. The script is empty, so any question would fail the call.
#[tokio::test]
async fn inspecting_a_sealed_key_asks_for_nothing() {
    let (home, dir) = home("sealed-inspect");
    let node = sealed(&home, "correct horse battery").await;

    let inspected = super::inspect(&home).expect("inspect a sealed home");
    assert_eq!(inspected, super::Inspected::Found(node));
    let stored = keystore::KeyFile::device(home.key()).load().unwrap();
    let Some(Stored::Locked(locked)) = stored else {
        panic!("the key stays locked");
    };
    assert_eq!(locked.methods().collect::<Vec<_>>(), [Method::Passphrase]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Writing again the key a home already holds is a no-op even when its owner sealed it: the passphrase
/// proves the sealed file is that key, and the file stays sealed.
#[tokio::test]
async fn rewriting_a_sealed_key_proves_it_and_keeps_it_sealed() {
    let (home, dir) = home("sealed-rewrite");
    sealed(&home, "correct horse battery").await;
    let seed = super::resolve_with(
        super::Identity::Persisted,
        &home,
        &mut Scripted::new(["correct horse battery"]),
    )
    .expect("open the sealed key")
    .with_bytes(|seed| *seed);
    let before = std::fs::read(home.key()).expect("read the sealed key");

    super::write_with(&seed, &home, &mut Scripted::new(["correct horse battery"]))
        .expect("the same key, proven, is a no-op");
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        before,
        "the sealed file is left exactly as it was"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `machine/` that cannot be made is named with the system's reason on every path that writes a key,
/// never the bare reason: here a join's write, into a home this user cannot write.
#[tokio::test]
async fn a_machine_dir_that_cannot_be_made_is_named() {
    use std::os::unix::fs::PermissionsExt as _;

    let (home, dir) = home("machine-blocked");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).expect("chmod 500");

    let written = super::write(&[7; 32], &home).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod 700");
    let message = format!(
        "{:#}",
        written.expect_err("no key can be made in a read-only home")
    );
    assert!(
        message.starts_with(&format!(
            "cannot make this machine's key in {}: ",
            home.machine().display()
        )),
        "the line names the directory: {message}"
    );
    std::fs::remove_dir_all(&dir).expect("clean up");
}

/// A sealed key file whose header names bytes no key could be is refused at tightbeam's bridge, naming the
/// file, before anything asks for its passphrase. Red when the header's claim becomes a key unchecked.
#[tokio::test]
async fn a_locked_file_with_a_malformed_header_names_the_file() {
    let (home, dir) = home("malformed-header");
    sealed(&home, "correct horse battery").await;
    let mut bytes = std::fs::read(home.key()).expect("read the sealed key");
    // Bytes 10 to 42 are the public key the header claims; all zeros is a small-order point.
    bytes[10..42].fill(0);
    std::fs::write(home.key(), &bytes).expect("write it back");
    let refused = super::inspect(&home).expect_err("a header no key could be");
    assert_eq!(
        format!("{refused:#}"),
        format!(
            "this machine's key file at {} is damaged and holds no usable key; start this machine over \
             with a new key: swoosh leave --new-key",
            crate::escape::EscapedPath(&home.key())
        )
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Beside a root kept in the home, the damaged key's line names no command: `leave --new-key` refuses a home
/// that keeps a root, and its refusal sends the person to `root backup`, which would print this line again.
/// Red when the line names `leave` there.
#[tokio::test]
async fn a_damaged_machine_key_beside_a_kept_root_names_no_command() {
    let (home, dir) = home("malformed-header-root-kept");
    sealed(&home, "correct horse battery").await;
    let mut bytes = std::fs::read(home.key()).expect("read the sealed key");
    // Bytes 10 to 42 are the public key the header claims; all zeros is a small-order point.
    bytes[10..42].fill(0);
    std::fs::write(home.key(), &bytes).expect("write it back");
    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    let refused = super::inspect(&home).expect_err("a header no key could be");
    assert_eq!(
        format!("{refused:#}"),
        format!(
            "this machine's key file at {} is damaged and holds no usable key.",
            crate::escape::EscapedPath(&home.key())
        )
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `bytes` as this machine's key in `home`, owner-only.
fn placed(home: &Home, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    super::make_machine_dir(home).expect("the key's dir");
    std::fs::write(home.key(), bytes).expect("write the key file");
    std::fs::set_permissions(home.key(), std::fs::Permissions::from_mode(0o600))
        .expect("chmod 600");
}

/// A root kept in `home`, with a `touch-id` lock beside its passphrase.
fn root_with_touch_id(home: &Home) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(
        home.root_key(),
        crate::testkit::touch_id::ROOT_PASSPHRASE_AND_TOUCH_ID,
    )
    .expect("write the root");
    std::fs::set_permissions(home.root_key(), std::fs::Permissions::from_mode(0o600))
        .expect("chmod 600");
}

/// The methods of this machine's key's locks.
fn locks(home: &Home) -> Vec<Method> {
    match keystore::KeyFile::device(home.key())
        .load()
        .expect("load")
        .expect("a key")
    {
        Stored::Plain(_) => Vec::new(),
        Stored::Locked(locked) => locked.methods().collect(),
    }
}

/// A passphrase the minimum takes.
const LONG: &str = "a passphrase long enough";

/// `lock touch-id` at this Mac, the touch scripted to prove the new lock.
async fn lock_touch_id(home: &Home, prompt: &mut Counting) -> eyre::Result<super::Locked> {
    super::lock(home, Method::TouchId, false, prompt).await
}

fn proving(answers: impl IntoIterator<Item = &'static str>) -> Counting {
    Counting::new(answers)
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Opened(None)])
}

/// Where no root is kept, `touch-id` replaces the passphrase as the key's one lock: the passphrase opens it,
/// the touch proves the new lock, then the passphrase lock comes off. The line saying what a new fingerprint
/// does comes before anything is asked. Red when the predicate says a root is kept.
#[tokio::test]
async fn lock_touch_id_where_no_root_is_kept_replaces_the_passphrase() {
    let (home, dir) = home("touch-id-replaces");
    sealed(&home, PASSPHRASE).await;
    let mut prompt = proving([PASSPHRASE]);
    let locked = lock_touch_id(&home, &mut prompt).await.unwrap();
    assert_eq!(locked, super::Locked::TouchId { passphrase: false });
    assert_eq!(prompt.events(), 1, "the passphrase that opens it");
    let [touch] = prompt.touches() else {
        panic!("one touch: {:?}", prompt.touches());
    };
    assert!(matches!(
        touch.act,
        TouchAct::BesidePassphrase {
            then: Then::Drop,
            ..
        }
    ));
    assert_eq!(touch.reason, crate::touch::CHECK_MACHINE_KEY);
    assert_eq!(prompt.said()[0], crate::touch::ONE_LOCK);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Where a root is kept, the passphrase stays beside the touch, since no verb gives this machine a new key
/// there; and with the root under `touch-id` too, the line says one dialog cannot show which of the two it
/// opens. Red when the shared predicate is not read.
#[tokio::test]
async fn lock_touch_id_beside_a_kept_root_keeps_the_passphrase() {
    let (home, dir) = home("touch-id-beside-root");
    sealed(&home, PASSPHRASE).await;
    root_with_touch_id(&home);
    let mut prompt = proving([PASSPHRASE]);
    let locked = lock_touch_id(&home, &mut prompt).await.unwrap();
    assert_eq!(locked, super::Locked::TouchId { passphrase: true });
    assert!(matches!(
        prompt.touches()[0].act,
        TouchAct::BesidePassphrase {
            then: Then::Keep,
            ..
        }
    ));
    assert_eq!(
        prompt.said()[..2],
        [
            crate::touch::BESIDE_PASSPHRASE.to_owned(),
            crate::touch::SHARED_FINGER.to_owned()
        ]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plain key beside a kept root is sealed under a chosen passphrase first, then the touch goes beside it.
/// Red when it is sealed under `touch-id` alone.
#[tokio::test]
async fn lock_touch_id_on_a_plain_key_beside_a_root_chooses_a_passphrase_first() {
    let (home, dir) = home("touch-id-plain-root");
    super::inspect(&home).expect("a plain key");
    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    let mut prompt = proving([LONG]);
    lock_touch_id(&home, &mut prompt).await.unwrap();
    assert_eq!(
        locks(&home),
        [Method::Passphrase],
        "sealed before the touch"
    );
    assert!(matches!(
        prompt.touches()[0].act,
        TouchAct::BesidePassphrase {
            then: Then::Keep,
            ..
        }
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A touch that does not prove the new lock, after a plain key beside a root was sealed under a chosen
/// passphrase, says the passphrase stays, never that nothing changed. Red when it says nothing changed.
#[tokio::test]
async fn a_declined_touch_after_sealing_says_the_passphrase_stays() {
    let (home, dir) = home("touch-id-plain-root-declined");
    super::inspect(&home).expect("a plain key");
    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    let mut prompt = Counting::new([LONG])
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Declined]);
    let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
    assert_eq!(format!("{refused:#}"), super::SEALED_NOT_TOUCHED);
    assert_eq!(locks(&home), [Method::Passphrase]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plain key where no root is kept is sealed by the touch alone.
#[tokio::test]
async fn lock_touch_id_on_a_plain_key_seals_it_by_the_touch() {
    let (home, dir) = home("touch-id-plain");
    super::inspect(&home).expect("a plain key");
    let mut prompt = proving([]);
    lock_touch_id(&home, &mut prompt).await.unwrap();
    assert_eq!(prompt.events(), 0);
    assert!(matches!(prompt.touches()[0].act, TouchAct::SealPlain));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Over ssh, `lock touch-id` refuses before anything is asked or written, naming the variable.
#[tokio::test]
async fn lock_touch_id_over_ssh_refuses_naming_the_variable() {
    let (home, dir) = home("touch-id-ssh");
    sealed(&home, PASSPHRASE).await;
    let before = std::fs::read(home.key()).unwrap();
    let mut prompt = Counting::new([PASSPHRASE]).here(TouchHere::OverSsh("SSH_CLIENT"));
    let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
    assert_eq!(
        format!("{refused:#}"),
        "touch-id is set at this Mac's own screen, not over ssh (SSH_CLIENT is set); run it there: swoosh \
         lock touch-id"
    );
    assert_eq!(prompt.events(), 0);
    assert!(prompt.said().is_empty());
    assert_eq!(std::fs::read(home.key()).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Under `touch-id` alone, setting it again opens by the touch it has, two dialogs on one bound each; beside a
/// kept root, it gains a passphrase instead.
#[tokio::test]
async fn lock_touch_id_on_a_touch_id_only_key_sets_it_again_or_adds_a_passphrase() {
    let (home, dir) = home("touch-id-again");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let mut prompt = proving([]);
    lock_touch_id(&home, &mut prompt).await.unwrap();
    assert!(matches!(prompt.touches()[0].act, TouchAct::Again));
    assert_eq!(prompt.touches()[0].dialogs(), 2);

    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    let mut prompt = proving([LONG]);
    let locked = lock_touch_id(&home, &mut prompt).await.unwrap();
    assert_eq!(locked, super::Locked::TouchId { passphrase: true });
    assert!(matches!(
        prompt.touches()[0].act,
        TouchAct::AddPassphrase {
            then: Then::Keep,
            ..
        }
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A passphrase for a key under `touch-id` alone replaces it where no root is kept.
#[tokio::test]
async fn lock_passphrase_on_a_touch_id_only_key_replaces_it() {
    let (home, dir) = home("passphrase-replaces-touch");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let mut prompt = proving([LONG]);
    let locked = super::lock(&home, Method::Passphrase, false, &mut prompt)
        .await
        .unwrap();
    assert_eq!(locked, super::Locked::Set { first: true });
    assert!(matches!(
        prompt.touches()[0].act,
        TouchAct::AddPassphrase {
            then: Then::Drop,
            ..
        }
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Beside a kept root, the passphrase is not removed from a key under `touch-id` too, so the key never ends
/// on the touch alone there. Red when the refusal is dropped.
#[tokio::test]
async fn lock_remove_beside_a_root_keeps_the_passphrase_by_the_touch() {
    let (home, dir) = home("remove-keeps-passphrase");
    placed(&home, &DEVICE_PASSPHRASE_AND_TOUCH_ID);
    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    let before = std::fs::read(home.key()).unwrap();
    let mut prompt = Counting::new([PASSPHRASE]);
    let refused = super::lock(&home, Method::Passphrase, true, &mut prompt)
        .await
        .unwrap_err();
    assert_eq!(format!("{refused:#}"), super::KEEPS_PASSPHRASE);
    assert_eq!(prompt.events(), 0);
    assert_eq!(std::fs::read(home.key()).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `lock touch-id --remove` opens with the passphrase where there is one, and leaves it the one lock.
#[tokio::test]
async fn lock_touch_id_remove_leaves_the_passphrase() {
    let (home, dir) = home("remove-touch-id");
    placed(&home, &DEVICE_PASSPHRASE_AND_TOUCH_ID);
    let mut prompt = Counting::new([PASSPHRASE]);
    let locked = super::lock(&home, Method::TouchId, true, &mut prompt)
        .await
        .unwrap();
    assert_eq!(locked, super::Locked::TouchIdRemoved { plain: false });
    assert_eq!(locks(&home), [Method::Passphrase]);
    assert!(prompt.touches().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `lock touch-id --remove` on a key with no `touch-id` changes nothing and asks nothing.
#[tokio::test]
async fn lock_touch_id_remove_with_none_changes_nothing() {
    let (home, dir) = home("remove-no-touch-id");
    sealed(&home, PASSPHRASE).await;
    let mut prompt = Counting::refusing();
    let locked = super::lock(&home, Method::TouchId, true, &mut prompt)
        .await
        .unwrap();
    assert_eq!(locked, super::Locked::NoTouchId);
    assert_eq!(prompt.events(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A key under `touch-id` alone opens by the touch for a serving verb, as the node it was sealed as.
#[tokio::test]
async fn a_touch_id_only_key_resolves_by_the_touch() {
    let (home, dir) = home("resolve-touch-id");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let mut prompt = Counting::refusing()
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Opened(Some(keystore::Secret::take(
            &mut [0x11; 32],
        )))]);
    let secret = super::resolve_with(super::Identity::Persisted, &home, &mut prompt).unwrap();
    assert_eq!(
        secret.node_id(),
        crate::testkit::TestNode::seeded(0x11).node_id()
    );
    assert_eq!(prompt.touches()[0].reason, crate::touch::USE_MACHINE_KEY);
    let _ = std::fs::remove_dir_all(&dir);
}
