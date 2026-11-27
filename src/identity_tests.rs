//! The persisted identity file's failure modes: a corrupt, too-open, or ALREADY-PROVISIONED
//! `key` is refused, never silently replaced, a write is atomic (a failed one leaves the store
//! exactly as it was), and a sealed key opens only under its passphrase and never becomes a new identity.

use std::path::PathBuf;

use keystore::{Method, Stored};

use super::{Methods, Root};
use crate::home::Home;
use crate::passphrase::Scripted;
use crate::testkit::Counting;
use crate::testkit::touch_id::{DEVICE_PASSPHRASE_AND_TOUCH_ID, DEVICE_TOUCH_ID_ALONE, PASSPHRASE};
use crate::touch::{TouchAct, TouchHere, Touched};

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
    assert!(
        matches!(
            locked,
            super::Locked::Made {
                now: Methods::Passphrase,
                ..
            }
        ),
        "{locked:?}"
    );
    crate::testkit::stored_key(&keystore::KeyFile::new(home.key()))
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
    let stored = keystore::KeyFile::new(home.key()).load().unwrap();
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
    match keystore::KeyFile::new(home.key())
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

/// Where no root is kept, `touch-id` goes beside the passphrase, which opens the key for it, and the touch
/// proves the new lock. The line saying what the key will open with comes before anything is asked, as a
/// warning. Red when the passphrase is dropped, or the line is the one-lock notice.
#[tokio::test]
async fn lock_touch_id_on_a_passphrase_key_goes_beside_it() {
    let (home, dir) = home("touch-id-beside");
    sealed(&home, PASSPHRASE).await;
    let mut prompt = proving([PASSPHRASE]);
    let locked = lock_touch_id(&home, &mut prompt).await.unwrap();
    assert_eq!(added_as(locked), Some((Methods::TouchId, Root::NotKept)));
    assert_eq!(prompt.events(), 1, "the passphrase that opens it");
    let [touch] = prompt.touches() else {
        panic!("one touch: {:?}", prompt.touches());
    };
    assert!(matches!(touch.act, TouchAct::BesidePassphrase { .. }));
    assert_eq!(touch.reason, crate::touch::CHECK_MACHINE_KEY);
    assert_eq!(prompt.said()[0], crate::touch::TOUCH_ID_BESIDE);
    assert_eq!(
        prompt.warned(),
        [crate::touch::TOUCH_ID_BESIDE, "", ""],
        "the notice and the blank lines around the prompts are warnings, and the wait for the touch is not"
    );
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
    assert_eq!(added_as(locked), Some((Methods::TouchId, Root::Kept)));
    assert!(matches!(
        prompt.touches()[0].act,
        TouchAct::BesidePassphrase { .. }
    ));
    assert_eq!(
        prompt.warned(),
        [
            crate::touch::TOUCH_ID_BESIDE,
            crate::touch::SHARED_FINGER,
            "",
            ""
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
        TouchAct::BesidePassphrase { .. }
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
    assert_eq!(
        format!("{refused:#}"),
        "Touch ID was cancelled\n  Added a passphrase to this machine's key, which now opens with the passphrase."
    );
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
        "Touch ID is set at this Mac's own screen, not over ssh (SSH_CLIENT is set); run it there: swoosh \
         lock touch-id"
    );
    assert_eq!(prompt.events(), 0);
    assert!(prompt.said().is_empty());
    assert_eq!(std::fs::read(home.key()).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Under `touch-id` alone, the key already has the lock asked for: nothing is asked, said, touched or
/// written, with or without a root kept here. Beside a root it answers that the key still needs its
/// passphrase, which is `lock passphrase`'s to add. Red when a passphrase is chosen there, the file is
/// written, or the answer beside a root reads as the one lock asked for.
#[tokio::test]
async fn touch_id_on_touch_id_alone_beside_a_root_changes_nothing() {
    let (home, dir) = home("touch-id-again");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let before = std::fs::read(home.key()).unwrap();
    for (root_kept, answer) in [
        (false, super::Locked::Unchanged(super::Why::TouchIdAlone)),
        (true, super::Locked::Unchanged(super::Why::NeedsPassphrase)),
    ] {
        if root_kept {
            std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
        }
        let mut prompt = proving([LONG]);
        let locked = lock_touch_id(&home, &mut prompt).await.unwrap();
        assert_eq!(locked, answer);
        assert!(prompt.touches().is_empty(), "{:?}", prompt.touches());
        assert_eq!(prompt.events(), 0, "no passphrase chosen");
        assert!(prompt.said().is_empty(), "{:?}", prompt.said());
        assert_eq!(std::fs::read(home.key()).unwrap(), before);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `lock touch-id` on a key under `touch-id` alone with no root kept answers by the lock's health, read
/// with no dialog: one that does not open here, or cannot be checked now, is refused with the line that says
/// why, never called done, and nothing is touched or written. Red when the health is not read.
#[tokio::test]
async fn lock_touch_id_on_a_touch_id_only_key_that_does_not_open_is_refused() {
    let (home, dir) = home("touch-id-has-not-live");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let before = std::fs::read(home.key()).unwrap();
    for (health, refusal) in [
        (
            keystore::Health::Dead,
            "Touch ID does not open this machine's key on this Mac now.\n\
             if you added a fingerprint, removing it lets Touch ID open the key again.\n\
             otherwise, give this machine a new key and join again: swoosh leave --new-key",
        ),
        (
            keystore::Health::Unchecked,
            "Touch ID cannot be checked now (the screen may be locked, or Touch ID locked out), and this \
             machine's key has no other lock; unlock this Mac and run this again",
        ),
    ] {
        let mut prompt = Counting::refusing().at_this_mac(health);
        let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
        assert_eq!(format!("{refused:#}"), refusal, "{health:?}");
        assert!(prompt.touches().is_empty());
        assert_eq!(prompt.events(), 0);
        assert_eq!(std::fs::read(home.key()).unwrap(), before);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Over ssh, `lock touch-id` on a key under `touch-id` alone is refused as any set is, never called done:
/// the health that answers it is read only at this Mac's own screen. Red when the answer comes first.
#[tokio::test]
async fn lock_touch_id_on_a_touch_id_only_key_over_ssh_is_refused() {
    let (home, dir) = home("touch-id-has-ssh");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let mut prompt = Counting::refusing().here(TouchHere::OverSsh("SSH_TTY"));
    let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
    assert!(
        format!("{refused:#}").contains("not over ssh (SSH_TTY is set)"),
        "{refused:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A passphrase for a key under `touch-id` alone goes beside it where a root is kept, said as such, with
/// the dialog naming that act. Red when it reads as a first passphrase.
#[tokio::test]
async fn lock_passphrase_on_a_touch_id_only_key_beside_a_root_goes_beside_it() {
    let (home, dir) = home("passphrase-beside-touch");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    let mut prompt = proving([LONG]);
    let locked = super::lock(&home, Method::Passphrase, false, &mut prompt)
        .await
        .unwrap();
    assert_eq!(added_as(locked), Some((Methods::Passphrase, Root::Kept)));
    assert_eq!(
        prompt.touches()[0].reason,
        crate::touch::ADD_PASSPHRASE_TO_MACHINE_KEY
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `lock touch-id --remove` on a key under `touch-id` alone opens it by the touch, with the dialog naming
/// the removal, and leaves it plain.
#[tokio::test]
async fn lock_touch_id_remove_on_a_touch_id_only_key_names_the_removal() {
    let (home, dir) = home("remove-touch-id-alone");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let mut prompt = proving([]);
    let locked = super::lock(&home, Method::TouchId, true, &mut prompt)
        .await
        .unwrap();
    assert!(
        matches!(
            locked,
            super::Locked::Removed {
                method: Method::TouchId,
                ..
            }
        ),
        "{locked:?}"
    );
    assert!(matches!(prompt.touches()[0].act, TouchAct::RemoveTouchId));
    assert_eq!(
        prompt.touches()[0].reason,
        crate::touch::REMOVE_TOUCH_ID_FROM_MACHINE_KEY
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A touch that fails after a plain key beside a root was sealed under a chosen passphrase says why, then
/// that the passphrase stays. Red when the failure says only that the touch did not open.
#[tokio::test]
async fn a_failed_touch_after_sealing_says_the_passphrase_stays() {
    let (home, dir) = home("touch-id-plain-root-failed");
    super::inspect(&home).expect("a plain key");
    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    let mut prompt = Counting::new([LONG])
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Failed(eyre::eyre!("the enclave refused"))]);
    let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
    assert_eq!(
        format!("{refused:#}"),
        "Touch ID failed\n  Added a passphrase to this machine's key, which now opens with the passphrase.\n  \
         the enclave refused"
    );
    assert_eq!(locks(&home), [Method::Passphrase]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Where no root is kept, adding a lock never takes the other off: `touch-id` on a key under a passphrase
/// goes beside it, and a passphrase on a key under `touch-id` goes beside that, each by its one act, which
/// adds. A scripted touch writes nothing, and the key store's software enclave is its own tests' alone, so the
/// lock list after a real touch is the hardware acts' (`touch_tests::hardware_acts`); what a passphrase alone
/// can take off is read from the file here: the passphrase is still on it. Red when either answers as the one
/// lock it was before this changed, or the passphrase comes off the file.
#[tokio::test]
async fn adding_a_lock_never_drops_one() {
    let (home, dir) = home("add-never-drops");
    sealed(&home, PASSPHRASE).await;
    let mut prompt = proving([PASSPHRASE]);
    let locked = lock_touch_id(&home, &mut prompt).await.unwrap();
    assert_eq!(added_as(locked), Some((Methods::TouchId, Root::NotKept)));
    assert!(matches!(
        prompt.touches()[0].act,
        TouchAct::BesidePassphrase { .. }
    ));
    assert_eq!(
        locks(&home),
        [Method::Passphrase],
        "the passphrase stays on"
    );

    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let mut prompt = proving([LONG]);
    let locked = super::lock(&home, Method::Passphrase, false, &mut prompt)
        .await
        .unwrap();
    assert_eq!(added_as(locked), Some((Methods::Passphrase, Root::NotKept)));
    assert!(matches!(
        prompt.touches()[0].act,
        TouchAct::AddPassphrase { .. }
    ));
    assert_eq!(
        prompt.touches()[0].reason,
        crate::touch::ADD_PASSPHRASE_TO_MACHINE_KEY
    );
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
    assert_eq!(
        locked,
        super::Locked::Removed {
            method: Method::TouchId,
            now: super::Now::Read(super::Locks::Passphrase),
            failed: None,
        }
    );
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
    assert_eq!(
        locked,
        super::Locked::Unchanged(super::Why::NoSuchLock(Method::TouchId))
    );
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

/// Under `touch-id` alone, a lock that does not open here is refused before a new passphrase is typed:
/// `lock` routes the touch first. Red when the passphrase is chosen before the route.
#[tokio::test]
async fn a_dead_touch_id_only_key_refuses_before_a_passphrase_is_chosen() {
    let (home, dir) = home("dead-before-choose");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let mut prompt = Counting::new([LONG]).at_this_mac(keystore::Health::Dead);
    let refused = super::lock(&home, Method::Passphrase, false, &mut prompt)
        .await
        .unwrap_err();
    assert!(
        format!("{refused:#}").starts_with("Touch ID does not open this machine's key"),
        "{refused:#}"
    );
    assert_eq!(prompt.events(), 0, "no passphrase chosen");
    assert!(
        prompt.said().is_empty(),
        "nothing is said before the refusal: {:?}",
        prompt.said()
    );

    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    let mut prompt = Counting::new([LONG]).at_this_mac(keystore::Health::Dead);
    let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
    assert!(
        format!("{refused:#}").starts_with("Touch ID does not open this machine's key"),
        "{refused:#}"
    );
    assert_eq!(prompt.events(), 0, "no passphrase chosen beside a root");
    assert!(prompt.touches().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Setting `touch-id` again over a lock that does not open here says first to check for a fingerprint
/// nobody added, as a warning, before the passphrase is asked. Red when the old lock's health is not read.
#[tokio::test]
async fn setting_a_dead_touch_id_again_says_to_check_touch_id_first() {
    let (home, dir) = home("dead-reset");
    placed(&home, &DEVICE_PASSPHRASE_AND_TOUCH_ID);
    let mut prompt = Counting::new([PASSPHRASE])
        .at_this_mac(keystore::Health::Dead)
        .touching([Touched::Opened(None)]);
    let locked = lock_touch_id(&home, &mut prompt).await.unwrap();
    assert_eq!(
        locked,
        super::Locked::Changed {
            method: Method::TouchId,
            now: super::Now::Read(super::Locks::Both(Some(keystore::Health::Dead))),
            failed: None,
        }
    );
    assert_eq!(
        prompt.warned(),
        [
            crate::touch::CHANGES_TOUCH_ID.to_owned(),
            "warning: Touch ID does not open this machine's key on this Mac now.\n\
             the new lock will open with every fingerprint now in Touch ID & Password; if one is not yours, \
             press ctrl-c and remove it first."
                .to_owned(),
            String::new(),
            String::new(),
        ],
        "the fingerprint line is said once, in the warning"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Joining again the invite whose key a home holds under `touch-id` alone opens it by the touch, and writes
/// nothing: the open proves it. Red when the claim is proven by a passphrase the file does not hold.
#[tokio::test]
async fn rewriting_a_touch_id_only_key_proves_it_by_the_touch_and_writes_nothing() {
    let (home, dir) = home("touch-id-rewrite");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    let before = std::fs::read(home.key()).unwrap();
    let mut prompt = Counting::refusing()
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Opened(Some(keystore::Secret::take(
            &mut [0x11; 32],
        )))]);
    super::write_with(&[0x11; 32], &home, &mut prompt).expect("the same key, proven, is a no-op");
    let [touch] = prompt.touches() else {
        panic!("one touch: {:?}", prompt.touches());
    };
    assert!(matches!(touch.act, TouchAct::Open));
    assert_eq!(touch.reason, crate::touch::USE_MACHINE_KEY);
    assert_eq!(prompt.events(), 0);
    assert_eq!(std::fs::read(home.key()).unwrap(), before);

    let mut prompt = Counting::refusing()
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::TimedOut]);
    let refused = super::write_with(&[0x11; 32], &home, &mut prompt).unwrap_err();
    assert_eq!(format!("{refused:#}"), crate::touch::TIMED_OUT);
    assert_eq!(std::fs::read(home.key()).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The state a root arriving beside a key under `touch-id` alone leaves is read from the header alone:
/// the key's lock list, and a root kept here. Red when either half is dropped.
#[tokio::test]
async fn touch_id_alone_beside_a_root_needs_both() {
    let (home, dir) = home("alone-beside-root");
    placed(&home, &DEVICE_TOUCH_ID_ALONE);
    assert!(!super::touch_id_alone_beside_root(&home), "no root kept");
    std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
    assert!(super::touch_id_alone_beside_root(&home));
    placed(&home, &DEVICE_PASSPHRASE_AND_TOUCH_ID);
    assert!(
        !super::touch_id_alone_beside_root(&home),
        "a passphrase beside it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// What a [`Heard`] prompt heard, in order: each line said or warned, and each ask and touch.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Heard {
    Line(String),
    Unlock,
    Choose,
    Touch,
}

/// A prompt that answers as `inner` does and keeps one log of everything in order, which `Counting` keeps
/// apart; and runs `on_ask` before each unlock or choose is answered, for a home that changes under a prompt.
struct Logged<F: FnMut()> {
    inner: Counting,
    on_ask: F,
    heard: Vec<Heard>,
}

impl<F: FnMut()> crate::passphrase::Prompt for Logged<F> {
    fn terminal(&self) -> bool {
        self.inner.terminal()
    }

    fn unlock(
        &mut self,
        asked: crate::passphrase::Asked<'_>,
    ) -> eyre::Result<keystore::Passphrase> {
        self.heard.push(Heard::Unlock);
        (self.on_ask)();
        self.inner.unlock(asked)
    }

    fn choose(
        &mut self,
        asked: crate::passphrase::Asked<'_>,
    ) -> eyre::Result<crate::passphrase::Choice> {
        self.heard.push(Heard::Choose);
        (self.on_ask)();
        self.inner.choose(asked)
    }

    fn say(&mut self, line: &str) {
        self.heard.push(Heard::Line(line.to_owned()));
        self.inner.say(line);
    }

    fn warn(&mut self, line: &str) {
        self.heard.push(Heard::Line(line.to_owned()));
        self.inner.warn(line);
    }

    fn touch_here(&self) -> TouchHere {
        self.inner.touch_here()
    }

    fn health(&self, locked: &keystore::Locked) -> Option<keystore::Health> {
        self.inner.health(locked)
    }

    fn touch(&mut self, touch: crate::touch::Touch) -> Touched {
        self.heard.push(Heard::Touch);
        self.inner.touch(touch)
    }
}

/// `inner`, logged, with nothing run at an unlock.
fn logged(inner: Counting) -> Logged<impl FnMut()> {
    Logged {
        inner,
        on_ask: || {},
        heard: Vec::new(),
    }
}

/// Every change that moves the lock set says first what the key opens with now and after: the first thing
/// heard, warned, before any passphrase is asked or chosen and before the touch, a blank line after it where
/// a prompt follows; and a waiting line, said where the prompts are, that names the act its dialog's reason
/// names. A passphrase change keeps the lock set, so its first event is the ask. The whole conversation,
/// exactly, the blank line between the wait and the result included. Red when a line is missing, extra, or
/// comes after an ask or a touch, when a blank line is dropped, or when a waiting line is warned, or it or a
/// reason names another act. `home.lock` is not seen by the log, so this does not show the lines come
/// before it.
#[tokio::test]
async fn every_change_says_now_and_after_first() {
    use crate::touch as t;
    let line = |text: &str| Heard::Line(text.to_owned());
    let add = "Touch the sensor to add Touch ID…";
    // One cell a line: tag, start, root kept, method, remove, what is heard through the first touch, and the
    // dialog's reason.
    #[rustfmt::skip]
    let cells = [
        ("none-p", Start::None, false, Method::Passphrase, false, vec![line(t::MAKES_UNDER_PASSPHRASE), line(""), Heard::Choose], None),
        ("plain-p", Start::Plain, false, Method::Passphrase, false, vec![line(t::SEALS_UNDER_PASSPHRASE), line(""), Heard::Choose], None),
        ("none-t", Start::None, false, Method::TouchId, false, vec![line(t::MAKES_UNDER_TOUCH_ID), line("Touch the sensor to make this machine's key…"), Heard::Touch, line("")], Some(t::MAKE_MACHINE_KEY)),
        ("none-root-t", Start::None, true, Method::TouchId, false, vec![line(t::MAKES_BESIDE_ROOT), line(""), Heard::Choose, line(add), Heard::Touch, line("")], Some(t::CHECK_MACHINE_KEY)),
        ("plain-t", Start::Plain, false, Method::TouchId, false, vec![line(t::SEALS_UNDER_TOUCH_ID), line(add), Heard::Touch, line("")], Some(t::CHECK_MACHINE_KEY)),
        ("plain-root-t", Start::Plain, true, Method::TouchId, false, vec![line(t::SEALS_BESIDE_ROOT), line(""), Heard::Choose, line(add), Heard::Touch, line("")], Some(t::CHECK_MACHINE_KEY)),
        ("p-t", Start::P, false, Method::TouchId, false, vec![line(t::TOUCH_ID_BESIDE), line(""), Heard::Unlock, line(add), Heard::Touch, line("")], Some(t::CHECK_MACHINE_KEY)),
        ("p-root-t", Start::P, true, Method::TouchId, false, vec![line(t::TOUCH_ID_BESIDE), line(""), Heard::Unlock, line(add), Heard::Touch, line("")], Some(t::CHECK_MACHINE_KEY)),
        ("t-p", Start::T, false, Method::Passphrase, false, vec![line(t::BESIDE_TOUCH_ID), line(""), Heard::Choose, line("Touch the sensor to add the passphrase…"), Heard::Touch, line("")], Some(t::ADD_PASSPHRASE_TO_MACHINE_KEY)),
        ("t-root-p", Start::T, true, Method::Passphrase, false, vec![line(t::BESIDE_TOUCH_ID), line(""), Heard::Choose, line("Touch the sensor to add the passphrase…"), Heard::Touch, line("")], Some(t::ADD_PASSPHRASE_TO_MACHINE_KEY)),
        ("pt-t", Start::Pt, false, Method::TouchId, false, vec![line(t::CHANGES_TOUCH_ID), line(t::EVERY_FINGERPRINT), line(""), Heard::Unlock, line(add), Heard::Touch, line("")], Some(t::CHECK_MACHINE_KEY)),
        ("pt-root-t", Start::Pt, true, Method::TouchId, false, vec![line(t::CHANGES_TOUCH_ID), line(t::EVERY_FINGERPRINT), line(""), Heard::Unlock, line(add), Heard::Touch, line("")], Some(t::CHECK_MACHINE_KEY)),
        ("p-p", Start::P, false, Method::Passphrase, false, vec![Heard::Unlock, Heard::Choose], None),
        ("p-less-p", Start::P, false, Method::Passphrase, true, vec![line(t::TAKES_LAST_LOCK_OFF), line(""), Heard::Unlock], None),
        ("t-less-t", Start::T, false, Method::TouchId, true, vec![line(t::TAKES_LAST_LOCK_OFF), line("Touch the sensor to remove Touch ID…"), Heard::Touch, line("")], Some(t::REMOVE_TOUCH_ID_FROM_MACHINE_KEY)),
        ("pt-less-p", Start::Pt, false, Method::Passphrase, true, vec![line(t::TAKES_PASSPHRASE_OFF), line(""), Heard::Unlock], None),
        ("pt-less-t", Start::Pt, false, Method::TouchId, true, vec![line(t::TAKES_TOUCH_ID_OFF), line(""), Heard::Unlock], None),
    ];
    for (tag, start, root, method, remove, heard, reason) in cells {
        let (home, dir) = home(&format!("now-and-after-{tag}"));
        match start {
            Start::None => {}
            Start::Plain => drop(super::inspect(&home).expect("a plain key")),
            Start::P => drop(sealed(&home, PASSPHRASE).await),
            Start::T => placed(&home, &DEVICE_TOUCH_ID_ALONE),
            Start::Pt => placed(&home, &DEVICE_PASSPHRASE_AND_TOUCH_ID),
        }
        if root {
            std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
        }
        let mut counting = proving([PASSPHRASE, LONG]);
        if tag == "none-t" {
            // The make is written by the touch itself, so the file it leaves stands in for it.
            counting = counting.publishing(landing_as(&DEVICE_TOUCH_ID_ALONE));
        }
        let mut prompt = logged(counting);
        // A run that ends Ok is heard whole. Taking the passphrase off a key whose Touch ID opens on no
        // enclave (the fixtures') is refused by the key store after the ask, so that one is heard through it.
        match super::lock(&home, method, remove, &mut prompt).await {
            Ok(_) => assert_eq!(prompt.heard, heard, "{tag}, {start:?}"),
            Err(_) => assert_eq!(
                prompt.heard.get(..heard.len()),
                Some(&heard[..]),
                "{tag}, {start:?}: {:?}",
                prompt.heard
            ),
        }
        assert!(
            !prompt
                .inner
                .warned()
                .iter()
                .any(|line| line.starts_with("Touch the sensor")),
            "{tag}: a waiting line rides with the prompts, not the warnings"
        );
        let asked = heard
            .iter()
            .position(|heard| !matches!(heard, Heard::Line(_)))
            .unwrap_or(heard.len());
        // The waiting line attends the touch, where the person looks for the dialog; the rest are warnings.
        let before: Vec<&String> = prompt.inner.said()[..asked]
            .iter()
            .filter(|line| !line.starts_with("Touch the sensor"))
            .collect();
        assert_eq!(
            prompt
                .inner
                .warned()
                .iter()
                .take(before.len())
                .collect::<Vec<_>>(),
            before,
            "{tag}: the lines before the first ask are warnings"
        );
        assert_eq!(
            prompt.inner.touches().first().map(|touch| touch.reason),
            reason,
            "{tag}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Whether `touch-id` on a key under a passphrase is an add or a change is read under `home.lock`, after the
/// prompts: a `touch-id` lock taken off or put on while the passphrase was typed answers as the file then
/// is, never as it was read first. Red when the answer comes from the read before the prompts.
#[tokio::test]
async fn touch_id_beside_a_passphrase_answers_by_the_file_under_the_lock() {
    let (scratch, scratch_dir) = home("under-lock-passphrase-alone");
    sealed(&scratch, PASSPHRASE).await;
    let passphrase_alone = std::fs::read(scratch.key()).unwrap();
    let _ = std::fs::remove_dir_all(&scratch_dir);
    for (tag, first, then, answer) in [
        (
            "lost",
            DEVICE_PASSPHRASE_AND_TOUCH_ID.to_vec(),
            passphrase_alone.clone(),
            super::Locked::Added {
                method: Methods::TouchId,
                now: super::Now::Read(super::Locks::Passphrase),
                root: Root::NotKept,
                failed: None,
            },
        ),
        (
            "gained",
            passphrase_alone.clone(),
            DEVICE_PASSPHRASE_AND_TOUCH_ID.to_vec(),
            super::Locked::Changed {
                method: Method::TouchId,
                now: super::Now::Read(super::Locks::Both(Some(keystore::Health::Live))),
                failed: None,
            },
        ),
    ] {
        let (home, dir) = home(&format!("under-lock-{tag}"));
        placed(&home, &first);
        let key = home.key();
        let mut prompt = Logged {
            inner: proving([PASSPHRASE]),
            on_ask: move || std::fs::write(&key, &then).expect("swap the key file"),
            heard: Vec::new(),
        };
        let locked = lock_touch_id_with(&home, &mut prompt).await.unwrap();
        assert_eq!(locked, answer, "{tag}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// `lock touch-id` at this Mac, asked through any prompt.
async fn lock_touch_id_with(
    home: &Home,
    prompt: &mut impl crate::passphrase::Prompt,
) -> eyre::Result<super::Locked> {
    super::lock(home, Method::TouchId, false, prompt).await
}

/// Whether a root is kept, for the step a result offers, is read under `home.lock`: a root that arrives while
/// the passphrase is typed or chosen keeps the passphrase on, so the result offers no step to take it off.
/// Red when it is read before the prompts.
#[tokio::test]
async fn a_root_that_arrives_during_the_prompts_is_read_under_the_lock() {
    for (tag, key, method, answer) in [
        ("p-plus-t", None, Method::TouchId, Methods::TouchId),
        (
            "t-plus-p",
            Some(&DEVICE_TOUCH_ID_ALONE[..]),
            Method::Passphrase,
            Methods::Passphrase,
        ),
    ] {
        let (home, dir) = home(&format!("root-arrives-{tag}"));
        match key {
            Some(bytes) => placed(&home, bytes),
            None => {
                sealed(&home, PASSPHRASE).await;
            }
        }
        let root = home.root_key();
        let answers = if key.is_some() { [LONG] } else { [PASSPHRASE] };
        let mut prompt = Logged {
            inner: proving(answers),
            on_ask: move || std::fs::write(&root, b"a root kept here").expect("a root arrives"),
            heard: Vec::new(),
        };
        let locked = super::lock(&home, method, false, &mut prompt)
            .await
            .unwrap();
        assert_eq!(added_as(locked), Some((answer, Root::Kept)), "{tag}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The locks an add put on, and whether a root is kept, where `locked` is an add.
fn added_as(locked: super::Locked) -> Option<(Methods, Root)> {
    match locked {
        super::Locked::Added { method, root, .. } => Some((method, root)),
        _ => None,
    }
}

/// `bytes` at `path`, owner-only, as a key store write would leave them.
fn put(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, bytes).expect("write the key file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
}

/// The key a touch's act is on: the one it writes, or the one the file's header names now.
fn acted_on(touch: &crate::touch::Touch) -> keystore::PublicKey {
    match &touch.act {
        TouchAct::Write(secret) => secret.public_key(),
        _ => match touch.file.load().expect("load").expect("a key") {
            Stored::Plain(secret) => secret.public_key(),
            Stored::Locked(locked) => locked.public_key(),
        },
    }
}

/// A stand-in for what the key store's act leaves on disk, since a scripted touch writes nothing: the file
/// `land` makes from the key the act is on.
fn landing(
    land: impl Fn(&keystore::PublicKey) -> Vec<u8> + 'static,
) -> impl FnMut(&crate::touch::Touch) + 'static {
    move |touch| put(touch.file.path(), &land(&acted_on(touch)))
}

/// `fixture`'s locks under the key the act is on.
fn landing_as(fixture: &'static [u8]) -> impl FnMut(&crate::touch::Touch) + 'static {
    landing(move |public| crate::testkit::touch_id::claiming(fixture, public))
}

/// What `home`'s key file holds, as the result reads it, Touch ID reading live.
fn now_in(home: &Home) -> super::Locks {
    let stored = keystore::KeyFile::new(home.key())
        .load()
        .expect("load")
        .expect("a key");
    super::Locks::of(
        &stored,
        &Counting::new([]).at_this_mac(keystore::Health::Live),
    )
}

/// The fixtures' key, plain: what taking the last lock off leaves, which names no key in a header.
const PLAIN: [u8; 32] = [0x11; 32];

/// The state a cell starts from.
#[derive(Clone, Copy, Debug)]
enum Start {
    None,
    Plain,
    P,
    T,
    Pt,
}

/// Every start a key can be in, by every act `lock` takes, each a scripted run: every one gives its own outcome, and every lock
/// set in it is the file's header read after the act. A touch that lands leaves the file its act would, so
/// the set read back is the act's. Taking the passphrase off both locks is not here: the key store refuses
/// to leave a key under a Touch ID lock that opens on no enclave, and the fixtures' opens on none, so that
/// result's bytes are the screen's row alone. Red when two acts share an outcome, or a set is not the file's.
#[tokio::test]
async fn each_cell_has_its_own_outcome() {
    use keystore::Health::Live;

    use super::{Locked, Locks, Now, Why};

    let pt = &DEVICE_PASSPHRASE_AND_TOUCH_ID[..];
    let t = &DEVICE_TOUCH_ID_ALONE[..];
    let made = |now| {
        move |key| Locked::Made {
            key,
            now,
            failed: None,
        }
    };
    let fixed = |locked: Locked| move |_| locked.clone();
    type Cell = (
        &'static str,
        Start,
        bool,
        Method,
        bool,
        Option<&'static [u8]>,
        &'static [&'static str],
        Box<dyn Fn(bifrost::NodeId) -> Locked>,
    );
    // One cell a line: tag, start, root kept, method, remove, what a landed touch leaves, the answers, and the
    // outcome. The `unlanded` cells leave the file as it was, so a set taken from the ask is caught.
    #[rustfmt::skip]
    let cells: Vec<Cell> = vec![
        ("none-p", Start::None, false, Method::Passphrase, false, None, &[LONG], Box::new(made(Methods::Passphrase))),
        ("none-t", Start::None, false, Method::TouchId, false, Some(t), &[], Box::new(made(Methods::TouchId))),
        ("none-root-t", Start::None, true, Method::TouchId, false, Some(pt), &[LONG], Box::new(made(Methods::Both))),
        ("plain-p", Start::Plain, false, Method::Passphrase, false, None, &[LONG], Box::new(fixed(Locked::Added { method: Methods::Passphrase, now: super::Now::Read(super::Locks::Passphrase), root: Root::NotKept, failed: None }))),
        ("plain-t", Start::Plain, false, Method::TouchId, false, Some(t), &[], Box::new(fixed(Locked::Added { method: Methods::TouchId, now: super::Now::Read(super::Locks::TouchId(Some(Live))), root: Root::NotKept, failed: None }))),
        ("plain-root-t", Start::Plain, true, Method::TouchId, false, Some(pt), &[LONG], Box::new(fixed(Locked::Added { method: Methods::Both, now: super::Now::Read(super::Locks::Both(Some(Live))), root: Root::Kept, failed: None }))),
        ("p-p", Start::P, false, Method::Passphrase, false, None, &[PASSPHRASE, LONG], Box::new(fixed(Locked::Changed { method: Method::Passphrase, now: super::Now::Read(super::Locks::Passphrase), failed: None }))),
        ("p-t", Start::P, false, Method::TouchId, false, Some(pt), &[PASSPHRASE], Box::new(fixed(Locked::Added { method: Methods::TouchId, now: super::Now::Read(super::Locks::Both(Some(Live))), root: Root::NotKept, failed: None }))),
        ("p-p-remove", Start::P, false, Method::Passphrase, true, None, &[PASSPHRASE], Box::new(fixed(Locked::Removed { method: Method::Passphrase, now: super::Now::Read(super::Locks::None), failed: None }))),
        ("p-t-unlanded", Start::P, false, Method::TouchId, false, None, &[PASSPHRASE], Box::new(fixed(Locked::Added { method: Methods::TouchId, now: super::Now::Read(super::Locks::Passphrase), root: Root::NotKept, failed: None }))),
        ("p-t-remove", Start::P, false, Method::TouchId, true, None, &[], Box::new(fixed(Locked::Unchanged(Why::NoSuchLock(Method::TouchId))))),
        ("t-p", Start::T, false, Method::Passphrase, false, Some(pt), &[LONG], Box::new(fixed(Locked::Added { method: Methods::Passphrase, now: super::Now::Read(super::Locks::Both(Some(Live))), root: Root::NotKept, failed: None }))),
        ("t-t", Start::T, false, Method::TouchId, false, None, &[], Box::new(fixed(Locked::Unchanged(Why::TouchIdAlone)))),
        ("t-root-t", Start::T, true, Method::TouchId, false, None, &[], Box::new(fixed(Locked::Unchanged(Why::NeedsPassphrase)))),
        ("t-p-remove", Start::T, false, Method::Passphrase, true, None, &[], Box::new(fixed(Locked::Unchanged(Why::NoSuchLock(Method::Passphrase))))),
        ("t-t-remove", Start::T, false, Method::TouchId, true, Some(&PLAIN), &[], Box::new(fixed(Locked::Removed { method: Method::TouchId, now: super::Now::Read(super::Locks::None), failed: None }))),
        ("t-t-remove-unlanded", Start::T, false, Method::TouchId, true, None, &[], Box::new(fixed(Locked::Removed { method: Method::TouchId, now: super::Now::Read(super::Locks::TouchId(Some(Live))), failed: None }))),
        ("pt-p", Start::Pt, false, Method::Passphrase, false, None, &[PASSPHRASE, LONG], Box::new(fixed(Locked::Changed { method: Method::Passphrase, now: Now::Read(Locks::Both(Some(Live))), failed: None }))),
        ("pt-t", Start::Pt, false, Method::TouchId, false, Some(pt), &[PASSPHRASE], Box::new(fixed(Locked::Changed { method: Method::TouchId, now: Now::Read(Locks::Both(Some(Live))), failed: None }))),
        ("pt-t-remove", Start::Pt, false, Method::TouchId, true, None, &[PASSPHRASE], Box::new(fixed(Locked::Removed { method: Method::TouchId, now: super::Now::Read(super::Locks::Passphrase), failed: None }))),
        ("plain-p-remove", Start::Plain, false, Method::Passphrase, true, None, &[], Box::new(fixed(Locked::Unchanged(Why::NoLock)))),
        ("none-p-remove", Start::None, false, Method::Passphrase, true, None, &[], Box::new(fixed(Locked::Unchanged(Why::NoKey)))),
        ("none-t-remove", Start::None, false, Method::TouchId, true, None, &[], Box::new(fixed(Locked::Unchanged(Why::NoKey)))),
    ];
    let mut seen = Vec::new();
    for (tag, start, root_kept, method, remove, lands, answers, answer) in cells {
        let (home, dir) = home(&format!("cell-{tag}"));
        match start {
            Start::None => {}
            Start::Plain => {
                super::inspect(&home).expect("a plain key");
            }
            Start::P => {
                sealed(&home, PASSPHRASE).await;
            }
            Start::T => placed(&home, t),
            Start::Pt => placed(&home, pt),
        }
        if root_kept {
            std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
        }
        let mut prompt = Counting::new(answers.iter().copied())
            .at_this_mac(Live)
            .touching([Touched::Opened(None)]);
        if let Some(fixture) = lands {
            prompt = prompt.publishing(landing_as(fixture));
        }
        let locked = super::lock(&home, method, remove, &mut prompt)
            .await
            .unwrap_or_else(|error| panic!("{tag}: {error:#}"));
        let key = keystore::KeyFile::new(home.key())
            .load()
            .expect("load")
            .map(|_| crate::testkit::stored_key(&keystore::KeyFile::new(home.key())));
        let expected =
            answer(key.unwrap_or_else(|| bifrost::NodeId::from_ed25519_secret(&[0; 32])));
        assert_eq!(locked, expected, "{tag}");
        match &locked {
            Locked::Added { now, .. }
            | Locked::Removed { now, .. }
            | Locked::Changed { now, .. } => {
                assert_eq!(*now, Now::Read(now_in(&home)), "{tag}: the set read back");
            }
            Locked::Made { now, .. } => {
                assert_eq!(
                    now_in(&home).methods(),
                    Some(*now),
                    "{tag}: the set read back"
                );
            }
            Locked::Unchanged(_) => {}
        }
        assert!(
            !seen.contains(&locked),
            "{tag}: {locked:?} is another cell's"
        );
        if !matches!(
            locked,
            Locked::Unchanged(Why::NoKey | Why::NoSuchLock(_)) | Locked::Changed { .. }
        ) {
            seen.push(locked);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(
        matches!(
            super::lock(
                &{
                    let (home, _) = home("cell-pt-root-p-remove");
                    placed(&home, pt);
                    std::fs::write(home.root_key(), b"a root kept here").expect("a root");
                    home
                },
                Method::Passphrase,
                true,
                &mut Counting::new([PASSPHRASE]),
            )
            .await,
            Err(refused) if format!("{refused:#}") == super::KEEPS_PASSPHRASE
        ),
        "PT beside a root keeps its passphrase"
    );
}

/// How each end of a touch that did not land reads as a head, with the failure's own chain where it has one.
const MISSES: [(&str, &str); 4] = [
    ("declined", "Touch ID was cancelled"),
    ("not here", "Touch ID did not open the new lock on this Mac"),
    ("failed", "Touch ID failed"),
    ("timed out", crate::touch::TIMED_OUT),
];

/// The touch end each of [`MISSES`] names.
fn miss(tag: &str) -> Touched {
    match tag {
        "declined" => Touched::Declined,
        "not here" => Touched::NotHere,
        "failed" => Touched::Failed(eyre::eyre!("the enclave refused")),
        _ => Touched::TimedOut,
    }
}

/// The refusal for `tag`'s miss: its head, then `detail`, then a failure's chain on its own line.
fn refusal(tag: &str, head: &str, detail: &str) -> String {
    if tag == "failed" {
        format!("{head}\n  {detail}\n  the enclave refused")
    } else {
        format!("{head}\n  {detail}")
    }
}

/// On an empty home, a `lock touch-id` whose touch does not land says so and that this command made no key,
/// read from the file: nothing is there. Red when the line says nothing changed or that the touch did not
/// open this machine's key, or a key is there.
#[tokio::test]
async fn a_missed_make_says_no_key_was_made() {
    for (tag, head) in MISSES {
        let (home, dir) = home(&format!("missed-make-{tag}"));
        let mut prompt = Counting::new([])
            .at_this_mac(keystore::Health::Live)
            .touching([miss(tag)]);
        let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
        let printed = format!("{refused:#}");
        assert_eq!(printed, refusal(tag, head, super::MADE_NO_KEY), "{tag}");
        assert!(!printed.contains("nothing changed"), "{tag}");
        assert!(
            !printed.contains("did not open this machine's key"),
            "{tag}"
        );
        assert!(!home.key().exists(), "{tag}: no key");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A make whose touch did not land is `Made` only over a file holding the key this run drew, under the Touch
/// ID lock it wrote: a failure can come after the file is in place. Any other file there (another key, as a
/// first `serve` mints with no `home.lock`, this run's key under no Touch ID lock, or one that cannot be
/// read) was not made by this command, and says so, naming `swoosh status`, never `Made` and never that no
/// key was made. Red when the key or the lock set is not checked, or an unreadable file is called made.
#[tokio::test]
async fn a_make_is_made_only_over_this_runs_key() {
    let (mine, mine_dir) = home("make-over-mine");
    let mut prompt = Counting::new([])
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Failed(eyre::eyre!("the directory was not synced"))])
        .publishing(landing_as(&DEVICE_TOUCH_ID_ALONE));
    let locked = lock_touch_id(&mine, &mut prompt).await.unwrap();
    assert_eq!(
        locked,
        super::Locked::Made {
            key: crate::testkit::stored_key(&keystore::KeyFile::new(mine.key())),
            now: Methods::TouchId,
            failed: Some("the directory was not synced".to_owned()),
        }
    );
    let _ = std::fs::remove_dir_all(&mine_dir);

    let theirs = |_: &keystore::PublicKey| DEVICE_TOUCH_ID_ALONE.to_vec();
    let mine_by_passphrase = |touch: &crate::touch::Touch| {
        let TouchAct::Write(secret) = &touch.act else {
            panic!("a make writes: {:?}", touch.act);
        };
        let passphrase =
            crate::passphrase::passphrase(zeroize::Zeroizing::new(PASSPHRASE.to_owned()))
                .expect("a passphrase");
        touch
            .file
            .write(secret, keystore::Protection::Passphrase(&passphrase))
            .expect("this run's key, under a passphrase");
    };
    for (tag, _) in MISSES {
        for (what, others, answer) in [
            (
                "theirs",
                Box::new(landing(theirs)) as Box<dyn FnMut(&crate::touch::Touch)>,
                Refusal::AlreadyThere,
            ),
            (
                "theirs-plain",
                Box::new(landing(|_| PLAIN.to_vec())),
                Refusal::AlreadyThere,
            ),
            (
                "mine-by-passphrase",
                Box::new(mine_by_passphrase),
                Refusal::Unconfirmed { read: false },
            ),
            (
                "unreadable",
                Box::new(landing(|_| b"not a key".to_vec())),
                Refusal::Unconfirmed { read: true },
            ),
        ] {
            let (home, dir) = home(&format!("make-over-{what}-{tag}"));
            let mut prompt = Counting::new([])
                .at_this_mac(keystore::Health::Live)
                .touching([miss(tag)])
                .publishing(others);
            let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
            assert_eq!(
                Refusal::of(&refused),
                Some(answer),
                "{what}, {tag}: {refused:#}"
            );
            assert!(
                !format!("{refused:#}").contains(super::MADE_NO_KEY),
                "{what}, {tag}"
            );
            assert!(home.key().exists(), "{what}, {tag}: the file is left");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// Which refusal a make that found a file it cannot call its own gave: another's key, read whole, or a file
/// it could not confirm, with or without the read's error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    AlreadyThere,
    Unconfirmed { read: bool },
    Gone,
}

impl Refusal {
    fn of(refused: &eyre::Report) -> Option<Self> {
        if let Some(unconfirmed) = refused.downcast_ref::<super::Unconfirmed>() {
            return Some(Self::Unconfirmed {
                read: unconfirmed.read.is_some(),
            });
        }
        if refused.downcast_ref::<super::Gone>().is_some() {
            return Some(Self::Gone);
        }
        (format!("{refused:#}") == super::KEY_ALREADY_THERE).then_some(Self::AlreadyThere)
    }
}

/// Where this command wrote a key file and cannot say what it holds when read back, it claims nothing: a first
/// key beside a root whose file is gone after its touch is gone, never made or not; a plain key sealed beside a
/// root whose file reads back plain, or cannot be read, is unconfirmed, with the read's error where one failed.
/// A write that landed on a key that was there and then cannot be read back is the act, unconfirmed, not a
/// failure. Red when any of these claims an outcome, or a landed add exits as failed.
#[tokio::test]
async fn a_file_this_command_cannot_read_back_claims_nothing() {
    let (first, first_dir) = home("unconfirmed-gone");
    std::fs::write(first.root_key(), b"a root kept here").expect("a root beside it");
    let mut prompt = Counting::new([LONG])
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Declined])
        .publishing(|touch| std::fs::remove_file(touch.file.path()).expect("the file goes"));
    let refused = lock_touch_id(&first, &mut prompt).await.unwrap_err();
    assert_eq!(Refusal::of(&refused), Some(Refusal::Gone), "{refused:#}");
    let _ = std::fs::remove_dir_all(&first_dir);

    for (what, lands, answer) in [
        (
            "plain",
            PLAIN.to_vec(),
            Refusal::Unconfirmed { read: false },
        ),
        (
            "unreadable",
            b"not a key".to_vec(),
            Refusal::Unconfirmed { read: true },
        ),
    ] {
        let (plain, plain_dir) = home(&format!("unconfirmed-sealed-{what}"));
        super::inspect(&plain).expect("a plain key");
        std::fs::write(plain.root_key(), b"a root kept here").expect("a root beside it");
        let mut prompt = Counting::new([LONG])
            .at_this_mac(keystore::Health::Live)
            .touching([Touched::Declined])
            .publishing(landing(move |_| lands.clone()));
        let refused = lock_touch_id(&plain, &mut prompt).await.unwrap_err();
        assert_eq!(Refusal::of(&refused), Some(answer), "{what}: {refused:#}");
        let _ = std::fs::remove_dir_all(&plain_dir);
    }

    let (added, added_dir) = home("unconfirmed-added");
    placed(&added, &DEVICE_TOUCH_ID_ALONE);
    let mut prompt = Counting::new([LONG])
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Opened(None)])
        .publishing(landing(|_| b"not a key".to_vec()));
    let locked = super::lock(&added, Method::Passphrase, false, &mut prompt)
        .await
        .expect("the add landed, so it is not a failure");
    let super::Locked::Added {
        method: Methods::Passphrase,
        now: super::Now::Unread(unread),
        ..
    } = &locked
    else {
        panic!("an unconfirmed add: {locked:?}");
    };
    assert_eq!(unread.path, added.key().to_string_lossy());
    assert!(
        unread.read.contains("not in a format this build reads"),
        "{}",
        unread.read
    );
    let _ = std::fs::remove_dir_all(&added_dir);
}

/// A Touch ID lock's health is read from a real header, so a lock that reads dead here reaches the result as
/// dead, beside a passphrase or alone, and as unknown where nothing can say; and a dead lock is never what a
/// line says the key opens with. Red when the health is dropped between the header and the result.
#[test]
fn a_dead_touch_id_lock_reads_dead_from_its_header() {
    use keystore::Health::{Dead, Live};

    use super::Locks;

    let read = |bytes: &[u8], health: Option<keystore::Health>| {
        let (home, dir) = home(&format!("dead-header-{}-{health:?}", bytes.len()));
        placed(&home, bytes);
        let stored = keystore::KeyFile::new(home.key())
            .load()
            .expect("load")
            .expect("a key");
        let prompt = match health {
            Some(health) => Counting::new([]).at_this_mac(health),
            None => Counting::new([]),
        };
        let locks = Locks::of(&stored, &prompt);
        let _ = std::fs::remove_dir_all(&dir);
        locks
    };
    assert_eq!(
        read(&DEVICE_PASSPHRASE_AND_TOUCH_ID, Some(Dead)),
        Locks::Both(Some(Dead))
    );
    assert_eq!(
        read(&DEVICE_TOUCH_ID_ALONE, Some(Dead)),
        Locks::TouchId(Some(Dead))
    );
    assert_eq!(
        read(&DEVICE_PASSPHRASE_AND_TOUCH_ID, None),
        Locks::Both(None)
    );
    assert_eq!(
        read(&DEVICE_TOUCH_ID_ALONE, Some(Live)),
        Locks::TouchId(Some(Live))
    );
    assert_eq!(Locks::Both(Some(Dead)).opens_with(), None);
    assert_eq!(Locks::TouchId(Some(Dead)).opens_with(), None);
}

/// Beside a root, a key is sealed under a chosen passphrase before the touch that adds Touch ID, at both
/// places that seal one: a first key, made either way, and a plain key, which keeps the passphrase it was
/// given. A touch that does not land, a timeout included, says so and then what the key was left with, read
/// back: the made key and its passphrase, or the passphrase added; and a failure after Touch ID landed is the
/// key as it is. Red when only the touch's end prints, a plain key's line says it was made, or the line is
/// not the file's.
#[tokio::test]
async fn a_sealed_make_that_times_out_keeps_its_last_line() {
    for (tag, head) in MISSES {
        let (first, first_dir) = home(&format!("sealed-first-{tag}"));
        std::fs::write(first.root_key(), b"a root kept here").expect("a root beside it");
        let mut prompt = Counting::new([LONG])
            .at_this_mac(keystore::Health::Live)
            .touching([miss(tag)]);
        let refused = lock_touch_id(&first, &mut prompt).await.unwrap_err();
        let key = crate::testkit::stored_key(&keystore::KeyFile::new(first.key()));
        assert_eq!(
            format!("{refused:#}"),
            refusal(
                tag,
                head,
                &format!(
                    "Made this machine's key, locked with the passphrase you chose:\n    {key}"
                )
            ),
            "{tag}"
        );
        let opened = super::resolve_with(
            super::Identity::Persisted,
            &first,
            &mut Counting::new([LONG]),
        )
        .expect("the chosen passphrase opens it");
        assert_eq!(opened.node_id(), key, "{tag}");
        let _ = std::fs::remove_dir_all(&first_dir);

        let (home, dir) = home(&format!("sealed-plain-{tag}"));
        super::inspect(&home).expect("a plain key");
        std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
        let mut prompt = Counting::new([LONG])
            .at_this_mac(keystore::Health::Live)
            .touching([miss(tag)]);
        let refused = lock_touch_id(&home, &mut prompt).await.unwrap_err();
        assert_eq!(
            format!("{refused:#}"),
            refusal(
                tag,
                head,
                "Added a passphrase to this machine's key, which now opens with the passphrase."
            ),
            "{tag}"
        );
        assert_eq!(locks(&home), [Method::Passphrase], "{tag}");
        let _ = std::fs::remove_dir_all(&dir);
    }
    for (tag, plain) in [
        ("sealed-first-landed", false),
        ("sealed-plain-landed", true),
    ] {
        let (home, dir) = home(tag);
        if plain {
            super::inspect(&home).expect("a plain key");
        }
        std::fs::write(home.root_key(), b"a root kept here").expect("a root beside it");
        let mut prompt = Counting::new([LONG])
            .at_this_mac(keystore::Health::Live)
            .touching([Touched::Failed(eyre::eyre!("the directory was not synced"))])
            .publishing(landing_as(&DEVICE_PASSPHRASE_AND_TOUCH_ID));
        let locked = lock_touch_id(&home, &mut prompt).await.unwrap();
        let expected = if plain {
            super::Locked::Added {
                method: Methods::Both,
                now: super::Now::Read(super::Locks::Both(Some(keystore::Health::Live))),
                root: Root::Kept,
                failed: Some("the directory was not synced".to_owned()),
            }
        } else {
            super::Locked::Made {
                key: crate::testkit::stored_key(&keystore::KeyFile::new(home.key())),
                now: Methods::Both,
                failed: Some("the directory was not synced".to_owned()),
            }
        };
        assert_eq!(locked, expected, "{tag}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A cancelled `lock touch-id` on an empty home made no key, so the `lock passphrase` after it makes one, and
/// says so, never that it added a lock. Red when the second answers as an add.
#[tokio::test]
async fn lock_after_a_missed_make_says_made() {
    let (home, dir) = home("missed-then-made");
    let mut prompt = Counting::new([])
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Declined]);
    let _ = lock_touch_id(&home, &mut prompt).await.unwrap_err();
    let locked = super::lock(&home, Method::Passphrase, false, &mut Counting::new([LONG]))
        .await
        .unwrap();
    assert_eq!(
        locked,
        super::Locked::Made {
            key: crate::testkit::stored_key(&keystore::KeyFile::new(home.key())),
            now: Methods::Passphrase,
            failed: None,
        }
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Taking the passphrase off both locks is refused before a word where Touch ID does not open here, or cannot
/// be checked: the key store would refuse the removal after the passphrase, which a line would already have
/// said leaves Touch ID to open the key. Red when the line or the ask comes first, or the refusal is another.
#[tokio::test]
async fn a_passphrase_removal_over_a_touch_id_that_does_not_open_says_nothing_first() {
    for (tag, health) in [
        ("dead", keystore::Health::Dead),
        ("unchecked", keystore::Health::Unchecked),
    ] {
        let (home, dir) = home(&format!("remove-passphrase-{tag}"));
        placed(&home, &DEVICE_PASSPHRASE_AND_TOUCH_ID);
        let mut prompt = logged(Counting::new([PASSPHRASE]).at_this_mac(health));
        let refused = super::lock(&home, Method::Passphrase, true, &mut prompt)
            .await
            .expect_err("refused");
        let lines = crate::touch::Lines::of(
            crate::passphrase::Asked::MachineKey,
            &keystore::KeyFile::new(home.key()),
            true,
        );
        let said = match health {
            keystore::Health::Unchecked => lines.unchecked(),
            _ => lines.dead(),
        };
        assert_eq!(format!("{refused:#}"), said, "{tag}");
        assert!(prompt.heard.is_empty(), "{tag}: {:?}", prompt.heard);
        assert_eq!(locks(&home), [Method::Passphrase, Method::TouchId], "{tag}");
        let _ = std::fs::remove_dir_all(&dir);
    }
    // A build with no enclave, where Touch ID opens nothing, says the passphrase stays.
    let (home, dir) = home("remove-passphrase-no-enclave");
    placed(&home, &DEVICE_PASSPHRASE_AND_TOUCH_ID);
    let mut prompt = logged(Counting::new([PASSPHRASE]).here(TouchHere::NoEnclave));
    let refused = super::lock(&home, Method::Passphrase, true, &mut prompt)
        .await
        .expect_err("refused");
    assert_eq!(
        format!("{refused:#}"),
        "the passphrase stays: Touch ID opens this key only on the Mac that set it"
    );
    assert!(prompt.heard.is_empty(), "{:?}", prompt.heard);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A write whose key store answered that its directory was not synced is in place: a written result, its
/// failure said beside it; any other failure is the write's. A first key beside a root made so is made under
/// the passphrase alone, and says Touch ID was not added; a file there that is not this run's is not
/// confirmed. Red when an unsynced write reads as a miss, or another file is called made.
#[test]
fn a_write_in_place_but_unsynced_is_a_written_result() {
    let unsynced = || keystore::Error::Unsynced {
        path: PathBuf::from("/h/machine/key"),
        source: std::io::Error::other("the disk went away"),
    };
    let failed = super::written(Err(unsynced())).expect("in place");
    assert!(failed.is_some_and(|failed| failed.contains("the disk went away")));
    assert!(super::written(Ok(())).expect("done").is_none());
    assert!(
        super::written(Err(keystore::Error::Absent {
            path: PathBuf::from("/h/machine/key")
        }))
        .is_err()
    );

    let (home, dir) = home("unsynced-first-key");
    super::make_machine_dir(&home).expect("the key's dir");
    let file = keystore::KeyFile::new(home.key());
    let secret = keystore::Secret::generate().unwrap();
    let passphrase =
        keystore::Passphrase::try_from(zeroize::Zeroizing::new(LONG.to_owned())).unwrap();
    file.write(&secret, keystore::Protection::Passphrase(&passphrase))
        .unwrap();
    let drawn = super::Drawn::of(&secret);
    let made = drawn.touch_id_not_added(&file, "synced nothing".to_owned());
    let made = made
        .downcast_ref::<super::TouchIdNotAdded>()
        .expect("made, without Touch ID");
    assert_eq!(made.key, drawn.key);
    assert_eq!(made.failed, "synced nothing");
    let other = super::Drawn::of(&keystore::Secret::generate().unwrap());
    let refused = other.touch_id_not_added(&file, "synced nothing".to_owned());
    assert!(refused.is::<super::Unconfirmed>(), "{refused:#}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Touch ID put on a key whose key store answered, after the touch, that the directory was not synced: the
/// lock is in place, so it is added, with the failure said beside it. Red when it reads as a touch that did
/// not open.
#[tokio::test]
async fn an_added_lock_whose_write_is_unsynced_is_added_with_its_failure() {
    let (home, dir) = home("touch-id-unsynced");
    sealed(&home, PASSPHRASE).await;
    let unsynced = keystore::Error::Unsynced {
        path: home.key(),
        source: std::io::Error::other("the disk went away"),
    };
    let mut prompt = Counting::new([PASSPHRASE])
        .at_this_mac(keystore::Health::Live)
        .touching([Touched::Failed(eyre::Report::new(unsynced))]);
    let locked = lock_touch_id(&home, &mut prompt).await.expect("added");
    let super::Locked::Added {
        failed: Some(failed),
        ..
    } = locked
    else {
        panic!("{locked:?}");
    };
    assert!(failed.contains("the disk went away"), "{failed}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plain key beside a root, sealed under the passphrase with a failure after the seal was in place, keeps
/// that failure to its result, whether or not the touch after it landed. Red when the seal's failure is
/// dropped. The key store's own write cannot be made to answer so here; this holds what follows it.
#[tokio::test]
async fn a_seal_in_place_but_unsynced_says_so_on_its_result() {
    let (home, dir) = home("sealed-unsynced");
    sealed(&home, PASSPHRASE).await;
    let file = keystore::KeyFile::new(home.key());
    let prompt = Counting::new([]).at_this_mac(keystore::Health::Live);
    let locked = super::sealed_then_touched(
        Touched::Opened(None),
        Some("synced nothing".to_owned()),
        &file,
        &prompt,
        Root::Kept,
    )
    .expect("added");
    assert_eq!(
        locked,
        super::Locked::Added {
            method: Methods::Passphrase,
            now: super::Now::Read(super::Locks::Passphrase),
            root: Root::Kept,
            failed: Some("synced nothing".to_owned()),
        }
    );
    let _ = std::fs::remove_dir_all(&dir);
}
