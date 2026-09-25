//! `protect`: a key is sealed, unsealed, and re-sealed in place as the same node; an empty home is
//! created under the method asked for; and a wrong passphrase changes nothing.

use keystore::{Method, Stored};

use super::{Protected, protect};
use crate::identity::identity_tests::{home, sealed};
use crate::identity::{Identity, inspect, resolve_with};
use crate::passphrase::Scripted;

/// An empty home asked for `passphrase` gets its first key already sealed: no plain copy of it is ever
/// written, and the node it reports is the one the file opens as.
#[test]
fn an_empty_home_is_created_sealed() {
    let (home, dir) = home("protect-create");
    let node = sealed(&home, "correct horse");

    let stored = inspect(&home).expect("inspect").into_stored();
    assert!(matches!(stored, Stored::Locked(_)), "created sealed");
    let opened = resolve_with(
        Identity::Persisted,
        &home,
        &mut Scripted::new(["correct horse"]),
    )
    .expect("open it");
    assert_eq!(opened.node_id(), node);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A plain key is sealed in place and stays the same node; sealing asks only for the new passphrase.
#[test]
fn a_plain_key_is_sealed_as_the_same_node() {
    let (home, dir) = home("protect-seal");
    let node = resolve_with(Identity::Persisted, &home, &mut Scripted::new([]))
        .expect("mint a plain key")
        .node_id();

    let done = protect(
        &home,
        Method::Passphrase,
        &mut Scripted::new(["correct horse"]),
    )
    .expect("seal it");
    assert_eq!(done, Protected::Rewritten);
    assert_eq!(
        inspect(&home).expect("inspect").into_stored().method(),
        Method::Passphrase
    );
    let opened = resolve_with(
        Identity::Persisted,
        &home,
        &mut Scripted::new(["correct horse"]),
    )
    .expect("open it");
    assert_eq!(opened.node_id(), node, "sealing never changes the node");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A sealed key is unsealed under its passphrase, and a plain key asked for plain is left alone with
/// nothing asked.
#[test]
fn a_sealed_key_is_unsealed_and_plain_stays_plain() {
    let (home, dir) = home("protect-unseal");
    let node = sealed(&home, "correct horse");

    let done =
        protect(&home, Method::Plain, &mut Scripted::new(["correct horse"])).expect("unseal it");
    assert_eq!(done, Protected::Rewritten);
    let stored = inspect(&home).expect("inspect").into_stored();
    assert!(matches!(stored, Stored::Plain(_)));
    assert_eq!(stored.node_id(), node);

    let again = protect(&home, Method::Plain, &mut Scripted::new([])).expect("plain again");
    assert_eq!(again, Protected::Unchanged);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Changing the passphrase: the current one, then the new one; afterwards only the new one opens it.
#[test]
fn a_passphrase_is_changed_by_protecting_again() {
    let (home, dir) = home("protect-rotate");
    let node = sealed(&home, "correct horse");

    protect(
        &home,
        Method::Passphrase,
        &mut Scripted::new(["correct horse", "battery staple"]),
    )
    .expect("rotate");
    let opened = resolve_with(
        Identity::Persisted,
        &home,
        &mut Scripted::new(["battery staple"]),
    )
    .expect("the new passphrase opens it");
    assert_eq!(opened.node_id(), node);
    assert!(
        resolve_with(
            Identity::Persisted,
            &home,
            &mut Scripted::new(["correct horse"])
        )
        .is_err(),
        "the old passphrase no longer opens it"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A wrong current passphrase refuses before a new one is asked for, and the file is untouched. The
/// script holds only the wrong answer, so asking for a new passphrase would fail differently.
#[test]
fn a_wrong_current_passphrase_is_refused_before_asking_for_a_new_one() {
    let (home, dir) = home("protect-wrong");
    sealed(&home, "correct horse");
    let before = std::fs::read(home.key()).expect("read the key");

    let refused = protect(&home, Method::Passphrase, &mut Scripted::new(["wrong"]));
    let Err(error) = refused else {
        panic!("a wrong passphrase refuses");
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("wrong passphrase"),
        "the unlock refused, not a missing answer: {message}"
    );
    assert_eq!(
        std::fs::read(home.key()).expect("read it back"),
        before,
        "the file is untouched"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `protect` never interleaves with a restore: while one holds the home, it is refused and the key file
/// is untouched.
#[test]
fn protect_is_refused_while_a_restore_holds_the_home() {
    let (home, dir) = home("protect-locked");
    resolve_with(Identity::Persisted, &home, &mut Scripted::new([])).expect("a plain key");
    let before = std::fs::read(home.key()).expect("read the key");
    let restoring = crate::identity::lock::HomeLock::replacing(&home).expect("a restore holds it");

    let refused = protect(&home, Method::Passphrase, &mut Scripted::new(["pass"]));
    assert_eq!(std::fs::read(home.key()).expect("read it back"), before);
    assert!(refused.is_err());
    drop(restoring);

    let _ = std::fs::remove_dir_all(&dir);
}
