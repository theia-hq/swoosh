//! The home lock's one rule: a replacing holder excludes every other, and sharing holders coexist.

use super::HomeLock;
use crate::identity::identity_tests::home;

/// Two serving nodes, or a node and a `protect`, share the home; a restore beside either is refused, and
/// a node cannot start while a restore holds it.
#[test]
fn replacing_excludes_and_sharing_coexists() {
    let (home, dir) = home("home-lock");

    let serving = HomeLock::serving(&home).expect("a node takes the lock");
    let rewriting = HomeLock::rewriting(&home).expect("protect shares it with a node");
    assert!(
        HomeLock::replacing(&home).is_err(),
        "a restore is refused while a node serves"
    );
    drop((serving, rewriting));

    let replacing = HomeLock::replacing(&home).expect("with nobody serving, a restore takes it");
    assert!(
        HomeLock::serving(&home).is_err(),
        "a node cannot start mid-restore"
    );
    drop(replacing);

    let _ = std::fs::remove_dir_all(&dir);
}
