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

/// The serving check holds the lock exclusive for an instant; a node that starts inside that instant waits
/// it out instead of reporting a restore that is not running.
#[test]
fn a_serve_starting_during_the_serving_check_is_not_refused() {
    let (home, dir) = home("home-lock-probe");

    let (held, taken) = std::sync::mpsc::channel();
    let probe = {
        let home = home.clone();
        std::thread::spawn(move || {
            let probe = HomeLock::replacing(&home).unwrap();
            held.send(()).unwrap();
            std::thread::sleep(core::time::Duration::from_millis(20));
            drop(probe);
        })
    };
    taken.recv().unwrap();
    let serving = HomeLock::serving(&home);
    probe.join().unwrap();
    assert!(
        serving.is_ok(),
        "a node starting during the check is not refused"
    );
    drop(serving);

    let _ = std::fs::remove_dir_all(&dir);
}
