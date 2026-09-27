//! `Standing::read` over every standing, every damaged shape, and every crash state it finishes.
//!
//! Each home is built on disk the way the product leaves it: a device key file, a pin, a badge a root
//! signed, a root directory whose key file has a header, and the latch of roots revoked here. The root
//! key files are plain 32-byte files, which load with their key and no header to seal, except in the one
//! test that proves a sealed header is read without a prompt.

use core::time::Duration;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Protection};
use nauthy::DisabledRoots;
use tightbeam::identity::AsVerifyKey as _;
use zeroize::Zeroizing;

use super::{Disagreement, Finished, SEAM, Seam, Standing, StandingError};
use crate::config;
use crate::home::Home;
use crate::testkit::{TestNode, TestRoot, hand_signed};

/// This machine's key, in every home here.
const OWN: u8 = 0x11;
/// The root this machine trusts or holds.
const ROOT: u8 = 0x21;
/// Another root.
const OTHER: u8 = 0x31;

/// A fresh home with this machine's key in it, plain.
fn home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-standing-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).expect("create the home");
    let home = Home::resolve(Some(dir)).expect("resolve the home");
    let mut seed = TestNode::seeded(OWN).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .expect("write this machine's key");
    home
}

fn own() -> NodeId {
    TestNode::seeded(OWN).node_id()
}

fn root() -> NodeId {
    TestRoot::seeded(ROOT).node_id()
}

fn other() -> NodeId {
    TestRoot::seeded(OTHER).node_id()
}

fn until() -> SystemTime {
    nauthy::Request::expires_in(Duration::from_secs(30 * 24 * 60 * 60))
}

async fn pin(home: &Home, key: NodeId) {
    config::write_signet(home, key)
        .await
        .expect("write the pin");
}

/// A device standing for this machine, signed by the root seeded `by`.
async fn badge(home: &Home, by: u8) {
    let badge = TestRoot::seeded(by)
        .device_badge(own(), until())
        .expect("sign a device standing");
    config::write_badge(home, &badge)
        .await
        .expect("write the device standing");
}

/// A device standing this machine signed for itself, as a home from before roots had their own keys holds.
async fn self_signed_badge(home: &Home) {
    let badge = TestRoot::seeded(OWN)
        .device_badge(own(), until())
        .expect("sign a device standing");
    config::write_badge(home, &badge)
        .await
        .expect("write the device standing");
}

/// A root directory at `dir` whose `root.key` holds the root seeded `seed`, plain, with a `state` and a
/// `lock` beside it.
fn root_dir(dir: &Path, seed: u8) {
    use std::os::unix::fs::OpenOptionsExt as _;

    config::create_store_dir(dir).expect("create the root directory");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("root.key"))
        .expect("create root.key");
    std::io::Write::write_all(&mut file, &[seed; 32]).expect("write root.key");
    std::fs::write(dir.join("state"), b"state").expect("write state");
    std::fs::write(dir.join("lock"), b"").expect("write lock");
}

async fn revoke(home: &Home, key: NodeId) {
    let mut latch = DisabledRoots::load(home.disabled_roots())
        .await
        .expect("load the latch");
    latch
        .disable(key.verify_key().expect("a usable key"))
        .await
        .expect("revoke the root here");
}

/// The update files, as a device that has synced holds them.
fn update_files(home: &Home) -> [PathBuf; 4] {
    let files = [
        home.roster(),
        home.roster_synced(),
        home.roster_seed(),
        home.roster_fork(),
    ];
    for file in &files {
        std::fs::write(file, b"update").expect("write an update file");
    }
    files
}

/// Hold `<dir>/lock` as a command working on `dir` does. Released on drop.
fn hold(dir: &Path) -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("lock"))
        .expect("open the lock");
    // SAFETY: `file` owns a valid fd for the whole call.
    let taken = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(taken, 0, "take the lock");
    file
}

/// Run `step` once, the first time the read reaches `at` on `dir`, on this thread. Cleared on drop.
fn at_seam(at: Seam, dir: PathBuf, step: impl FnOnce() + 'static) -> SeamGuard {
    let mut step = Some(step);
    SEAM.set(Some(Box::new(move |reached, path| {
        if reached == at
            && path == dir
            && let Some(step) = step.take()
        {
            step();
        }
    })));
    SeamGuard
}

struct SeamGuard;

impl Drop for SeamGuard {
    fn drop(&mut self) {
        SEAM.set(None);
    }
}

/// Replace the key in a root directory's `root.key` with the root seeded `seed`, keeping the directory
/// and its `lock`.
fn rekey(dir: &Path, seed: u8) {
    std::fs::write(dir.join("root.key"), [seed; 32]).expect("rewrite root.key");
}

async fn read(home: &Home) -> super::Read {
    Standing::read(home).await.expect("read the standing")
}

async fn damaged(home: &Home) -> Disagreement {
    match Standing::read(home).await {
        Err(StandingError::Damaged(disagreement)) => disagreement,
        other => panic!("expected a damaged home, read {other:?}"),
    }
}

// Every standing.

#[tokio::test]
async fn an_empty_home_is_unpinned() {
    let read = read(&home("empty")).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert!(read.finished.is_empty());
}

/// A pin with no device standing is left only by a crash while leaving, and reads as damaged, naming `leave`.
#[tokio::test]
async fn a_pin_with_no_badge_is_damaged() {
    let home = home("pin-no-badge");
    pin(&home, root()).await;
    match Standing::read(&home).await {
        Err(StandingError::Damaged(what)) => {
            assert_eq!(what, Disagreement::PinWithoutStanding { pin: root() });
            assert!(super::damaged_line(&what).contains("swoosh leave"));
        }
        other => panic!("a pin with no badge is damaged: {other:?}"),
    }
}

#[tokio::test]
async fn a_pin_and_a_standing_from_it_is_a_device_until_the_standings_end() {
    let home = home("device");
    pin(&home, root()).await;
    let before = until();
    badge(&home, ROOT).await;
    let Standing::Device { pin, until } = read(&home).await.standing else {
        panic!("expected a device");
    };
    assert_eq!(pin, root());
    let off = until
        .duration_since(before)
        .unwrap_or_else(|early| early.duration());
    assert!(
        off < Duration::from_secs(5),
        "until is the standing's own end"
    );
}

#[tokio::test]
async fn a_held_pinned_root_with_its_standing_holds_the_root() {
    let home = home("holds-root");
    root_dir(&home.root(), ROOT);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    assert!(matches!(
        read(&home).await.standing,
        Standing::HoldsRoot { pin, .. } if pin == root()
    ));
}

#[tokio::test]
async fn a_root_with_no_pin_is_an_interrupted_mint_whatever_the_badge_holds() {
    for (tag, write_badge) in [("none", None), ("same", Some(ROOT)), ("other", Some(OTHER))] {
        let home = home(&format!("mint-{tag}"));
        root_dir(&home.root(), ROOT);
        if let Some(by) = write_badge {
            badge(&home, by).await;
        }
        assert_eq!(
            read(&home).await.standing,
            Standing::InterruptedMint { root_key: root() },
            "badge {tag}"
        );
    }
    let home = home("mint-torn");
    root_dir(&home.root(), ROOT);
    std::fs::write(home.badge(), b"torn").expect("tear the badge");
    assert_eq!(
        read(&home).await.standing,
        Standing::InterruptedMint { root_key: root() }
    );
}

#[tokio::test]
async fn a_sealed_root_key_is_read_by_its_header_without_a_prompt() {
    let home = home("sealed");
    config::create_store_dir(&home.root()).expect("create root/");
    let passphrase = crate::passphrase::passphrase(Zeroizing::new("correct horse".to_owned()))
        .expect("a passphrase");
    let mut seed = TestRoot::seeded(ROOT).seed();
    KeyFile::root(home.root().join("root.key"))
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .expect("seal the root key");
    assert_eq!(
        read(&home).await.standing,
        Standing::InterruptedMint { root_key: root() }
    );
}

// Damaged homes.

#[tokio::test]
async fn a_home_whose_badge_is_self_signed_with_no_pin_reads_damaged() {
    let home = home("self-badge");
    self_signed_badge(&home).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::StandingWithoutPin {
            standing_root: own()
        }
    );
}

/// A pin file holding a torsioned key is a stored key that is not a key: the home reads as damaged.
#[tokio::test]
async fn a_torsioned_pin_reads_damaged() {
    let home = home("torsioned-pin");
    std::fs::write(
        home.signet(),
        format!("{}\n", crate::testkit::torsioned_text()),
    )
    .expect("write the pin");
    assert_eq!(
        damaged(&home).await,
        Disagreement::UnreadablePin {
            path: home.signet()
        }
    );
}

#[tokio::test]
async fn a_pin_naming_this_machines_own_key_reads_damaged() {
    let home = home("own-pin");
    pin(&home, own()).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::OwnKeyPinned { key: own() }
    );
    // The whole of such a home: its own badge, rooted at the pin it names.
    self_signed_badge(&home).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::OwnKeyPinned { key: own() }
    );
}

#[tokio::test]
async fn a_standing_with_no_pin_and_no_root_reads_damaged() {
    let home = home("badge-no-pin");
    badge(&home, ROOT).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::StandingWithoutPin {
            standing_root: root()
        }
    );
}

#[tokio::test]
async fn a_standing_not_rooted_at_the_pin_reads_damaged() {
    let home = home("badge-other-root");
    pin(&home, root()).await;
    badge(&home, OTHER).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::StandingFromAnotherRoot {
            standing_root: other(),
            pin: root()
        }
    );
}

#[tokio::test]
async fn a_root_pinned_to_another_key_reads_damaged() {
    let home = home("root-other-pin");
    root_dir(&home.root(), ROOT);
    pin(&home, other()).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::RootNotPinned {
            root: root(),
            pin: other()
        }
    );
}

#[tokio::test]
async fn a_held_root_with_no_standing_reads_damaged() {
    let home = home("root-no-badge");
    root_dir(&home.root(), ROOT);
    pin(&home, root()).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::RootWithoutStanding { root: root() }
    );
}

#[tokio::test]
async fn a_torn_standing_reads_damaged() {
    let home = home("torn-badge");
    pin(&home, root()).await;
    std::fs::write(home.badge(), b"torn").expect("tear the badge");
    assert_eq!(
        damaged(&home).await,
        Disagreement::UnreadableStanding { path: home.badge() }
    );
}

#[tokio::test]
async fn a_standing_for_another_key_reads_damaged() {
    let home = home("badge-other-key");
    pin(&home, root()).await;
    let badge = TestRoot::seeded(ROOT)
        .device_badge(TestNode::seeded(0x41).node_id(), until())
        .expect("sign a standing for another machine");
    config::write_badge(&home, &badge)
        .await
        .expect("write the device standing");
    assert_eq!(
        damaged(&home).await,
        Disagreement::StandingForAnotherKey { path: home.badge() }
    );
    // Held here too.
    root_dir(&home.root(), ROOT);
    assert_eq!(
        damaged(&home).await,
        Disagreement::StandingForAnotherKey { path: home.badge() }
    );
}

#[tokio::test]
async fn a_lapsed_standing_is_still_this_machines() {
    let home = home("badge-lapsed");
    pin(&home, root()).await;
    let lapsed = SystemTime::now() - Duration::from_secs(24 * 60 * 60);
    let badge = TestRoot::seeded(ROOT)
        .device_badge(own(), lapsed)
        .expect("sign a lapsed standing");
    config::write_badge(&home, &badge)
        .await
        .expect("write the device standing");
    assert!(matches!(
        read(&home).await.standing,
        Standing::Device { pin, until } if pin == root() && until < SystemTime::now()
    ));
}

#[tokio::test]
async fn a_standing_with_no_readable_end_date_reads_damaged() {
    assert_eq!(hand_signed::ROOT_SEED, ROOT);
    assert_eq!(hand_signed::DEVICE_SEED, OWN);
    for (tag, badge) in [
        ("none", hand_signed::without_end_date()),
        ("unreadable", hand_signed::unreadable_end_date()),
    ] {
        let home = home(&format!("badge-end-{tag}"));
        pin(&home, root()).await;
        config::write_badge(&home, &badge)
            .await
            .expect("write the device standing");
        assert_eq!(
            damaged(&home).await,
            Disagreement::UnreadableStanding { path: home.badge() },
            "{tag}"
        );
    }
}

#[tokio::test]
async fn a_malformed_pin_reads_damaged() {
    let home = home("torn-pin");
    std::fs::write(home.signet(), b"ed01torn\n").expect("tear the pin");
    assert_eq!(
        damaged(&home).await,
        Disagreement::UnreadablePin {
            path: home.signet()
        }
    );
}

#[tokio::test]
async fn a_root_with_no_key_file_reads_damaged() {
    let home = home("root-no-key");
    config::create_store_dir(&home.root()).expect("create root/");
    assert_eq!(
        damaged(&home).await,
        Disagreement::UnreadableRoot {
            path: home.root().join("root.key")
        }
    );
}

// Crash states.

#[tokio::test]
async fn standing_read_finishes_an_interrupted_move() {
    let home = home("move");
    root_dir(&home.root_moving(), ROOT);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    let read = read(&home).await;
    assert!(!home.root_moving().exists(), "root.moving/ is deleted");
    assert_eq!(read.finished, [Finished::Moved]);
    assert!(matches!(read.standing, Standing::Device { pin, .. } if pin == root()));
}

#[tokio::test]
async fn a_move_still_under_way_is_left_alone() {
    let home = home("move-held");
    root_dir(&home.root_moving(), ROOT);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    let _held = hold(&home.root_moving());
    let read = read(&home).await;
    assert!(home.root_moving().join("root.key").exists());
    assert!(read.finished.is_empty());
    assert!(matches!(read.standing, Standing::Device { pin, .. } if pin == root()));
}

#[tokio::test]
async fn an_interrupted_retirement_is_finished_by_the_read() {
    let home = home("retire");
    root_dir(&home.root_revoking(), ROOT);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    let files = update_files(&home);
    revoke(&home, root()).await;
    let read = read(&home).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert_eq!(read.finished, [Finished::Retired { root: Some(root()) }]);
    assert!(!home.root_revoking().exists());
    for gone in files.iter().chain([&home.badge(), &home.signet()]) {
        assert!(!gone.exists(), "{} is removed", gone.display());
    }
}

#[tokio::test]
async fn a_retirement_still_under_way_is_left_alone() {
    let home = home("retire-held");
    root_dir(&home.root_revoking(), ROOT);
    let _held = hold(&home.root_revoking());
    let read = read(&home).await;
    assert!(home.root_revoking().join("root.key").exists());
    assert!(read.finished.is_empty());
    assert_eq!(read.standing, Standing::Unpinned);
}

#[tokio::test]
async fn a_retirement_keeps_a_pin_to_another_root() {
    let home = home("retire-other-pin");
    root_dir(&home.root_revoking(), ROOT);
    pin(&home, other()).await;
    badge(&home, OTHER).await;
    let read = read(&home).await;
    assert!(!home.root_revoking().exists());
    assert!(matches!(read.standing, Standing::Device { pin, .. } if pin == other()));
}

#[tokio::test]
async fn a_revoked_root_left_in_the_home_is_never_finished_as_a_mint() {
    let home = home("revoked-root");
    root_dir(&home.root(), ROOT);
    revoke(&home, root()).await;
    let read = read(&home).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert_eq!(read.finished, [Finished::Retired { root: Some(root()) }]);
    assert!(!home.root().exists());
    assert!(!home.root_revoking().exists());
}

#[tokio::test]
async fn a_revoked_root_in_use_is_never_read_as_a_mint() {
    let home = home("revoked-root-held");
    root_dir(&home.root(), ROOT);
    revoke(&home, root()).await;
    let _held = hold(&home.root());
    let read = read(&home).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert!(home.root().join("root.key").exists(), "a held root is left");
}

#[tokio::test]
async fn a_held_revoked_root_is_retired_with_its_standing() {
    let home = home("revoked-holder");
    root_dir(&home.root(), ROOT);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    let files = update_files(&home);
    revoke(&home, root()).await;
    let read = read(&home).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert_eq!(read.finished, [Finished::Retired { root: Some(root()) }]);
    for gone in files
        .iter()
        .chain([&home.badge(), &home.signet(), &home.root()])
    {
        assert!(!gone.exists(), "{} is removed", gone.display());
    }
}

#[tokio::test]
async fn apply_on_a_device_killed_after_the_latch_is_finished_by_the_read() {
    let home = home("revoked-pin");
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    let files = update_files(&home);
    revoke(&home, root()).await;
    let read = read(&home).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert_eq!(read.finished, [Finished::Retired { root: Some(root()) }]);
    for gone in files.iter().chain([&home.badge(), &home.signet()]) {
        assert!(!gone.exists(), "{} is removed", gone.display());
    }
}

#[tokio::test]
async fn a_retirement_removes_the_standing_first_and_the_pin_last() {
    let home = home("retire-order");
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    update_files(&home);
    // The last update file cannot be removed: a crash at that step, after every earlier one.
    std::fs::remove_file(home.roster_fork()).expect("clear the fork file");
    std::fs::create_dir(home.roster_fork()).expect("block the fork file");
    std::fs::write(home.roster_fork().join("x"), b"x").expect("fill it");
    revoke(&home, root()).await;

    let failed = Standing::read(&home).await;
    assert!(matches!(failed, Err(StandingError::Finish { .. })));
    assert!(!home.badge().exists(), "the device standing went first");
    assert!(home.signet().exists(), "the pin is still here, going last");

    std::fs::remove_dir_all(home.roster_fork()).expect("unblock");
    let read = read(&home).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert!(!home.signet().exists());
}

// Races: another command changes the home between two of the read's steps.

#[tokio::test]
async fn a_lock_opened_on_a_directory_since_replaced_is_not_taken() {
    let home = home("race-move");
    root_dir(&home.root_moving(), ROOT);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    // Between the read's open and its lock, the move finishes elsewhere and a new move starts, holding
    // its own `root.moving/`.
    let held = std::rc::Rc::new(core::cell::RefCell::new(None));
    let _seam = at_seam(Seam::LockOpened, home.root_moving(), {
        let dir = home.root_moving();
        let held = std::rc::Rc::clone(&held);
        move || {
            std::fs::remove_dir_all(&dir).expect("finish the first move");
            root_dir(&dir, OTHER);
            *held.borrow_mut() = Some(hold(&dir));
        }
    });
    let read = read(&home).await;
    assert!(held.borrow().is_some(), "the seam ran");
    assert!(
        home.root_moving().join("root.key").exists(),
        "the new move's root.moving/ is left"
    );
    assert!(read.finished.is_empty());
}

#[tokio::test]
async fn a_root_minted_in_place_of_one_retired_under_the_read_is_left() {
    let home = home("race-mint");
    root_dir(&home.root(), ROOT);
    revoke(&home, root()).await;
    // Between the read's open and its lock, another read retires the revoked root and a mint puts a new
    // live root at `root/`.
    let _seam = at_seam(Seam::LockOpened, home.root(), {
        let dir = home.root();
        move || {
            std::fs::remove_dir_all(&dir).expect("retire the revoked root");
            root_dir(&dir, OTHER);
        }
    });
    let read = read(&home).await;
    assert_eq!(
        read.standing,
        Standing::InterruptedMint { root_key: other() }
    );
    assert!(read.finished.is_empty());
    assert!(
        home.root().join("root.key").exists(),
        "the new root is left"
    );
    assert!(!home.root_revoking().exists());
}

#[tokio::test]
async fn a_root_is_checked_again_once_its_lock_is_held() {
    let home = home("race-rekey");
    root_dir(&home.root(), ROOT);
    revoke(&home, root()).await;
    // The same directory and lock, now holding a live root: only the check under the lock sees it.
    let _seam = at_seam(Seam::LockOpened, home.root(), {
        let dir = home.root();
        move || rekey(&dir, OTHER)
    });
    let read = read(&home).await;
    assert_eq!(
        read.standing,
        Standing::InterruptedMint { root_key: other() }
    );
    assert!(read.finished.is_empty());
    assert!(!home.root_revoking().exists());
}

#[tokio::test]
async fn a_revoked_root_gone_before_its_rename_is_already_done() {
    let home = home("race-gone");
    root_dir(&home.root(), ROOT);
    revoke(&home, root()).await;
    let _seam = at_seam(Seam::BeforeRetireRename, home.root(), {
        let dir = home.root();
        move || std::fs::remove_dir_all(&dir).expect("remove root/")
    });
    let read = read(&home).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert!(read.finished.is_empty());
    assert!(!home.root().exists());
    assert!(!home.root_revoking().exists());
}

// A retirement whose key file is unreadable: only a standing under a revoked key is removed.

/// A `root.revoking/` with a lock and no key file.
fn keyless_revoking(home: &Home) {
    config::create_store_dir(&home.root_revoking()).expect("create root.revoking/");
    std::fs::write(home.root_revoking().join("lock"), b"").expect("write lock");
}

#[tokio::test]
async fn a_keyless_retirement_keeps_a_live_pin_to_another_root() {
    let home = home("keyless-pin");
    keyless_revoking(&home);
    pin(&home, other()).await;
    badge(&home, OTHER).await;
    let read = read(&home).await;
    assert!(!home.root_revoking().exists());
    assert_eq!(read.finished, [Finished::Retired { root: None }]);
    assert!(matches!(read.standing, Standing::Device { pin, .. } if pin == other()));
}

#[tokio::test]
async fn a_keyless_retirement_keeps_a_live_badge_with_no_pin_so_it_reads_damaged() {
    let home = home("keyless-badge");
    keyless_revoking(&home);
    badge(&home, OTHER).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::StandingWithoutPin {
            standing_root: other()
        }
    );
    assert!(!home.root_revoking().exists());
}

#[tokio::test]
async fn a_keyless_retirement_removes_a_standing_under_a_revoked_key() {
    let home = home("keyless-revoked");
    keyless_revoking(&home);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    revoke(&home, root()).await;
    let read = read(&home).await;
    assert_eq!(read.standing, Standing::Unpinned);
    assert_eq!(read.finished, [Finished::Retired { root: Some(root()) }]);
    assert!(!home.badge().exists());
    assert!(!home.signet().exists());
}

// Stray files.

#[tokio::test]
async fn a_stray_root_new_beside_a_root_is_removed() {
    let home = home("stray");
    root_dir(&home.root(), ROOT);
    root_dir(&home.root_new(), OTHER);
    let read = read(&home).await;
    assert!(!home.root_new().exists());
    assert!(read.finished.is_empty(), "removed silently");
    assert!(home.root().join("root.key").exists());
}

#[tokio::test]
async fn a_root_new_alone_is_left_for_the_next_mint() {
    let home = home("root-new-alone");
    root_dir(&home.root_new(), ROOT);
    assert_eq!(read(&home).await.standing, Standing::Unpinned);
    assert!(home.root_new().join("root.key").exists());
}

// The lines.

#[test]
fn each_finished_state_prints_its_line() {
    assert_eq!(
        Finished::Moved.to_string(),
        "finished moving your root off this machine."
    );
    assert_eq!(
        Finished::Retired { root: Some(root()) }.to_string(),
        format!(
            "finished retiring root {}… on this machine.",
            root().short()
        )
    );
}
