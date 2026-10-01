//! `Standing::read` over every standing, every damaged shape, and the files a revoked root left, which it
//! reads as absent and never removes.
//!
//! Each home is built on disk the way the product leaves it: a device key file, a pin, a badge a root
//! signed, a `root.key` whose key file has a header, and the latch of roots revoked here. The root key
//! files are plain 32-byte files, which load with their key and no header to seal, except in the one test
//! that proves a sealed header is read without a prompt.

use core::time::Duration;
use std::path::PathBuf;
use std::time::SystemTime;

use bifrost::NodeId;
use keystore::{KeyFile, Protection};
use tightbeam::identity::AsVerifyKey as _;
use zeroize::Zeroizing;

use super::{Disagreement, Standing, StandingError};
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
    crate::identity::make_machine_dir(&home).unwrap();
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
    config::write_signet(&crate::testkit::lock(), home, key).expect("write the pin");
}

/// A device standing for this machine, signed by the root seeded `by`.
async fn badge(home: &Home, by: u8) {
    let badge = TestRoot::seeded(by)
        .device_badge(own(), until())
        .expect("sign a device standing");
    config::write_badge(&crate::testkit::lock(), home, &badge).expect("write the device standing");
}

/// A device standing this machine signed for itself, as a home from before roots had their own keys holds.
async fn self_signed_badge(home: &Home) {
    let badge = TestRoot::seeded(OWN)
        .device_badge(own(), until())
        .expect("sign a device standing");
    config::write_badge(&crate::testkit::lock(), home, &badge).expect("write the device standing");
}

/// A `root.key` in `home` holding the root seeded `seed`, plain.
fn root_key(home: &Home, seed: u8) {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(home.root_key())
        .expect("create root.key");
    std::io::Write::write_all(&mut file, &[seed; 32]).expect("write root.key");
}

async fn revoke(home: &Home, key: NodeId) {
    crate::revoked::add(
        &crate::testkit::lock(),
        home,
        [nauthy::Revocation::Key(
            key.verify_key().expect("a usable key"),
        )],
    )
    .expect("revoke the root here");
}

/// The update files, as a device that has synced holds them.
fn update_files(home: &Home) -> [PathBuf; 4] {
    let files = [
        home.devices(),
        home.synced(),
        home.invited_by(),
        home.devices_conflict(),
    ];
    for file in &files {
        std::fs::write(file, b"update").expect("write an update file");
    }
    files
}

async fn read(home: &Home) -> Standing {
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
    assert_eq!(read(&home("empty")).await, Standing::Unpinned);
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
    let Standing::Device { pin, until } = read(&home).await else {
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
    root_key(&home, ROOT);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    assert!(matches!(
        read(&home).await,
        Standing::HoldsRoot { pin, .. } if pin == root()
    ));
}

#[tokio::test]
async fn a_root_with_no_pin_is_an_interrupted_mint_whatever_the_badge_holds() {
    for (tag, write_badge) in [("none", None), ("same", Some(ROOT)), ("other", Some(OTHER))] {
        let home = home(&format!("mint-{tag}"));
        root_key(&home, ROOT);
        if let Some(by) = write_badge {
            badge(&home, by).await;
        }
        assert_eq!(
            read(&home).await,
            Standing::InterruptedMint { root_key: root() },
            "badge {tag}"
        );
    }
    let home = home("mint-torn");
    root_key(&home, ROOT);
    std::fs::write(home.key_cert(), b"torn").expect("tear the badge");
    assert_eq!(
        read(&home).await,
        Standing::InterruptedMint { root_key: root() }
    );
}

#[tokio::test]
async fn a_sealed_root_key_is_read_by_its_header_without_a_prompt() {
    let home = home("sealed");
    let passphrase = crate::passphrase::passphrase(Zeroizing::new("correct horse".to_owned()))
        .expect("a passphrase");
    let mut seed = TestRoot::seeded(ROOT).seed();
    KeyFile::root(home.root_key())
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .expect("seal the root key");
    assert_eq!(
        read(&home).await,
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
        home.root_pub(),
        format!("{}\n", crate::testkit::torsioned_text()),
    )
    .expect("write the pin");
    assert_eq!(
        damaged(&home).await,
        Disagreement::UnreadablePin {
            path: home.root_pub()
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
    root_key(&home, ROOT);
    pin(&home, other()).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::RootNotPinned {
            root: root(),
            pin: other()
        }
    );
}

/// Beside a root kept here, a standing from another root is no stopped switch (`join` never runs where a
/// root is kept): it reads as no standing from the root, which `join` refuses.
#[tokio::test]
async fn a_held_root_with_a_standing_from_another_reads_as_no_standing() {
    let home = home("root-other-badge");
    root_key(&home, ROOT);
    pin(&home, root()).await;
    badge(&home, OTHER).await;
    assert_eq!(
        damaged(&home).await,
        Disagreement::RootWithoutStanding { root: root() }
    );
}

#[tokio::test]
async fn a_held_root_with_no_standing_reads_damaged() {
    let home = home("root-no-badge");
    root_key(&home, ROOT);
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
    std::fs::write(home.key_cert(), b"torn").expect("tear the badge");
    assert_eq!(
        damaged(&home).await,
        Disagreement::UnreadableStanding {
            path: home.key_cert()
        }
    );
}

#[tokio::test]
async fn a_standing_for_another_key_reads_damaged() {
    let home = home("badge-other-key");
    pin(&home, root()).await;
    let badge = TestRoot::seeded(ROOT)
        .device_badge(TestNode::seeded(0x41).node_id(), until())
        .expect("sign a standing for another machine");
    config::write_badge(&crate::testkit::lock(), &home, &badge).expect("write the device standing");
    assert_eq!(
        damaged(&home).await,
        Disagreement::StandingForAnotherKey {
            path: home.key_cert()
        }
    );
    // Held here too.
    root_key(&home, ROOT);
    assert_eq!(
        damaged(&home).await,
        Disagreement::StandingForAnotherKey {
            path: home.key_cert()
        }
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
    config::write_badge(&crate::testkit::lock(), &home, &badge).expect("write the device standing");
    assert!(matches!(
        read(&home).await,
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
        config::write_badge(&crate::testkit::lock(), &home, &badge)
            .expect("write the device standing");
        assert_eq!(
            damaged(&home).await,
            Disagreement::UnreadableStanding {
                path: home.key_cert()
            },
            "{tag}"
        );
    }
}

#[tokio::test]
async fn a_malformed_pin_reads_damaged() {
    let home = home("torn-pin");
    std::fs::write(home.root_pub(), b"ed01torn\n").expect("tear the pin");
    assert_eq!(
        damaged(&home).await,
        Disagreement::UnreadablePin {
            path: home.root_pub()
        }
    );
}

#[tokio::test]
async fn a_root_key_with_no_readable_header_reads_damaged() {
    let home = home("root-no-key");
    std::fs::write(home.root_key(), b"not a key").expect("write root.key");
    assert_eq!(
        damaged(&home).await,
        Disagreement::UnreadableRoot {
            path: home.root_key()
        }
    );
}

// A root revoked here.

/// Every file in `home`, by name, with its length and modification time: what a read must leave as it was.
fn listing(home: &Home) -> Vec<(String, u64, SystemTime)> {
    let mut files: Vec<_> = std::fs::read_dir(home.dir())
        .expect("list the home")
        .map(|entry| {
            let entry = entry.expect("an entry");
            let meta = entry.metadata().expect("its metadata");
            (
                entry.file_name().to_string_lossy().into_owned(),
                meta.len(),
                meta.modified().expect("its mtime"),
            )
        })
        .collect();
    files.sort();
    files
}

#[tokio::test]
async fn a_revoked_root_left_in_the_home_is_never_read_as_a_mint() {
    let home = home("revoked-root");
    root_key(&home, ROOT);
    revoke(&home, root()).await;
    assert_eq!(read(&home).await, Standing::Unpinned);
    assert!(home.root_key().exists(), "a read deletes no root key");
    assert_eq!(
        Standing::revoked_root(&home).await.expect("read the root"),
        Some(root())
    );
}

#[tokio::test]
async fn a_held_revoked_root_and_its_pin_read_as_absent_and_stay() {
    let home = home("revoked-holder");
    root_key(&home, ROOT);
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    update_files(&home);
    revoke(&home, root()).await;
    let before = listing(&home);
    assert_eq!(read(&home).await, Standing::Unpinned);
    assert_eq!(
        listing(&home),
        before,
        "the read renames and deletes nothing"
    );
}

#[tokio::test]
async fn a_revoked_pin_reads_as_no_pin_and_its_standing_as_none() {
    let home = home("revoked-pin");
    pin(&home, root()).await;
    badge(&home, ROOT).await;
    update_files(&home);
    revoke(&home, root()).await;
    let before = listing(&home);
    assert_eq!(read(&home).await, Standing::Unpinned);
    assert_eq!(
        listing(&home),
        before,
        "the read renames and deletes nothing"
    );
    assert_eq!(
        Standing::revoked_root(&home).await.expect("read the root"),
        None,
        "no root is kept here"
    );
}

#[tokio::test]
async fn a_live_root_kept_here_is_no_revoked_root() {
    let home = home("live-root");
    root_key(&home, ROOT);
    assert_eq!(
        Standing::revoked_root(&home).await.expect("read the root"),
        None
    );
}

// The lines.

#[test]
fn a_stopped_join_or_leave_names_the_verb_that_finishes_it() {
    assert_eq!(
        super::damaged_line(&Disagreement::StandingWithoutPin {
            standing_root: root()
        }),
        "joining did not finish; to finish it: swoosh join"
    );
    assert_eq!(
        super::damaged_line(&Disagreement::PinWithoutStanding { pin: root() }),
        "leaving did not finish; to finish it: swoosh leave"
    );
    assert_eq!(
        super::damaged_line(&Disagreement::OwnKeyPinned { key: own() }),
        format!(
            "root: this machine's records disagree (this machine trusts its own key {} as a root): \
             swoosh cannot tell which root it trusts. A root kept on this machine stays. To start over: \
             swoosh leave",
            crate::credential::short(&own())
        )
    );
}
