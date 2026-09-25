//! `leave` over homes built on disk the way the product leaves them: a device of a root, a machine that is
//! no root's device, a damaged home, and the machine where a root is kept. Each run is in process, with a
//! scripted passphrase and a fixed day.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Parser;
use keystore::{KeyFile, Passphrase, Protection, Stored};
use swoosh::config;
use swoosh::contacts::{ContactsStore, ME, Petname};
use swoosh::home::Home;
use swoosh::identity::HomeLock;
use swoosh::roster::{Epoch, RosterDoc, fold};
use swoosh::standing::Standing;
use swoosh::testkit::{Counting, TestNode, TestRoot};
use zeroize::Zeroizing;

use super::LeaveCmd;

/// This machine's key.
const OWN: u8 = 0x11;
/// The root this machine is a device of.
const ROOT: u8 = 0x21;
/// Another root.
const OTHER: u8 = 0x31;

const DAY: u64 = 24 * 60 * 60;
/// The day every run here takes place: 2026-09-25.
const TODAY: u64 = 1_790_294_400;
const PASS: &str = "correct horse battery staple";

static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

fn node(seed: u8) -> NodeId {
    TestNode::seeded(seed).node_id()
}

fn root(seed: u8) -> NodeId {
    TestRoot::seeded(seed).node_id()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A fresh home holding this machine's key, locked under [`PASS`] when `locked`.
fn scratch_with(tag: &str, locked: bool) -> Home {
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("swoosh-leave-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let passphrase = Passphrase::try_from(Zeroizing::new(PASS.to_owned())).unwrap();
    let protection = if locked {
        Protection::Passphrase(&passphrase)
    } else {
        Protection::Plain
    };
    let mut seed = TestNode::seeded(OWN).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut seed), protection)
        .unwrap();
    home
}

fn scratch(tag: &str) -> Home {
    scratch_with(tag, false)
}

/// Make `home` a device of `ROOT` named `laptop`, holding an update, a revoked key and `me`.
async fn device(home: &Home, until: u64) {
    let root = TestRoot::seeded(ROOT);
    config::write_badge(
        home,
        &root
            .device_badge(
                node(OWN),
                SystemTime::UNIX_EPOCH + Duration::from_secs(until),
            )
            .unwrap(),
    )
    .await
    .unwrap();
    config::write_signet(home, root.node_id()).await.unwrap();
    let member = root
        .member(
            TestNode::seeded(OWN).verify_key(),
            "laptop".parse().unwrap(),
        )
        .unwrap();
    let doc = RosterDoc::with_revocations(
        Epoch(1),
        vec![member],
        vec![],
        vec![TestNode::seeded(0x66).verify_key()],
    )
    .unwrap();
    fold(home, &root.sign_update(&doc)).await.unwrap();
    std::fs::write(home.roster_seed(), format!("{}\n", node(0x41))).unwrap();
}

fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            files.insert(path.clone(), std::fs::read(&path).unwrap());
        }
    }
    files
}

#[derive(Debug, Parser)]
struct Cli {
    #[command(flatten)]
    leave: LeaveCmd,
}

/// What one `leave` did.
struct Ran {
    result: eyre::Result<()>,
    out: String,
    err: String,
    prompts: usize,
}

impl Ran {
    fn refusal(&self) -> String {
        match &self.result {
            Ok(()) => panic!("leave refused: {}", self.err),
            Err(error) => format!("{error:#}"),
        }
    }

    fn left(&self) {
        if let Err(error) = &self.result {
            panic!("leave left: {error:#}\n{}", self.err);
        }
    }
}

async fn leave(home: &Home, args: &[&str]) -> Ran {
    let cmd = Cli::try_parse_from(core::iter::once("leave").chain(args.iter().copied()))
        .unwrap()
        .leave;
    let mut prompt = Counting::new([PASS]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = cmd
        .leave(
            home,
            &mut prompt,
            SystemTime::UNIX_EPOCH + Duration::from_secs(TODAY),
            &mut out,
            &mut err,
        )
        .await;
    Ran {
        result,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
        prompts: prompt.events(),
    }
}

async fn read(home: &Home) -> Standing {
    Standing::read(home).await.unwrap().standing
}

fn stored_key(home: &Home) -> NodeId {
    KeyFile::device(home.key())
        .load()
        .unwrap()
        .unwrap()
        .node_id()
}

/// Keep `ROOT` in `home`: a plain 32-byte key file, which the standing reads by its key without a prompt.
fn keep_root(home: &Home) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    config::create_store_dir(&home.root()).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(home.root().join("root.key"))
        .unwrap()
        .write_all(&TestRoot::seeded(ROOT).seed())
        .unwrap();
}

#[tokio::test]
async fn leave_removes_the_standing_and_the_pin_and_keeps_the_revocations() {
    let home = scratch("device");
    device(&home, now() + 90 * DAY).await;
    let Standing::Device { until, .. } = read(&home).await else {
        panic!("a device");
    };
    let until = until
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let revoked_keys = std::fs::read(home.revoked_keys()).unwrap();
    let ran = leave(&home, &[]).await;
    ran.left();
    assert_eq!(read(&home).await, Standing::Unpinned);
    for path in [
        home.badge(),
        home.signet(),
        home.roster(),
        home.roster_synced(),
        home.roster_seed(),
        home.roster_fork(),
    ] {
        assert!(!path.exists(), "{} is gone", path.display());
    }
    let store = ContactsStore::open(home.contacts()).await.unwrap();
    assert!(
        store
            .contacts()
            .devices(&Petname::stored(ME).unwrap())
            .is_none(),
        "no list of the old root's devices stays"
    );
    assert_eq!(
        std::fs::read(home.revoked_keys()).unwrap(),
        revoked_keys,
        "every revocation it learned stays"
    );
    assert_eq!(
        ran.err.trim(),
        format!(
            "this machine no longer trusts root root:{}. Your root still lists it as me/laptop until {}: \
             revoke it there with swoosh revoke me/laptop.",
            root(ROOT),
            swoosh::root::Date(until)
        )
    );
    assert!(ran.out.is_empty(), "plain leave prints nothing on stdout");
}

#[tokio::test]
async fn leave_refuses_on_a_machine_that_is_no_device() {
    let home = scratch("unpinned");
    let before = snapshot(home.dir());
    let ran = leave(&home, &[]).await;
    assert_eq!(ran.refusal(), "this machine is not one of your devices.");
    assert!(snapshot(home.dir()) == before, "nothing is written");
}

#[tokio::test]
async fn leave_refuses_where_the_root_is_kept() {
    for args in [&[][..], &["--new-key"][..]] {
        let home = scratch("holds-root");
        keep_root(&home);
        device(&home, now() + 90 * DAY).await;
        assert!(matches!(read(&home).await, Standing::HoldsRoot { .. }));
        let before = snapshot(home.dir());
        let ran = leave(&home, args).await;
        assert!(ran.refusal().contains("swoosh move-root <dir>"), "{args:?}");
        assert!(snapshot(home.dir()) == before, "{args:?} writes nothing");
        assert!(ran.out.is_empty());
    }
}

#[tokio::test]
async fn leave_on_a_damaged_home_removes_the_standing_and_the_pin_and_keeps_the_root() {
    let home = scratch("damaged");
    keep_root(&home);
    // A root kept here under a pin to another root.
    config::write_signet(&home, root(OTHER)).await.unwrap();
    assert!(
        Standing::read(&home).await.is_err(),
        "the home reads as damaged"
    );
    let ran = leave(&home, &[]).await;
    ran.left();
    assert!(!home.signet().exists());
    assert!(home.root().join("root.key").exists(), "the root stays");
    assert!(matches!(
        read(&home).await,
        Standing::InterruptedMint { .. }
    ));
    assert_eq!(
        ran.err.trim(),
        format!("this machine no longer trusts root root:{}.", root(OTHER))
    );
}

#[tokio::test]
async fn leave_new_key_on_an_unpinned_home_replaces_the_key() {
    let home = scratch("new-key-unpinned");
    let ran = leave(&home, &["--new-key"]).await;
    ran.left();
    let key = stored_key(&home);
    assert_ne!(key, node(OWN), "the key is replaced");
    assert_eq!(ran.out, format!("{key}\n"), "stdout is the new key alone");
    let kept = home.dir().join("key.replaced-2026-09-25");
    assert_eq!(
        KeyFile::device(&kept).load().unwrap().unwrap().node_id(),
        node(OWN),
        "the old key is kept aside"
    );
    assert!(
        ran.err
            .contains(&format!("kept the old key at {}", kept.display())),
        "{}",
        ran.err
    );
    assert!(
        ran.err
            .contains("links this machine made under its old key stop working.")
    );
    assert!(
        !ran.err.contains("no longer trusts"),
        "it only replaces the key: {}",
        ran.err
    );
    assert_eq!(ran.prompts, 0, "a plain key gets a plain key");
}

#[tokio::test]
async fn leave_new_key_on_a_device_leaves_and_keeps_the_old_key_and_links_aside() {
    let home = scratch("new-key-device");
    device(&home, now() + 90 * DAY).await;
    std::fs::write(home.links(), b"a link row\n").unwrap();
    // A day that already has a kept key takes the first free number.
    std::fs::write(home.dir().join("key.replaced-2026-09-25"), b"earlier").unwrap();
    let ran = leave(&home, &["--new-key"]).await;
    ran.left();
    assert_eq!(read(&home).await, Standing::Unpinned);
    assert_eq!(
        std::fs::read(home.dir().join("key.replaced-2026-09-25")).unwrap(),
        b"earlier",
        "an earlier kept key is never replaced"
    );
    assert!(home.dir().join("key.replaced-2026-09-25-1").exists());
    assert_eq!(
        std::fs::read(home.dir().join("links.replaced-2026-09-25-1")).unwrap(),
        b"a link row\n"
    );
    assert!(!home.links().exists(), "the old key's links are set aside");
    assert!(
        ran.err
            .contains("Give the new key to the machine that keeps your root to invite it again."),
        "{}",
        ran.err
    );
    assert_eq!(ran.out.lines().count(), 1, "stdout is the new key alone");
}

#[tokio::test]
async fn leave_new_key_locks_the_new_key_when_the_old_one_was_locked() {
    let home = scratch_with("new-key-locked", true);
    let ran = leave(&home, &["--new-key"]).await;
    ran.left();
    assert_eq!(ran.prompts, 1, "a new passphrase is chosen, once");
    assert!(matches!(
        KeyFile::device(home.key()).load().unwrap().unwrap(),
        Stored::Locked(_)
    ));
}

#[tokio::test]
async fn leave_new_key_refuses_while_serve_runs() {
    let home = scratch("new-key-serving");
    device(&home, now() + 90 * DAY).await;
    let _serving = HomeLock::serving(&home).unwrap();
    let before = snapshot(home.dir());
    let ran = leave(&home, &["--new-key"]).await;
    assert_eq!(ran.refusal(), "stop swoosh serve first.");
    assert!(ran.out.is_empty());
    assert!(snapshot(home.dir()) == before, "nothing is written");
}

#[tokio::test]
async fn leave_under_a_running_serve_says_its_sessions_end() {
    let home = scratch("serving");
    device(&home, now() + 90 * DAY).await;
    let _serving = HomeLock::serving(&home).unwrap();
    let ran = leave(&home, &[]).await;
    ran.left();
    assert!(
        ran.err.contains(&format!(
            "sessions this machine admitted under root root:{} end now",
            root(ROOT)
        )),
        "{}",
        ran.err
    );
}
