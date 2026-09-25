//! `Root` over every check before the prompt, the mint and its interruptions, the bring-forward, and the
//! commit.
//!
//! Each home is built on disk the way the product leaves it: this machine's key, a pin, a standing the root
//! signed, and a root directory holding a sealed `root.key` and a signed `state`. The sealed key is made
//! once per process and copied, because sealing is the slow part of a test here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::RefCell;
use core::time::Duration;
use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use keystore::{KeyFile, Passphrase, Protection, Stored};
use nauthy::{DisabledRoots, RevocationId, VerifyKey};
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};
use zeroize::Zeroizing;

use super::{Committed, Minted, Root, RootError, RootPlace, RootVerb, STOP, Seam};
use crate::codec::{Id, MAX_REVOKED, MAX_REVOKED_KEYS};
use crate::config;
use crate::contacts::DeviceLabel;
use crate::home::Home;
use crate::passphrase::Prompt;
use crate::roster::{Epoch, Member, RosterDoc};
use crate::standing::Standing;
use crate::state::{self, Row, State};
use crate::testkit::{Counting, STANDING_UNTIL, TestNode, TestRoot};

/// This machine's key.
const OWN: u8 = 0x11;
/// The root this machine trusts or holds.
const ROOT: u8 = 0x21;
/// Another root.
const OTHER: u8 = 0x31;
/// Another device of the root.
const LAPTOP: u8 = 0x41;
/// A third.
const PHONE: u8 = 0x42;

/// The passphrase every sealed root here opens under.
const PASS: &str = "correct horse battery staple";

const DAY: u64 = 24 * 60 * 60;

fn key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

fn name(text: &str) -> DeviceLabel {
    text.parse().unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An id the standing of `seed` could carry, ending at `expires`.
fn id(seed: u8, expires: u64) -> Id {
    Id {
        expires,
        id: RevocationId::from_bytes(vec![seed; 64]),
    }
}

/// A live row for the device `seed`, signed by `ROOT`, with `ids`.
fn row(seed: u8, label: &str, ids: Vec<Id>) -> Row {
    Row {
        key: key(seed),
        label: name(label),
        until: STANDING_UNTIL,
        duration: 90 * DAY,
        seeded: false,
        invite_until: 0,
        revoked_on: 0,
        ids,
        standing: TestRoot::seeded(ROOT).standing(key(seed)).unwrap(),
    }
}

/// The update `row` stands in.
fn member(row: &Row) -> Member {
    Member {
        node: row.key,
        label: row.label.clone(),
        until: row.until,
        duration: row.duration,
        ids: row.ids.clone(),
        standing: row.standing.clone(),
    }
}

/// This machine's own row.
fn own_row() -> Row {
    row(OWN, "desk", vec![id(OWN, STANDING_UNTIL)])
}

fn records(last: u64, rows: Vec<Row>, revoked: Vec<Id>, keys: Vec<VerifyKey>) -> State {
    State::new(Epoch(last), rows, revoked, keys).unwrap()
}

/// A fresh home with this machine's key in it, plain.
fn home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-root-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut seed = TestNode::seeded(OWN).seed();
    KeyFile::device(home.identity_key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .unwrap();
    home
}

/// A directory beside `home` for a copy of a root.
fn beside(home: &Home, what: &str) -> PathBuf {
    home.dir().with_extension(what)
}

fn passphrase() -> Passphrase {
    Passphrase::try_from(Zeroizing::new(PASS.to_owned())).unwrap()
}

/// The root seeded `seed`, sealed under [`PASS`], as the bytes of its key file. Sealed once per seed.
fn sealed(seed: u8) -> Vec<u8> {
    static SEALED: OnceLock<Mutex<HashMap<u8, Vec<u8>>>> = OnceLock::new();
    let cache = SEALED.get_or_init(Mutex::default);
    let mut cache = cache.lock().unwrap();
    cache
        .entry(seed)
        .or_insert_with(|| {
            let dir = std::env::temp_dir()
                .join(format!("swoosh-root-sealed-{seed}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            config::create_store_dir(&dir).unwrap();
            let path = dir.join("root.key");
            let mut bytes = TestRoot::seeded(seed).seed();
            KeyFile::root(&path)
                .write(
                    &keystore::Secret::take(&mut bytes),
                    Protection::Passphrase(&passphrase()),
                )
                .unwrap();
            let sealed = std::fs::read(&path).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            sealed
        })
        .clone()
}

/// Write an owner-only file.
fn private(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

/// A copy of the root seeded `seed` at `dir`, holding `records`.
fn copy(dir: &Path, seed: u8, records: &State) {
    config::create_store_dir(dir).unwrap();
    private(&dir.join("root.key"), &sealed(seed));
    state::write(dir, &TestRoot::seeded(seed).sign_state(records)).unwrap();
}

/// Make `home` a device of the root seeded `seed`: its pin, and a standing that root signed for it.
async fn device_of(home: &Home, seed: u8) {
    let root = TestRoot::seeded(seed);
    config::write_signet(home, root.node_id()).await.unwrap();
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
    let badge = root
        .device_badge(TestNode::seeded(OWN).node_id(), until)
        .unwrap();
    config::write_badge(home, &badge).await.unwrap();
}

/// Make `home` hold the root seeded `ROOT`, with `records`.
async fn holds(home: &Home, records: &State) {
    device_of(home, ROOT).await;
    copy(&home.root(), ROOT, records);
}

/// Write `doc`, signed by `ROOT`, as the update this home holds.
fn held(home: &Home, doc: &RosterDoc) {
    std::fs::write(home.roster(), TestRoot::seeded(ROOT).sign_update(doc)).unwrap();
}

/// Present, printing to a buffer: what it returned, and what it printed.
async fn present(
    home: &Home,
    place: RootPlace,
    verb: RootVerb,
    prompt: &mut impl Prompt,
) -> (Result<Root, RootError>, String) {
    let mut out = Vec::new();
    let root = Root::present_to(home, place, verb, prompt, &mut out).await;
    (root, String::from_utf8(out).unwrap())
}

/// Commit, and the update it cut as this home now holds it.
async fn commit(mut root: Root) -> (Committed, RosterDoc) {
    let committed = root.commit_to(&mut io::sink()).await.unwrap();
    let update =
        crate::roster::verify(&committed.bytes, TestRoot::seeded(ROOT).verify_key()).unwrap();
    (committed, update)
}

async fn standing(home: &Home) -> Standing {
    Standing::read(home).await.unwrap().standing
}

// --- the mint ---

#[tokio::test]
async fn mint_asks_choose_then_repeat() {
    let home = home("mint-asks");
    let mut prompt = Counting::new([PASS]);
    let minted = Root::mint_to(&home, &mut prompt, &mut io::sink())
        .await
        .unwrap();
    assert!(matches!(minted, Minted::Made(_)));
    assert_eq!(
        prompt.events(),
        1,
        "choosing and repeating is one prompt event"
    );
    assert_eq!(
        prompt.reads(),
        2,
        "the passphrase is read twice, and never a third time"
    );
}

#[tokio::test]
async fn the_first_invite_mints_a_sealed_root_and_this_machines_standing() {
    let home = home("mint-sealed");
    let Minted::Made(mut root) = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink())
        .await
        .unwrap()
    else {
        panic!("an unpinned home makes a root");
    };
    let root_key = root.key();
    match KeyFile::root(home.root().join("root.key")).load().unwrap() {
        Some(Stored::Locked(locked)) => assert_eq!(locked.node_id(), root_key),
        other => panic!("the root key is sealed, of the root kind: {other:?}"),
    }
    let badge = config::load_badge(&home).await.unwrap().unwrap();
    assert_eq!(
        badge.root(),
        root_key.verify_key(),
        "the standing roots at the new root"
    );
    assert!(matches!(standing(&home).await, Standing::HoldsRoot { pin, .. } if pin == root_key));
    assert!(
        !home.root().join("standing").exists(),
        "the pin is written, so the staged standing is gone"
    );

    root.sign_standing(key(LAPTOP), name("laptop"), Duration::from_secs(90 * DAY))
        .unwrap();
    let committed = root.commit_to(&mut io::sink()).await.unwrap();
    let update = crate::roster::verify(&committed.bytes, root_key.verify_key()).unwrap();
    assert_eq!(update.epoch(), Epoch(1));
    assert_eq!(
        update.members().len(),
        2,
        "this machine and the device it invited"
    );
    assert!(
        committed.targets.is_empty(),
        "nothing to offer: this machine, and a device just added"
    );
}

#[tokio::test]
async fn an_interrupted_mint_completes_without_a_prompt() {
    let home = home("mint-renamed");
    STOP.set(Some(Seam::Renamed));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());
    assert!(matches!(
        standing(&home).await,
        Standing::InterruptedMint { .. }
    ));

    let mut prompt = Counting::refusing();
    let finished = Root::mint_to(&home, &mut prompt, &mut io::sink())
        .await
        .unwrap();
    assert!(matches!(finished, Minted::Finished));
    assert_eq!(prompt.events(), 0);
    assert!(matches!(standing(&home).await, Standing::HoldsRoot { .. }));
}

#[tokio::test]
async fn a_mint_killed_between_badge_and_pin_finishes_without_a_prompt() {
    let home = home("mint-badged");
    STOP.set(Some(Seam::Badged));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());
    assert!(home.badge().exists() && !home.signet().exists());
    assert!(matches!(
        standing(&home).await,
        Standing::InterruptedMint { .. }
    ));

    let mut prompt = Counting::refusing();
    let finished = Root::mint_to(&home, &mut prompt, &mut io::sink())
        .await
        .unwrap();
    assert!(matches!(finished, Minted::Finished));
    assert_eq!(prompt.events(), 0);
    assert!(matches!(standing(&home).await, Standing::HoldsRoot { .. }));
}

#[tokio::test]
async fn an_interrupted_mint_with_no_standing_prompts_once() {
    let home = home("mint-bare");
    STOP.set(Some(Seam::Renamed));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());
    std::fs::remove_file(home.root().join("standing")).unwrap();

    let mut prompt = Counting::new([PASS]);
    let Minted::Made(mut root) = Root::mint_to(&home, &mut prompt, &mut io::sink())
        .await
        .unwrap()
    else {
        panic!("a finish that asked hands back the root it unlocked, so the act asks no more");
    };
    assert!(matches!(standing(&home).await, Standing::HoldsRoot { .. }));
    // The act goes on to its cut on the one prompt.
    root.sign_standing(key(LAPTOP), name("laptop"), Duration::from_secs(90 * DAY))
        .unwrap();
    let _committed = root.commit_to(&mut io::sink()).await.unwrap();
    assert_eq!(prompt.events(), 1, "the whole act asks once");
    assert_eq!(
        prompt.reads(),
        1,
        "the existing passphrase, asked once, never chosen again"
    );
}

#[tokio::test]
async fn an_interrupted_mint_takes_no_standing_that_is_not_its_own() {
    let home = home("mint-foreign");
    STOP.set(Some(Seam::Renamed));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());
    // A standing another root signed, left where the mint keeps this machine's.
    let foreign = TestRoot::seeded(OTHER).standing(key(OWN)).unwrap();
    std::fs::write(home.root().join("standing"), format!("{foreign}\n")).unwrap();

    let mut prompt = Counting::new([PASS]);
    let minted = Root::mint_to(&home, &mut prompt, &mut io::sink())
        .await
        .unwrap();
    assert!(matches!(minted, Minted::Made(_)), "{minted:?}");
    assert_eq!(prompt.events(), 1, "it signs a standing of its own instead");
    let Standing::HoldsRoot { pin, .. } = standing(&home).await else {
        panic!("the mint finished");
    };
    let badge = config::load_badge(&home).await.unwrap().unwrap();
    assert_eq!(
        badge.root(),
        pin.verify_key(),
        "the badge roots at this root"
    );
}

/// The stderr the prompt and the output share, in the order written.
#[derive(Clone, Default)]
struct Log(Rc<RefCell<Vec<u8>>>);

impl Write for Log {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A prompt that marks the log where it asks.
struct Marking(Log, Counting);

impl Prompt for Marking {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, path: &Path) -> eyre::Result<Passphrase> {
        let _ = writeln!(self.0, "<prompt>");
        self.1.unlock(path)
    }

    fn choose(&mut self, path: &Path) -> eyre::Result<Passphrase> {
        let _ = writeln!(self.0, "<prompt>");
        self.1.choose(path)
    }
}

#[tokio::test]
async fn the_first_root_act_announces_before_the_prompt_and_after_the_mint() {
    let home = home("mint-lines");
    let log = Log::default();
    let mut prompt = Marking(log.clone(), Counting::new([PASS]));
    let Minted::Made(mut root) = Root::mint_to(&home, &mut prompt, &mut log.clone())
        .await
        .unwrap()
    else {
        panic!("an unpinned home makes a root");
    };
    root.sign_standing(key(LAPTOP), name("laptop"), Duration::from_secs(90 * DAY))
        .unwrap();
    let _committed = root.commit_to(&mut log.clone()).await.unwrap();

    let date = |label: &str| {
        let row = root.rows().iter().find(|row| row.label.as_str() == label);
        super::Date(row.unwrap().until).to_string()
    };
    let own = root.rows().iter().find(|row| row.key == key(OWN)).unwrap();
    let expected = format!(
        "This makes your root on this machine: a second key, not a machine, that vouches for all your devices.\n\
         It is locked with a passphrase, which you type whenever you add, renew or revoke a device.\n\
         <prompt>\n\
         made your root root:{}…, kept on this machine, locked with a passphrase.\n\
         This machine is me/{} until {}. me/laptop can join until {}.\n\
         Back up your root now, off this disk: swoosh backup <dir>\n\
         To keep it off this machine: swoosh move-root <dir>\n",
        root.key().short(),
        own.label,
        date(own.label.as_str()),
        date("laptop"),
    );
    assert_eq!(String::from_utf8(log.0.borrow().clone()).unwrap(), expected);
}

// --- present: every check before the prompt ---

#[tokio::test]
async fn present_checks_everything_before_the_prompt() {
    let records = records(0, vec![own_row()], Vec::new(), Vec::new());

    // Step 1: a machine that is no device of the root, to an act that cuts.
    let unpinned = home("check-1");
    let dir = beside(&unpinned, "copy");
    copy(&dir, ROOT, &records);
    let mut prompt = Counting::refusing();
    let (refused, _) = present(
        &unpinned,
        RootPlace::Dir(dir.clone()),
        RootVerb::Revoke,
        &mut prompt,
    )
    .await;
    assert!(matches!(refused, Err(RootError::NotADevice)));
    assert_eq!(prompt.events(), 0);

    // Step 2: a copy where a root is kept.
    let holder = home("check-2");
    holds(&holder, &records).await;
    let (refused, _) = present(
        &holder,
        RootPlace::Dir(dir.clone()),
        RootVerb::Invite,
        &mut prompt,
    )
    .await;
    assert!(matches!(refused, Err(RootError::HeldHere)));

    // Step 3: a plain root key.
    let plain = home("check-3");
    device_of(&plain, ROOT).await;
    let plain_dir = beside(&plain, "copy");
    config::create_store_dir(&plain_dir).unwrap();
    private(&plain_dir.join("root.key"), &TestRoot::seeded(ROOT).seed());
    let (refused, _) = present(
        &plain,
        RootPlace::Dir(plain_dir),
        RootVerb::Invite,
        &mut prompt,
    )
    .await;
    assert!(matches!(refused, Err(RootError::Plain)));

    // Step 4: a root other than the one this machine trusts.
    let elsewhere = home("check-4");
    device_of(&elsewhere, OTHER).await;
    let (refused, _) = present(
        &elsewhere,
        RootPlace::Dir(dir.clone()),
        RootVerb::Invite,
        &mut prompt,
    )
    .await;
    assert!(matches!(refused, Err(RootError::Mismatch { .. })));

    // Step 5: a root revoked here.
    let latched = home("check-5");
    DisabledRoots::open_for_repair(latched.disabled_roots())
        .disable(TestRoot::seeded(ROOT).verify_key())
        .await
        .unwrap();
    let (refused, _) = present(
        &latched,
        RootPlace::Dir(dir.clone()),
        RootVerb::Backup,
        &mut prompt,
    )
    .await;
    assert!(matches!(refused, Err(RootError::Revoked { .. })));

    // Step 6: a copy that cannot be written, to an act that writes it.
    let device = home("check-6");
    device_of(&device, ROOT).await;
    let stick = beside(&device, "stick");
    copy(&stick, ROOT, &records);
    std::fs::set_permissions(&stick, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (refused, _) = present(
        &device,
        RootPlace::Dir(stick.clone()),
        RootVerb::Invite,
        &mut prompt,
    )
    .await;
    std::fs::set_permissions(&stick, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(refused, Err(RootError::ReadOnly { .. })));

    // Step 7: a copy another command is using.
    let held_lock = super::DirLock::take(&dir).unwrap();
    let (refused, _) = present(
        &device,
        RootPlace::Dir(dir.clone()),
        RootVerb::Invite,
        &mut prompt,
    )
    .await;
    drop(held_lock);
    assert!(matches!(refused, Err(RootError::InUse)));

    // Step 8: records changed outside swoosh.
    std::fs::write(dir.join("state"), b"not the root's records").unwrap();
    let (refused, _) = present(&device, RootPlace::Dir(dir), RootVerb::Invite, &mut prompt).await;
    assert!(matches!(refused, Err(RootError::State(_))));

    assert_eq!(prompt.events(), 0, "no refusal costs a prompt");
}

#[tokio::test]
async fn present_refuses_a_latched_root() {
    let home = home("latched");
    let dir = beside(&home, "copy");
    copy(
        &dir,
        ROOT,
        &records(0, vec![own_row()], Vec::new(), Vec::new()),
    );
    DisabledRoots::open_for_repair(home.disabled_roots())
        .disable(TestRoot::seeded(ROOT).verify_key())
        .await
        .unwrap();
    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Dir(dir), RootVerb::Backup, &mut prompt).await;
    assert!(
        matches!(refused, Err(RootError::Revoked { .. })),
        "{refused:?}"
    );
    assert_eq!(prompt.events(), 0);
}

#[tokio::test]
async fn present_refuses_a_copy_where_a_root_is_held() {
    let home = home("held-here");
    let records = records(0, vec![own_row()], Vec::new(), Vec::new());
    holds(&home, &records).await;
    let dir = beside(&home, "copy");
    copy(&dir, ROOT, &records);
    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Dir(dir), RootVerb::Backup, &mut prompt).await;
    assert!(matches!(refused, Err(RootError::HeldHere)), "{refused:?}");
    assert_eq!(prompt.events(), 0);
}

#[tokio::test]
async fn a_tampered_state_is_refused_before_the_prompt() {
    let home = home("tampered");
    device_of(&home, ROOT).await;
    let dir = beside(&home, "copy");
    let records = records(
        0,
        vec![own_row(), row(LAPTOP, "laptop", Vec::new())],
        Vec::new(),
        Vec::new(),
    );
    copy(&dir, ROOT, &records);
    // Repoint the laptop's row at another key, as someone who can write the copy would.
    let mut bytes = std::fs::read(dir.join("state")).unwrap();
    let laptop = *key(LAPTOP).bytes();
    let at = bytes
        .windows(laptop.len())
        .position(|window| window == laptop)
        .unwrap();
    bytes[at..at + laptop.len()].copy_from_slice(key(PHONE).bytes());
    std::fs::write(dir.join("state"), bytes).unwrap();

    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Dir(dir), RootVerb::Invite, &mut prompt).await;
    assert!(matches!(refused, Err(RootError::State(_))), "{refused:?}");
    assert_eq!(prompt.events(), 0);
}

#[tokio::test]
async fn a_device_key_file_in_the_root_slot_is_refused_by_kind() {
    let home = home("wrong-kind");
    device_of(&home, ROOT).await;
    let dir = beside(&home, "copy");
    config::create_store_dir(&dir).unwrap();
    let mut seed = TestRoot::seeded(ROOT).seed();
    KeyFile::device(dir.join("root.key"))
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase()),
        )
        .unwrap();
    state::write(
        &dir,
        &TestRoot::seeded(ROOT).sign_state(&records(0, vec![own_row()], Vec::new(), Vec::new())),
    )
    .unwrap();

    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Dir(dir), RootVerb::Invite, &mut prompt).await;
    assert!(
        matches!(
            refused,
            Err(RootError::KeyFile(keystore::Error::Format {
                source: keystore::FormatError::WrongKind { .. },
                ..
            }))
        ),
        "{refused:?}"
    );
    assert_eq!(prompt.events(), 0);
}

#[tokio::test]
async fn an_unpinned_machine_refuses_a_cutting_root_act() {
    let home = home("unpinned-cut");
    let dir = beside(&home, "copy");
    copy(
        &dir,
        ROOT,
        &records(0, vec![own_row()], Vec::new(), Vec::new()),
    );
    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Dir(dir), RootVerb::Revoke, &mut prompt).await;
    assert!(matches!(refused, Err(RootError::NotADevice)), "{refused:?}");
    assert_eq!(prompt.events(), 0);
}

// --- the bounds ---

#[tokio::test]
async fn a_cut_at_max_revoked_keys_refuses_before_the_prompt() {
    let home = home("max-keys");
    let full: Vec<VerifyKey> = (0..MAX_REVOKED_KEYS)
        .map(|nth| {
            let mut bytes = [0xee_u8; 32];
            bytes[..8].copy_from_slice(&(nth as u64).to_be_bytes());
            VerifyKey::new(bytes)
        })
        .collect();
    holds(&home, &records(0, vec![own_row()], Vec::new(), full)).await;
    held(
        &home,
        &RosterDoc::with_revocations(
            Epoch(1),
            vec![member(&own_row())],
            Vec::new(),
            vec![key(LAPTOP)],
        )
        .unwrap(),
    );
    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Home, RootVerb::Revoke, &mut prompt).await;
    assert!(
        matches!(refused, Err(RootError::TooManyKeys { count }) if count == MAX_REVOKED_KEYS + 1),
        "{refused:?}"
    );
    assert_eq!(prompt.events(), 0);
}

#[tokio::test]
async fn update_number_overflow_refuses() {
    let home = home("overflow");
    holds(&home, &records(0, vec![own_row()], Vec::new(), Vec::new())).await;
    held(
        &home,
        &RosterDoc::new(Epoch(u64::MAX), vec![member(&own_row())]).unwrap(),
    );
    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Home, RootVerb::Invite, &mut prompt).await;
    assert!(matches!(refused, Err(RootError::Exhausted)), "{refused:?}");
    assert_eq!(prompt.events(), 0);
}

// --- bring forward ---

/// A home whose `state` lists the laptop with four live ids, and whose update renews it a fifth time.
async fn fifth_id(tag: &str) -> Home {
    let home = home(tag);
    let later = now() + 10 * DAY;
    let four = (1..=4).map(|nth| id(nth, later + u64::from(nth))).collect();
    holds(
        &home,
        &records(
            1,
            vec![own_row(), row(LAPTOP, "laptop", four)],
            Vec::new(),
            Vec::new(),
        ),
    )
    .await;
    let mut renewed = row(LAPTOP, "laptop", vec![id(5, later + 5)]);
    renewed.until = STANDING_UNTIL + 1;
    held(
        &home,
        &RosterDoc::new(Epoch(2), vec![member(&own_row()), member(&renewed)]).unwrap(),
    );
    home
}

#[tokio::test]
async fn bring_forward_revokes_a_fifth_live_id_it_cannot_keep() {
    let home = fifth_id("fifth-revoked").await;
    let (root, out) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    assert!(
        out.contains("+1 older renewals of me/laptop revoked"),
        "{out}"
    );
    let (_, update) = commit(root.unwrap()).await;
    assert!(
        update
            .revoked()
            .iter()
            .any(|revoked| revoked.id == id(1, 0).id),
        "the oldest id beyond four is revoked, not dropped"
    );
    let laptop = update
        .members()
        .iter()
        .find(|member| member.node == key(LAPTOP))
        .unwrap();
    assert_eq!(laptop.ids.len(), 4);
}

#[tokio::test]
async fn bring_forward_of_a_fifth_id_keeps_the_device() {
    let home = fifth_id("fifth-kept").await;
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let (_, update) = commit(root.unwrap()).await;
    assert!(
        update
            .members()
            .iter()
            .any(|member| member.node == key(LAPTOP))
    );
    assert!(!update.revoked_keys().contains(&key(LAPTOP)));
}

#[tokio::test]
async fn bring_forward_keeps_a_devices_duration() {
    let home = home("duration");
    holds(&home, &records(0, vec![own_row()], Vec::new(), Vec::new())).await;
    let mut phone = row(PHONE, "phone", Vec::new());
    phone.duration = 60 * DAY;
    held(
        &home,
        &RosterDoc::new(Epoch(1), vec![member(&own_row()), member(&phone)]).unwrap(),
    );
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let (_, update) = commit(root.unwrap()).await;
    let phone = update
        .members()
        .iter()
        .find(|member| member.node == key(PHONE))
        .unwrap();
    assert_eq!(phone.duration, 60 * DAY);
}

#[tokio::test]
async fn a_current_copy_prints_no_bring_forward() {
    let home = home("current");
    holds(&home, &records(1, vec![own_row()], Vec::new(), Vec::new())).await;
    held(
        &home,
        &RosterDoc::new(Epoch(1), vec![member(&own_row())]).unwrap(),
    );
    let (_, out) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::refusing(),
    )
    .await;
    assert!(!out.contains("brought forward"), "{out}");

    held(
        &home,
        &RosterDoc::new(Epoch(2), vec![member(&own_row())]).unwrap(),
    );
    let (_, out) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::refusing(),
    )
    .await;
    assert!(
        out.contains("brought forward"),
        "a copy behind its devices says so: {out}"
    );
}

#[tokio::test]
async fn bring_forward_never_takes_devices_from_the_copy_over_the_update() {
    let home = home("update-wins");
    holds(
        &home,
        &records(
            0,
            vec![own_row(), row(LAPTOP, "laptop", Vec::new())],
            Vec::new(),
            Vec::new(),
        ),
    )
    .await;
    let theirs = row(PHONE, "laptop", Vec::new());
    held(
        &home,
        &RosterDoc::new(Epoch(1), vec![member(&own_row()), member(&theirs)]).unwrap(),
    );
    let (root, out) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    assert!(
        out.contains("was also added on another copy of your root"),
        "{out}"
    );
    let (_, update) = commit(root.unwrap()).await;
    let laptop = update
        .members()
        .iter()
        .find(|member| member.label.as_str() == "laptop")
        .unwrap();
    assert_eq!(
        laptop.node,
        key(PHONE),
        "the update's device keeps the name"
    );
    assert!(
        update.revoked_keys().contains(&key(LAPTOP)),
        "the copy's is revoked"
    );
}

#[tokio::test]
async fn a_rolled_back_state_renews_no_revoked_device() {
    let home = home("rolled-back");
    // Due: in the last half of its 60 days.
    let mut laptop = row(LAPTOP, "laptop", vec![id(LAPTOP, now() + 10 * DAY)]);
    laptop.until = now() + 10 * DAY;
    laptop.duration = 60 * DAY;
    holds(
        &home,
        &records(0, vec![own_row(), laptop], Vec::new(), Vec::new()),
    )
    .await;
    // Its devices revoked the laptop's key since this copy was made.
    held(
        &home,
        &RosterDoc::with_revocations(
            Epoch(1),
            vec![member(&own_row())],
            Vec::new(),
            vec![key(LAPTOP)],
        )
        .unwrap(),
    );
    let (_, out) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::refusing(),
    )
    .await;
    assert!(!out.contains("renewing"), "{out}");
}

#[tokio::test]
async fn a_revoked_key_survives_its_standings_expiry_in_the_update() {
    let home = home("key-survives");
    let mut gone = row(LAPTOP, "laptop", vec![id(LAPTOP, 1)]);
    gone.revoked_on = 1;
    holds(
        &home,
        &records(
            0,
            vec![own_row(), gone],
            vec![id(LAPTOP, 1)],
            vec![key(LAPTOP)],
        ),
    )
    .await;
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let (_, update) = commit(root.unwrap()).await;
    assert!(
        update.revoked().is_empty(),
        "an ended standing's id is not carried"
    );
    assert!(
        update.revoked_keys().contains(&key(LAPTOP)),
        "a revoked key is carried for good"
    );
}

#[tokio::test]
async fn a_root_act_never_publishes_a_devices_own_grant_revocations() {
    let home = home("own-grants");
    let later = now() + 10 * DAY;
    holds(
        &home,
        &records(
            0,
            vec![own_row(), row(LAPTOP, "laptop", vec![id(LAPTOP, later)])],
            Vec::new(),
            Vec::new(),
        ),
    )
    .await;
    // This machine revoked a link it signed, and the laptop's standing and key.
    let grant = RevocationId::from_bytes(vec![0x99; 64]);
    std::fs::write(
        home.revoked(),
        format!("{}\n{}\n", grant.to_hex(), id(LAPTOP, 0).id.to_hex()),
    )
    .unwrap();
    std::fs::write(
        home.revoked_keys(),
        format!(
            "{}\n{}\n",
            TestNode::seeded(PHONE).node_id(),
            TestNode::seeded(LAPTOP).node_id()
        ),
    )
    .unwrap();
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let (_, update) = commit(root.unwrap()).await;
    let revoked: Vec<String> = update
        .revoked()
        .iter()
        .map(|revoked| revoked.id.to_hex())
        .collect();
    assert_eq!(
        revoked,
        vec![id(LAPTOP, 0).id.to_hex()],
        "only the root's own device's id"
    );
    assert_eq!(update.revoked_keys(), &[key(LAPTOP)], "only a row's key");
}

// --- commit ---

#[tokio::test]
async fn a_commit_publishes_a_row_the_held_update_lacks() {
    let home = home("pending-row");
    holds(
        &home,
        &records(
            1,
            vec![own_row(), row(LAPTOP, "laptop", Vec::new())],
            Vec::new(),
            Vec::new(),
        ),
    )
    .await;
    held(
        &home,
        &RosterDoc::new(Epoch(1), vec![member(&own_row())]).unwrap(),
    );
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let (committed, update) = commit(root.unwrap()).await;
    assert_eq!(committed.number, Epoch(2));
    assert!(
        update
            .members()
            .iter()
            .any(|member| member.node == key(LAPTOP))
    );
    assert_eq!(committed.targets, vec![key(LAPTOP)]);
    assert_eq!(
        crate::roster::verify(
            &std::fs::read(home.roster()).unwrap(),
            TestRoot::seeded(ROOT).verify_key()
        )
        .unwrap()
        .epoch(),
        Epoch(2),
        "the cut is this machine's update now"
    );
}

// --- inspect, serve, and the process ---

#[tokio::test]
async fn inspect_never_unlocks() {
    let home = home("inspect");
    let records = records(3, vec![own_row()], Vec::new(), Vec::new());
    holds(&home, &records).await;
    // A write that stopped after `state.new`: inspect reads it and leaves it staged.
    let staged = home.root().join("state.new");
    std::fs::rename(home.root().join("state"), &staged).unwrap();
    // Another command holds the lock; inspect takes none.
    let _held = super::DirLock::take(&home.root()).unwrap();

    let inspected = Root::inspect(&home, RootPlace::Home).await.unwrap();
    assert_eq!(inspected.root, TestRoot::seeded(ROOT).node_id());
    assert_eq!(inspected.state, records);
    assert!(
        staged.exists() && !home.root().join("state").exists(),
        "inspect never promotes"
    );
}

#[test]
fn reaching_never_names_root() {
    let source = include_str!("reaching.rs");
    let named = source
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
        .any(|word| word == "Root" || word.contains("root::") || word.ends_with("::Root"));
    assert!(!named, "the dial path never reaches the root");
}

/// The child half of [`a_root_act_sets_rlimit_core_zero`]: a root act, then the limit it left.
#[tokio::test]
#[ignore = "run in its own process by a_root_act_sets_rlimit_core_zero"]
async fn rlimit_child() {
    let home = home("rlimit");
    let _ = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::refusing(),
    )
    .await;
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `limit` is a live, writable `rlimit` for the call to fill.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
}

#[test]
fn a_root_act_sets_rlimit_core_zero() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "root::root_tests::rlimit_child",
            "--include-ignored",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("1 passed"), "{stdout}");
}

// --- the review's fixes ---

/// A prompt with nobody at a terminal: every event fails.
struct NoTerminal(Counting);

impl Prompt for NoTerminal {
    fn terminal(&self) -> bool {
        false
    }

    fn unlock(&mut self, path: &Path) -> eyre::Result<Passphrase> {
        self.0.unlock(path)
    }

    fn choose(&mut self, path: &Path) -> eyre::Result<Passphrase> {
        self.0.choose(path)
    }
}

#[tokio::test]
async fn a_root_act_with_no_terminal_refuses_before_the_prompt() {
    let home = home("no-terminal");
    holds(&home, &records(0, vec![own_row()], Vec::new(), Vec::new())).await;
    let mut prompt = NoTerminal(Counting::new([PASS]));
    let (refused, _) = present(&home, RootPlace::Home, RootVerb::Invite, &mut prompt).await;
    let Err(refused) = refused else {
        panic!("no terminal, no root");
    };
    assert!(
        matches!(refused, RootError::NoTerminalToUnlock),
        "{refused:?}"
    );
    assert_eq!(
        refused.to_string(),
        "using your root asks for its passphrase, which needs a terminal: run this at one."
    );
    assert_eq!(prompt.0.events(), 0);
}

#[tokio::test]
async fn a_copy_that_is_only_read_never_promotes_its_staged_state() {
    let home = home("read-only-copy");
    let records = records(2, vec![own_row()], Vec::new(), Vec::new());
    let dir = beside(&home, "stick");
    copy(&dir, ROOT, &records);
    // A write that stopped after `state.new`, on a stick that cannot be written now.
    std::fs::rename(dir.join("state"), dir.join("state.new")).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (root, _) = present(
        &home,
        RootPlace::Dir(dir.clone()),
        RootVerb::Backup,
        &mut Counting::new([PASS]),
    )
    .await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = root.unwrap();
    assert_eq!(root.rows(), records.rows(), "it reads the staged records");
    assert!(
        dir.join("state.new").exists() && !dir.join("state").exists(),
        "a backup never writes its source"
    );
}

#[tokio::test]
async fn a_planted_probe_link_is_not_followed() {
    let home = home("probe-link");
    let dir = beside(&home, "copy");
    copy(
        &dir,
        ROOT,
        &records(0, vec![own_row()], Vec::new(), Vec::new()),
    );
    let target = beside(&home, "victim");
    std::fs::write(&target, b"keep me").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("lock.probe")).unwrap();
    let (root, _) = present(
        &home,
        RootPlace::Dir(dir.clone()),
        RootVerb::Lock,
        &mut Counting::new([PASS]),
    )
    .await;
    root.unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
    assert!(!dir.join("lock.probe").exists());
}

#[tokio::test]
async fn a_planted_lock_link_is_not_followed() {
    let home = home("lock-link");
    let dir = beside(&home, "copy");
    copy(
        &dir,
        ROOT,
        &records(0, vec![own_row()], Vec::new(), Vec::new()),
    );
    let target = beside(&home, "planted");
    let _ = std::fs::remove_file(&target);
    std::os::unix::fs::symlink(&target, dir.join("lock")).unwrap();
    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Dir(dir), RootVerb::Lock, &mut prompt).await;
    assert!(matches!(refused, Err(RootError::Io { .. })), "{refused:?}");
    assert!(!target.exists(), "the lock creates nothing through a link");
    assert_eq!(prompt.events(), 0);
}

#[tokio::test]
async fn the_first_invite_under_this_machines_name_moves_this_machine() {
    let home = home("mint-clash");
    let Minted::Made(mut root) = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink())
        .await
        .unwrap()
    else {
        panic!("an unpinned home makes a root");
    };
    let suggested = root
        .rows()
        .iter()
        .find(|row| row.key == key(OWN))
        .unwrap()
        .label
        .clone();
    root.sign_standing(
        key(LAPTOP),
        suggested.clone(),
        Duration::from_secs(90 * DAY),
    )
    .unwrap();
    let label = |root: &Root, seed: u8| {
        root.rows()
            .iter()
            .find(|row| row.key == key(seed))
            .unwrap()
            .label
            .to_string()
    };
    assert_eq!(
        label(&root, LAPTOP),
        suggested.to_string(),
        "the invited device keeps its name"
    );
    assert_eq!(
        label(&root, OWN),
        format!("{suggested}-2"),
        "this machine moves"
    );

    // Once the root has published, a name is taken for good.
    let _committed = root.commit_to(&mut io::sink()).await.unwrap();
    let own = name(&label(&root, OWN));
    let refused = root
        .sign_standing(key(PHONE), own, Duration::from_secs(90 * DAY))
        .unwrap_err();
    assert!(
        matches!(refused, RootError::NameTaken { .. }),
        "{refused:?}"
    );
}

#[tokio::test]
async fn the_device_refusals_print_their_lines() {
    let home = home("refusal-lines");
    let mut gone = row(LAPTOP, "laptop", Vec::new());
    gone.revoked_on = 86_400 * 20_000;
    holds(
        &home,
        &records(
            1,
            vec![own_row(), gone, row(PHONE, "phone", Vec::new())],
            Vec::new(),
            vec![key(LAPTOP), key(0x51)],
        ),
    )
    .await;
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let mut root = root.unwrap();
    let short = |seed: u8| key(seed).node_id().short();
    let days = Duration::from_secs(90 * DAY);

    let line = root.renew(&[name("nas")], None).unwrap_err().to_string();
    assert_eq!(
        line,
        "you have no device nas. For a machine with no console: swoosh invite nas --new-key. Otherwise: \
         swoosh invite nas <its key>."
    );
    let line = root.revoke_device(&name("nas")).unwrap_err().to_string();
    assert_eq!(line, "me/nas is not one of your devices (`swoosh status`)");

    let line = root
        .sign_standing(key(LAPTOP), name("new"), days)
        .unwrap_err()
        .to_string();
    assert_eq!(
        line,
        format!(
            "{}… was revoked on 2024-10-04; a revoked key is not re-admitted. On that machine: swoosh leave \
             --new-key, then invite the new key.",
            short(LAPTOP)
        )
    );
    let line = root
        .sign_standing(key(0x51), name("new"), days)
        .unwrap_err()
        .to_string();
    assert!(
        line.starts_with(&format!("{}… was revoked; ", short(0x51))),
        "no row, no date: {line}"
    );

    let line = root
        .sign_standing(key(OWN), name("new"), days)
        .unwrap_err()
        .to_string();
    assert_eq!(
        line,
        "that is this machine's key; it is already your device me/desk"
    );

    let line = root
        .sign_standing(key(0x61), name("phone"), days)
        .unwrap_err()
        .to_string();
    assert_eq!(
        line,
        format!(
            "me/phone is {}…. To replace it: swoosh revoke me/phone, then invite the new key.",
            short(PHONE)
        )
    );
}

/// A home holding a root that has revoked as many unexpired ids as one update carries, and a laptop with
/// one live id.
async fn full_revocations(tag: &str) -> Home {
    let home = home(tag);
    let later = now() + 10 * DAY;
    let full: Vec<Id> = (0..MAX_REVOKED)
        .map(|nth| {
            let mut bytes = vec![0xdd_u8; 64];
            bytes[..8].copy_from_slice(&(nth as u64).to_be_bytes());
            Id {
                expires: later,
                id: RevocationId::from_bytes(bytes),
            }
        })
        .collect();
    holds(
        &home,
        &records(
            0,
            vec![own_row(), row(LAPTOP, "laptop", vec![id(LAPTOP, later)])],
            full,
            Vec::new(),
        ),
    )
    .await;
    home
}

#[tokio::test]
async fn revoking_past_max_revoked_refuses_with_its_line() {
    let home = full_revocations("revoke-bound").await;
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Revoke,
        &mut Counting::new([PASS]),
    )
    .await;
    let mut root = root.unwrap();
    let refused = root.revoke_device(&name("laptop")).unwrap_err();
    assert!(
        matches!(refused, RootError::TooManyRevoked { count, .. } if count == MAX_REVOKED + 1),
        "{refused:?}"
    );
    assert!(
        root.rows().iter().all(|row| !row.is_revoked()),
        "nothing is revoked on a refusal"
    );
}

#[tokio::test]
async fn a_commit_over_a_bound_refuses_with_its_line() {
    let home = full_revocations("commit-bound").await;
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Revoke,
        &mut Counting::new([PASS]),
    )
    .await;
    let mut root = root.unwrap();
    let over = id(0x77, now() + 10 * DAY);
    root.act
        .book
        .revoked
        .insert(over.id.as_bytes().to_vec(), over);
    let refused = root.commit_to(&mut io::sink()).await.unwrap_err();
    assert!(
        matches!(refused, RootError::TooManyRevoked { .. }),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_fork_that_adds_nothing_prints_nothing() {
    let home = home("empty-fork");
    holds(&home, &records(1, vec![own_row()], Vec::new(), Vec::new())).await;
    let same = RosterDoc::new(Epoch(1), vec![member(&own_row())]).unwrap();
    held(&home, &same);
    std::fs::write(
        home.roster_fork(),
        TestRoot::seeded(ROOT).sign_update(&same),
    )
    .unwrap();
    let (_, out) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::refusing(),
    )
    .await;
    assert!(!out.contains("brought forward"), "{out}");
}
