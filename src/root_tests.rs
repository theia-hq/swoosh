//! `Root` over every check before the prompt, the mint and its interruptions, the bring-forward, and the
//! commit.
//!
//! Each home is built on disk the way the product leaves it: this machine's key, a pin, a standing the root
//! signed, and a sealed `root.key` beside the list of devices the root signed last, `devices`. A copy is a
//! directory holding the same two files. The sealed key is made once per process and copied, because
//! sealing is the slow part of a test here.
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

use bifrost::NodeId;
use keystore::{KeyFile, Passphrase, Protection, Stored};
use nauthy::{Revocation, RevocationId, VerifyKey};
use tightbeam::identity::AsVerifyKey as _;
use zeroize::Zeroizing;

use super::{Committed, MEANWHILE, Minted, Root, RootError, RootPlace, RootVerb, STOP, Seam};
use crate::codec::{Id, MAX_REVOKED, MAX_REVOKED_KEYS};
use crate::config;
use crate::contacts::DeviceLabel;
use crate::home::Home;
use crate::passphrase::{Asked, Choice, Prompt};
use crate::reach_report::{Missed, Reach, Why};
use crate::roster::{Epoch, Member, RevokedDevice, RosterDoc};
use crate::standing::Standing;
use crate::sync::{Answer, Dial, ExchangeError};
use crate::testkit::{Answering, Counting, Loopback, STANDING_UNTIL, TestNode, TestRoot};

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
/// A fourth.
const NAS: u8 = 0x43;
/// A device an act adds.
const TV: u8 = 0x44;

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

/// A live device `seed`, signed by `ROOT`, with `ids`.
fn row(seed: u8, label: &str, ids: Vec<Id>) -> Member {
    Member {
        node: key(seed),
        label: name(label),
        until: STANDING_UNTIL,
        duration: 90 * DAY,
        invite_until: 0,
        ids,
        standing: TestRoot::seeded(ROOT).standing(key(seed)).unwrap(),
    }
}

/// `row`, as an update lists it.
fn member(row: &Member) -> Member {
    row.clone()
}

/// This machine's own row.
fn own_row() -> Member {
    row(OWN, "desk", vec![id(OWN, STANDING_UNTIL)])
}

/// A list the root signs: update `last`, listing `rows`, revoking `revoked` and `keys`.
fn records(last: u64, rows: Vec<Member>, revoked: Vec<Id>, keys: Vec<VerifyKey>) -> RosterDoc {
    RosterDoc::with_revocations(
        Epoch(last),
        rows,
        revoked,
        keys.into_iter().map(crate::testkit::revoked).collect(),
    )
    .unwrap()
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
    crate::identity::make_machine_dir(&home).unwrap();
    KeyFile::device(home.key())
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

/// A copy of the root seeded `seed` at `dir`: its key, and `records` beside it as the list it signed last.
fn copy(dir: &Path, seed: u8, records: &RosterDoc) {
    config::create_store_dir(dir).unwrap();
    private(&dir.join("root.key"), &sealed(seed));
    std::fs::write(
        dir.join("devices"),
        TestRoot::seeded(seed).sign_update(records),
    )
    .unwrap();
}

/// Make `home` a device of the root seeded `seed`: its pin, and a standing that root signed for it.
async fn device_of(home: &Home, seed: u8) {
    let root = TestRoot::seeded(seed);
    config::write_signet(&crate::testkit::lock(), home, root.node_id()).unwrap();
    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL);
    let badge = root
        .device_badge(TestNode::seeded(OWN).node_id(), until)
        .unwrap();
    config::write_badge(&crate::testkit::lock(), home, &badge).unwrap();
}

/// Make `home` hold the root seeded `ROOT`: its key beside `records`, the home's own `devices`.
async fn holds(home: &Home, records: &RosterDoc) {
    device_of(home, ROOT).await;
    private(&home.root_key(), &sealed(ROOT));
    held(home, records);
}

/// Make `home` a device of the root seeded `ROOT` holding `held`, with a copy of that root at a directory
/// beside it holding `records`: the place to present it from.
async fn with_copy(home: &Home, records: &RosterDoc, held_here: &RosterDoc) -> RootPlace {
    device_of(home, ROOT).await;
    held(home, held_here);
    let dir = beside(home, "copy");
    let _ = std::fs::remove_dir_all(&dir);
    copy(&dir, ROOT, records);
    RootPlace::Dir(dir)
}

/// Write `doc`, signed by `ROOT`, as the update this home holds.
fn held(home: &Home, doc: &RosterDoc) {
    std::fs::write(home.devices(), TestRoot::seeded(ROOT).sign_update(doc)).unwrap();
}

/// Present, printing to a buffer: what it returned, and what it printed.
async fn present(
    home: &Home,
    place: RootPlace,
    verb: RootVerb,
    prompt: &mut impl Prompt,
) -> (Result<Root, RootError>, String) {
    let mut out = Vec::new();
    // Every device answers that it holds the same update, so an act that cuts brings forward from what
    // this home holds, as each test sets it up.
    let dial = Answering::with(Answer::Same);
    let root = Root::present_to(home, place, verb, prompt, &dial, &mut out).await;
    (root, String::from_utf8(out).unwrap())
}

/// Commit, and the update it cut as this home now holds it.
async fn commit(mut root: Root) -> (Committed, RosterDoc) {
    let committed = root.commit_to(&mut io::sink()).await.unwrap();
    let update =
        crate::roster::verify(&committed.bytes, TestRoot::seeded(ROOT).verify_key()).unwrap();
    (committed, update)
}

/// A device `seed` of the root seeded `ROOT` beside `home`, standing until `until` and holding `update`.
async fn sibling(home: &Home, seed: u8, until: u64, update: &RosterDoc) -> Home {
    let dir = beside(home, &format!("device-{seed}"));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).unwrap();
    let device = Home::resolve(Some(dir)).unwrap();
    let mut secret = TestNode::seeded(seed).seed();
    crate::identity::make_machine_dir(&device).unwrap();
    KeyFile::device(device.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    let root = TestRoot::seeded(ROOT);
    config::write_signet(&crate::testkit::lock(), &device, root.node_id()).unwrap();
    let badge = root
        .device_badge(
            TestNode::seeded(seed).node_id(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(until),
        )
        .unwrap();
    config::write_badge(&crate::testkit::lock(), &device, &badge).unwrap();
    crate::roster::fold(
        &crate::home::HomeWrite::take(&device).await.unwrap(),
        &device,
        &root.sign_update(update),
    )
    .await
    .unwrap();
    device
}

async fn standing(home: &Home) -> Standing {
    Standing::read(home).await.unwrap()
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
    match KeyFile::root(home.root_key()).load().unwrap() {
        Some(Stored::Locked(_)) => assert_eq!(
            crate::testkit::stored_key(&KeyFile::root(home.root_key())),
            root_key
        ),
        other => panic!("the root key is sealed, of the root kind: {other:?}"),
    }
    let badge = config::load_badge(&home).await.unwrap().unwrap();
    assert_eq!(
        badge.root(),
        root_key.verify_key().expect("a usable key"),
        "the standing roots at the new root"
    );
    assert!(matches!(standing(&home).await, Standing::HoldsRoot { pin, .. } if pin == root_key));
    let first = crate::roster::verify(
        &std::fs::read(home.devices()).unwrap(),
        root_key.verify_key().expect("a usable key"),
    )
    .unwrap();
    assert_eq!(first.epoch(), Epoch(1), "the mint's own list");
    assert_eq!(
        first
            .members()
            .iter()
            .map(|member| member.node)
            .collect::<Vec<_>>(),
        vec![key(OWN)],
        "listing only this machine"
    );

    root.sign_standing(key(LAPTOP), name("laptop"), Duration::from_secs(90 * DAY))
        .unwrap();
    let committed = root.commit_to(&mut io::sink()).await.unwrap();
    let update = crate::roster::verify(
        &committed.bytes,
        root_key.verify_key().expect("a usable key"),
    )
    .unwrap();
    assert_eq!(update.epoch(), Epoch(2));
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
async fn a_mint_stopped_after_its_list_finishes_without_a_prompt() {
    let home = home("mint-listed");
    STOP.set(Some(Seam::Listed));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());
    assert!(home.devices().exists() && !home.key_cert().exists() && !home.root_pub().exists());
    assert!(matches!(
        standing(&home).await,
        Standing::InterruptedMint { .. }
    ));

    // The finish the next `invite` runs: the list beside the key carries this machine's standing.
    let mut prompt = Counting::refusing();
    let finished = Root::mint_to(&home, &mut prompt, &mut io::sink())
        .await
        .unwrap();
    assert!(matches!(finished, Minted::Finished));
    assert_eq!(prompt.events(), 0, "no prompt once devices is written");
    let Standing::HoldsRoot { pin, .. } = standing(&home).await else {
        panic!("the mint finished");
    };
    let badge = config::load_badge(&home).await.unwrap().unwrap();
    let list = crate::roster::verify(
        &std::fs::read(home.devices()).unwrap(),
        pin.verify_key().expect("a usable key"),
    )
    .unwrap();
    assert_eq!(
        list.members()[0].standing.as_str(),
        badge.as_str(),
        "this machine's standing is the one its list carries"
    );
}

#[tokio::test]
async fn a_mint_killed_between_badge_and_pin_finishes_without_a_prompt() {
    let home = home("mint-badged");
    STOP.set(Some(Seam::Badged));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());
    assert!(home.key_cert().exists() && !home.root_pub().exists());
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
async fn an_interrupted_mint_with_no_list_prompts_once() {
    let home = home("mint-bare");
    STOP.set(Some(Seam::Keyed));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());
    assert!(home.root_key().exists() && !home.devices().exists());

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
    STOP.set(Some(Seam::Keyed));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());
    // A standing another root signed, left where this machine keeps its own.
    let foreign = TestRoot::seeded(OTHER).standing(key(OWN)).unwrap();
    config::write_badge(&crate::testkit::lock(), &home, &foreign).unwrap();

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
        pin.verify_key().expect("a usable key"),
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

    fn unlock(&mut self, asked: Asked<'_>) -> eyre::Result<Passphrase> {
        let _ = writeln!(self.0, "<prompt>");
        self.1.unlock(asked)
    }

    fn choose(&mut self, asked: Asked<'_>) -> eyre::Result<Choice> {
        let _ = writeln!(self.0, "<prompt>");
        self.1.choose(asked)
    }

    fn say(&mut self, line: &str) {
        self.1.say(line);
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
    let own = root.rows().iter().find(|row| row.node == key(OWN)).unwrap();
    let expected = format!(
        "This makes your root on this machine: a second key, not a machine, that vouches for all your devices.\n\
         It is locked with a passphrase, which you type whenever you add, renew or revoke a device.\n\
         <prompt>\n\
         made your root root:{}, kept on this machine, locked with a passphrase.\n\
         This machine is me/{} until {}. me/laptop can join until {}.\n\
         Back up your root now, off this disk: swoosh root backup <dir>\n\
         To keep it off this machine, back it up, then: swoosh root forget <dir>\n",
        crate::credential::short(&root.key()),
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
    crate::revoked::add(
        &crate::testkit::lock(),
        &latched,
        [Revocation::Key(TestRoot::seeded(ROOT).verify_key())],
    )
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

    // Step 7: records changed outside swoosh.
    std::fs::write(dir.join("devices"), b"not the root's records").unwrap();
    let (refused, _) = present(&device, RootPlace::Dir(dir), RootVerb::Invite, &mut prompt).await;
    assert!(matches!(refused, Err(RootError::Damaged { .. })));

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
    crate::revoked::add(
        &crate::testkit::lock(),
        &home,
        [Revocation::Key(TestRoot::seeded(ROOT).verify_key())],
    )
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
async fn a_tampered_list_is_refused_before_the_prompt() {
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
    let mut bytes = std::fs::read(dir.join("devices")).unwrap();
    let laptop = *key(LAPTOP).bytes();
    let at = bytes
        .windows(laptop.len())
        .position(|window| window == laptop)
        .unwrap();
    bytes[at..at + laptop.len()].copy_from_slice(key(PHONE).bytes());
    std::fs::write(dir.join("devices"), bytes).unwrap();

    let mut prompt = Counting::refusing();
    let (refused, _) = present(&home, RootPlace::Dir(dir), RootVerb::Invite, &mut prompt).await;
    assert!(
        matches!(refused, Err(RootError::Damaged { .. })),
        "{refused:?}"
    );
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
    std::fs::write(
        dir.join("devices"),
        TestRoot::seeded(ROOT).sign_update(&records(0, vec![own_row()], Vec::new(), Vec::new())),
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
async fn a_cut_at_max_revoked_keys_refuses_before_it_signs() {
    let home = home("max-keys");
    let full: Vec<VerifyKey> = (0..MAX_REVOKED_KEYS)
        .map(|nth| {
            let mut seed = [0xee_u8; 32];
            seed[..8].copy_from_slice(&(nth as u64).to_be_bytes());
            TestNode::from_seed(seed).verify_key()
        })
        .collect();
    let place = with_copy(
        &home,
        &records(0, vec![own_row()], Vec::new(), full),
        &RosterDoc::with_revocations(
            Epoch(1),
            vec![member(&own_row())],
            Vec::new(),
            vec![crate::testkit::revoked(key(LAPTOP))],
        )
        .unwrap(),
    )
    .await;
    // The prompt comes before the records are brought forward, so the bound refuses after it.
    let mut prompt = Counting::new([PASS]);
    let (refused, _) = present(&home, place, RootVerb::Revoke, &mut prompt).await;
    assert!(
        matches!(refused, Err(RootError::TooManyKeys { count }) if count == MAX_REVOKED_KEYS + 1),
        "{refused:?}"
    );
    assert_eq!(prompt.events(), 1);
}

#[tokio::test]
async fn update_number_overflow_refuses() {
    let home = home("overflow");
    holds(
        &home,
        &records(u64::MAX, vec![own_row()], Vec::new(), Vec::new()),
    )
    .await;
    let mut prompt = Counting::new([PASS]);
    let (refused, _) = present(&home, RootPlace::Home, RootVerb::Invite, &mut prompt).await;
    assert!(matches!(refused, Err(RootError::Exhausted)), "{refused:?}");
    assert_eq!(prompt.events(), 1);
}

// --- bring forward ---

/// A device holding an update that renews the laptop a fifth time, with a copy of the root whose list
/// gives the laptop four live ids: the home, and the copy.
async fn fifth_id(tag: &str) -> (Home, RootPlace) {
    let home = home(tag);
    let later = now() + 10 * DAY;
    let four = (1..=4).map(|nth| id(nth, later + u64::from(nth))).collect();
    let mut renewed = row(LAPTOP, "laptop", vec![id(5, later + 5)]);
    renewed.until = STANDING_UNTIL + 1;
    let place = with_copy(
        &home,
        &records(
            1,
            vec![own_row(), row(LAPTOP, "laptop", four)],
            Vec::new(),
            Vec::new(),
        ),
        &RosterDoc::new(Epoch(2), vec![member(&own_row()), member(&renewed)]).unwrap(),
    )
    .await;
    (home, place)
}

#[tokio::test]
async fn bring_forward_revokes_a_fifth_live_id_it_cannot_keep() {
    let (home, place) = fifth_id("fifth-revoked").await;
    let (root, out) = present(&home, place, RootVerb::Invite, &mut Counting::new([PASS])).await;
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
    let (home, place) = fifth_id("fifth-kept").await;
    let (root, _) = present(&home, place, RootVerb::Invite, &mut Counting::new([PASS])).await;
    let (_, update) = commit(root.unwrap()).await;
    assert!(
        update
            .members()
            .iter()
            .any(|member| member.node == key(LAPTOP))
    );
    assert!(!update.is_revoked_key(&key(LAPTOP)));
}

#[tokio::test]
async fn bring_forward_keeps_a_devices_duration() {
    let home = home("duration");
    let mut phone = row(PHONE, "phone", Vec::new());
    phone.duration = 60 * DAY;
    let place = with_copy(
        &home,
        &records(0, vec![own_row()], Vec::new(), Vec::new()),
        &RosterDoc::new(Epoch(1), vec![member(&own_row()), member(&phone)]).unwrap(),
    )
    .await;
    let (root, _) = present(&home, place, RootVerb::Invite, &mut Counting::new([PASS])).await;
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
    let place = with_copy(
        &home,
        &records(1, vec![own_row()], Vec::new(), Vec::new()),
        &RosterDoc::new(Epoch(1), vec![member(&own_row())]).unwrap(),
    )
    .await;
    let (_, out) = present(
        &home,
        place.clone(),
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    assert!(!out.contains("brought forward"), "{out}");

    held(
        &home,
        &RosterDoc::new(Epoch(2), vec![member(&own_row())]).unwrap(),
    );
    let (_, out) = present(&home, place, RootVerb::Invite, &mut Counting::new([PASS])).await;
    assert!(
        out.contains("brought forward"),
        "a copy behind its devices says so: {out}"
    );
}

#[tokio::test]
async fn bring_forward_never_takes_devices_from_the_copy_over_the_update() {
    let home = home("update-wins");
    let theirs = row(PHONE, "laptop", Vec::new());
    let place = with_copy(
        &home,
        &records(
            0,
            vec![own_row(), row(LAPTOP, "laptop", Vec::new())],
            Vec::new(),
            Vec::new(),
        ),
        &RosterDoc::new(Epoch(1), vec![member(&own_row()), member(&theirs)]).unwrap(),
    )
    .await;
    let (root, out) = present(&home, place, RootVerb::Invite, &mut Counting::new([PASS])).await;
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
    assert!(update.is_revoked_key(&key(LAPTOP)), "the copy's is revoked");
}

#[tokio::test]
async fn a_rolled_back_copy_renews_no_revoked_device() {
    let home = home("rolled-back");
    // Due: in the last half of its 60 days.
    let mut laptop = row(LAPTOP, "laptop", vec![id(LAPTOP, now() + 10 * DAY)]);
    laptop.until = now() + 10 * DAY;
    laptop.duration = 60 * DAY;
    // Its devices revoked the laptop's key since this copy was made.
    let place = with_copy(
        &home,
        &records(0, vec![own_row(), laptop], Vec::new(), Vec::new()),
        &RosterDoc::with_revocations(
            Epoch(1),
            vec![member(&own_row())],
            Vec::new(),
            vec![crate::testkit::revoked(key(LAPTOP))],
        )
        .unwrap(),
    )
    .await;
    let (_, out) = present(&home, place, RootVerb::Invite, &mut Counting::refusing()).await;
    assert!(!out.contains("renewing"), "{out}");
}

/// A revoked device's name rides with its key: a device folds the update another copy of the root cut
/// revoking the laptop, and a copy behind it, brought forward from what the device holds, signs that name
/// on with the key. The other copy had renamed it, so the name signed is the update's, not the copy's row.
#[tokio::test]
async fn a_revoked_devices_name_survives_a_fold_and_a_bring_forward() {
    let home = home("revoked-name-forward");
    let laptop = row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]);
    let gone = RevokedDevice {
        node: key(LAPTOP),
        label: name("work-laptop"),
    };
    let behind = records(1, vec![own_row(), laptop], Vec::new(), Vec::new());
    let place = with_copy(&home, &behind, &behind).await;
    let elsewhere = RosterDoc::with_revocations(
        Epoch(2),
        vec![member(&own_row())],
        Vec::new(),
        vec![gone.clone()],
    )
    .unwrap();
    crate::roster::fold(
        &crate::home::HomeWrite::take(&home).await.unwrap(),
        &home,
        &TestRoot::seeded(ROOT).sign_update(&elsewhere),
    )
    .await
    .unwrap();
    let folded = crate::roster::held(&home, TestRoot::seeded(ROOT).verify_key()).unwrap();
    assert_eq!(
        folded.revoked_devices(),
        core::slice::from_ref(&gone),
        "the fold keeps the name"
    );

    let (root, _) = present(&home, place, RootVerb::Invite, &mut Counting::new([PASS])).await;
    let mut root = root.unwrap();
    root.sign_standing(key(TV), name("tv"), Duration::from_secs(90 * DAY))
        .unwrap();
    let (_, update) = commit(root).await;
    assert_eq!(
        update.revoked_devices(),
        [gone],
        "the copy brought forward signs the name on"
    );
}

#[tokio::test]
async fn a_revoked_key_survives_its_standings_expiry_in_the_update() {
    let home = home("key-survives");
    holds(
        &home,
        &records(1, vec![own_row()], vec![id(LAPTOP, 1)], vec![key(LAPTOP)]),
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
    root.sign_standing(key(TV), name("tv"), Duration::from_secs(90 * DAY))
        .unwrap();
    let (_, update) = commit(root).await;
    assert!(
        update.revoked().is_empty(),
        "an ended standing's id is not carried"
    );
    assert!(
        update.is_revoked_key(&key(LAPTOP)),
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
    crate::revoked::add(
        &crate::testkit::lock(),
        &home,
        [
            Revocation::Id(grant),
            Revocation::Id(id(LAPTOP, 0).id),
            Revocation::Key(key(PHONE)),
            Revocation::Key(key(LAPTOP)),
        ],
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
    assert_eq!(
        update.revoked_keys().collect::<Vec<_>>(),
        [key(LAPTOP)],
        "only a row's key"
    );
}

// --- commit ---

#[tokio::test]
async fn a_commit_publishes_a_row_the_held_update_lacks() {
    let home = home("pending-row");
    let place = with_copy(
        &home,
        &records(
            1,
            vec![own_row(), row(LAPTOP, "laptop", Vec::new())],
            Vec::new(),
            Vec::new(),
        ),
        &RosterDoc::new(Epoch(1), vec![member(&own_row())]).unwrap(),
    )
    .await;
    let (root, _) = present(&home, place, RootVerb::Invite, &mut Counting::new([PASS])).await;
    let (committed, update) = commit(root.unwrap()).await;
    assert_eq!(committed.number, Epoch(2));
    assert!(
        update
            .members()
            .iter()
            .any(|member| member.node == key(LAPTOP))
    );
    assert_eq!(
        committed
            .targets
            .iter()
            .map(|device| device.key)
            .collect::<Vec<_>>(),
        vec![TestNode::seeded(LAPTOP).node_id()]
    );
    assert_eq!(
        crate::roster::verify(
            &std::fs::read(home.devices()).unwrap(),
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
    // Another command holds the home's lock; inspect takes none.
    let _held = crate::home::HomeWrite::take(&home).await.unwrap();

    let inspected = Root::inspect(&home, RootPlace::Home).await.unwrap();
    assert_eq!(inspected.root, TestRoot::seeded(ROOT).node_id());
    assert_eq!(inspected.rows(), records.members());
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

    fn unlock(&mut self, asked: Asked<'_>) -> eyre::Result<Passphrase> {
        self.0.unlock(asked)
    }

    fn choose(&mut self, asked: Asked<'_>) -> eyre::Result<Choice> {
        self.0.choose(asked)
    }

    fn say(&mut self, line: &str) {
        self.0.say(line);
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
        .find(|row| row.node == key(OWN))
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
            .find(|row| row.node == key(seed))
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
    holds(
        &home,
        &records(
            2,
            vec![own_row(), row(PHONE, "phone", Vec::new())],
            Vec::new(),
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
    let mut root = root.unwrap();
    let short = |seed: u8| crate::credential::short(&key(seed));
    let days = Duration::from_secs(90 * DAY);

    let line = root.renew(&[name("nas")], None).unwrap_err().to_string();
    assert_eq!(
        line,
        "you have no device nas. For a machine with no console: swoosh invite nas --new-key. Otherwise: \
         swoosh invite nas <its key>."
    );
    let line = root
        .revoke_device(&name("nas"), key(NAS), &[])
        .unwrap_err()
        .to_string();
    assert_eq!(line, "me/nas is not one of your devices (`swoosh status`)");

    let line = root
        .sign_standing(key(LAPTOP), name("new"), days)
        .unwrap_err()
        .to_string();
    assert_eq!(
        line,
        format!(
            "{} was me/gone's key and is revoked; a revoked key is not re-admitted. Give that machine a \
             new key and invite that one. On that machine: swoosh leave --new-key",
            short(LAPTOP)
        )
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
            "me/phone is {}. To replace it: swoosh revoke me/phone, then invite the new key.",
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
    let refused = root
        .revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap_err();
    assert!(
        matches!(refused, RootError::TooManyRevoked { count, .. } if count == MAX_REVOKED + 1),
        "{refused:?}"
    );
    assert!(
        root.rows().iter().any(|row| row.node == key(LAPTOP)),
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
    let same = RosterDoc::new(Epoch(1), vec![member(&own_row())]).unwrap();
    holds(&home, &same).await;
    std::fs::write(
        home.devices_conflict(),
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

/// A copy at 3 whose `runner` is the nas takes a fork at 2 passed on in an exchange: cut when `runner`
/// was the laptop, revoking the phone. The laptop was revoked and the name reused (`reused`), or its row
/// moved to the nas key. Then it invites `tv` and commits.
#[tokio::test]
async fn a_fork_below_the_held_update_brings_forward_only_its_revocations() {
    for reused in [true, false] {
        let home = home(if reused {
            "stale-fork-reused"
        } else {
            "stale-fork-rekeyed"
        });
        let old = row(LAPTOP, "runner", vec![id(LAPTOP, STANDING_UNTIL)]);
        let new = row(NAS, "runner", vec![id(NAS, STANDING_UNTIL)]);
        let keys = if reused {
            vec![key(LAPTOP)]
        } else {
            Vec::new()
        };
        holds(
            &home,
            &records(3, vec![own_row(), new.clone()], Vec::new(), keys),
        )
        .await;
        let fork = RosterDoc::with_revocations(
            Epoch(2),
            vec![member(&own_row()), member(&old)],
            Vec::new(),
            vec![crate::testkit::revoked(key(PHONE))],
        )
        .unwrap();
        crate::roster::fold_fork(
            &crate::home::HomeWrite::take(&home).await.unwrap(),
            &home,
            &TestRoot::seeded(ROOT).sign_update(&fork),
        )
        .await
        .unwrap();
        let (root, out) = present(
            &home,
            RootPlace::Home,
            RootVerb::Invite,
            &mut Counting::new([PASS]),
        )
        .await;
        let mut root = root.unwrap();
        root.sign_standing(key(TV), name("tv"), Duration::from_secs(90 * DAY))
            .unwrap();
        let (_, update) = commit(root).await;

        assert!(
            !out.contains("was also added on another copy of your root"),
            "reused {reused}: {out}"
        );
        assert!(
            update.is_revoked_key(&key(PHONE)),
            "reused {reused}: the fork's revocation is brought forward"
        );
        assert!(
            !update.is_revoked_key(&key(NAS)),
            "reused {reused}: the device under the name now keeps it"
        );
        let runner: Vec<_> = update
            .members()
            .iter()
            .filter(|member| member.label.as_str() == "runner")
            .map(|member| member.node)
            .collect();
        assert_eq!(runner, vec![key(NAS)], "reused {reused}");
    }
}

/// A device holds update 3, where `runner` is the laptop, and keeps a fork at 3 passed on in an exchange.
/// A copy of the root at 5, whose `runner` is the nas, is presented from a dir: the laptop was revoked and
/// the name reused (`reused`), or its row moved to the nas key. The held update revokes the phone, the fork
/// the tv. Then it invites `other` and commits.
#[tokio::test]
async fn a_held_update_below_the_records_brings_forward_only_its_revocations() {
    for reused in [true, false] {
        let home = home(if reused {
            "stale-held-reused"
        } else {
            "stale-held-rekeyed"
        });
        device_of(&home, ROOT).await;
        let old = row(LAPTOP, "runner", vec![id(LAPTOP, STANDING_UNTIL)]);
        let new = row(NAS, "runner", vec![id(NAS, STANDING_UNTIL)]);
        let keys = if reused {
            vec![key(LAPTOP)]
        } else {
            Vec::new()
        };
        let dir = beside(&home, "copy");
        copy(
            &dir,
            ROOT,
            &records(5, vec![own_row(), new.clone()], Vec::new(), keys),
        );
        held(
            &home,
            &RosterDoc::with_revocations(
                Epoch(3),
                vec![member(&own_row()), member(&old)],
                Vec::new(),
                vec![crate::testkit::revoked(key(PHONE))],
            )
            .unwrap(),
        );
        let fork = RosterDoc::with_revocations(
            Epoch(3),
            vec![member(&own_row()), member(&old)],
            Vec::new(),
            vec![crate::testkit::revoked(key(TV))],
        )
        .unwrap();
        crate::roster::fold_fork(
            &crate::home::HomeWrite::take(&home).await.unwrap(),
            &home,
            &TestRoot::seeded(ROOT).sign_update(&fork),
        )
        .await
        .unwrap();
        assert!(
            home.devices_conflict().exists(),
            "reused {reused}: a fork is kept"
        );
        let (root, out) = present(
            &home,
            RootPlace::Dir(dir),
            RootVerb::Invite,
            &mut Counting::new([PASS]),
        )
        .await;
        let mut root = root.unwrap();
        root.sign_standing(key(OTHER), name("other"), Duration::from_secs(90 * DAY))
            .unwrap();
        let (committed, update) = commit(root).await;

        assert_eq!(committed.number, Epoch(6), "reused {reused}");
        assert!(
            !out.contains("was also added on another copy of your root"),
            "reused {reused}: {out}"
        );
        assert!(
            update.is_revoked_key(&key(PHONE)),
            "reused {reused}: the held update's revocation is brought forward"
        );
        assert!(
            update.is_revoked_key(&key(TV)),
            "reused {reused}: the fork's revocation is brought forward"
        );
        assert!(
            !update.is_revoked_key(&key(NAS)),
            "reused {reused}: the device under the name now keeps it"
        );
        let runner: Vec<_> = update
            .members()
            .iter()
            .filter(|member| member.label.as_str() == "runner")
            .map(|member| member.node)
            .collect();
        assert_eq!(runner, vec![key(NAS)], "reused {reused}");
    }
}

#[tokio::test]
async fn a_revocation_only_cut_advances_the_number() {
    let home = home("revocation-only");
    let laptop = row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]);
    let rows = vec![own_row(), laptop.clone()];
    holds(&home, &records(1, rows, vec![], vec![])).await;

    let mut prompt = Counting::new([PASS]);
    let (root, _) = present(&home, RootPlace::Home, RootVerb::Revoke, &mut prompt).await;
    let mut root = root.unwrap();
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();
    let (committed, update) = commit(root).await;

    assert_eq!(
        committed.number,
        Epoch(2),
        "a revoke alone moves the number"
    );
    assert!(update.is_revoked_key(&key(LAPTOP)));
}

#[tokio::test]
async fn revoking_a_device_by_its_key_never_takes_the_live_device_of_its_name() {
    let home = home("revoke-by-key");
    // The copy names the laptop me/nas; the list held here, cut since, gives the name to the phone.
    let old = row(LAPTOP, "nas", vec![id(LAPTOP, STANDING_UNTIL)]);
    let new = row(PHONE, "nas", vec![id(PHONE, STANDING_UNTIL)]);
    let place = with_copy(
        &home,
        &records(1, vec![own_row(), old], Vec::new(), Vec::new()),
        &records(2, vec![own_row(), new], Vec::new(), vec![key(LAPTOP)]),
    )
    .await;
    let mut prompt = Counting::new([PASS]);
    let (root, _) = present(&home, place, RootVerb::Revoke, &mut prompt).await;
    let mut root = root.unwrap();
    root.revoke_device(&name("nas"), key(LAPTOP), &[key(PHONE)])
        .unwrap();
    let (_, update) = commit(root).await;
    assert!(
        !update.is_revoked_key(&key(PHONE)),
        "the device now named nas stays one of your devices"
    );
    assert!(
        update
            .members()
            .iter()
            .any(|member| member.node == key(PHONE)),
        "and stays listed"
    );
}

// --- the exchange before a cut ---

#[tokio::test]
async fn a_cutting_act_that_cannot_list_your_devices_says_it_could_not_check() {
    let home = home("unlisted");
    let laptop = row(LAPTOP, "laptop", Vec::new());
    holds(
        &home,
        &records(1, vec![own_row(), laptop], Vec::new(), Vec::new()),
    )
    .await;
    std::fs::write(home.contacts(), "not = [an address book").unwrap();

    let log = Log::default();
    let mut prompt = Marking(log.clone(), Counting::new([PASS]));
    let dial = Answering::with(Answer::Same);
    let root = Root::present_to(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut prompt,
        &dial,
        &mut log.clone(),
    )
    .await;

    assert!(root.is_ok(), "the act goes on from what is held here");
    assert_eq!(dial.calls(), 0, "no device could be listed to ask");
    assert_eq!(
        String::from_utf8(log.0.borrow().clone()).unwrap(),
        "<prompt>\n\
         could not check this root against your devices (last synced never). If another copy of it has \
         been used since, a device will report two copies.\n",
        "the line prints after the prompt, which comes before the sync"
    );
}

#[tokio::test]
async fn a_device_that_missed_its_renewal_update_gets_it_from_the_next() {
    let home = home("missed-renewal");
    // me/laptop's standing ends in ten days, and was signed eighty days ago.
    let ends = now() + 10 * DAY;
    let laptop = Member {
        until: ends,
        ids: vec![id(LAPTOP, ends)],
        ..row(LAPTOP, "laptop", Vec::new())
    };
    let phone = row(PHONE, "phone", vec![id(PHONE, STANDING_UNTIL)]);
    let rows = vec![own_row(), laptop, phone];
    let first = records(1, rows, Vec::new(), Vec::new());
    holds(&home, &first).await;

    // me/laptop, a device of the same root holding the first update and its standing.
    let device = sibling(&home, LAPTOP, ends, &first).await;

    // One act renews me/laptop; its update never reaches it.
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let mut root = root.unwrap();
    let renewed = root.renew(&[name("laptop")], None).unwrap();
    assert_eq!(renewed.renewed.len(), 1, "me/laptop is renewed");
    let renewed_until = renewed.renewed[0].until;
    let (missed, _) = commit(root).await;
    assert_eq!(missed.number, Epoch(2));

    // The next act only revokes me/phone.
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Revoke,
        &mut Counting::new([PASS]),
    )
    .await;
    let mut root = root.unwrap();
    root.revoke_device(&name("phone"), key(PHONE), &[]).unwrap();
    let (next, _) = commit(root).await;
    assert_eq!(next.number, Epoch(3));

    crate::roster::fold(
        &crate::home::HomeWrite::take(&device).await.unwrap(),
        &device,
        &next.bytes,
    )
    .await
    .unwrap();
    let badge = config::load_badge(&device).await.unwrap().unwrap();
    assert_eq!(
        badge.cap().expiry().unwrap(),
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(renewed_until)),
        "me/laptop takes its renewed standing from the next update"
    );
}

// --- the offer ---

/// Each device answers as scripted, by key; any other does not answer.
struct Scripted(Vec<(u8, Answer)>);

impl Dial for Scripted {
    async fn exchange(&self, peer: NodeId) -> Result<Answer, ExchangeError> {
        self.0
            .iter()
            .find(|(seed, _)| TestNode::seeded(*seed).node_id() == peer)
            .map(|(_, answer)| *answer)
            .ok_or_else(|| eyre::eyre!("no device answers").into())
    }
    async fn offer(
        &self,
        peer: NodeId,
        _number: Epoch,
        _bytes: &[u8],
    ) -> Result<Answer, ExchangeError> {
        self.exchange(peer).await
    }
}

/// This home holding the root with this machine and the devices `others` (seed, name) at update 1: the
/// update it holds, and the root presented to revoke.
async fn revoking(tag: &str, others: &[(u8, &str)]) -> (Home, RosterDoc, Root) {
    let home = home(tag);
    let mut rows = vec![own_row()];
    rows.extend(
        others
            .iter()
            .map(|(seed, label)| row(*seed, label, vec![id(*seed, STANDING_UNTIL)])),
    );
    let first = records(1, rows, Vec::new(), Vec::new());
    holds(&home, &first).await;
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Revoke,
        &mut Counting::new([PASS]),
    )
    .await;
    (home, first, root.unwrap())
}

fn silent(label: &str) -> Missed {
    Missed {
        name: format!("me/{label}"),
        why: Why::Silent,
    }
}

#[tokio::test]
async fn a_cut_from_a_non_serving_device_is_offered() {
    let (home, first, mut root) = revoking("offered", &[(LAPTOP, "laptop"), (NAS, "nas")]).await;
    let nas = sibling(&home, NAS, STANDING_UNTIL, &first).await;
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();
    let (committed, _) = commit(root).await;
    assert!(
        !crate::revoked::open(&nas)
            .unwrap()
            .is_revoked_key(&key(LAPTOP)),
        "before the offer, me/nas still admits me/laptop"
    );

    let dial = Loopback::new(
        home.clone(),
        [(TestNode::seeded(NAS).node_id(), nas.clone())],
    );
    let reach = committed.offer(&dial).await;

    assert!(
        crate::revoked::open(&nas)
            .unwrap()
            .is_revoked_key(&key(LAPTOP)),
        "me/nas blocks the revoked device"
    );
    assert_eq!(
        reach,
        Reach::Published {
            took: vec!["me/nas".to_owned()],
            missed: Vec::new(),
            until: Some(STANDING_UNTIL),
        }
    );
}

#[tokio::test]
async fn reach_says_held_when_no_device_took_it_and_nothing_serves() {
    let (_home, _, mut root) = revoking("held", &[(LAPTOP, "laptop"), (PHONE, "phone")]).await;
    root.revoke_device(&name("phone"), key(PHONE), &[]).unwrap();
    let (committed, _) = commit(root).await;

    let reach = committed.offer(&Answering::nobody()).await;

    assert_eq!(
        reach,
        Reach::Held {
            missed: vec![silent("laptop")],
            until: Some(STANDING_UNTIL),
        }
    );
}

#[tokio::test]
async fn reach_says_published_while_this_machine_serves() {
    let (home, _, mut root) = revoking("serving", &[(LAPTOP, "laptop"), (PHONE, "phone")]).await;
    root.revoke_device(&name("phone"), key(PHONE), &[]).unwrap();
    let (committed, _) = commit(root).await;
    let _serving = crate::testkit::serving(&home, None);

    let reach = committed.offer(&Answering::nobody()).await;

    assert_eq!(
        reach,
        Reach::Published {
            took: Vec::new(),
            missed: vec![silent("laptop")],
            until: Some(STANDING_UNTIL),
        },
        "this machine serves the cut to a device that asks"
    );
}

#[tokio::test]
async fn a_cut_below_the_fleet_floor_reports_behind() {
    let (home, first, mut root) = revoking("behind", &[(LAPTOP, "laptop"), (NAS, "nas")]).await;
    // me/nas already holds a later list than the one this copy of the root cuts.
    let later = RosterDoc::new(Epoch(5), first.members().to_vec()).unwrap();
    let nas = sibling(&home, NAS, STANDING_UNTIL, &later).await;
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();
    let (committed, _) = commit(root).await;
    assert_eq!(committed.number, Epoch(2));

    let dial = Loopback::new(home.clone(), [(TestNode::seeded(NAS).node_id(), nas)]);
    assert_eq!(committed.offer(&dial).await, Reach::Behind);
}

#[tokio::test]
async fn the_offer_skips_revoked_keys_and_new_devices() {
    let home = home("skips");
    let rows = vec![
        own_row(),
        row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]),
    ];
    holds(&home, &records(1, rows, Vec::new(), vec![key(PHONE)])).await;
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let mut root = root.unwrap();
    root.sign_standing(key(TV), name("tv"), Duration::from_secs(90 * DAY))
        .unwrap();
    let (committed, _) = commit(root).await;

    let dial = Loopback::new(home.clone(), []);
    let _reach = committed.offer(&dial).await;

    assert_eq!(
        dial.dialed(),
        vec![TestNode::seeded(LAPTOP).node_id()],
        "only me/laptop: never the revoked me/phone, the new me/tv, or this machine"
    );
}

#[tokio::test]
async fn an_offer_to_a_machine_that_is_not_a_device_is_not_taken() {
    let (home, first, mut root) =
        revoking("not-a-device", &[(LAPTOP, "laptop"), (NAS, "nas")]).await;
    // me/nas left: it holds no pin and no standing, and takes nothing.
    let nas = sibling(&home, NAS, STANDING_UNTIL, &first).await;
    std::fs::remove_file(nas.key_cert()).unwrap();
    std::fs::remove_file(nas.root_pub()).unwrap();
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();
    let (committed, _) = commit(root).await;

    let dial = Loopback::new(home.clone(), [(TestNode::seeded(NAS).node_id(), nas)]);
    assert_eq!(
        committed.offer(&dial).await,
        Reach::Held {
            missed: vec![silent("nas")],
            until: Some(STANDING_UNTIL),
        },
        "a machine that took nothing is never counted as having it"
    );
}

#[tokio::test]
async fn an_offer_after_a_newer_fold_reports_behind() {
    let (home, first, mut root) = revoking("newer-fold", &[(LAPTOP, "laptop"), (NAS, "nas")]).await;
    let nas = sibling(&home, NAS, STANDING_UNTIL, &first).await;
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();
    let (committed, _) = commit(root).await;
    assert_eq!(committed.number, Epoch(2));

    // Before the offer runs, this machine folds a later list from another copy of the root, one that does
    // not carry this act's revocation, and me/nas holds it too.
    let later = TestRoot::seeded(ROOT)
        .sign_update(&RosterDoc::new(Epoch(3), first.members().to_vec()).unwrap());
    crate::roster::fold(
        &crate::home::HomeWrite::take(&home).await.unwrap(),
        &home,
        &later,
    )
    .await
    .unwrap();
    crate::roster::fold(
        &crate::home::HomeWrite::take(&nas).await.unwrap(),
        &nas,
        &later,
    )
    .await
    .unwrap();

    let dial = Loopback::new(home.clone(), [(TestNode::seeded(NAS).node_id(), nas)]);
    assert_eq!(
        committed.offer(&dial).await,
        Reach::Behind,
        "me/nas holding the later list does not hold this cut"
    );
}

#[tokio::test]
async fn a_forked_offer_reports_behind() {
    // me/nas recorded the cut as a fork of its own list at that number.
    let (_home, _, mut root) = revoking("fork-recorded", &[(LAPTOP, "laptop"), (NAS, "nas")]).await;
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();
    let (committed, _) = commit(root).await;
    let dial = Scripted(vec![(NAS, Answer::ForkRecorded { floor: Epoch(2) })]);
    assert_eq!(committed.offer(&dial).await, Reach::Behind);

    // me/nas holds another list at the cut's number, and sends it back.
    let (home, first, mut root) = revoking("forked", &[(LAPTOP, "laptop"), (NAS, "nas")]).await;
    let nas = sibling(&home, NAS, STANDING_UNTIL, &first).await;
    let other = RosterDoc::with_revocations(
        Epoch(2),
        first.members().to_vec(),
        vec![id(OTHER, STANDING_UNTIL)],
        Vec::new(),
    )
    .unwrap();
    crate::roster::fold(
        &crate::home::HomeWrite::take(&nas).await.unwrap(),
        &nas,
        &TestRoot::seeded(ROOT).sign_update(&other),
    )
    .await
    .unwrap();
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();
    let (committed, _) = commit(root).await;
    let dial = Loopback::new(home.clone(), [(TestNode::seeded(NAS).node_id(), nas)]);
    assert_eq!(committed.offer(&dial).await, Reach::Behind);
}

/// A prompt that, while a root act waits at it, has this home fold `bytes`, as an exchange answered by this
/// machine's `serve` would: on a thread of its own, taking `home.lock` itself. The fold must finish while the
/// prompt is up; one that cannot, because the act holds `home.lock` across its prompt, is given up on after
/// a bound and recorded as `None`, so the test fails rather than hangs.
struct FoldingPrompt {
    home: Home,
    bytes: Vec<u8>,
    folded: Option<crate::roster::Folded>,
}

impl FoldingPrompt {
    fn new(home: &Home, update: &RosterDoc) -> Self {
        Self {
            home: home.clone(),
            bytes: TestRoot::seeded(ROOT).sign_update(update),
            folded: None,
        }
    }
}

impl Prompt for FoldingPrompt {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, _asked: Asked<'_>) -> eyre::Result<Passphrase> {
        let (home, bytes) = (self.home.clone(), self.bytes.clone());
        let (folded, fold) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let done = runtime.block_on(async {
                let home_lock = crate::home::HomeWrite::take(&home).await.unwrap();
                crate::roster::fold(&home_lock, &home, &bytes)
                    .await
                    .unwrap()
            });
            let _ = folded.send(done);
        });
        self.folded = fold.recv_timeout(Duration::from_secs(10)).ok();
        crate::passphrase::passphrase(Zeroizing::new(PASS.to_owned()))
    }

    fn choose(&mut self, _asked: Asked<'_>) -> eyre::Result<Choice> {
        eyre::bail!("nothing is chosen here")
    }

    fn say(&mut self, _line: &str) {}
}

/// The list another copy of the root cut at update 2: the act's devices, and one more revoked id.
fn cut_elsewhere(first: &RosterDoc) -> RosterDoc {
    RosterDoc::with_revocations(
        Epoch(2),
        first.members().to_vec(),
        vec![id(OTHER, STANDING_UNTIL)],
        Vec::new(),
    )
    .unwrap()
}

/// This home holding the root with this machine, me/laptop and me/nas at update 1, presented to revoke
/// with `prompt`; and the update it held.
async fn presented_with(tag: &str, prompt: &mut impl Prompt) -> (Home, RosterDoc, Root) {
    let home = home(tag);
    let rows = vec![
        own_row(),
        row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]),
        row(NAS, "nas", vec![id(NAS, STANDING_UNTIL)]),
    ];
    let first = records(1, rows, Vec::new(), Vec::new());
    holds(&home, &first).await;
    let (root, _) = present(&home, RootPlace::Home, RootVerb::Revoke, prompt).await;
    (home, first, root.unwrap())
}

#[tokio::test]
async fn a_write_under_the_guard_never_takes_the_lock_again() {
    // A root act's commit folds its own cut under the `home.lock` it holds. A fold that took the lock
    // itself would wait on the act's own hold for good, so the commit is bounded here.
    let (home, _, mut root) = revoking("under-guard", &[(LAPTOP, "laptop")]).await;
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();
    let committed = tokio::time::timeout(Duration::from_secs(10), root.commit_to(&mut io::sink()))
        .await
        .expect("the commit's own fold finishes under the act's lock")
        .unwrap();
    assert!(matches!(
        crate::roster::read_held(&home.devices(), TestRoot::seeded(ROOT).verify_key()),
        Some((held, _)) if held.epoch() == committed.number
    ));
}

#[tokio::test]
async fn the_home_lock_is_never_held_across_a_prompt() {
    let first = RosterDoc::new(
        Epoch(1),
        [
            own_row(),
            row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]),
            row(NAS, "nas", vec![id(NAS, STANDING_UNTIL)]),
        ]
        .iter()
        .map(member)
        .collect(),
    )
    .unwrap();
    let home = home("prompt-unlocked");
    let mut prompt = FoldingPrompt::new(&home, &cut_elsewhere(&first));
    let (_home, _, _root) = presented_with("prompt-unlocked", &mut prompt).await;
    assert_eq!(
        prompt.folded,
        Some(crate::roster::Folded::Newer),
        "a fold of this home finished while the act waited at its prompt"
    );
}

#[tokio::test]
async fn a_list_folded_during_the_prompt_is_brought_forward_before_the_cut() {
    let first = RosterDoc::new(
        Epoch(1),
        [
            own_row(),
            row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]),
            row(NAS, "nas", vec![id(NAS, STANDING_UNTIL)]),
        ]
        .iter()
        .map(member)
        .collect(),
    )
    .unwrap();
    let home = home("prompt-folded");
    let mut prompt = FoldingPrompt::new(&home, &cut_elsewhere(&first));
    let (home, first, mut root) = presented_with("prompt-folded", &mut prompt).await;
    assert_eq!(prompt.folded, Some(crate::roster::Folded::Newer));
    let nas = sibling(&home, NAS, STANDING_UNTIL, &first).await;
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();

    let committed = root
        .commit_to(&mut io::sink())
        .await
        .expect("the act cuts above the list folded while it waited");
    assert_eq!(
        committed.number,
        Epoch(3),
        "above the list folded meanwhile"
    );
    let cut = crate::roster::verify(&committed.bytes, TestRoot::seeded(ROOT).verify_key()).unwrap();
    assert!(
        cut.revoked()
            .iter()
            .any(|revoked| revoked.id == id(OTHER, STANDING_UNTIL).id),
        "the cut carries the revocation of the list folded meanwhile"
    );
    assert!(cut.is_revoked_key(&key(LAPTOP)), "and its own");
    assert!(matches!(
        crate::roster::read_held(&home.devices(), TestRoot::seeded(ROOT).verify_key()),
        Some((held, _)) if held.epoch() == Epoch(3)
    ));
    let dial = Loopback::new(
        home.clone(),
        [(TestNode::seeded(NAS).node_id(), nas.clone())],
    );
    let _reach = committed.offer(&dial).await;
    assert!(
        crate::revoked::open(&nas)
            .unwrap()
            .is_revoked_key(&key(LAPTOP)),
        "me/nas took the cut"
    );
}

/// Fold `update`, signed by the root, into `home`, as a fold beside the act would: the list moves after the
/// act read its records, once its prompt was answered, and before it commits.
async fn fold_meanwhile(home: &Home, update: &RosterDoc) -> crate::roster::Folded {
    let bytes = TestRoot::seeded(ROOT).sign_update(update);
    let home_lock = crate::home::HomeWrite::take(home).await.unwrap();
    crate::roster::fold(&home_lock, home, &bytes).await.unwrap()
}

#[tokio::test]
async fn a_device_added_whose_name_the_list_gave_away_meanwhile_stops_the_act() {
    // After the act read its records, this home folded a list another copy of the root cut, which names a
    // different key me/tv. The act's own me/tv no longer holds, so it stops and offers nothing.
    let rows = [
        own_row(),
        row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]),
        row(NAS, "nas", vec![id(NAS, STANDING_UNTIL)]),
    ];
    let mut elsewhere: Vec<Member> = rows.iter().map(member).collect();
    elsewhere.push(member(&row(PHONE, "tv", vec![id(PHONE, STANDING_UNTIL)])));
    let elsewhere = RosterDoc::new(Epoch(2), elsewhere).unwrap();
    let (home, first, mut root) =
        presented_with("prompt-name-taken", &mut Counting::new([PASS])).await;
    assert_eq!(
        fold_meanwhile(&home, &elsewhere).await,
        crate::roster::Folded::Newer
    );
    let nas = sibling(&home, NAS, STANDING_UNTIL, &first).await;
    root.sign_standing(key(TV), name("tv"), Duration::from_secs(30 * DAY))
        .unwrap();

    let dial = Loopback::new(home.clone(), [(TestNode::seeded(NAS).node_id(), nas)]);
    let mut out = Vec::new();
    let error = match root.commit_to(&mut out).await {
        Ok(committed) => {
            let _reach = committed.offer(&dial).await;
            None
        }
        Err(error) => Some(error),
    };
    assert!(dial.dialed().is_empty(), "nothing was offered");
    let error = error.expect("the act stops");
    assert!(matches!(error, RootError::ListChanged), "{error:?}");
    assert_eq!(
        error.to_string(),
        "your devices' list changed while this ran: run it again."
    );
}

#[tokio::test]
async fn a_device_whose_key_the_list_revoked_meanwhile_is_never_handed_a_new_one() {
    // me/laptop came with its key. After an invite read its records, this home folded a list another copy
    // of the root cut, which revokes laptop's key and id. A new key for me/laptop would bring it back
    // to life past that revocation, so the act stops.
    let laptop = Member {
        invite_until: STANDING_UNTIL,
        ..row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)])
    };
    let rows = [
        own_row(),
        laptop,
        row(NAS, "nas", vec![id(NAS, STANDING_UNTIL)]),
    ];
    let first = RosterDoc::new(Epoch(1), rows.iter().map(member).collect()).unwrap();
    let elsewhere = RosterDoc::with_revocations(
        Epoch(2),
        [&rows[0], &rows[2]].into_iter().map(member).collect(),
        vec![id(LAPTOP, STANDING_UNTIL)],
        vec![crate::testkit::revoked(key(LAPTOP))],
    )
    .unwrap();
    let home = home("prompt-rekey-revoked");
    holds(&home, &first).await;
    let (root, _) = present(
        &home,
        RootPlace::Home,
        RootVerb::Invite,
        &mut Counting::new([PASS]),
    )
    .await;
    let mut root = root.unwrap();
    assert_eq!(
        fold_meanwhile(&home, &elsewhere).await,
        crate::roster::Folded::Newer
    );
    root.rekey(&name("laptop"), Duration::from_secs(30 * DAY))
        .unwrap();

    let mut out = Vec::new();
    let error = root.commit_to(&mut out).await.map(|_| ()).unwrap_err();
    assert!(matches!(error, RootError::ListChanged), "{error:?}");
    assert!(
        out.is_empty(),
        "a stopped act prints nothing it did not write: {}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        matches!(
            crate::roster::read_held(&home.devices(), TestRoot::seeded(ROOT).verify_key()),
            Some((held, _)) if held.epoch() == Epoch(2)
        ),
        "nothing was cut"
    );
}

#[tokio::test]
async fn a_device_the_list_handed_a_new_key_meanwhile_is_never_left_live_by_a_revoke() {
    // revoke found me/laptop's key when it read its records. After that, this home folded a list another
    // copy of the root cut, which hands me/laptop a new key. Revoking only the old key would leave
    // the device live under the new one, so the act stops and prints nothing.
    let rekeyed = row(
        TV,
        "laptop",
        vec![id(LAPTOP, STANDING_UNTIL), id(TV, STANDING_UNTIL)],
    );
    let elsewhere = RosterDoc::new(
        Epoch(2),
        vec![
            member(&own_row()),
            member(&rekeyed),
            member(&row(NAS, "nas", vec![id(NAS, STANDING_UNTIL)])),
        ],
    )
    .unwrap();
    let (home, _, mut root) =
        presented_with("prompt-revoke-rekeyed", &mut Counting::new([PASS])).await;
    assert_eq!(
        fold_meanwhile(&home, &elsewhere).await,
        crate::roster::Folded::Newer
    );
    root.revoke_device(&name("laptop"), key(LAPTOP), &[])
        .unwrap();

    let mut out = Vec::new();
    let error = root.commit_to(&mut out).await.map(|_| ()).unwrap_err();
    assert!(matches!(error, RootError::NameMoved { .. }), "{error:?}");
    assert_eq!(
        error.to_string(),
        "me/laptop is now listed under a key this revoke did not see, so your root did not revoke it",
        "the refusal names no command: running the revoke again would take the name's new key"
    );
    assert!(
        out.is_empty(),
        "a stopped act prints nothing it did not write: {}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        matches!(
            crate::roster::read_held(&home.devices(), TestRoot::seeded(ROOT).verify_key()),
            Some((held, _)) if held.epoch() == Epoch(2)
        ),
        "nothing was cut"
    );
}

#[tokio::test]
async fn a_key_the_list_named_meanwhile_is_never_added_under_another_name() {
    // After the act read its records, this home folded a list another copy of the root cut, which names
    // the key TV me/phone. Adding TV as me/tv would rename that device, so the act stops.
    let rows = [
        own_row(),
        row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]),
        row(NAS, "nas", vec![id(NAS, STANDING_UNTIL)]),
    ];
    let mut elsewhere: Vec<Member> = rows.iter().map(member).collect();
    elsewhere.push(member(&row(TV, "phone", vec![id(TV, STANDING_UNTIL)])));
    let elsewhere = RosterDoc::new(Epoch(2), elsewhere).unwrap();
    let (home, _, mut root) = presented_with("prompt-key-named", &mut Counting::new([PASS])).await;
    assert_eq!(
        fold_meanwhile(&home, &elsewhere).await,
        crate::roster::Folded::Newer
    );
    root.sign_standing(key(TV), name("tv"), Duration::from_secs(30 * DAY))
        .unwrap();

    let error = root
        .commit_to(&mut io::sink())
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, RootError::ListChanged), "{error:?}");
    assert!(
        matches!(
            crate::roster::read_held(&home.devices(), TestRoot::seeded(ROOT).verify_key()),
            Some((held, _)) if held.epoch() == Epoch(2)
        ),
        "nothing was cut"
    );
}

/// A prompt that, while a mint or its finish waits at it, joins this home to the root seeded `OTHER`, as a
/// `join` run beside it would, then answers.
struct JoiningPrompt {
    home: Home,
}

impl JoiningPrompt {
    fn join(&self) -> eyre::Result<Passphrase> {
        let standing = TestRoot::seeded(OTHER).standing(key(OWN)).unwrap();
        crate::joining::join(
            &crate::home::HomeWrite::wait(&self.home).unwrap(),
            &self.home,
            crate::joining::Join {
                root: TestRoot::seeded(OTHER).node_id(),
                standing: &standing,
                from: TestNode::seeded(LAPTOP).node_id(),
                name: &"own".parse().unwrap(),
                pin_changes: true,
            },
        )
        .unwrap();
        crate::passphrase::passphrase(Zeroizing::new(PASS.to_owned()))
    }
}

impl Prompt for JoiningPrompt {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, _asked: Asked<'_>) -> eyre::Result<Passphrase> {
        self.join()
    }

    fn choose(&mut self, _asked: Asked<'_>) -> eyre::Result<Choice> {
        self.join().map(Choice::Chosen)
    }

    fn say(&mut self, _line: &str) {}
}

#[tokio::test]
async fn a_join_during_a_mints_prompt_stops_the_mint() {
    let home = home("mint-joined");
    let mut prompt = JoiningPrompt { home: home.clone() };
    let error = Root::mint_to(&home, &mut prompt, &mut io::sink())
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(error, RootError::StandingChanged), "{error:?}");
    assert_eq!(
        error.to_string(),
        "this machine's records changed while this ran: run it again."
    );
    assert_eq!(
        config::load_signet(&home).await.unwrap(),
        Some(TestRoot::seeded(OTHER).node_id()),
        "the root it joined is still the one it trusts"
    );
    assert!(!home.root_key().exists(), "no root was made");
}

#[tokio::test]
async fn a_join_during_a_finishs_prompt_stops_the_finish() {
    let home = home("finish-joined");
    STOP.set(Some(Seam::Keyed));
    let stopped = Root::mint_to(&home, &mut Counting::new([PASS]), &mut io::sink()).await;
    STOP.set(None);
    assert!(stopped.is_err());

    let mut prompt = JoiningPrompt { home: home.clone() };
    let finished = Root::mint_to(&home, &mut prompt, &mut io::sink()).await;
    assert!(finished.is_err(), "the finish stops");
    assert_eq!(
        config::load_signet(&home).await.unwrap(),
        Some(TestRoot::seeded(OTHER).node_id()),
        "the root it joined is still the one it trusts"
    );
}

#[tokio::test]
async fn a_refused_offer_is_never_counted_as_taken() {
    let (_home, _, mut root) = revoking(
        "refused",
        &[(LAPTOP, "laptop"), (NAS, "nas"), (PHONE, "phone")],
    )
    .await;
    root.revoke_device(&name("phone"), key(PHONE), &[]).unwrap();
    let (committed, _) = commit(root).await;

    let dial = Scripted(vec![(NAS, Answer::Gave), (LAPTOP, Answer::Refused)]);
    let reach = committed.offer(&dial).await;

    assert_eq!(
        reach,
        Reach::Published {
            took: vec!["me/nas".to_owned()],
            missed: vec![Missed {
                name: "me/laptop".to_owned(),
                why: Why::Refused,
            }],
            until: Some(STANDING_UNTIL),
        }
    );
}

// --- restore's write order, at its seams ---

/// A restore on a device of this root, killed after `root.key`, already holds the copy's list: on a device
/// `root.key` is the commit point, so the list lands before it. The rerun refuses as already here, and the
/// next act that cuts carries this machine's row. Red when `root.key` is written first.
#[tokio::test]
async fn a_restore_on_a_device_killed_after_its_key_holds_the_copys_list() {
    let home = home("restore-killed-device");
    device_of(&home, ROOT).await;
    held(&home, &records(1, vec![own_row()], Vec::new(), Vec::new()));
    let dir = beside(&home, "copy");
    let _ = std::fs::remove_dir_all(&dir);
    let laptop = row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]);
    copy(
        &dir,
        ROOT,
        &records(3, vec![laptop], Vec::new(), Vec::new()),
    );

    STOP.set(Some(Seam::Keyed));
    let killed = super::restore(&home, &dir, &mut Counting::new([PASS])).await;
    STOP.set(None);
    assert!(killed.is_err(), "stopped at the seam");
    let pin = TestRoot::seeded(ROOT).verify_key();
    let held_now = crate::roster::read_held(&home.devices(), pin).unwrap().0;
    assert_eq!(held_now.epoch(), Epoch(3), "the copy's list landed first");
    assert!(matches!(standing(&home).await, Standing::HoldsRoot { .. }));

    let again = super::restore(&home, &dir, &mut Counting::new([PASS])).await;
    assert!(
        matches!(again, Err(super::RestoreError::AlreadyHere)),
        "{again:?}"
    );

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
            .any(|member| member.node == key(OWN)),
        "the next cut carries this machine's row"
    );
}

/// A list that lands while a restore's re-cut waits for the lock, and already lists this machine, is carried
/// by the re-cut: it cuts above that list and offers the cut. Red when this machine's own row counts as a
/// device the act added, which stops the re-cut.
#[tokio::test]
async fn a_restore_whose_re_cut_meets_a_moved_list_carries_it_and_offers_the_cut() {
    let home = home("restore-recut-moved");
    let dir = beside(&home, "copy");
    let _ = std::fs::remove_dir_all(&dir);
    let laptop = row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]);
    copy(
        &dir,
        ROOT,
        &records(1, vec![laptop.clone()], Vec::new(), Vec::new()),
    );
    let fleet = records(3, vec![laptop.clone()], Vec::new(), Vec::new());
    let device = sibling(&home, LAPTOP, STANDING_UNTIL, &fleet).await;
    let dial = Loopback::new(
        home.clone(),
        [(TestNode::seeded(LAPTOP).node_id(), device.clone())],
    );

    let restored = super::restore(&home, &dir, &mut Counting::new([PASS]))
        .await
        .unwrap();
    // Another copy of the root cut past the fleet's list, listing this machine and me/nas.
    let nas = row(NAS, "nas", vec![id(NAS, STANDING_UNTIL)]);
    let moved = records(4, vec![laptop, own_row(), nas], Vec::new(), Vec::new());
    MEANWHILE.set(Some(TestRoot::seeded(ROOT).sign_update(&moved)));
    let synced = restored.sync(&home, &dial).await;
    MEANWHILE.set(None);
    synced.expect("a moved list never stops the re-cut");
    let pin = TestRoot::seeded(ROOT).verify_key();
    let here = crate::roster::read_held(&home.devices(), pin).unwrap().0;
    assert_eq!(here.epoch(), Epoch(5), "cut above the moved list");
    for listed in [key(OWN), key(NAS)] {
        assert!(here.members().iter().any(|member| member.node == listed));
    }
    let theirs = crate::roster::read_held(&device.devices(), pin).unwrap().0;
    assert_eq!(theirs.epoch(), Epoch(5), "the cut was offered");
}

/// A list that lands while an act waits for the lock, revoking this machine's key after the act renewed
/// this machine's lapsed row, never stops the act: that renewal is no device the act renewed. The act goes
/// on, as any act that cuts with this machine's key revoked does, and the list it leaves revokes the key.
/// Red when the renewal counts as one the act made.
#[tokio::test]
async fn a_list_revoking_this_machine_after_its_row_was_renewed_never_stops_the_act() {
    let home = home("own-renewed-revoked");
    let lapsed = Member {
        until: now() - DAY,
        ..row(OWN, "desk", vec![id(OWN, now() - DAY)])
    };
    let laptop = row(LAPTOP, "laptop", vec![id(LAPTOP, STANDING_UNTIL)]);
    holds(
        &home,
        &records(1, vec![lapsed, laptop.clone()], Vec::new(), Vec::new()),
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
    let moved = records(2, vec![laptop], Vec::new(), vec![key(OWN)]);
    MEANWHILE.set(Some(TestRoot::seeded(ROOT).sign_update(&moved)));
    let committed = root.commit_to(&mut io::sink()).await;
    MEANWHILE.set(None);
    let committed = committed.expect("the act goes on");
    let left =
        crate::roster::verify(&committed.bytes, TestRoot::seeded(ROOT).verify_key()).unwrap();
    assert!(left.is_revoked_key(&key(OWN)));
    assert!(
        !left.members().iter().any(|member| member.node == key(OWN)),
        "no live row for a revoked key"
    );
}
