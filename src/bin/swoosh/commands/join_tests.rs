//! `join` over homes built on disk the way the product leaves them: a fresh machine, one with its own key,
//! a device of a root, and the machine where a root is kept. Each join runs in process, with its stdin, its
//! terminal, its hostname and its clock given, and its first exchange run over devices that answer in
//! memory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Parser;
use keystore::{KeyFile, Passphrase, Protection};
use nauthy::Link;
use swoosh::config;
use swoosh::contacts::{ContactsStore, ME, Petname};
use swoosh::home::Home;
use swoosh::invite::Invite;
use swoosh::joining::AdmitLock;
use swoosh::passphrase::Prompt;
use swoosh::roster::{Epoch, Folded, RosterDoc, fold};
use swoosh::standing::Standing;
use swoosh::testkit::{Loopback, TestNode, TestRoot};
use zeroize::Zeroizing;

use super::{Io, JoinCmd};

/// This machine's key.
const OWN: u8 = 0x11;
/// The root this machine joins.
const ROOT: u8 = 0x21;
/// Another root.
const OTHER: u8 = 0x31;
/// The machine where the root is kept, which made the invite.
const FROM: u8 = 0x41;
/// Another machine.
const STRANGER: u8 = 0x42;

const DAY: u64 = 24 * 60 * 60;

static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn node(seed: u8) -> NodeId {
    TestNode::seeded(seed).node_id()
}

fn root(seed: u8) -> NodeId {
    TestRoot::seeded(seed).node_id()
}

/// A fresh home with no key.
fn empty(tag: &str) -> Home {
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("swoosh-join-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).unwrap();
    Home::resolve(Some(dir)).unwrap()
}

/// A fresh home holding the key `seed`, plain.
fn keyed(tag: &str, seed: u8) -> Home {
    let home = empty(tag);
    let mut bytes = TestNode::seeded(seed).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut bytes), Protection::Plain)
        .unwrap();
    home
}

/// A fresh home holding this machine's key, plain.
fn scratch(tag: &str) -> Home {
    keyed(tag, OWN)
}

/// A standing `by` signed for `device`, ending at `until`.
fn standing(by: u8, device: NodeId, until: u64) -> Link {
    TestRoot::seeded(by)
        .device_badge(device, at(until))
        .unwrap()
}

/// The bound invite `swoosh invite <name> <device>` prints where the root `by` is kept.
fn bound(by: u8, device: NodeId, name: &str, until: u64) -> String {
    Invite::bound(
        node(FROM),
        name.parse().unwrap(),
        standing(by, device, until),
    )
    .to_string()
}

/// The bound invite for this machine, from `ROOT`, ending in 90 days.
fn for_me() -> String {
    bound(ROOT, node(OWN), "laptop", now() + 90 * DAY)
}

/// The key-carrying invite `swoosh invite <name> --new-key` prints where `ROOT` is kept.
fn carrying(seed: [u8; 32], name: &str) -> String {
    let device = NodeId::from_ed25519_secret(&seed);
    Invite::keyed(
        seed,
        node(FROM),
        name.parse().unwrap(),
        standing(ROOT, device, now() + 90 * DAY),
    )
    .to_string()
}

/// Every file under `dir`, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.insert(path.clone(), std::fs::read(&path).unwrap());
            }
        }
    }
    files
}

/// A passphrase prompt that can or cannot reach a person, and asks nothing.
struct Asks {
    terminal: bool,
}

impl Prompt for Asks {
    fn terminal(&self) -> bool {
        self.terminal
    }

    fn unlock(&mut self, _path: &Path) -> eyre::Result<Passphrase> {
        eyre::bail!("join asks for no passphrase")
    }

    fn choose(&mut self, _path: &Path) -> eyre::Result<Passphrase> {
        eyre::bail!("join asks for no passphrase")
    }
}

#[derive(Debug, Parser)]
struct Cli {
    #[command(flatten)]
    join: JoinCmd,
}

fn parse(args: &[&str]) -> JoinCmd {
    Cli::try_parse_from(core::iter::once("join").chain(args.iter().copied()))
        .unwrap()
        .join
}

/// How one `join` is run.
struct Setup<'a> {
    args: &'a [&'a str],
    stdin: &'a str,
    terminal_stdin: bool,
    prompt_terminal: bool,
    hostname: &'a str,
    now: SystemTime,
}

impl Default for Setup<'_> {
    fn default() -> Self {
        Self {
            args: &[],
            stdin: "",
            terminal_stdin: false,
            prompt_terminal: true,
            hostname: "laptop.local",
            now: SystemTime::now(),
        }
    }
}

/// What one `join` did.
struct Ran {
    result: eyre::Result<Option<NodeId>>,
    err: String,
}

impl Ran {
    fn refusal(&self) -> String {
        match &self.result {
            Ok(_) => panic!("join refused: {}", self.err),
            Err(error) => format!("{error:#}"),
        }
    }

    fn joined(&self) -> Option<NodeId> {
        match &self.result {
            Ok(from) => *from,
            Err(error) => panic!("join joined: {error:#}\n{}", self.err),
        }
    }
}

async fn run(home: &Home, setup: Setup<'_>) -> Ran {
    let mut err = Vec::new();
    let prompt = Asks {
        terminal: setup.prompt_terminal,
    };
    let result = parse(setup.args)
        .admit(
            home,
            Io {
                input: setup.stdin.as_bytes(),
                input_terminal: setup.terminal_stdin,
                prompt: &prompt,
                hostname: setup.hostname,
                now: setup.now,
                err: &mut err,
            },
        )
        .await;
    Ran {
        result,
        err: String::from_utf8(err).unwrap(),
    }
}

/// `swoosh join` with `invite` on stdin.
async fn join(home: &Home, invite: &str) -> Ran {
    join_with(home, invite, &[]).await
}

/// `swoosh join <args>` with `invite` on stdin.
async fn join_with(home: &Home, invite: &str, args: &[&str]) -> Ran {
    let stdin = format!("{invite}\n");
    run(
        home,
        Setup {
            args,
            stdin: &stdin,
            ..Setup::default()
        },
    )
    .await
}

/// Assert `ran` refused with `line`, leaving `home` as `before`.
fn refused_before_writing(ran: &Ran, line: &str, home: &Home, before: &BTreeMap<PathBuf, Vec<u8>>) {
    let refusal = ran.refusal();
    assert!(refusal.contains(line), "{refusal}");
    assert!(
        snapshot(home.dir()) == *before,
        "the home is unchanged after: {refusal}"
    );
}

async fn read(home: &Home) -> Standing {
    Standing::read(home).await.unwrap().standing
}

/// This machine's own name under `me`, as `status` reads it.
async fn me_name(home: &Home) -> Option<String> {
    let store = ContactsStore::open(home.contacts()).await.unwrap();
    let me = Petname::stored(ME).unwrap();
    store
        .contacts()
        .devices(&me)?
        .find(|(_, key)| **key == node(OWN))
        .map(|(label, _)| label.to_string())
}

/// An update `by` signed at `number`, listing this machine as `name`.
fn update(by: u8, number: u64, name: &str) -> Vec<u8> {
    let root = TestRoot::seeded(by);
    let member = root
        .member(TestNode::seeded(OWN).verify_key(), name.parse().unwrap())
        .unwrap();
    root.sign_update(&RosterDoc::new(Epoch(number), vec![member]).unwrap())
}

/// Make `home` a device of `by` until `until`, holding nothing else.
async fn device_of(home: &Home, by: u8, until: u64) {
    config::write_badge(home, &standing(by, node(OWN), until))
        .await
        .unwrap();
    config::write_signet(home, root(by)).await.unwrap();
}

/// Keep `ROOT` in `home`: a plain 32-byte key file, which the standing reads by its key without a prompt.
pub(super) fn keep_root(home: &Home) {
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

// --- reading the invite ---

#[tokio::test]
async fn a_secret_invite_in_argv_is_refused() {
    let home = empty("argv-secret");
    let before = snapshot(home.dir());
    let invite = carrying([0x77; 32], "runner");
    let ran = run(
        &home,
        Setup {
            args: &[&invite],
            ..Setup::default()
        },
    )
    .await;
    refused_before_writing(
        &ran,
        "this invite contains a private key; pass it on stdin: swoosh join",
        &home,
        &before,
    );
    let seed = invite
        .trim_start_matches("invite:")
        .split('.')
        .next()
        .unwrap();
    assert!(!ran.refusal().contains(seed), "the key is never echoed");
    assert!(!ran.err.contains(seed), "nor printed");

    // Refused at the count: a first field that is no key at all is never decoded.
    let garbled = format!(
        "invite:!!!not-base32!!!.{}",
        invite.split_once('.').unwrap().1
    );
    let ran = run(
        &home,
        Setup {
            args: &[&garbled],
            ..Setup::default()
        },
    )
    .await;
    refused_before_writing(&ran, "this invite contains a private key", &home, &before);
}

#[tokio::test]
async fn join_dash_reads_the_invite_from_stdin() {
    let home = scratch("dash");
    let ran = join_with(&home, &for_me(), &["-"]).await;
    ran.joined();
    assert!(matches!(read(&home).await, Standing::Device { pin, .. } if pin == root(ROOT)));
}

#[tokio::test]
async fn bare_join_at_a_terminal_prints_the_key_and_the_invite_command() {
    let home = scratch("bare-terminal");
    let stdin = format!("{}\n", for_me());
    let ran = run(
        &home,
        Setup {
            stdin: &stdin,
            terminal_stdin: true,
            hostname: "Laptop.local",
            ..Setup::default()
        },
    )
    .await;
    ran.joined();
    let key = node(OWN);
    let lines: Vec<&str> = ran.err.lines().collect();
    assert_eq!(lines[0], format!("This machine's key: {key}"));
    assert_eq!(
        lines[1],
        format!("On the machine where your root is kept:  swoosh invite laptop {key}")
    );
    assert_eq!(lines[2], "Then paste the invite here:");
    assert!(
        lines[3].starts_with("joined root"),
        "the invite is read after the lines: {}",
        ran.err
    );

    // A hostname that leaves no name: the literal placeholder.
    let home = scratch("bare-terminal-no-name");
    let ran = run(
        &home,
        Setup {
            stdin: &stdin,
            terminal_stdin: true,
            hostname: "...",
            ..Setup::default()
        },
    )
    .await;
    ran.joined();
    assert!(
        ran.err
            .contains(&format!("swoosh invite <name> {}", node(OWN))),
        "{}",
        ran.err
    );
}

#[tokio::test]
async fn piped_join_prints_no_key_lines() {
    let home = scratch("piped");
    let ran = join(&home, &for_me()).await;
    ran.joined();
    assert!(!ran.err.contains("This machine's key"), "{}", ran.err);
}

// --- what the invite's hints can and cannot do ---

#[tokio::test]
async fn a_tampered_from_or_name_changes_no_trust() {
    let until = now() + 90 * DAY;
    let signed = standing(ROOT, node(OWN), until);
    let honest = Invite::bound(node(FROM), "laptop".parse().unwrap(), signed.clone()).to_string();
    let tampered = Invite::bound(node(STRANGER), "evil".parse().unwrap(), signed).to_string();

    let clean = scratch("tamper-clean");
    join(&clean, &honest).await.joined();
    let home = scratch("tamper");
    let ran = join(&home, &tampered).await;
    assert_eq!(
        ran.joined(),
        Some(node(STRANGER)),
        "the hint is only who to ask"
    );

    for (file, path) in [
        ("pin", Home::signet as fn(&Home) -> PathBuf),
        ("badge", Home::badge),
    ] {
        assert_eq!(
            std::fs::read(path(&home)).unwrap(),
            std::fs::read(path(&clean)).unwrap(),
            "the {file} is the standing's, whatever the hints say"
        );
    }
    assert_eq!(read(&home).await, read(&clean).await);
    assert_eq!(
        me_name(&home).await.as_deref(),
        Some("evil"),
        "until the first fold"
    );

    // The first fold of the root's update lays down the root's name for this machine.
    assert_eq!(
        fold(&home, &update(ROOT, 1, "laptop")).await.unwrap(),
        Folded::Newer
    );
    assert_eq!(me_name(&home).await.as_deref(), Some("laptop"));
}

// --- the same root, and a switch ---

#[tokio::test]
async fn a_same_root_join_keeps_the_floor_and_the_fork() {
    let home = scratch("same-root");
    join(&home, &bound(ROOT, node(OWN), "laptop", now() + 30 * DAY))
        .await
        .joined();
    fold(&home, &update(ROOT, 3, "laptop")).await.unwrap();
    std::fs::write(home.roster_fork(), b"a fork kept as evidence").unwrap();
    let held = std::fs::read(home.roster()).unwrap();
    let seed = std::fs::read(home.roster_seed()).unwrap();

    // Later than the standing the fold may have picked up, so the join is a renewal.
    let renewal = Invite::bound(
        node(STRANGER),
        "laptop".parse().unwrap(),
        standing(ROOT, node(OWN), swoosh::testkit::STANDING_UNTIL + DAY),
    )
    .to_string();
    join(&home, &renewal).await.joined();
    assert_eq!(
        std::fs::read(home.roster()).unwrap(),
        held,
        "the floor stays"
    );
    assert!(home.roster_fork().exists(), "the fork stays");
    assert_eq!(
        std::fs::read(home.roster_seed()).unwrap(),
        seed,
        "the first device to ask stays"
    );
    // A replay of the update below the floor still changes nothing.
    assert_eq!(
        fold(&home, &update(ROOT, 2, "laptop")).await.unwrap(),
        Folded::NotNewer
    );
}

#[tokio::test]
async fn a_switch_to_a_new_root_ignores_the_old_standings_date() {
    let home = scratch("switch-date");
    device_of(&home, ROOT, now() + 365 * DAY).await;
    let ran = join_with(
        &home,
        &bound(OTHER, node(OWN), "laptop", now() + 90 * DAY),
        &["--switch"],
    )
    .await;
    ran.joined();
    assert!(matches!(read(&home).await, Standing::Device { pin, .. } if pin == root(OTHER)));
    assert!(
        ran.err.contains(&format!(
            "this machine now trusts root root:{} (was root:{}).",
            root(OTHER),
            root(ROOT)
        )),
        "{}",
        ran.err
    );
}

#[tokio::test]
async fn a_switched_device_accepts_its_new_roots_first_update() {
    let home = scratch("switch-floor");
    join(&home, &for_me()).await.joined();
    fold(&home, &update(ROOT, 5, "laptop")).await.unwrap();
    join_with(
        &home,
        &bound(OTHER, node(OWN), "laptop", now() + 90 * DAY),
        &["--switch"],
    )
    .await
    .joined();
    assert!(
        !home.roster().exists(),
        "the old root's update goes with its pin"
    );
    assert_eq!(
        fold(&home, &update(OTHER, 1, "laptop")).await.unwrap(),
        Folded::Newer,
        "the new root's first update is newer than nothing"
    );
}

// --- the first exchange ---

#[tokio::test]
async fn a_joined_device_pulls_its_first_update_unprompted() {
    // The machine that made the invite: a device of the root, holding its update.
    let inviter = keyed("pull-inviter", FROM);
    config::write_badge(&inviter, &standing(ROOT, node(FROM), now() + 90 * DAY))
        .await
        .unwrap();
    config::write_signet(&inviter, root(ROOT)).await.unwrap();
    fold(&inviter, &update(ROOT, 4, "laptop")).await.unwrap();

    let home = scratch("pull");
    let from = join(&home, &for_me())
        .await
        .joined()
        .expect("a machine to ask");
    assert_eq!(from, node(FROM), "the one the invite names");
    let dial = Loopback::new(home.clone(), [(node(FROM), inviter.clone())]);
    super::pull(&dial, from).await;
    assert_eq!(dial.dialed(), vec![node(FROM)]);
    assert_eq!(
        std::fs::read(home.roster()).unwrap(),
        std::fs::read(inviter.roster()).unwrap(),
        "the device holds the root's update from the start"
    );
}

#[tokio::test]
async fn an_offer_after_join_switch_under_serve_folds_the_new_roots_update() {
    let home = scratch("offer-after-switch");
    join(&home, &for_me()).await.joined();
    fold(&home, &update(ROOT, 7, "laptop")).await.unwrap();
    join_with(
        &home,
        &bound(OTHER, node(OWN), "laptop", now() + 90 * DAY),
        &["--switch"],
    )
    .await
    .joined();

    // Another device of the new root offers its update: this machine answers as its `serve` does, reading
    // the pin as it stands now.
    let other = keyed("offer-other", FROM);
    config::write_badge(&other, &standing(OTHER, node(FROM), now() + 90 * DAY))
        .await
        .unwrap();
    config::write_signet(&other, root(OTHER)).await.unwrap();
    let bytes = update(OTHER, 1, "laptop");
    fold(&other, &bytes).await.unwrap();
    let dial = Loopback::new(other, [(node(OWN), home.clone())]);
    let answer = swoosh::sync::Dial::offer(&dial, node(OWN), Epoch(1), &bytes)
        .await
        .unwrap();
    assert_eq!(answer, swoosh::sync::Answer::Gave);
    assert_eq!(std::fs::read(home.roster()).unwrap(), bytes);
}

// --- what it prints ---

#[tokio::test]
async fn join_prints_the_lock_line_once() {
    let home = scratch("lock-line");
    let line = "this machine's key is not locked; swoosh lock locks it.";
    let first = join(&home, &bound(ROOT, node(OWN), "laptop", now() + 30 * DAY)).await;
    first.joined();
    assert!(first.err.contains(line), "{}", first.err);
    let second = join(&home, &bound(ROOT, node(OWN), "laptop", now() + 60 * DAY)).await;
    second.joined();
    assert!(!second.err.contains(line), "{}", second.err);
}

#[tokio::test]
async fn join_says_what_it_joined_and_how_to_check_it() {
    let home = scratch("lines");
    let until = now() + 90 * DAY;
    let ran = join(&home, &bound(ROOT, node(OWN), "laptop", until)).await;
    ran.joined();
    let root = root(ROOT);
    assert!(
        ran.err.contains(&format!(
            "joined root root:{root}: this machine is its device until {}.",
            swoosh::root::Date(until)
        )),
        "{}",
        ran.err
    );
    assert!(
        ran.err.contains(&format!(
            "Check that root:{root} is the root: line on the machine that keeps your root; the invite alone \
             does not prove who sent it."
        )),
        "{}",
        ran.err
    );
}

#[tokio::test]
async fn a_key_carrying_invite_becomes_this_machines_key() {
    let home = empty("carrying");
    let seed = [0x78; 32];
    join(&home, &carrying(seed, "runner")).await.joined();
    let key = KeyFile::device(home.key())
        .load()
        .unwrap()
        .unwrap()
        .node_id();
    assert_eq!(key, NodeId::from_ed25519_secret(&seed));
    assert!(matches!(read(&home).await, Standing::Device { pin, .. } if pin == root(ROOT)));
}

// --- one test per refusal, each before any write ---

#[tokio::test]
async fn join_refuses_an_invite_whose_standing_has_passed() {
    let home = scratch("lapsed");
    let until = now() + 10 * DAY;
    let before = snapshot(home.dir());
    let stdin = format!("{}\n", bound(ROOT, node(OWN), "laptop", until));
    let ran = run(
        &home,
        Setup {
            stdin: &stdin,
            now: at(until + 1),
            ..Setup::default()
        },
    )
    .await;
    refused_before_writing(
        &ran,
        &format!(
            "this invite ended on {}. With your root: swoosh invite laptop (for a device that starts from its \
             invite each time: swoosh invite laptop --new-key), then join what it prints.",
            swoosh::root::Date(until)
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn join_refuses_while_serve_admit_runs() {
    let home = scratch("admitting");
    let _serving = AdmitLock::admitting(&home, root(OTHER)).unwrap();
    let before = snapshot(home.dir());
    let ran = join(&home, &for_me()).await;
    refused_before_writing(&ran, "stop swoosh serve first.", &home, &before);
}

#[tokio::test]
async fn join_refuses_a_key_carrying_invite_on_a_machine_with_a_key() {
    let home = scratch("carrying-has-key");
    let before = snapshot(home.dir());
    let ran = join(&home, &carrying([0x79; 32], "runner")).await;
    refused_before_writing(
        &ran,
        &format!(
            "this invite carries its own key, and this machine already has one ({}). Use it on a fresh \
             machine (an empty --home <dir>), or invite this machine's key: swoosh invite runner {}",
            node(OWN),
            node(OWN)
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn join_refuses_an_invite_whose_root_is_this_machines_key() {
    let home = keyed("own-root", ROOT);
    let before = snapshot(home.dir());
    let invite = Invite::bound(
        node(FROM),
        "laptop".parse().unwrap(),
        standing(ROOT, root(ROOT), now() + 90 * DAY),
    )
    .to_string();
    let ran = join(&home, &invite).await;
    refused_before_writing(
        &ran,
        "a machine cannot be its own root's device.",
        &home,
        &before,
    );
}

#[tokio::test]
async fn join_refuses_a_bound_invite_for_another_key() {
    let home = scratch("other-key");
    let before = snapshot(home.dir());
    let ran = join(
        &home,
        &bound(ROOT, node(STRANGER), "laptop", now() + 90 * DAY),
    )
    .await;
    refused_before_writing(
        &ran,
        &format!(
            "this invite is for another machine's key; this machine is {own}. Invite this machine: swoosh \
             invite laptop {own}",
            own = node(OWN)
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn join_refuses_a_bound_invite_on_a_machine_with_no_key() {
    let home = empty("no-key");
    let before = snapshot(home.dir());
    let ran = join(&home, &for_me()).await;
    refused_before_writing(
        &ran,
        "this invite is for an existing machine's key, and this machine has no key yet. Ask for an invite \
         with its key inside: swoosh invite laptop --new-key",
        &home,
        &before,
    );
}

#[tokio::test]
async fn join_refuses_where_the_root_is_kept() {
    let home = scratch("holds-root");
    keep_root(&home);
    device_of(&home, ROOT, now() + 90 * DAY).await;
    assert!(matches!(read(&home).await, Standing::HoldsRoot { .. }));
    let before = snapshot(home.dir());
    let ran = join(&home, &bound(OTHER, node(OWN), "laptop", now() + 90 * DAY)).await;
    refused_before_writing(&ran, "swoosh move-root <dir>", &home, &before);
    assert!(
        !ran.refusal().contains("--switch"),
        "it names only move-root"
    );
}

#[tokio::test]
async fn join_refuses_another_root_without_switch() {
    let home = scratch("no-switch");
    device_of(&home, ROOT, now() + 90 * DAY).await;
    let before = snapshot(home.dir());
    let ran = join(&home, &bound(OTHER, node(OWN), "laptop", now() + 90 * DAY)).await;
    refused_before_writing(
        &ran,
        &format!(
            "this machine trusts root:{}; this invite is from root:{}. To move this machine to it: swoosh join \
             --switch.",
            root(ROOT),
            root(OTHER)
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn join_refuses_an_earlier_date_on_the_same_root() {
    let home = scratch("earlier");
    let held = now() + 90 * DAY;
    let earlier = now() + 30 * DAY;
    device_of(&home, ROOT, held).await;
    let before = snapshot(home.dir());
    let ran = join(&home, &bound(ROOT, node(OWN), "laptop", earlier)).await;
    refused_before_writing(
        &ran,
        &format!(
            "this invite ends {}, before this machine's current date {}, so it changes nothing here. To end \
             this device sooner: with your root, swoosh revoke me/laptop; then here, swoosh leave --new-key, \
             and invite the new key.",
            swoosh::root::Date(earlier),
            swoosh::root::Date(held)
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn join_refuses_a_root_revoked_here() {
    let home = scratch("revoked-root");
    nauthy::DisabledRoots::open_for_repair(home.disabled_roots())
        .disable(TestRoot::seeded(ROOT).verify_key())
        .await
        .unwrap();
    let before = snapshot(home.dir());
    let ran = join(&home, &for_me()).await;
    refused_before_writing(
        &ran,
        &format!(
            "root:{} was revoked on this machine; recovery is a new root.",
            root(ROOT)
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn join_refuses_a_locked_key_over_pipes() {
    let home = empty("locked-pipes");
    let passphrase =
        Passphrase::try_from(Zeroizing::new("correct horse battery staple".to_owned())).unwrap();
    let mut seed = TestNode::seeded(OWN).seed();
    KeyFile::device(home.key())
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .unwrap();
    let before = snapshot(home.dir());
    let stdin = format!("{}\n", for_me());
    let ran = run(
        &home,
        Setup {
            stdin: &stdin,
            prompt_terminal: false,
            ..Setup::default()
        },
    )
    .await;
    refused_before_writing(
        &ran,
        "this machine's key has a passphrase: run this with -t after --, and paste the invite at the prompt",
        &home,
        &before,
    );

    // At a terminal it joins, and says nothing about locking a key that is locked.
    let ran = join(&home, &for_me()).await;
    ran.joined();
    assert!(!ran.err.contains("is not locked"), "{}", ran.err);
}

#[tokio::test]
async fn join_refuses_a_damaged_home() {
    let home = scratch("damaged");
    // A standing from one root under a pin to another: a switch that stopped between its writes.
    config::write_badge(&home, &standing(OTHER, node(OWN), now() + 90 * DAY))
        .await
        .unwrap();
    config::write_signet(&home, root(ROOT)).await.unwrap();
    let before = snapshot(home.dir());
    let ran = join_with(&home, &for_me(), &["--switch"]).await;
    refused_before_writing(&ran, "Run swoosh leave to start over", &home, &before);
}

#[tokio::test]
async fn join_refuses_text_that_is_not_an_invite() {
    let home = scratch("not-an-invite");
    let before = snapshot(home.dir());
    let ran = join(&home, "swoosh:ed01notalink").await;
    refused_before_writing(&ran, "this is not a swoosh invite", &home, &before);
}
