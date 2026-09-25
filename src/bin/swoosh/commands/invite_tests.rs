//! `invite` over homes built on disk the way the product leaves them: the machine where the root is kept,
//! with a sealed root, its signed records and the update it last cut; a device of that root; and a fresh
//! home. Each act runs in process, with a scripted passphrase, devices that answer in memory, and a tape
//! that records what printed, when the passphrase was asked, and when the cut was offered.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Parser;
use keystore::{KeyFile, Passphrase, Protection};
use nauthy::{Cap, Link, VerifyKey};
use swoosh::config;
use swoosh::contacts::{ContactsStore, DeviceLabel};
use swoosh::home::Home;
use swoosh::invite::Invite;
use swoosh::passphrase::Prompt;
use swoosh::root::{Date, Root, RootPlace};
use swoosh::roster::{Epoch, Id, Member, RosterDoc};
use swoosh::state::{self, Row, State};
use swoosh::sync::{Answer, Dial, ExchangeError};
use swoosh::testkit::{Answering, Counting, TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;
use zeroize::Zeroizing;

use super::InviteCmd;

/// This machine's key.
const OWN: u8 = 0x11;
/// The root this machine keeps, or trusts.
const ROOT: u8 = 0x21;
/// Other devices of the root.
const LAPTOP: u8 = 0x41;
const PHONE: u8 = 0x42;
const NAS: u8 = 0x43;
/// A machine an act adds.
const TV: u8 = 0x44;
/// A device whose key came in its invite.
const CI: u8 = 0x45;
/// A device the root revoked.
const OLD: u8 = 0x46;
/// A device another copy of the root revoked.
const PAD: u8 = 0x47;
/// A device revoked on this machine only.
const WATCH: u8 = 0x48;
/// A person in the address book.
const ALICE: u8 = 0x51;

const PASS: &str = "correct horse battery staple";

const HOUR: u64 = 60 * 60;
const DAY: u64 = 24 * HOUR;
const NINETY: u64 = 90 * DAY;

static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

fn node(seed: u8) -> NodeId {
    TestNode::seeded(seed).node_id()
}

fn name(text: &str) -> DeviceLabel {
    text.parse().unwrap()
}

/// A fresh home holding this machine's key, plain.
fn scratch(tag: &str) -> Home {
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("swoosh-invite-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut seed = TestNode::seeded(OWN).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .unwrap();
    home
}

/// A standing `ROOT` signed for the device `seed`, ending at `until`.
fn standing(seed: u8, until: u64) -> Link {
    TestRoot::seeded(ROOT)
        .device_badge(
            node(seed),
            SystemTime::UNIX_EPOCH + Duration::from_secs(until),
        )
        .unwrap()
}

/// The id `standing` is revoked by, for a standing ending at `until`.
fn id_of(standing: &Link, until: u64) -> Id {
    let cap = Cap::parse(standing.as_str()).unwrap();
    Id {
        expires: until,
        id: cap.root_revocation_id().unwrap(),
    }
}

/// A row for the device `seed` named `label`, renewed for `duration` once per end in `ends`; its standing
/// is the one ending last.
fn signed(seed: u8, label: &str, duration: u64, ends: &[u64]) -> Row {
    let mut ids = Vec::new();
    let mut newest = None;
    for until in ends {
        let link = standing(seed, *until);
        ids.push(id_of(&link, *until));
        newest = Some((link, *until));
    }
    let (standing, until) = newest.unwrap();
    Row {
        key: key(seed),
        label: name(label),
        until,
        duration,
        seeded: false,
        invite_until: 0,
        revoked_on: 0,
        ids,
        standing,
    }
}

/// A live device renewed ten days ago: not due, and a renewal by name would move its date.
fn live(seed: u8, label: &str) -> Row {
    signed(seed, label, NINETY, &[now() + 80 * DAY])
}

/// A device inside the last half of its duration: due to renew.
fn due(seed: u8, label: &str) -> Row {
    signed(seed, label, NINETY, &[now() + 20 * DAY])
}

/// A device renewed an hour ago.
fn fresh(seed: u8, label: &str) -> Row {
    signed(seed, label, NINETY, &[now() + NINETY - HOUR])
}

/// A device whose date passed five days ago.
fn lapsed(seed: u8, label: &str) -> Row {
    signed(seed, label, NINETY, &[now() - 5 * DAY])
}

/// A device revoked a day ago.
fn revoked(seed: u8, label: &str) -> Row {
    Row {
        revoked_on: now() - DAY,
        ..due(seed, label)
    }
}

/// A device whose key came in its invite, which ends when its standing does.
fn carrying(row: Row) -> Row {
    Row {
        seeded: true,
        invite_until: row.until,
        ..row
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

/// The records `rows` make, with each revoked row's key revoked and `revoked` ids.
fn records(epoch: u64, rows: &[Row], revoked: Vec<Id>) -> State {
    let keys = rows
        .iter()
        .filter(|row| row.is_revoked())
        .map(|row| row.key)
        .collect();
    State::new(Epoch(epoch), rows.to_vec(), revoked, keys).unwrap()
}

/// The update carrying `state` exactly: its live rows, its revoked ids and keys.
fn update_of(state: &State) -> RosterDoc {
    RosterDoc::with_revocations(
        state.last_update(),
        state
            .rows()
            .iter()
            .filter(|row| !row.is_revoked())
            .map(member)
            .collect(),
        state.revoked().to_vec(),
        state.revoked_keys().to_vec(),
    )
    .unwrap()
}

/// `doc`, signed by `ROOT`, as the update `home` holds.
fn held(home: &Home, doc: &RosterDoc) {
    std::fs::write(home.roster(), TestRoot::seeded(ROOT).sign_update(doc)).unwrap();
}

/// `ROOT`'s key file sealed under [`PASS`], sealed once per process.
fn sealed() -> Vec<u8> {
    static SEALED: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();
    let mut cache = SEALED.get_or_init(Mutex::default).lock().unwrap();
    cache
        .get_or_insert_with(|| {
            let dir =
                std::env::temp_dir().join(format!("swoosh-invite-sealed-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            config::create_store_dir(&dir).unwrap();
            let path = dir.join("root.key");
            let passphrase = Passphrase::try_from(Zeroizing::new(PASS.to_owned())).unwrap();
            let mut seed = TestRoot::seeded(ROOT).seed();
            KeyFile::root(&path)
                .write(
                    &keystore::Secret::take(&mut seed),
                    Protection::Passphrase(&passphrase),
                )
                .unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            bytes
        })
        .clone()
}

/// A copy of `ROOT` at `dir`, holding `state`, with its lock file already made.
fn copy(dir: &Path, state: &State) {
    use std::os::unix::fs::OpenOptionsExt as _;

    config::create_store_dir(dir).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("root.key"))
        .unwrap()
        .write_all(&sealed())
        .unwrap();
    state::write(dir, &TestRoot::seeded(ROOT).sign_state(state)).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("lock"))
        .unwrap();
}

/// Make `home` a device of `ROOT`: its pin, and `own` as its standing.
async fn device_of(home: &Home, own: &Row) {
    config::write_signet(home, TestRoot::seeded(ROOT).node_id())
        .await
        .unwrap();
    config::write_badge(home, &own.standing).await.unwrap();
}

/// Make `home` keep `ROOT` with `rows` (this machine's own row first) and `revoked` ids, holding the update
/// that carries exactly those records.
async fn holds(home: &Home, rows: &[Row], revoked: Vec<Id>) {
    device_of(home, &rows[0]).await;
    let state = records(1, rows, revoked);
    copy(&home.root(), &state);
    held(home, &update_of(&state));
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

/// The records kept in `home`, read as `status` reads them.
async fn kept(home: &Home) -> State {
    Root::inspect(home, RootPlace::Home).await.unwrap().state
}

/// The row named `label` in `state`.
fn row_of<'a>(state: &'a State, label: &str) -> &'a Row {
    state
        .rows()
        .iter()
        .find(|row| row.label.as_str() == label)
        .unwrap_or_else(|| panic!("a row named {label}"))
}

/// Everything an act printed and asked, in the order it happened.
#[derive(Clone, Default)]
struct Tape(Rc<RefCell<String>>);

impl Tape {
    fn push(&self, text: &str) {
        self.0.borrow_mut().push_str(text);
    }

    fn text(&self) -> String {
        self.0.borrow().clone()
    }

    /// Where `needle` first appears, which must be somewhere.
    fn at(&self, needle: &str) -> usize {
        let text = self.text();
        text.find(needle)
            .unwrap_or_else(|| panic!("{needle:?} is on the tape: {text}"))
    }
}

/// One stream of an act, kept on its own and on the tape.
struct Stream {
    bytes: Vec<u8>,
    tape: Tape,
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        self.tape.push(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The scripted passphrase, marking the tape each time it is asked.
struct Asked {
    inner: Counting,
    terminal: bool,
    tape: Tape,
}

impl Prompt for Asked {
    fn terminal(&self) -> bool {
        self.terminal
    }

    fn unlock(&mut self, path: &Path) -> eyre::Result<Passphrase> {
        self.tape.push("<prompt>\n");
        self.inner.unlock(path)
    }

    fn choose(&mut self, path: &Path) -> eyre::Result<Passphrase> {
        self.tape.push("<prompt>\n");
        self.inner.choose(path)
    }
}

/// Devices that answer `answer` in memory, marking the tape at each offer.
struct Devices {
    inner: Answering,
    tape: Tape,
}

impl Dial for Devices {
    async fn exchange(&self, peer: NodeId) -> Result<Answer, ExchangeError> {
        self.inner.exchange(peer).await
    }

    async fn offer(
        &self,
        peer: NodeId,
        number: Epoch,
        bytes: &[u8],
    ) -> Result<Answer, ExchangeError> {
        self.tape.push("<offer>\n");
        self.inner.offer(peer, number, bytes).await
    }
}

#[derive(Debug, Parser)]
struct Cli {
    #[command(flatten)]
    invite: InviteCmd,
}

fn parse(args: &[&str]) -> InviteCmd {
    Cli::try_parse_from(core::iter::once("invite").chain(args.iter().copied()))
        .unwrap()
        .invite
}

/// What one `invite` did.
struct Ran {
    result: eyre::Result<()>,
    out: String,
    err: String,
    tape: Tape,
    prompts: usize,
}

impl Ran {
    /// The refusal, which there must be.
    fn refusal(&self) -> String {
        match &self.result {
            Ok(()) => panic!("the act refused: out {} err {}", self.out, self.err),
            Err(error) => format!("{error:#}"),
        }
    }

    /// The invite on stdout, which is its only line.
    fn invite(&self) -> Invite {
        assert!(self.result.is_ok(), "{:?}: {}", self.result, self.err);
        assert_eq!(self.out.lines().count(), 1, "one line: {}", self.out);
        Invite::parse(self.out.trim_end()).unwrap()
    }
}

/// Run `swoosh invite <args>` on `home`.
async fn invite(home: &Home, args: &[&str]) -> Ran {
    invite_at(home, args, true).await
}

/// Run `swoosh invite <args>` on `home`, at a terminal or not.
async fn invite_at(home: &Home, args: &[&str], terminal: bool) -> Ran {
    let tape = Tape::default();
    let mut out = Stream {
        bytes: Vec::new(),
        tape: tape.clone(),
    };
    let mut err = Stream {
        bytes: Vec::new(),
        tape: tape.clone(),
    };
    let mut prompt = Asked {
        inner: Counting::new([PASS]),
        terminal,
        tape: tape.clone(),
    };
    let dial = Devices {
        inner: Answering::with(Answer::Same),
        tape: tape.clone(),
    };
    let cmd = parse(args);
    let result = if cmd.name.is_some() {
        cmd.issue(home, &mut prompt, &dial, &mut out, &mut err)
            .await
    } else {
        cmd.due(home, &mut out, &mut err).await
    };
    Ran {
        result,
        out: String::from_utf8(out.bytes).unwrap(),
        err: String::from_utf8(err.bytes).unwrap(),
        tape,
        prompts: prompt.inner.events(),
    }
}

/// Assert `ran` refused with `line`, before any prompt, leaving `home` as `before`.
fn refused_before_writing(ran: &Ran, line: &str, home: &Home, before: &BTreeMap<PathBuf, Vec<u8>>) {
    let refusal = ran.refusal();
    assert!(refusal.contains(line), "{refusal}");
    assert_eq!(ran.prompts, 0, "refused before the passphrase");
    assert!(ran.out.is_empty(), "nothing on stdout: {}", ran.out);
    assert!(
        snapshot(home.dir()) == *before,
        "the home is unchanged after: {refusal}"
    );
}

// --- the forms and their refusals ---

#[tokio::test]
async fn invite_unknown_label_without_key_or_new_key_refuses_and_writes_nothing() {
    let home = scratch("unknown");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["phone"]).await;
    refused_before_writing(
        &ran,
        "you have no device phone. For a machine with no console: swoosh invite phone --new-key. \
         Otherwise: swoosh invite phone <its key>.",
        &home,
        &before,
    );
}

#[tokio::test]
async fn invite_live_label_other_key_refuses() {
    let home = scratch("other-key");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["laptop", &node(PHONE).to_string()]).await;
    refused_before_writing(
        &ran,
        &format!(
            "me/laptop is {}…. To replace it: swoosh revoke me/laptop, then invite the new key.",
            swoosh::credential::short(&key(LAPTOP))
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn invite_new_key_on_a_self_keyed_device_refuses() {
    let home = scratch("self-keyed");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["laptop", "--new-key"]).await;
    refused_before_writing(
        &ran,
        "me/laptop keeps its own key; renew it without --new-key. For a new key: on it, swoosh leave \
         --new-key; then here, swoosh revoke me/laptop and invite the new key.",
        &home,
        &before,
    );
}

#[tokio::test]
async fn invite_label_that_is_a_contact_refuses() {
    let home = scratch("contact");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let mut store = ContactsStore::open(home.contacts()).await.unwrap();
    store
        .contacts_mut()
        .add("alice".parse().unwrap(), None, node(ALICE));
    store.save().await.unwrap();
    let before = snapshot(home.dir());
    let ran = invite(&home, &["alice", &node(TV).to_string()]).await;
    refused_before_writing(
        &ran,
        "alice is a contact: to let alice use a service, swoosh share <service> alice",
        &home,
        &before,
    );
}

#[test]
fn invite_refuses_a_name_outside_the_rule() {
    let key = node(TV).to_string();
    for bad in ["bad.name", "under_score", &"a".repeat(64)] {
        let error = Cli::try_parse_from(["invite", bad, key.as_str()])
            .expect_err("a name outside the rule is refused");
        assert_eq!(error.exit_code(), 2, "{bad}: a usage error");
        let rule = bad.parse::<DeviceLabel>().unwrap_err().to_string();
        assert!(
            error.to_string().contains(&rule),
            "{bad}: the rule's line: {error}"
        );
    }
    let error = Cli::try_parse_from(["invite", "bad.name", key.as_str()]).unwrap_err();
    assert!(
        error.to_string().contains(
            "bad.name is not a name: a name uses a-z, 0-9 and -, and starts with a letter or digit."
        ),
        "{error}"
    );
}

/// Text that is a key is never a name: typed where the name goes, it is refused, naming the form that
/// takes a key; one nobody can hold is refused with the line every typed key refuses with.
#[test]
fn invite_refuses_a_key_typed_as_the_name() {
    let key = node(TV).to_string();
    for args in [vec![key.as_str()], vec![key.as_str(), "--new-key"]] {
        let error = Cli::try_parse_from(core::iter::once("invite").chain(args))
            .expect_err("a key is not a name");
        assert_eq!(error.exit_code(), 2, "a usage error");
        assert!(
            error.to_string().contains(&format!(
                "{key} is a key, not a name: swoosh invite <name> {key}"
            )),
            "{error}"
        );
    }
    let torsioned = swoosh::testkit::torsioned_text();
    let error = Cli::try_parse_from(["invite", torsioned.as_str()]).unwrap_err();
    assert_eq!(error.exit_code(), 2);
    assert!(
        error.to_string().contains(&format!(
            "{torsioned} is not a usable key: carries a torsion component"
        )),
        "{error}"
    );
}

/// A torsioned key is refused as the key an invite admits, naming the check it failed, never read as a
/// name to renew.
#[test]
fn a_torsioned_key_is_refused_as_an_invite_key() {
    let key = swoosh::testkit::torsioned_text();
    let error = Cli::try_parse_from(["invite", "tv", key.as_str()])
        .expect_err("a torsioned key is refused");
    assert_eq!(error.exit_code(), 2, "a typed bad key is a usage error");
    let error = error.to_string();
    assert!(
        error.contains(&format!(
            "{key} is not a usable key: carries a torsion component"
        )),
        "the refusal names the key and the check: {error}"
    );
    assert!(!error.contains("to renew"), "{error}");
}

#[test]
fn invite_refuses_a_reserved_name() {
    let key = node(TV).to_string();
    for reserved in ["me", "root", "anyone"] {
        let error = Cli::try_parse_from(["invite", reserved, key.as_str()])
            .expect_err("a reserved name is refused");
        assert_eq!(error.exit_code(), 2, "{reserved}: a usage error");
    }
}

#[tokio::test]
async fn invite_refuses_this_machines_key() {
    let home = scratch("own-key");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["tv", &node(OWN).to_string()]).await;
    refused_before_writing(
        &ran,
        "that is this machine's key; it is already your device me/desk",
        &home,
        &before,
    );
}

#[tokio::test]
async fn invite_refuses_on_a_device_without_the_root() {
    let home = scratch("device");
    let own = live(OWN, "desk");
    device_of(&home, &own).await;
    held(&home, &update_of(&records(1, &[own], Vec::new())));
    let before = snapshot(home.dir());
    let ran = invite(&home, &["tv", &node(TV).to_string()]).await;
    refused_before_writing(
        &ran,
        "your root is not on this machine: run this where it is, or add --root <dir>.",
        &home,
        &before,
    );
}

/// A root whose making or restore stopped before its pin: what its records refuse is refused before the
/// passphrase, and nothing is finished or written.
#[tokio::test]
async fn invite_refuses_on_a_half_made_root_before_the_prompt() {
    let home = scratch("half-made");
    copy(
        &home.root(),
        &records(0, &[live(OWN, "desk"), live(LAPTOP, "laptop")], Vec::new()),
    );
    let before = snapshot(home.dir());
    let ran = invite(&home, &["phone"]).await;
    refused_before_writing(&ran, "you have no device phone.", &home, &before);
    let ran = invite(&home, &["tv", &node(OWN).to_string()]).await;
    refused_before_writing(
        &ran,
        "that is this machine's key; it is already your device me/desk",
        &home,
        &before,
    );
    let ran = invite(&home, &["laptop", &node(PHONE).to_string()]).await;
    refused_before_writing(&ran, "me/laptop is ", &home, &before);
}

#[tokio::test]
async fn invite_with_two_positionals_always_reads_name_and_key() {
    let cmd = parse(&["laptop", "nas"]);
    assert_eq!(cmd.name, Some(name("laptop")));
    assert_eq!(cmd.key.as_deref(), Some("nas"));

    let home = scratch("two-names");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop"), live(NAS, "nas")],
        Vec::new(),
    )
    .await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["laptop", "nas"]).await;
    refused_before_writing(&ran, "nas is not a key", &home, &before);
}

#[tokio::test]
async fn invite_second_positional_that_is_not_a_key_refuses() {
    let home = scratch("not-a-key");
    holds(&home, &[live(OWN, "desk"), live(NAS, "nas")], Vec::new()).await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["tv", "nas"]).await;
    refused_before_writing(
        &ran,
        "nas is not a key: to renew nas, swoosh invite nas",
        &home,
        &before,
    );
}

// --- bare `invite` ---

#[tokio::test]
async fn bare_invite_lists_due_and_writes_nothing() {
    let home = scratch("bare");
    holds(
        &home,
        &[live(OWN, "desk"), due(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &[]).await;
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(ran.out, "swoosh invite laptop\n");
    assert_eq!(ran.prompts, 0, "bare invite never asks");
    assert!(snapshot(home.dir()) == before, "bare invite writes nothing");
}

#[tokio::test]
async fn bare_invite_lists_only_due_devices() {
    let now = now();
    let home = scratch("bare-only-due");
    let rows = [
        live(OWN, "desk"),
        due(LAPTOP, "laptop"),
        live(PHONE, "phone"),
        // In its window, but at four renewals in force: the renewal skips it, so it is not due.
        signed(
            NAS,
            "nas",
            NINETY,
            &[
                now + 5 * DAY,
                now + 10 * DAY,
                now + 15 * DAY,
                now + 20 * DAY,
            ],
        ),
        lapsed(TV, "tv"),
        carrying(due(CI, "ci")),
        revoked(OLD, "old"),
        // Due in the records, but revoked by another copy of the root: the update held here says so.
        due(PAD, "pad"),
        // Due in the records, but its key revoked on this machine only.
        due(WATCH, "watch"),
    ];
    holds(&home, &rows, Vec::new()).await;
    let state = records(1, &rows, Vec::new());
    let mut keys = state.revoked_keys().to_vec();
    keys.push(key(PAD));
    let members = rows
        .iter()
        .filter(|row| !row.is_revoked() && row.key != key(PAD))
        .map(member)
        .collect();
    held(
        &home,
        &RosterDoc::with_revocations(Epoch(2), members, Vec::new(), keys).unwrap(),
    );
    std::fs::write(home.revoked_keys(), format!("{}\n", key(WATCH))).unwrap();
    let ran = invite(&home, &[]).await;
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(ran.out, "swoosh invite laptop\n");
}

#[tokio::test]
async fn bare_invite_prints_one_line_per_due_device() {
    let home = scratch("bare-each");
    holds(
        &home,
        &[
            live(OWN, "desk"),
            due(LAPTOP, "laptop"),
            due(PHONE, "phone"),
        ],
        Vec::new(),
    )
    .await;
    let ran = invite(&home, &[]).await;
    let mut lines: Vec<&str> = ran.out.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines, ["swoosh invite laptop", "swoosh invite phone"]);
}

// --- what an act renews on its own ---

/// Add the TV: an act that cuts, and so renews whatever is due.
async fn add_tv(home: &Home) -> Ran {
    let ran = invite(home, &["tv", &node(TV).to_string()]).await;
    assert!(ran.result.is_ok(), "{:?}: {}", ran.result, ran.err);
    ran
}

#[tokio::test]
async fn a_seeded_row_is_never_renewed_on_its_own() {
    let home = scratch("seeded");
    let ci = carrying(due(CI, "ci"));
    let laptop = due(LAPTOP, "laptop");
    holds(
        &home,
        &[live(OWN, "desk"), ci.clone(), laptop.clone()],
        Vec::new(),
    )
    .await;
    add_tv(&home).await;
    let state = kept(&home).await;
    assert_eq!(
        row_of(&state, "ci").until,
        ci.until,
        "a key-carrying row waits"
    );
    assert!(
        row_of(&state, "laptop").until > laptop.until,
        "a due row renews"
    );
}

#[tokio::test]
async fn renewal_skips_a_revoked_device() {
    let home = scratch("skip-revoked");
    let old = revoked(OLD, "old");
    holds(&home, &[live(OWN, "desk"), old.clone()], Vec::new()).await;
    add_tv(&home).await;
    assert_eq!(row_of(&kept(&home).await, "old").until, old.until);
}

#[tokio::test]
async fn renewal_skips_a_row_whose_key_is_revoked() {
    let home = scratch("skip-revoked-key");
    let laptop = due(LAPTOP, "laptop");
    let own = live(OWN, "desk");
    holds(&home, &[own.clone(), laptop.clone()], Vec::new()).await;
    // Another copy of the root revoked the laptop; the update this machine holds says so.
    let elsewhere =
        RosterDoc::with_revocations(Epoch(2), vec![member(&own)], Vec::new(), vec![key(LAPTOP)])
            .unwrap();
    held(&home, &elsewhere);
    add_tv(&home).await;
    let state = kept(&home).await;
    let row = row_of(&state, "laptop");
    assert_eq!(row.until, laptop.until, "a revoked key is never renewed");
    assert!(row.is_revoked());
}

#[tokio::test]
async fn renewal_keeps_a_row_with_only_a_capped_revoked_id() {
    let now = now();
    let home = scratch("capped-id");
    let laptop = signed(LAPTOP, "laptop", NINETY, &[now + 10 * DAY, now + 20 * DAY]);
    let capped = laptop.ids[0].clone();
    holds(&home, &[live(OWN, "desk"), laptop.clone()], vec![capped]).await;
    add_tv(&home).await;
    let state = kept(&home).await;
    let row = row_of(&state, "laptop");
    assert!(!row.is_revoked(), "a revoked id alone never marks its row");
    assert!(row.until > laptop.until, "and the row renews");
}

#[tokio::test]
async fn renewal_never_revives_an_expired_device_on_its_own() {
    let home = scratch("expired");
    let laptop = lapsed(LAPTOP, "laptop");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    add_tv(&home).await;
    assert_eq!(row_of(&kept(&home).await, "laptop").until, laptop.until);
}

#[tokio::test]
async fn a_renewal_runs_its_full_duration_from_now() {
    let home = scratch("full-duration");
    holds(
        &home,
        &[live(OWN, "desk"), due(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let before = now();
    add_tv(&home).await;
    let after = now();
    let until = row_of(&kept(&home).await, "laptop").until;
    assert!(
        (before + NINETY..=after + NINETY).contains(&until),
        "{until} runs 90 days from the act"
    );
}

#[tokio::test]
async fn a_short_lived_device_is_never_renewed_on_its_own() {
    let home = scratch("short-lived");
    let laptop = signed(LAPTOP, "laptop", 20 * DAY, &[now() + 5 * DAY]);
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    add_tv(&home).await;
    assert_eq!(row_of(&kept(&home).await, "laptop").until, laptop.until);
}

#[tokio::test]
async fn a_replayed_update_never_shortens_a_standing() {
    let home = scratch("replayed");
    let own = live(OWN, "desk");
    let laptop = live(LAPTOP, "laptop");
    holds(&home, &[own.clone(), laptop.clone()], Vec::new()).await;
    // A newer update that carries an older, shorter standing for the laptop.
    let shorter = signed(LAPTOP, "laptop", NINETY, &[now() + 30 * DAY]);
    let replay = RosterDoc::new(Epoch(2), vec![member(&own), member(&shorter)]).unwrap();
    held(&home, &replay);
    add_tv(&home).await;
    let state = kept(&home).await;
    let row = row_of(&state, "laptop");
    assert_eq!(row.until, laptop.until);
    assert_eq!(row.standing.as_str(), laptop.standing.as_str());
}

#[tokio::test]
async fn renewal_prints_its_list_before_the_prompt() {
    let home = scratch("list-first");
    holds(
        &home,
        &[live(OWN, "desk"), due(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = add_tv(&home).await;
    let listed = format!(
        "renewing 1 device: me/laptop ({}…)",
        swoosh::credential::short(&key(LAPTOP))
    );
    assert!(ran.tape.at(&listed) < ran.tape.at("<prompt>"));
}

// --- renewing by name ---

#[tokio::test]
async fn renewing_a_lapsed_row_prints_its_key_and_the_revoke_line_before_the_prompt() {
    let laptop = lapsed(LAPTOP, "laptop");
    let line = format!(
        "renewing me/laptop ({key}), which ended on {}. Whatever machine holds {key} picks this up the \
         next time it reaches one of your devices. If that is not a machine you still have, stop here and \
         run: swoosh revoke me/laptop",
        Date(laptop.until),
        key = key(LAPTOP)
    );

    let home = scratch("lapsed-line");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    let ran = invite(&home, &["laptop"]).await;
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert!(ran.tape.at(&line) < ran.tape.at("<prompt>"));

    // At no terminal, the line still prints, before anything is signed.
    let home = scratch("lapsed-line-no-terminal");
    holds(&home, &[live(OWN, "desk"), laptop], Vec::new()).await;
    let before = snapshot(home.dir());
    let ran = invite_at(&home, &["laptop"], false).await;
    assert!(ran.result.is_err());
    assert!(ran.err.contains(&line), "{}", ran.err);
    assert!(snapshot(home.dir()) == before, "nothing signed");
}

#[tokio::test]
async fn a_named_renewal_at_four_prints_the_stored_standing() {
    let now = now();
    let home = scratch("at-four");
    let laptop = signed(
        LAPTOP,
        "laptop",
        NINETY,
        &[
            now + 50 * DAY,
            now + 55 * DAY,
            now + 60 * DAY,
            now + 65 * DAY,
        ],
    );
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    let ran = invite(&home, &["laptop"]).await;
    assert_eq!(
        ran.invite().standing.as_str(),
        laptop.standing.as_str(),
        "the stored standing, never a refusal"
    );
    assert_eq!(
        ran.err,
        format!(
            "me/laptop needs no renewal (until {}). If it left, or its date passed, on it: swoosh join and \
             paste this line.\n",
            Date(laptop.until)
        )
    );
}

#[tokio::test]
async fn a_named_renewal_under_a_day_signs_nothing() {
    let home = scratch("under-a-day");
    let laptop = fresh(LAPTOP, "laptop");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["laptop"]).await;
    assert_eq!(ran.invite().standing.as_str(), laptop.standing.as_str());
    assert_eq!(ran.prompts, 0, "no prompt");
    assert!(snapshot(home.dir()) == before, "nothing signed or written");
}

#[tokio::test]
async fn invite_own_name_prints_no_join_line() {
    let own = fresh(OWN, "desk");
    let alone = format!("me/desk needs no renewal (until {}).\n", Date(own.until));

    // Nothing else to sign: the stored standing, with no lock or prompt.
    let home = scratch("own-name");
    holds(&home, core::slice::from_ref(&own), Vec::new()).await;
    let ran = invite(&home, &["desk"]).await;
    assert_eq!(ran.invite().standing.as_str(), own.standing.as_str());
    assert_eq!(ran.prompts, 0);
    assert_eq!(ran.err, alone);

    // Something else to sign: after the unlock, the same line alone.
    let home = scratch("own-name-cut");
    holds(&home, &[own.clone(), due(LAPTOP, "laptop")], Vec::new()).await;
    let ran = invite(&home, &["desk"]).await;
    assert_eq!(ran.invite().standing.as_str(), own.standing.as_str());
    assert_eq!(ran.prompts, 1);
    assert!(ran.err.contains(&alone), "{}", ran.err);
    assert!(!ran.err.contains("swoosh join"), "{}", ran.err);
}

#[tokio::test]
async fn invite_revives_a_lapsed_device_by_name() {
    let home = scratch("revive");
    holds(
        &home,
        &[live(OWN, "desk"), lapsed(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = invite(&home, &["laptop"]).await;
    let printed = ran.invite();
    let state = kept(&home).await;
    let row = row_of(&state, "laptop");
    assert!(row.until > now(), "the lapsed device runs again");
    assert_eq!(printed.standing.as_str(), row.standing.as_str());
    assert!(printed.seed.is_none(), "a bound invite");
}

#[tokio::test]
async fn a_named_renewal_of_a_device_revoked_here_prints_no_standing_and_cuts() {
    // Its standing revoked on this machine only: renewing it signs a new one, and the cut carries the
    // revocation.
    let home = scratch("revoked-here-id");
    let laptop = fresh(LAPTOP, "laptop");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    std::fs::write(home.revoked(), format!("{}\n", laptop.ids[0].id.to_hex())).unwrap();
    let ran = invite(&home, &["laptop"]).await;
    let printed = ran.invite();
    assert_ne!(
        printed.standing.as_str(),
        laptop.standing.as_str(),
        "never the revoked standing"
    );
    assert_eq!(ran.prompts, 1);
    let update = swoosh::roster::held(&home, TestRoot::seeded(ROOT).verify_key()).unwrap();
    assert_eq!(update.epoch(), Epoch(2), "cut");
    assert!(
        update.revoked().iter().any(|id| id.id == laptop.ids[0].id),
        "the cut carries the revocation"
    );

    // Its key revoked on this machine only: it is no device to renew.
    let home = scratch("revoked-here-key");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    std::fs::write(home.revoked_keys(), format!("{}\n", key(LAPTOP))).unwrap();
    let ran = invite(&home, &["laptop"]).await;
    assert!(ran.result.is_err());
    assert!(ran.out.is_empty(), "never its standing: {}", ran.out);
}

#[tokio::test]
async fn a_capped_oldest_id_on_an_offline_device_rejoins_by_named_renew() {
    let now = now();
    let home = scratch("capped-rejoin");
    let own = live(OWN, "desk");
    let ends = [
        now + 50 * DAY,
        now + 55 * DAY,
        now + 60 * DAY,
        now + 65 * DAY,
    ];
    let laptop = signed(LAPTOP, "laptop", NINETY, &ends);
    holds(&home, &[own.clone(), laptop.clone()], Vec::new()).await;
    // Another copy renewed it once more, and its update carries its four newest: bringing that forward
    // holds five, and caps the oldest.
    let elsewhere = signed(
        LAPTOP,
        "laptop",
        NINETY,
        &[ends[1], ends[2], ends[3], now + 70 * DAY],
    );
    held(
        &home,
        &RosterDoc::new(Epoch(2), vec![member(&own), member(&elsewhere)]).unwrap(),
    );
    let ran = invite(&home, &["laptop"]).await;
    let printed = ran.invite();
    assert_eq!(
        printed.standing.as_str(),
        elsewhere.standing.as_str(),
        "the newest standing, which the cap kept"
    );
    let state = kept(&home).await;
    assert!(
        state
            .revoked()
            .iter()
            .all(|id| id.id != elsewhere.ids[3].id),
        "the printed standing is not revoked"
    );
    assert!(
        state.revoked().iter().any(|id| id.id == laptop.ids[0].id),
        "the oldest was capped"
    );
}

// --- `--new-key` ---

#[tokio::test]
async fn invite_new_key_signs_the_same_day_as_an_automatic_renewal() {
    let home = scratch("new-key-same-day");
    holds(
        &home,
        &[live(OWN, "desk"), carrying(fresh(CI, "ci"))],
        Vec::new(),
    )
    .await;
    let ran = invite(&home, &["ci", "--new-key"]).await;
    assert!(ran.invite().seed.is_some(), "a key-carrying invite");
    assert_eq!(ran.prompts, 1);
}

#[tokio::test]
async fn invite_new_key_refuses_a_row_that_keeps_its_key() {
    let home = scratch("new-key-own");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["laptop", "--new-key"]).await;
    refused_before_writing(
        &ran,
        "me/laptop keeps its own key; renew it without --new-key.",
        &home,
        &before,
    );
}

#[tokio::test]
async fn invite_new_key_refuses_a_row_at_four_renewals() {
    let now = now();
    let home = scratch("new-key-four");
    let ends = [
        now + 50 * DAY,
        now + 55 * DAY,
        now + 60 * DAY,
        now + 65 * DAY,
    ];
    holds(
        &home,
        &[live(OWN, "desk"), carrying(signed(CI, "ci", NINETY, &ends))],
        Vec::new(),
    )
    .await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["ci", "--new-key"]).await;
    refused_before_writing(
        &ran,
        &format!(
            "me/ci has 4 renewals in force until {}. To hand it a new key now: swoosh revoke me/ci, then \
             swoosh invite ci --new-key.",
            Date(ends[0])
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn a_key_carrying_invite_says_who_holding_it_becomes() {
    let home = scratch("keyed-lines");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let ran = invite(&home, &["tv", "--new-key"]).await;
    assert!(ran.invite().seed.is_some(), "a key-carrying invite");
    let until = row_of(&kept(&home).await, "tv").until;
    let date = Date(until);
    assert_eq!(
        ran.err,
        format!(
            "me/tv will be one of your own devices: it reaches everything your devices serve.\n\
             me/tv runs 90d from now, until {date} (the default; --expires sets 1h to 365d).\n\
             anyone holding this invite becomes me/tv until {date}: send it privately.\n\
             it ends on {date} and is not renewed on its own\n"
        )
    );
}

#[tokio::test]
async fn invite_new_key_leaves_the_old_invite_valid_to_its_date() {
    let home = scratch("new-key-old");
    let ci = carrying(live(CI, "ci"));
    holds(&home, &[live(OWN, "desk"), ci.clone()], Vec::new()).await;
    let ran = invite(&home, &["ci", "--new-key"]).await;
    let printed = ran.invite();
    let seed = printed.seed.as_deref().copied().unwrap();
    let new = NodeId::from_ed25519_secret(&seed).verify_key().unwrap();
    let state = kept(&home).await;
    let row = row_of(&state, "ci");
    assert_eq!(row.key, new, "the row takes the new key");
    assert!(
        row.ids.contains(&ci.ids[0]),
        "the old key's id stays in the row"
    );
    assert!(!state.revoked().contains(&ci.ids[0]), "and is not revoked");
    assert!(
        !state.revoked_keys().contains(&key(CI)),
        "the old key is not revoked"
    );
    assert!(
        ran.err.contains(&format!(
            "The old invite works until {}.",
            Date(ci.invite_until)
        )),
        "{}",
        ran.err
    );
}

#[tokio::test]
async fn a_bound_renewal_of_a_key_carrying_row_keeps_the_warning() {
    let now = now();
    let home = scratch("bound-keeps-warning");
    // Its invite ends in ten days; its standing was signed eighty days ago.
    let ci = Row {
        invite_until: now + 10 * DAY,
        ..carrying(signed(CI, "ci", NINETY, &[now + 10 * DAY]))
    };
    holds(&home, &[live(OWN, "desk"), ci.clone()], Vec::new()).await;
    let ran = invite(&home, &["ci"]).await;
    assert!(ran.invite().seed.is_none(), "a bound invite");
    let state = kept(&home).await;
    let row = row_of(&state, "ci");
    assert!(row.until > ci.until, "renewed");
    assert_eq!(row.invite_until, ci.invite_until, "its invite's end stays");
    let stored = swoosh::identity::inspect(&home).unwrap().into_stored();
    let report = crate::commands::status::report::Report::gather(&home, &stored, now)
        .await
        .unwrap()
        .render();
    assert!(
        report.contains(&format!(
            "me/ci's key came in its invite, which ends on {}.",
            Date(ci.invite_until)
        )),
        "{report}"
    );
}

// --- the invite printed (84's add rules) ---

#[tokio::test]
async fn a_revoked_key_is_not_re_admitted() {
    let home = scratch("revoked-key");
    let old = revoked(OLD, "old");
    holds(&home, &[live(OWN, "desk"), old.clone()], Vec::new()).await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["new", &node(OLD).to_string()]).await;
    refused_before_writing(
        &ran,
        &format!(
            "{}… was revoked on {}; a revoked key is not re-admitted. On that machine: swoosh leave \
             --new-key, then invite the new key.",
            swoosh::credential::short(&key(OLD)),
            Date(old.revoked_on)
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn a_key_in_revoked_keys_is_not_re_admitted() {
    let home = scratch("revoked-keys");
    let own = live(OWN, "desk");
    holds(&home, core::slice::from_ref(&own), Vec::new()).await;
    // Another copy of the root added the laptop and revoked it; this copy never had a row for it, and
    // the update this machine holds carries only its key.
    held(
        &home,
        &RosterDoc::with_revocations(Epoch(2), vec![member(&own)], Vec::new(), vec![key(LAPTOP)])
            .unwrap(),
    );
    let ran = invite(&home, &["laptop", &node(LAPTOP).to_string()]).await;
    let refusal = ran.refusal();
    assert!(
        refusal.contains("a revoked key is not re-admitted"),
        "{refusal}"
    );
    assert_eq!(ran.prompts, 0);
}

#[tokio::test]
async fn an_invite_after_revoke_carries_a_new_key() {
    let home = scratch("after-revoke");
    holds(
        &home,
        &[live(OWN, "desk"), carrying(revoked(CI, "ci"))],
        Vec::new(),
    )
    .await;
    let ran = invite(&home, &["ci", "--new-key"]).await;
    let seed = ran.invite().seed.as_deref().copied().unwrap();
    assert_ne!(
        NodeId::from_ed25519_secret(&seed).verify_key().unwrap(),
        key(CI),
        "never the revoked key"
    );
}

#[tokio::test]
async fn two_invites_for_one_label_never_share_a_key() {
    let mut seeds = Vec::new();
    for tag in ["one-label-a", "one-label-b"] {
        let home = scratch(tag);
        holds(&home, &[live(OWN, "desk")], Vec::new()).await;
        let ran = invite(&home, &["ci", "--new-key"]).await;
        seeds.push(ran.invite().seed.as_deref().copied().unwrap());
    }
    assert_ne!(seeds[0], seeds[1]);
}

#[tokio::test]
async fn invite_for_a_key_under_another_name_is_refused() {
    let home = scratch("another-name");
    let laptop = live(LAPTOP, "laptop");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["tablet", &node(LAPTOP).to_string()]).await;
    refused_before_writing(
        &ran,
        &format!(
            "{}… is already your device me/laptop (until {}). To renew it: swoosh invite laptop. A machine \
             has one name.",
            swoosh::credential::short(&key(LAPTOP)),
            Date(laptop.until)
        ),
        &home,
        &before,
    );
}

#[tokio::test]
async fn the_invite_names_its_device_before_the_first_sync() {
    let home = scratch("names");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let printed = add_tv(&home).await.invite();
    assert_eq!(printed.name, name("tv"));
    assert_eq!(printed.from, node(OWN), "from this machine");
    let cap = Cap::parse(printed.standing.as_str()).unwrap();
    assert_eq!(cap.root(), TestRoot::seeded(ROOT).verify_key());
}

#[tokio::test]
async fn the_invite_prints_only_after_commit() {
    let home = scratch("after-commit");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    // The cut cannot be kept here: the commit fails.
    std::fs::remove_file(home.roster()).unwrap();
    std::fs::create_dir(home.roster()).unwrap();
    let ran = invite(&home, &["tv", &node(TV).to_string()]).await;
    assert!(ran.result.is_err());
    assert!(ran.out.is_empty(), "no invite: {}", ran.out);
}

#[tokio::test]
async fn the_invite_prints_before_the_offer() {
    let home = scratch("before-offer");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = add_tv(&home).await;
    let printed = ran.out.trim_end().to_owned();
    assert!(ran.tape.at(&printed) < ran.tape.at("<offer>"));
}

#[tokio::test]
async fn invite_stdout_is_only_the_invite() {
    let home = scratch("stdout");
    holds(
        &home,
        &[live(OWN, "desk"), due(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = add_tv(&home).await;
    let printed = ran.invite();
    assert_eq!(ran.out, format!("{printed}\n"));
    assert!(
        ran.err.contains(
            "me/tv will be one of your own devices: it reaches everything your devices serve."
        ),
        "{}",
        ran.err
    );
}

// --- the root, presented and kept ---

#[tokio::test]
async fn a_sealed_root_prompts_exactly_once_per_verb() {
    let home = scratch("once");
    holds(
        &home,
        &[live(OWN, "desk"), due(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = add_tv(&home).await;
    assert_eq!(ran.prompts, 1, "one prompt, the cut included");
}

#[tokio::test]
async fn a_presented_root_leaves_no_root_record_here() {
    let home = scratch("presented");
    let own = live(OWN, "desk");
    device_of(&home, &own).await;
    let state = records(1, &[own], Vec::new());
    held(&home, &update_of(&state));
    let dir = home.dir().with_extension("copy");
    let _ = std::fs::remove_dir_all(&dir);
    copy(&dir, &state);
    let dir_text = dir.to_str().unwrap().to_owned();
    let ran = invite(&home, &["tv", &node(TV).to_string(), "--root", &dir_text]).await;
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert!(!home.root().exists(), "no root.key here");
    assert!(!home.dir().join(state::FILE).exists(), "no state here");
    assert!(home.roster().is_file(), "the cut is kept here");
}

#[tokio::test]
async fn a_root_act_folds_its_own_cut_here() {
    let home = scratch("folds");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    add_tv(&home).await;
    let update = swoosh::roster::held(&home, TestRoot::seeded(ROOT).verify_key()).unwrap();
    assert!(
        update.members().iter().any(|member| member.node == key(TV)),
        "the new device is in the update this machine holds"
    );
}

#[tokio::test]
async fn a_failed_invite_writes_nothing() {
    let home = scratch("failed");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let before = snapshot(home.dir());
    let ran = invite(&home, &["tablet", &node(LAPTOP).to_string()]).await;
    refused_before_writing(&ran, "is already your device me/laptop", &home, &before);
}

// --- the device's side: joining what `invite` prints ---

#[derive(Debug, Parser)]
struct JoinCli {
    #[command(flatten)]
    join: crate::commands::join::JoinCmd,
}

/// A fresh home holding the key `seed`, plain: another machine than the one where the root is kept.
fn machine(tag: &str, seed: u8) -> Home {
    let home = scratch(tag);
    std::fs::remove_file(home.key()).unwrap();
    let mut bytes = TestNode::seeded(seed).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut bytes), Protection::Plain)
        .unwrap();
    home
}

/// `swoosh join` on `home`, with `invite` on stdin; what it printed on stderr.
async fn join(home: &Home, invite: &str) -> eyre::Result<String> {
    let cmd = JoinCli::try_parse_from(["join"]).unwrap().join;
    let stdin = format!("{invite}\n");
    let mut err = Vec::new();
    cmd.admit(
        home,
        crate::commands::join::Io {
            input: stdin.as_bytes(),
            input_terminal: false,
            prompt: &Counting::refusing(),
            hostname: "laptop",
            now: SystemTime::now(),
            err: &mut err,
        },
    )
    .await?;
    Ok(String::from_utf8(err).unwrap())
}

/// When `home`'s device standing ends, in unix seconds, if it is a device.
async fn device_until(home: &Home) -> Option<u64> {
    match swoosh::standing::Standing::read(home)
        .await
        .unwrap()
        .standing
    {
        swoosh::standing::Standing::Device { until, .. } => Some(
            until
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ),
        _ => None,
    }
}

#[tokio::test]
async fn a_lapsed_offline_device_renews_by_joining_the_printed_invite() {
    let home = scratch("lapsed-join-root");
    let laptop = lapsed(LAPTOP, "laptop");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    // The device, down while its standing ended: it holds the lapsed standing, which no device of the root
    // admits, so it cannot pull the renewal.
    let device = machine("lapsed-join-device", LAPTOP);
    device_of(&device, &laptop).await;
    assert_eq!(device_until(&device).await, Some(laptop.until));

    let ran = invite(&home, &["laptop"]).await;
    let printed = ran.invite();
    join(&device, &printed.to_string()).await.unwrap();
    let until = device_until(&device).await.expect("still a device");
    assert!(
        until > now(),
        "the device runs again, from the printed line"
    );
    assert_eq!(until, row_of(&kept(&home).await, "laptop").until);
}

#[tokio::test]
async fn a_machine_that_left_just_after_joining_rejoins_by_renew() {
    let home = scratch("left-rejoin-root");
    let laptop = fresh(LAPTOP, "laptop");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    let device = machine("left-rejoin-device", LAPTOP);
    let first = Invite::bound(node(OWN), name("laptop"), laptop.standing.clone());
    join(&device, &first.to_string()).await.unwrap();

    // It leaves an hour after joining.
    let cmd = LeaveCli::try_parse_from(["leave"]).unwrap().leave;
    cmd.leave(
        &device,
        &mut Counting::refusing(),
        SystemTime::now(),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(device_until(&device).await, None);

    // A renewal under a day signs nothing and prints the stored standing, which it joins again.
    let ran = invite(&home, &["laptop"]).await;
    assert_eq!(ran.prompts, 0);
    assert!(
        ran.err
            .contains("If it left, or its date passed, on it: swoosh join"),
        "{}",
        ran.err
    );
    join(&device, &ran.invite().to_string()).await.unwrap();
    assert_eq!(device_until(&device).await, Some(laptop.until));
}

#[derive(Debug, Parser)]
struct LeaveCli {
    #[command(flatten)]
    leave: crate::commands::leave::LeaveCmd,
}

#[tokio::test]
async fn every_making_verb_prints_only_its_artifact_on_stdout() {
    // `invite <name> <key>`: the invite.
    let home = scratch("artifacts");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let ran = add_tv(&home).await;
    let printed = ran.invite();
    assert_eq!(ran.out, format!("{printed}\n"));
    assert!(!ran.err.is_empty(), "the lines about it go to stderr");

    // `status --key`: the key.
    let home = machine("artifacts-status", TV);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    crate::commands::status::report::run_to(
        &home,
        crate::commands::status::report::Print::Key,
        &mut out,
        &mut err,
    )
    .await
    .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), format!("{}\n", node(TV)));

    // `leave --new-key`: the new key.
    let cmd = LeaveCli::try_parse_from(["leave", "--new-key"])
        .unwrap()
        .leave;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    cmd.leave(
        &home,
        &mut Counting::refusing(),
        SystemTime::now(),
        &mut out,
        &mut err,
    )
    .await
    .unwrap();
    let key = KeyFile::device(home.key())
        .load()
        .unwrap()
        .unwrap()
        .node_id();
    assert_eq!(String::from_utf8(out).unwrap(), format!("{key}\n"));
    assert!(!err.is_empty(), "the lines about it go to stderr");
}
