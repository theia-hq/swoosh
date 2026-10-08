//! `revoke` over homes built on disk the way the product leaves them, with the same builders `invite`'s
//! tests use: the machine where the root is kept, a device of that root with or without a copy of it, and
//! a fresh home. Each revoke runs in process, with a scripted passphrase and devices that answer in
//! memory, and a tape that records what printed and when the passphrase was asked.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::time::Duration;
use std::collections::HashMap;
use std::time::SystemTime;

use bifrost::NodeId;
use clap::{CommandFactory as _, Parser};
use keystore::Passphrase;
use nauthy::{Link, Revocations as _, Service};
use swoosh::contacts::ContactsStore;
use swoosh::grants::{Delegation, GrantKind, GrantRecord, Grants};
use swoosh::home::Home;
use swoosh::passphrase::{Asked as Question, Choice, Prompt};
use swoosh::root::{Date, RootPlace};
use swoosh::roster::{Epoch, RosterDoc};
use swoosh::sync::{Answer, Dial, ExchangeError};
use swoosh::testkit::{Counting, TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;

use super::super::invite::invite_tests::{
    Asked, CI, DAY, LAPTOP, NAS, NINETY, OWN, PASS, PHONE, ROOT, Row, Stream, Tape, carrying, copy,
    device_of, due, held, holds, invite, kept, kept_list, key, live, node, now, records, revoked,
    root_key_at, row_of, scratch, signed, snapshot,
};
use super::{RevokeCmd, Usage};

/// A key no root here has signed for, and that this machine never gave a link.
const STRANGER: u8 = 0x66;
/// A contact's root.
const ALICE_ROOT: u8 = 0x52;
/// Another issuer's key.
const FOREIGN: u8 = 0x77;

#[derive(Debug, Parser)]
struct Cli {
    #[command(flatten)]
    revoke: RevokeCmd,
}

fn parse(args: &[&str]) -> Result<RevokeCmd, clap::Error> {
    Cli::try_parse_from(core::iter::once("revoke").chain(args.iter().copied()))
        .map(|cli| cli.revoke)
}

/// Devices that answer from a table by key, and are silent when they are not in it.
struct Devices {
    answers: HashMap<NodeId, Answer>,
    tape: Tape,
}

impl Devices {
    /// Every device answers that it holds what it is offered.
    fn all(tape: &Tape) -> Self {
        let answers = [OWN, LAPTOP, PHONE, NAS, CI]
            .into_iter()
            .map(|seed| (node(seed), Answer::Same))
            .collect();
        Self {
            answers,
            tape: tape.clone(),
        }
    }
}

impl Dial for Devices {
    async fn exchange(&self, peer: NodeId) -> Result<Answer, ExchangeError> {
        self.tape.push("<exchange>\n");
        self.answers
            .get(&peer)
            .copied()
            .ok_or_else(|| eyre::eyre!("no answer").into())
    }

    async fn offer(
        &self,
        peer: NodeId,
        _number: Epoch,
        _bytes: &[u8],
    ) -> Result<Answer, ExchangeError> {
        self.tape.push("<offer>\n");
        self.exchange(peer).await
    }
}

/// What one `revoke` did.
pub(crate) struct Ran {
    result: eyre::Result<()>,
    err: String,
    tape: Tape,
    prompts: usize,
    /// Each confirmation asked, as asked.
    confirms: Vec<String>,
    /// Each line said where the person types, in order.
    said: Vec<String>,
}

/// A terminal with a person at it, or none: passphrases from `asked`, and `typed` for a confirmation.
/// Each confirmation is marked on the tape and kept, and so is each line said on the terminal.
struct Typing {
    asked: Asked,
    typed: Option<String>,
    confirms: Vec<String>,
    said: Vec<String>,
    /// Run once the person has typed the confirmation, before it is answered: a change to the home while
    /// they typed.
    then: Option<Box<dyn FnOnce()>>,
}

impl Typing {
    /// At a terminal or not, answering passphrases with `prompt` and a confirmation with `typed`.
    fn new(prompt: Counting, terminal: bool, typed: Option<&str>, tape: &Tape) -> Self {
        Self {
            asked: Asked {
                inner: prompt,
                terminal,
                tape: tape.clone(),
            },
            typed: typed.map(str::to_owned),
            confirms: Vec::new(),
            said: Vec::new(),
            then: None,
        }
    }
}

impl Prompt for Typing {
    fn terminal(&self) -> bool {
        self.asked.terminal()
    }

    fn unlock(&mut self, asked: Question<'_>) -> eyre::Result<Passphrase> {
        self.asked.unlock(asked)
    }

    fn choose(&mut self, asked: Question<'_>) -> eyre::Result<Choice> {
        self.asked.choose(asked)
    }

    fn say(&mut self, line: &str) {
        self.asked.tape.push(&format!("<tty>{line}\n"));
        self.said.push(line.to_owned());
        self.asked.say(line);
    }

    fn confirm(&mut self, question: &str) -> eyre::Result<String> {
        self.asked.tape.push("<confirm>\n");
        self.confirms.push(question.to_owned());
        if let Some(then) = self.then.take() {
            then();
        }
        self.typed
            .clone()
            .ok_or_else(|| eyre::eyre!("no confirmation scripted"))
    }
}

impl Ran {
    /// The refusal, which there must be.
    fn refusal(&self) -> String {
        match &self.result {
            Ok(()) => panic!("the revoke refused: {}", self.err),
            Err(error) => format!("{error:#}"),
        }
    }

    /// It ran, and printed `err`.
    pub(crate) fn ok(&self) -> &str {
        assert!(self.result.is_ok(), "{:?}: {}", self.result, self.err);
        &self.err
    }
}

/// Run `swoosh revoke <args>` on `home`, at a terminal with the passphrase, every device answering.
async fn revoke(home: &Home, args: &[&str]) -> Ran {
    let tape = Tape::default();
    let dial = Devices::all(&tape);
    run(home, args, b"", Counting::new([PASS]), dial, tape).await
}

/// Run `swoosh revoke <args>` on `home`, reading `stdin`, answering the passphrase with `prompt`, and
/// offering through `dial`.
async fn run(
    home: &Home,
    args: &[&str],
    stdin: &[u8],
    prompt: Counting,
    dial: impl Dial,
    tape: Tape,
) -> Ran {
    let typing = Typing::new(prompt, true, None, &tape);
    run_typing(home, args, stdin, typing, dial, tape).await
}

/// [`run`], asking `prompt`, which may type a confirmation or have no terminal.
async fn run_typing(
    home: &Home,
    args: &[&str],
    stdin: &[u8],
    mut prompt: Typing,
    dial: impl Dial,
    tape: Tape,
) -> Ran {
    let mut err = Stream {
        bytes: Vec::new(),
        tape: tape.clone(),
    };
    let cmd = parse(args).unwrap();
    let result = match cmd.block(home, stdin, &mut prompt, &dial, &mut err).await {
        Ok(Some(publish)) => publish.run(home, &mut prompt, &dial, &mut err).await,
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    Ran {
        result,
        err: String::from_utf8(err.bytes).unwrap(),
        tape,
        prompts: prompt.asked.inner.events(),
        confirms: prompt.confirms,
        said: prompt.said,
    }
}

/// Run `swoosh revoke root:<the key seeded seed>` on `home` at a terminal, the person typing `typed` at
/// the confirmation and the passphrase at its prompt.
pub(crate) async fn revoke_root(home: &Home, seed: u8, typed: &str) -> Ran {
    revoke_root_with(home, seed, Some(typed), Counting::new([PASS]), true).await
}

/// [`revoke_root`], answering passphrases with `prompt`, at a terminal or not.
async fn revoke_root_with(
    home: &Home,
    seed: u8,
    typed: Option<&str>,
    prompt: Counting,
    terminal: bool,
) -> Ran {
    let tape = Tape::default();
    let typing = Typing::new(prompt, terminal, typed, &tape);
    let dial = Devices::all(&tape);
    let target = format!("root:{}", node(seed));
    run_typing(home, &[&target], b"", typing, dial, tape).await
}

/// The first six characters of the key seeded `seed`: what a person types to revoke it as a root.
pub(crate) fn prefix(seed: u8) -> String {
    node(seed).to_string().chars().take(6).collect()
}

/// A root key in prose: `root:` and the short key.
fn root_short(seed: u8) -> String {
    format!("root:{}", short(seed))
}

/// Whether `home` blocks the device key `seed` here now.
async fn blocks_key(home: &Home, seed: u8) -> bool {
    swoosh::revoked::open(home)
        .unwrap()
        .is_revoked_key(&key(seed))
}

/// Whether `home`'s own block refuses `link`.
async fn blocks(home: &Home, link: &Link) -> bool {
    swoosh::revoked::open(home).unwrap().is_revoked(link.cap())
}

/// Whether `home`'s own block holds `id`.
async fn blocks_id(home: &Home, id: &swoosh::roster::Id) -> bool {
    swoosh::revoked::open(home)
        .unwrap()
        .is_revoked_any([&id.id])
}

/// A home that is a device of `ROOT` with no root kept, holding the update that lists `rows` (its own
/// row first).
async fn device(tag: &str, rows: &[Row]) -> Home {
    let home = scratch(tag);
    device_of(&home, &rows[0]).await;
    held(&home, &records(1, rows, Vec::new()));
    home
}

/// Record in `home`'s ledger a link for `ssh` given to `holder`, and return it: signed by this machine's
/// own key and bound to `holder` as a device, or to it as a root.
async fn gave(home: &Home, holder: NodeId, kind: GrantKind) -> Link {
    let service: Service = "ssh".parse().unwrap();
    let until = SystemTime::now() + Duration::from_secs(3600);
    let own = TestNode::seeded(OWN);
    let link = match kind {
        GrantKind::Fleet => own
            .fleet_slip(&service, holder.verify_key().unwrap(), until)
            .unwrap(),
        GrantKind::Device | GrantKind::Bearer => own
            .bound_slip(&service, holder.verify_key().unwrap(), until)
            .unwrap(),
    };
    let record = GrantRecord {
        target: service,
        kind,
        delegation: Delegation::Sealed,
        holder: holder.to_string(),
        root_id: link.cap().root_revocation_id().unwrap(),
        expiry: until,
    };
    Grants::at(home.links())
        .append(&swoosh::testkit::lock(), &record)
        .unwrap();
    link
}

/// `link` as a person types it.
fn typed(link: &Link) -> String {
    swoosh::link::Link::from(link.clone()).to_string()
}

fn short(seed: u8) -> String {
    swoosh::credential::short(&key(seed))
}

fn dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("swoosh-revoke-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

// --- the order: the block here, then the root ---

#[tokio::test]
async fn a_cancelled_revoke_prompt_still_blocks_here() {
    let home = scratch("revoke-cancelled");
    let laptop = signed(
        LAPTOP,
        "laptop",
        NINETY,
        &[now() + 50 * DAY, now() + 80 * DAY],
    );
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    let tape = Tape::default();
    let dial = Devices::all(&tape);
    let ran = run(&home, &["me/laptop"], b"", Counting::refusing(), dial, tape).await;
    assert_eq!(
        ran.refusal(),
        "me/laptop is blocked on this machine, not yet on your other devices; to finish, run it again: \
         swoosh revoke me/laptop",
        "one partway line"
    );
    assert_eq!(
        ran.prompts, 1,
        "the passphrase was asked, and the ask ended"
    );
    assert!(
        !ran.err.contains("revoked"),
        "no success line before the root step commits: {}",
        ran.err
    );
    assert!(blocks_key(&home, LAPTOP).await, "the key is blocked here");
    for id in &laptop.ids {
        assert!(blocks_id(&home, id).await, "every standing is blocked here");
    }
}

#[tokio::test]
async fn a_device_blocks_a_sibling_here_without_the_root() {
    let laptop = live(LAPTOP, "laptop");
    let home = device("revoke-sibling", &[live(OWN, "desk"), laptop.clone()]).await;
    let ran = revoke(&home, &["me/laptop"]).await;
    let _ = ran.ok();
    assert_eq!(ran.prompts, 0, "no root, no prompt");
    assert!(
        blocks(&home, &laptop.standing).await,
        "the sibling's standing is refused here, by the ids its row carries in the update"
    );
    assert!(blocks_key(&home, LAPTOP).await, "and its key");
}

#[tokio::test]
async fn revoke_prints_local_only_without_the_root() {
    let laptop = live(LAPTOP, "laptop");
    let home = device("revoke-local-only", &[live(OWN, "desk"), laptop.clone()]).await;
    let ran = revoke(&home, &["me/laptop"]).await;
    assert_eq!(
        ran.ok().trim_end(),
        format!(
            "revoked me/laptop on this machine only. Your other devices admit it until {}. To block it \
             everywhere, run this again where your root is kept, or here with --root <dir>.",
            Date(laptop.until)
        )
    );
    assert!(!ran.tape.text().contains("<offer>"), "nothing is offered");
}

#[tokio::test]
async fn revoke_root_flag_refuses_when_nothing_needs_the_root() {
    let home = scratch("revoke-root-flag");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    gave(&home, node(STRANGER), GrantKind::Device).await;
    let copy_dir = dir("root-flag-copy");
    let before = snapshot(home.dir());
    let copy = copy_dir.to_str().unwrap();
    for args in [
        vec![
            node(STRANGER).to_string(),
            "--root".to_owned(),
            copy.to_owned(),
        ],
        vec!["alice".to_owned(), "--root".to_owned(), copy.to_owned()],
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let ran = revoke(&home, &args).await;
        assert_eq!(
            ran.refusal(),
            "`--root` is only for acts that need your root"
        );
        assert_eq!(ran.prompts, 0, "no prompt");
        assert!(snapshot(home.dir()) == before, "nothing was written");
    }
}

// --- the target's shape ---

#[tokio::test]
async fn a_foreign_link_is_refused_not_ignored() {
    let home = scratch("revoke-foreign");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let link = TestRoot::seeded(FOREIGN)
        .bound_slip(
            &"ssh".parse().unwrap(),
            key(LAPTOP),
            SystemTime::now() + Duration::from_secs(3600),
        )
        .unwrap();
    let before = snapshot(home.dir());
    let ran = revoke(&home, &[&typed(&link)]).await;
    assert_eq!(
        ran.refusal(),
        format!(
            "this link was issued by {}, not by this machine or your root. Revoke it where it was issued.",
            short(FOREIGN)
        )
    );
    assert!(
        ran.result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<Usage>())
            .is_none(),
        "a refusal exits 1, not as a usage error"
    );
    assert!(snapshot(home.dir()) == before, "nothing was written");
}

#[test]
fn bare_me_is_refused() {
    let error = parse(&["me"]).expect_err("`me` alone refuses");
    assert_eq!(error.exit_code(), 2);
    assert!(
        error
            .to_string()
            .contains("`me` alone names all your devices; revoke one: `swoosh revoke me/<name>`"),
        "{error}"
    );
    let error = parse(&["ME"]).expect_err("`ME` alone refuses as `me` does");
    assert!(
        error
            .to_string()
            .contains("`me` alone names all your devices"),
        "{error}"
    );
    for reserved in ["root", "anyone", "me/root", "alice/anyone"] {
        let error = parse(&[reserved]).expect_err("a reserved name refuses");
        assert_eq!(error.exit_code(), 2, "{reserved}");
    }
    assert!(
        matches!(parse(&["nas"]).unwrap().target, super::Target::Person(_)),
        "a bare word is a person, never me/<name>"
    );
}

#[tokio::test]
async fn revoke_dash_reads_a_link_from_stdin() {
    let home = scratch("revoke-stdin");
    let link = gave(&home, node(PHONE), GrantKind::Device).await;
    let tape = Tape::default();
    let piped = format!("{}\n", typed(&link));
    let ran = run(
        &home,
        &["-"],
        piped.as_bytes(),
        Counting::refusing(),
        Devices::all(&tape),
        tape,
    )
    .await;
    assert_eq!(
        ran.ok().trim_end(),
        "revoked the link: blocked. Only this machine admitted it."
    );
    assert!(
        blocks(&home, &link).await,
        "the link read from stdin is revoked"
    );

    let tape = Tape::default();
    let root_key = format!("root:{}", node(ROOT));
    let ran = run(
        &home,
        &["-"],
        root_key.as_bytes(),
        Counting::refusing(),
        Devices::all(&tape),
        tape,
    )
    .await;
    let usage = ran
        .result
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<Usage>())
        .expect("a root key on stdin is a usage error");
    assert_eq!(usage.0, "stdin held no link.");

    let file = dir("stdin-path");
    std::fs::create_dir_all(&file).unwrap();
    let file = file.join("held");
    std::fs::write(&file, &root_key).unwrap();
    let error = parse(&[file.to_str().unwrap()]).expect_err("a root key in a file refuses");
    assert_eq!(error.exit_code(), 2);
    assert!(
        error
            .to_string()
            .contains(&format!("{} holds no swoosh: link.", file.display())),
        "{error}"
    );
}

// --- where it took effect ---

#[tokio::test]
async fn revoke_reports_which_devices_took_it() {
    let home = scratch("revoke-reach");
    let laptop = live(LAPTOP, "laptop");
    holds(
        &home,
        &[
            live(OWN, "desk"),
            laptop.clone(),
            live(PHONE, "phone"),
            live(NAS, "nas"),
        ],
        Vec::new(),
    )
    .await;
    gave(&home, node(LAPTOP), GrantKind::Device).await;
    let tape = Tape::default();
    let dial = Devices {
        answers: [(node(PHONE), Answer::Same)].into_iter().collect(),
        tape: tape.clone(),
    };
    let ran = run(
        &home,
        &["me/laptop"],
        b"",
        Counting::new([PASS]),
        dial,
        tape,
    )
    .await;
    let err = ran.ok();
    assert!(
        err.contains(&format!(
            "revoked me/laptop: me/phone has it; me/nas did not answer (it gets it on its next sync). A \
             device that never syncs admits it until {}.",
            Date(laptop.until)
        )),
        "{err}"
    );
    assert!(
        err.ends_with(
            "and the links this machine gave it: blocked (only this machine admitted them).\n\
             me/laptop can never rejoin your devices with its current key.\n\
             to add laptop again, first run this at its console: swoosh leave --new-key\n"
        ),
        "{err}"
    );
    assert!(
        ran.tape.at("<prompt>") < ran.tape.at("<offer>"),
        "offered after the passphrase"
    );
    let list = kept_list(&home);
    assert!(
        list.members()
            .iter()
            .all(|member| member.node != key(LAPTOP)),
        "the root's list no longer carries it"
    );
    assert!(list.is_revoked_key(&key(LAPTOP)), "and revokes its key");
}

#[tokio::test]
async fn a_full_row_never_blocks_a_revoke() {
    let home = scratch("revoke-full-row");
    let phone = signed(
        PHONE,
        "phone",
        NINETY,
        &[
            now() + 5 * DAY,
            now() + 10 * DAY,
            now() + 15 * DAY,
            now() + 20 * DAY,
        ],
    );
    holds(
        &home,
        &[
            live(OWN, "desk"),
            phone.clone(),
            due(LAPTOP, "laptop"),
            live(NAS, "nas"),
        ],
        Vec::new(),
    )
    .await;
    let ran = revoke(&home, &["me/nas"]).await;
    let err = ran.ok();
    assert!(err.contains("revoked me/nas: "), "{err}");
    let state = kept(&home).await;
    assert!(
        state.iter().all(|row| row.key != key(NAS)),
        "a full row beside it does not stop the revoke"
    );
    assert_eq!(
        row_of(&state, "phone").ids.len(),
        phone.ids.len(),
        "the full row is left as it is"
    );

    let ran = revoke(&home, &["me/phone"]).await;
    let err = ran.ok();
    assert!(err.contains("revoked me/phone: me/laptop has it."), "{err}");
    let list = kept_list(&home);
    assert!(list.is_revoked_key(&key(PHONE)));
    for id in &phone.ids {
        assert!(list.revoked().contains(id), "every id of the full row");
    }
}

#[tokio::test]
async fn revoking_a_device_revokes_its_renewed_standings() {
    let home = scratch("revoke-renewed");
    let ends = [now() + 30 * DAY, now() + 60 * DAY, now() + 80 * DAY];
    let laptop = signed(LAPTOP, "laptop", NINETY, &ends);
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    let ran = revoke(&home, &["me/laptop"]).await;
    let _ = ran.ok();
    let list = kept_list(&home);
    for id in &laptop.ids {
        assert!(
            list.revoked().contains(id),
            "the root revokes every live id"
        );
        assert!(blocks_id(&home, id).await, "and this machine blocks each");
    }
}

#[tokio::test]
async fn a_local_only_revoke_carried_by_a_later_root_act_is_published() {
    let own = live(OWN, "desk");
    let laptop = live(LAPTOP, "laptop");
    let home = device("revoke-carried", &[own.clone(), laptop.clone()]).await;
    let copy_dir = dir("carried-copy");
    copy(&copy_dir, &records(1, &[own, laptop], Vec::new()));
    let ran = revoke(&home, &["me/laptop"]).await;
    assert!(ran.ok().contains("on this machine only"));

    let root = copy_dir.to_str().unwrap();
    let tv = node(0x44).to_string();
    let ran = invite(&home, &["tv", &tv, "--root", root]).await;
    assert!(ran.result.is_ok(), "{:?}: {}", ran.result, ran.err);
    let inspected = swoosh::root::Root::inspect(&home, RootPlace::Dir(copy_dir.clone()))
        .await
        .unwrap();
    assert!(
        inspected.rows().iter().all(|row| row.node != key(LAPTOP)),
        "the root act drops the device this machine revoked"
    );
    assert!(
        inspected
            .listed_revoked_keys()
            .any(|key_| *key_ == key(LAPTOP)),
        "and its list carries its key"
    );
}

#[tokio::test]
async fn revoke_after_new_key_refuses_the_old_invite() {
    let home = scratch("revoke-after-new-key");
    let ci = carrying(live(CI, "ci"));
    holds(&home, &[live(OWN, "desk"), ci.clone()], Vec::new()).await;
    let ran = invite(&home, &["ci", "--new-key"]).await;
    let _ = ran.invite();

    let ran = revoke(&home, &["me/ci"]).await;
    let _ = ran.ok();
    assert!(
        blocks(&home, &ci.standing).await,
        "the old invite's standing is refused here"
    );
    assert!(
        kept_list(&home).revoked().contains(&ci.ids[0]),
        "and the root publishes its id"
    );
}

// --- a key ---

#[tokio::test]
async fn revoke_a_bare_key_that_is_a_root_takes_back_only_links() {
    let home = scratch("revoke-root-key");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let mut store = ContactsStore::open(&home).await.unwrap();
    store
        .contacts_mut()
        .set_signet("alice".parse().unwrap(), node(ALICE_ROOT));
    store.save(&swoosh::testkit::lock()).unwrap();
    let alice = gave(&home, node(ALICE_ROOT), GrantKind::Fleet).await;
    let yours = gave(&home, node(ROOT), GrantKind::Fleet).await;

    let ran = revoke(&home, &[&node(ALICE_ROOT).to_string()]).await;
    let err = ran.ok().to_owned();
    assert!(
        blocks(&home, &alice).await,
        "the link given to that key is revoked"
    );
    assert!(
        err.contains(&format!(
            "{} is also alice's root. This took back only the links given to that key. To end a root: \
             swoosh revoke --help",
            short(ALICE_ROOT)
        )),
        "{err}"
    );

    let ran = revoke(&home, &[&node(ROOT).to_string()]).await;
    let mine = ran.ok().to_owned();
    assert!(blocks(&home, &yours).await);
    assert!(
        mine.contains(&format!("{} is also your root.", short(ROOT))),
        "{mine}"
    );
    for line in err.lines().chain(mine.lines()) {
        assert!(!line.contains("swoosh revoke root:"), "{line}");
    }
    let revoked = swoosh::revoked::open(&home).unwrap();
    assert!(
        !revoked.is_revoked_key(&key(ALICE_ROOT)),
        "alice's root stays trusted"
    );
    assert!(
        !revoked.is_revoked_key(&key(ROOT)),
        "your root stays trusted"
    );
    assert!(
        matches!(
            swoosh::standing::Standing::read(&home).await.unwrap(),
            swoosh::standing::Standing::HoldsRoot { .. }
        ),
        "this machine still holds your root"
    );
}

#[tokio::test]
async fn revoke_a_key_with_no_links_here_says_nothing_was_revoked() {
    let home = scratch("revoke-no-links");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = revoke(&home, &[&node(STRANGER).to_string()]).await;
    assert_eq!(
        ran.refusal(),
        format!(
            "no link from this machine was given to {}; nothing revoked.",
            short(STRANGER)
        )
    );
    let ran = revoke(&home, &[&node(LAPTOP).to_string()]).await;
    assert!(
        ran.refusal().ends_with(&format!(
            "{} is also your device me/laptop: `swoosh revoke me/laptop` revokes the device.",
            short(LAPTOP)
        )),
        "{}",
        ran.refusal()
    );
    assert!(
        !blocks_key(&home, LAPTOP).await,
        "a key's form never revokes the device"
    );
    let ran = revoke(&home, &[&node(OWN).to_string()]).await;
    assert_eq!(
        ran.refusal(),
        format!(
            "no link from this machine was given to {}; nothing revoked.",
            short(OWN)
        ),
        "this machine's own key names no device to revoke, since `revoke me/desk` refuses"
    );
}

#[tokio::test]
async fn an_unknown_person_is_not_one_of_your_contacts() {
    let home = scratch("revoke-unknown-person");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let before = snapshot(home.dir());
    for typed in ["carol", "carol/laptop"] {
        let ran = revoke(&home, &[typed]).await;
        assert_eq!(
            ran.refusal(),
            "carol is not one of your contacts (`swoosh status`)",
            "{typed}"
        );
    }
    assert!(snapshot(home.dir()) == before, "nothing was written");
}

#[test]
fn revoke_help_line_names_the_root() {
    let cli = crate::Cli::command();
    let revoke = cli
        .find_subcommand("revoke")
        .expect("revoke is a top-level verb");
    let about = revoke.get_about().unwrap().to_string();
    assert!(
        about.starts_with(
            "Take back a link, a device, or everything you shared with a contact; or end a root for good"
        ),
        "{about}"
    );
    let usage = revoke.clone().render_usage().to_string();
    assert!(
        usage.contains(
            "<link | path | - | me/<name> | <person> | <person>/<name> | key | root key>"
        ),
        "{usage}"
    );
}

// --- the refusals before any write ---

#[tokio::test]
async fn an_unknown_device_or_this_machine_refuses_before_any_write() {
    let home = scratch("revoke-unknown");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let before = snapshot(home.dir());
    let ran = revoke(&home, &["me/phone"]).await;
    assert_eq!(
        ran.refusal(),
        "me/phone is not one of your devices (`swoosh status`)"
    );
    let ran = revoke(&home, &["me/desk"]).await;
    assert_eq!(
        ran.refusal(),
        "me/desk is this machine. To stop being one of your devices: swoosh leave"
    );
    assert_eq!(ran.prompts, 0);
    assert!(snapshot(home.dir()) == before, "nothing was written");
}

#[tokio::test]
async fn revoking_again_with_the_root_publishes_a_local_block() {
    let own = live(OWN, "desk");
    let laptop = live(LAPTOP, "laptop");
    let home = device(
        "revoke-again",
        &[own.clone(), laptop.clone(), live(PHONE, "phone")],
    )
    .await;
    let copy_dir = dir("again-copy");
    copy(
        &copy_dir,
        &records(1, &[own, laptop.clone(), live(PHONE, "phone")], Vec::new()),
    );
    let _ = revoke(&home, &["me/laptop"]).await.ok().to_owned();
    let root = copy_dir.to_str().unwrap();
    let ran = revoke(&home, &["me/laptop", "--root", root]).await;
    let err = ran.ok();
    assert!(
        err.contains(&format!(
            "revoked me/laptop: me/phone has it. A device that never syncs admits it until {}.",
            Date(laptop.until)
        )),
        "{err}"
    );
}

// --- a standing your root signed ---

#[tokio::test]
async fn an_old_link_never_revokes_the_device_now_named_for_it() {
    let old = revoked(LAPTOP, "nas");
    let new = live(PHONE, "nas");
    let rows = [live(OWN, "desk"), old.clone(), new.clone()];
    let line =
        "revoked the link: blocked here. Your root revoked the device it stands for already.";

    let home = scratch("revoke-old-link");
    // The root revoked the laptop: its list revokes its key and the ids it held, and carries no row.
    holds(&home, &rows, old.ids.clone()).await;
    let ran = revoke(&home, &[&typed(&old.standing)]).await;
    assert_eq!(ran.ok().trim_end(), line);
    assert_eq!(ran.prompts, 0, "no root act");
    assert!(
        blocks(&home, &old.standing).await,
        "the old link is blocked here"
    );
    assert!(
        !blocks_key(&home, PHONE).await,
        "the device now named nas is not"
    );
    let state = kept(&home).await;
    assert!(!kept_list(&home).is_revoked_key(&key(PHONE)));
    assert!(!row_of(&state, "desk").is_revoked());
    assert!(
        state
            .iter()
            .any(|row| row.key == key(PHONE) && !row.is_revoked()),
        "and stays one of your devices"
    );

    // On a device, the update names the old link's id among the revoked.
    let home = device("revoke-old-link-device", &[live(OWN, "desk"), new.clone()]).await;
    held(&home, &records(1, &rows, old.ids.clone()));
    let ran = revoke(&home, &[&typed(&old.standing)]).await;
    assert_eq!(ran.ok().trim_end(), line);
    assert!(!blocks_key(&home, PHONE).await);
}

#[tokio::test]
async fn a_link_revoked_alone_still_revokes_its_live_device() {
    let own = live(OWN, "desk");
    let laptop = live(LAPTOP, "laptop");
    let phone = live(PHONE, "phone");
    let home = scratch("revoke-id-alone");
    device_of(&home, &own).await;
    let ran = revoke(&home, &[&typed(&laptop.standing)]).await;
    assert!(ran.ok().contains("on this machine only"), "{}", ran.err);

    // The next root act carries the link's id, and only its id: laptop's row stays live.
    let copy_dir = dir("id-alone-copy");
    copy(
        &copy_dir,
        &records(1, &[own, laptop.clone(), phone], Vec::new()),
    );
    let root = copy_dir.to_str().unwrap();
    let ran = revoke(&home, &["me/phone", "--root", root]).await;
    let _ = ran.ok();
    let inspect = || swoosh::root::Root::inspect(&home, RootPlace::Dir(copy_dir.clone()));
    let inspected = inspect().await.unwrap();
    assert!(inspected.listed_revoked().any(|id| *id == laptop.ids[0]));
    assert!(inspected.rows().iter().any(|row| row.node == key(LAPTOP)));

    // The command the first revoke named revokes the device the link stands for.
    let ran = revoke(&home, &[&typed(&laptop.standing), "--root", root]).await;
    let _ = ran.ok();
    assert_eq!(ran.prompts, 1, "a root act");
    let inspected = inspect().await.unwrap();
    assert!(inspected.rows().iter().all(|row| row.node != key(LAPTOP)));
    assert!(
        inspected
            .listed_revoked_keys()
            .any(|key_| *key_ == key(LAPTOP))
    );
}

#[tokio::test]
async fn a_root_signed_link_is_never_complete_without_the_update() {
    let own = live(OWN, "desk");
    let laptop = live(LAPTOP, "laptop");
    let home = scratch("revoke-no-update");
    device_of(&home, &own).await;
    let ran = revoke(&home, &[&typed(&laptop.standing)]).await;
    assert_eq!(
        ran.ok().trim_end(),
        format!(
            "revoked the link on this machine only. Your other devices admit it until {}. To block it \
             everywhere, run this again where your root is kept, or here with --root <dir>.",
            Date(laptop.until)
        )
    );
    assert!(
        blocks(&home, &laptop.standing).await,
        "blocked here all the same"
    );
}

#[tokio::test]
async fn a_root_signed_link_refuses_when_your_devices_cannot_be_read() {
    let laptop = live(LAPTOP, "laptop");
    let home = scratch("revoke-unreadable");
    holds(&home, &[live(OWN, "desk"), laptop.clone()], Vec::new()).await;
    std::fs::write(home.devices(), b"not a list").unwrap();
    let ran = revoke(&home, &[&typed(&laptop.standing)]).await;
    let refusal = ran.refusal();
    assert!(
        refusal.contains(&format!(
            "this root's devices list was changed outside swoosh ({}): refusing to sign from it. Use \
             another copy.",
            home.devices().display()
        )),
        "the failed read is the refusal, naming the list's file: {refusal}"
    );
    assert!(
        !blocks(&home, &laptop.standing).await,
        "nothing is blocked on a read that failed"
    );
}

// --- one store, and a device that moved before the prompt ---

/// Devices where `from` holds `bytes`, a list newer than this machine's, and hands it over in an
/// exchange, as a real exchange folds it; every other device holds what it is offered.
struct Handing {
    home: Home,
    from: NodeId,
    bytes: Vec<u8>,
    tape: Tape,
}

impl Dial for Handing {
    async fn exchange(&self, peer: NodeId) -> Result<Answer, ExchangeError> {
        if peer != self.from {
            return Ok(Answer::Same);
        }
        let home_lock = swoosh::home::HomeWrite::take(&self.home).await.unwrap();
        match swoosh::roster::fold(&home_lock, &self.home, &self.bytes)
            .await
            .unwrap()
        {
            swoosh::roster::Folded::Newer => Ok(Answer::Took),
            _ => Ok(Answer::Same),
        }
    }

    async fn offer(
        &self,
        _peer: NodeId,
        _number: Epoch,
        _bytes: &[u8],
    ) -> Result<Answer, ExchangeError> {
        self.tape.push("<offer>\n");
        Ok(Answer::Same)
    }
}

/// `revoke me/laptop` found laptop's key before its prompt, and the act's own sync, before the prompt,
/// took a list another copy of the root cut, which hands me/laptop a new key. Revoking the key it found
/// would leave the device live under the new one, so the act stops: nothing is cut or offered.
#[tokio::test]
async fn a_revoke_never_leaves_live_a_device_its_own_sync_rekeyed() {
    let home = scratch("revoke-rekeyed-by-sync");
    let rows = [live(OWN, "desk"), live(LAPTOP, "laptop"), live(NAS, "nas")];
    holds(&home, &rows, Vec::new()).await;
    let rekeyed = [rows[0].clone(), live(STRANGER, "laptop"), rows[2].clone()];
    let elsewhere = records(2, &rekeyed, Vec::new());
    let tape = Tape::default();
    let dial = Handing {
        home: home.clone(),
        from: node(NAS),
        bytes: TestRoot::seeded(ROOT).sign_update(&elsewhere),
        tape: tape.clone(),
    };

    let ran = run(
        &home,
        &["me/laptop"],
        b"",
        Counting::new([PASS]),
        dial,
        tape,
    )
    .await;
    assert_eq!(
        ran.refusal(),
        "me/laptop is blocked on this machine, not yet on your other devices.\n\
         me/laptop is now listed under a key this revoke did not see, so your root did not revoke it",
        "the partway line, then the cause, which names no command: running the revoke again would take the name's new key"
    );
    assert!(!ran.tape.text().contains("<offer>"), "nothing is offered");
    assert!(
        !ran.err.contains("revoked me/laptop: me/"),
        "no line says the device was revoked everywhere: {}",
        ran.err
    );
    let held = swoosh::roster::held(&home, TestRoot::seeded(ROOT).verify_key()).unwrap();
    assert_eq!(held.epoch(), Epoch(2), "nothing was cut");
    assert!(
        held.members()
            .iter()
            .any(|member| member.node == key(STRANGER)),
        "the device is listed under its new key, for the next revoke to name"
    );
}

/// `revoke <this machine's own standing>`, on a machine whose root already revoked it: the link is blocked
/// here, but this machine's own key never lands in `revoked`, so every link it signed still admits.
#[tokio::test]
async fn revoking_this_machines_own_standing_never_blocks_its_key() {
    let own = revoked(OWN, "desk");
    let home = scratch("revoke-own-standing");
    // The root's list revokes this machine's key and the ids it held.
    holds(
        &home,
        &[own.clone(), live(LAPTOP, "laptop")],
        own.ids.clone(),
    )
    .await;
    let given = gave(&home, node(STRANGER), GrantKind::Device).await;

    let ran = revoke(&home, &[&typed(&own.standing)]).await;
    assert_eq!(
        ran.ok().trim_end(),
        "revoked the link: blocked here. Your root revoked the device it stands for already."
    );
    assert!(blocks(&home, &own.standing).await, "the link is blocked");
    assert!(
        !blocks_key(&home, OWN).await,
        "this machine's own key is never revoked here"
    );
    assert!(
        !blocks(&home, &given).await,
        "a link this machine signed still admits"
    );
}

/// A revoke, a fold and a root revoked here all land in the one `revoked`, beside its one witness, and
/// no other file of revocations appears in the home.
#[tokio::test]
async fn revoked_holds_ids_device_keys_and_roots_in_one_file() {
    let laptop = live(LAPTOP, "laptop");
    let home = device(
        "revoke-one-file",
        &[live(OWN, "desk"), laptop.clone(), live(PHONE, "phone")],
    )
    .await;
    let _ = revoke(&home, &["me/laptop"]).await.ok().to_owned();

    let folded = RosterDoc::with_revocations(
        Epoch(2),
        [live(OWN, "desk"), laptop]
            .iter()
            .map(super::super::invite::invite_tests::member)
            .collect(),
        Vec::new(),
        vec![swoosh::testkit::revoked(key(PHONE))],
    )
    .unwrap();
    let home_lock = swoosh::home::HomeWrite::take(&home).await.unwrap();
    swoosh::roster::fold(
        &home_lock,
        &home,
        &TestRoot::seeded(ROOT).sign_update(&folded),
    )
    .await
    .unwrap();
    // A root revoked here, through the one writer a root's revoke uses.
    swoosh::revoked::add(
        &home_lock,
        &home,
        [nauthy::Revocation::Key(key(ALICE_ROOT))],
    )
    .unwrap();
    drop(home_lock);

    let text = std::fs::read_to_string(home.revoked()).unwrap();
    for (kind, value) in [
        ("key", key(LAPTOP).to_string()),
        ("key", key(PHONE).to_string()),
        ("key", key(ALICE_ROOT).to_string()),
    ] {
        assert!(
            text.lines().any(|line| line == format!("{kind} {value}")),
            "{value} is in revoked: {text}"
        );
    }
    assert!(
        text.lines().any(|line| line.starts_with("id ")),
        "and the ids: {text}"
    );
    let entries = text.lines().count();
    assert_eq!(
        std::fs::read_to_string(home.revoked_written())
            .unwrap()
            .trim(),
        entries.to_string(),
        "one witness counts every entry"
    );
    for gone in ["revoked_keys", "revoked_keys.written", "disabled_roots"] {
        assert!(!home.dir().join(gone).exists(), "no {gone}");
    }
}

/// Every write to `revoked` is made under `home.lock`, which excludes its other writers, so none takes
/// the store's own lock and none leaves a `revoked.lock` in the home.
#[tokio::test]
async fn no_nauthy_lock_file_is_made_in_the_home() {
    let laptop = live(LAPTOP, "laptop");
    let home = device(
        "revoke-no-lock",
        &[live(OWN, "desk"), laptop.clone(), live(PHONE, "phone")],
    )
    .await;
    gave(&home, node(STRANGER), GrantKind::Device).await;
    let _ = revoke(&home, &["me/laptop"]).await.ok().to_owned();
    let _ = revoke(&home, &[&node(STRANGER).to_string()])
        .await
        .ok()
        .to_owned();
    let folded = RosterDoc::with_revocations(
        Epoch(2),
        [live(OWN, "desk"), laptop]
            .iter()
            .map(super::super::invite::invite_tests::member)
            .collect(),
        Vec::new(),
        vec![swoosh::testkit::revoked(key(PHONE))],
    )
    .unwrap();
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(&home).await.unwrap(),
        &home,
        &TestRoot::seeded(ROOT).sign_update(&folded),
    )
    .await
    .unwrap();
    assert!(blocks_key(&home, PHONE).await, "the fold wrote");
    assert!(
        !home.dir().join("revoked.lock").exists(),
        "no revoked.lock in the home"
    );
}

/// The list beside the key in the copy at `dir`.
fn list_in(dir: &std::path::Path) -> RosterDoc {
    swoosh::roster::verify(
        &std::fs::read(dir.join("devices")).unwrap(),
        TestRoot::seeded(ROOT).verify_key(),
    )
    .unwrap()
}

/// The stick workflow: one copy of the root on a stick, used on two machines that never sync with each
/// other in between. The second machine brings itself forward from the list on the stick, so its cut
/// carries the first's revocation; and a stale backup used after both cuts above every list it is shown.
#[tokio::test]
async fn a_stale_copy_cuts_above_the_fleet_from_the_newest_list() {
    let rows = [
        live(OWN, "desk"),
        live(LAPTOP, "laptop"),
        live(PHONE, "phone"),
    ];
    let first = device("stick-first", &rows).await;
    let second = device("stick-second", &rows).await;
    let stick = dir("stick");
    copy(&stick, &records(1, &rows, Vec::new()));
    let backup = dir("stick-backup");
    copy(&backup, &records(1, &rows, Vec::new()));
    let (stick_text, backup_text) = (stick.to_str().unwrap(), backup.to_str().unwrap());

    // The stick on the first machine revokes the phone.
    let ran = revoke(&first, &["me/phone", "--root", stick_text]).await;
    let _ = ran.ok();
    assert_eq!(list_in(&stick).epoch(), Epoch(2));

    // The stick on the second machine, which still holds list 1, invites the tv.
    let tv = node(0x44).to_string();
    let ran = invite(&second, &["tv", &tv, "--root", stick_text]).await;
    assert!(ran.result.is_ok(), "{:?}: {}", ran.result, ran.err);
    let cut = list_in(&stick);
    assert_eq!(cut.epoch(), Epoch(3), "above the list on the stick");
    assert!(
        cut.is_revoked_key(&key(PHONE)),
        "the second machine's cut carries the first's revocation"
    );

    // A backup made before both, used on the second machine: it cuts above the list held there.
    let watch = node(0x48).to_string();
    let ran = invite(&second, &["watch", &watch, "--root", backup_text]).await;
    assert!(ran.result.is_ok(), "{:?}: {}", ran.result, ran.err);
    let cut = list_in(&backup);
    assert_eq!(
        cut.epoch(),
        Epoch(4),
        "above the newest list, not the backup's"
    );
    assert!(cut.is_revoked_key(&key(PHONE)), "and carries it too");
    assert_eq!(kept_list(&second).epoch(), Epoch(4));
}

/// A revoke that stopped after writing the copy and before the home took the cut: the copy holds list 4
/// revoking the laptop, the home still lists it live at 3. Running the revoke again finds the laptop
/// marked revoked, cuts above 4 and offers the cut, so the revocation reaches the phone.
#[tokio::test]
async fn a_revoke_stopped_after_the_copy_write_is_finished_by_running_it_again() {
    let desk = live(OWN, "desk");
    let laptop = live(LAPTOP, "laptop");
    let phone = live(PHONE, "phone");
    let gone = Row {
        revoked_on: now() - DAY,
        ..laptop.clone()
    };
    let before = [desk.clone(), laptop.clone(), phone.clone()];
    let home = device("stopped-revoke", &before).await;
    held(&home, &records(3, &before, Vec::new()));
    let stick = dir("stopped-revoke");
    copy(
        &stick,
        &records(4, &[desk, gone, phone], laptop.ids.clone()),
    );

    let ran = revoke(&home, &["me/laptop", "--root", stick.to_str().unwrap()]).await;
    let _ = ran.ok();
    let list = kept_list(&home);
    assert_eq!(list.epoch(), Epoch(5), "a cut above the copy's list");
    assert!(list.is_revoked_key(&key(LAPTOP)));
    assert!(
        !list
            .members()
            .iter()
            .any(|member| member.node == key(LAPTOP))
    );
    assert_eq!(list_in(&stick).epoch(), Epoch(5));
    assert!(ran.tape.text().contains("<offer>"), "the cut is offered");
}

/// Where the root is kept, a device revoked here leaves the list's live rows, and the list carries its key
/// with the name it had: the next `status` shows it as `me/laptop`, its short key once, and `revoked`.
#[tokio::test]
async fn status_names_a_device_revoked_here() {
    let home = scratch("revoke-then-status");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let _ = revoke(&home, &["me/laptop"]).await.ok().to_owned();

    let stored = keystore::KeyFile::device(home.key()).load().unwrap();
    let out = super::super::status::report::Report::gather(&home, stored.as_ref(), now())
        .await
        .unwrap()
        .render();
    // A row's short key: `ed01`, 8 more characters and `…`.
    let short = swoosh::credential::short(&key(LAPTOP));
    let rows: Vec<&str> = out.lines().filter(|line| line.contains(&short)).collect();
    let [laptop] = rows.as_slice() else {
        panic!("one row names the laptop's key: {out}");
    };
    assert_eq!(
        laptop.split_whitespace().collect::<Vec<_>>(),
        ["me/laptop", short.as_str(), "revoked"],
        "the name, the key once, then the state: {out}"
    );
}

// --- the root form: `revoke root:<key>` ---

/// The ten lines `revoke --help` prints under "To replace your root:", exactly, indented as clap indents
/// its own sections.
const RECIPE_LINES: [&str; 10] = [
    "  desk$   (umask 077; swoosh ssh me/nas -- swoosh share ssh $(swoosh --home ~/.swoosh-rescue leave --new-key) --expires 7d > ~/nas.link)",
    "  desk$   swoosh --home ~/.swoosh-rescue ssh ~/nas.link -- -t swoosh revoke root:ed01OLD…",
    "  desk$   swoosh revoke root:ed01OLD…",
    "  desk$   swoosh invite laptop ed01L…",
    "  desk$   swoosh invite nas ed01NAS… > nas.invite",
    "  desk$   swoosh --home ~/.swoosh-rescue ssh ~/nas.link -- swoosh join < nas.invite",
    "  laptop$ swoosh revoke root:ed01OLD…; swoosh join",
    "  desk$   swoosh invite runner --new-key | gh secret set SWOOSH_INVITE --repo <you>/<repo>",
    "  friend$ swoosh contact add <you> root:ed01NEW…",
    "  desk$   swoosh ssh me/nas -- swoosh revoke - < ~/nas.link; rm -r ~/nas.link ~/.swoosh-rescue",
];

/// Whether `home` refuses the root seeded `seed` for good.
fn latched(home: &Home, seed: u8) -> bool {
    swoosh::revoked::open(home)
        .unwrap()
        .is_revoked_key(&TestRoot::seeded(seed).verify_key())
}

/// Make `seed`'s key the root of the contact `person` on `home`.
async fn contact_root(home: &Home, person: &str, seed: u8) {
    let mut store = ContactsStore::open(home).await.unwrap();
    store
        .contacts_mut()
        .set_signet(person.parse().unwrap(), node(seed));
    store.save(&swoosh::testkit::lock()).unwrap();
}

/// The `status` report for `home`, rendered.
async fn status(home: &Home) -> String {
    let stored = keystore::KeyFile::device(home.key()).load().unwrap();
    super::super::status::report::Report::gather(home, stored.as_ref(), now())
        .await
        .unwrap()
        .render()
}

/// A home of each kind a root's revoke reads, beside the root it names: the root kept here, this machine
/// one of its devices, a contact's root, and a root this machine does not know.
async fn every_kind(tag: &str) -> Vec<(&'static str, Home, u8)> {
    let holder = scratch(&format!("{tag}-holder"));
    holds(
        &holder,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let device = device(
        &format!("{tag}-device"),
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
    )
    .await;
    let contact = scratch(&format!("{tag}-contact"));
    contact_root(&contact, "alice", ALICE_ROOT).await;
    let unknown = scratch(&format!("{tag}-unknown"));
    vec![
        ("holder", holder, ROOT),
        ("device", device, ROOT),
        ("contact", contact, ALICE_ROOT),
        ("unknown", unknown, STRANGER),
    ]
}

#[tokio::test]
async fn revoke_with_a_root_key_takes_the_root_path_behind_the_prefix() {
    let home = scratch("root-path");
    let ran = revoke_root(&home, STRANGER, &prefix(STRANGER)).await;
    let err = ran.ok().to_owned();
    let kind = format!(
        "this machine does not know {}, and will never trust it.",
        root_short(STRANGER)
    );
    assert!(
        ran.tape.at(&format!("<tty>{kind}")) < ran.tape.at("<confirm>"),
        "{err}"
    );
    assert_eq!(ran.confirms.len(), 1, "the prefix is asked once");
    assert!(latched(&home, STRANGER), "the prefix latched the root");
    assert_eq!(
        err.lines().last().unwrap(),
        format!("revoked {} here for good.", root_short(STRANGER))
    );
    // Typed in any case, the prefix is still the root form.
    let upper = format!("ROOT:{}", node(ALICE_ROOT));
    assert!(matches!(
        parse(&[&upper]).unwrap().target,
        super::Target::Root(root) if root == node(ALICE_ROOT)
    ));
}

#[tokio::test]
async fn revoke_a_root_without_the_typed_prefix_refuses_and_writes_nothing() {
    for (kind, home, seed) in every_kind("no-prefix").await {
        let before = snapshot(home.dir());
        for typed in [Some("ed01xx"), Some(""), None] {
            let ran = revoke_root_with(&home, seed, typed, Counting::new([PASS]), true).await;
            let _ = ran.refusal();
            assert_eq!(ran.prompts, 0, "{kind}: no passphrase without the prefix");
            assert!(
                snapshot(home.dir()) == before,
                "{kind}: nothing was written for {typed:?}"
            );
        }
        let ran = revoke_root_with(&home, seed, Some("ed01xx"), Counting::new([PASS]), true).await;
        assert_eq!(
            ran.refusal(),
            format!("that was not {}; nothing was revoked.", prefix(seed)),
            "{kind}"
        );
        assert!(!latched(&home, seed), "{kind}: no latch");
    }
}

#[tokio::test]
async fn revoke_a_root_prompt_names_the_act() {
    let home = scratch("root-prompt");
    let ran = revoke_root(&home, STRANGER, &prefix(STRANGER)).await;
    let _ = ran.ok();
    assert_eq!(
        ran.confirms,
        [format!(
            "Type {} to revoke this root for good:",
            prefix(STRANGER)
        )]
    );
}

#[tokio::test]
async fn revoke_a_contacts_root_names_revoke_person_before_the_prompt() {
    let home = scratch("root-contact");
    contact_root(&home, "alice", ALICE_ROOT).await;
    let given = gave(&home, node(ALICE_ROOT), GrantKind::Fleet).await;
    let ran = revoke_root(&home, ALICE_ROOT, &prefix(ALICE_ROOT)).await;
    let err = ran.ok().to_owned();
    assert_eq!(
        ran.said,
        [
            format!(
                "{} is alice's root; this machine will never trust it again.",
                root_short(ALICE_ROOT)
            ),
            "to stop sharing with alice instead: swoosh revoke alice".to_owned(),
        ]
    );
    assert!(
        ran.tape
            .at("<tty>to stop sharing with alice instead: swoosh revoke alice")
            < ran.tape.at("<confirm>"),
        "{err}"
    );
    assert_eq!(
        err,
        format!("revoked {} here for good.\n", root_short(ALICE_ROOT))
    );
    assert!(latched(&home, ALICE_ROOT));
    assert!(
        blocks(&home, &given).await,
        "the links this machine gave that root are revoked"
    );
}

#[tokio::test]
async fn revoke_reads_only_a_link_from_stdin_or_a_path() {
    let home = scratch("root-stdin");
    let typed = format!("root:{}", node(STRANGER));
    let tape = Tape::default();
    let ran = run_typing(
        &home,
        &["-"],
        typed.as_bytes(),
        Typing::new(Counting::refusing(), true, Some(&prefix(STRANGER)), &tape),
        Devices::all(&tape),
        tape,
    )
    .await;
    let usage = ran
        .result
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<Usage>())
        .expect("a root key on stdin is a usage error");
    assert_eq!(usage.0, "stdin held no link.");
    assert!(ran.confirms.is_empty(), "nothing is asked");

    let file = dir("root-in-a-file");
    std::fs::create_dir_all(&file).unwrap();
    let file = file.join("held");
    std::fs::write(&file, &typed).unwrap();
    let error = parse(&[file.to_str().unwrap()]).expect_err("a root key in a file refuses");
    assert_eq!(error.exit_code(), 2);
    assert!(!latched(&home, STRANGER), "nothing latched");
}

#[tokio::test]
async fn revoke_asks_for_a_typed_prefix_only_for_a_root_key() {
    let home = scratch("prefix-only-root");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    contact_root(&home, "bob", ALICE_ROOT).await;
    gave(&home, node(ALICE_ROOT), GrantKind::Fleet).await;
    gave(&home, node(STRANGER), GrantKind::Device).await;
    for target in ["me/laptop", "bob", &node(STRANGER).to_string()] {
        let tape = Tape::default();
        let typing = Typing::new(Counting::new([PASS]), true, Some("ed01xx"), &tape);
        let ran = run_typing(&home, &[target], b"", typing, Devices::all(&tape), tape).await;
        let _ = ran.ok();
        assert!(ran.confirms.is_empty(), "{target}: no prefix is asked");
        assert!(!ran.err.contains("Type "), "{target}: {}", ran.err);
    }
}

#[tokio::test]
async fn revoke_a_root_with_the_root_flag_refuses() {
    let home = scratch("root-flag-root");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let before = snapshot(home.dir());
    let copy = dir("root-flag-root-copy");
    let target = format!("root:{}", node(ROOT));
    let tape = Tape::default();
    let typing = Typing::new(Counting::new([PASS]), true, Some(&prefix(ROOT)), &tape);
    let ran = run_typing(
        &home,
        &[&target, "--root", copy.to_str().unwrap()],
        b"",
        typing,
        Devices::all(&tape),
        tape,
    )
    .await;
    let usage = ran
        .result
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<Usage>())
        .expect("--root with a root key is a usage error, exit 2");
    assert_eq!(
        usage.0,
        "--root is for acts that use your root; revoking a root needs none."
    );
    assert!(ran.confirms.is_empty(), "refused before the prompt");
    assert!(snapshot(home.dir()) == before, "nothing latched");
}

#[tokio::test]
async fn revoke_a_root_on_the_holder_needs_the_passphrase_before_it_deletes() {
    let home = scratch("root-holder-wrong");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    let before = snapshot(home.dir());
    let wrong = Counting::new([
        "not it at all, sorry",
        "nor this one, either",
        "nor the third one",
    ]);
    let ran = revoke_root_with(&home, ROOT, Some(&prefix(ROOT)), wrong, true).await;
    assert_eq!(ran.refusal(), "that passphrase does not open your root.");
    assert_eq!(ran.prompts, 3, "three tries");
    assert!(
        ran.tape.at("<confirm>") < ran.tape.at("<prompt>"),
        "the prefix first"
    );
    assert!(
        home.root_key().exists(),
        "root.key survives a wrong passphrase"
    );
    assert!(snapshot(home.dir()) == before, "nothing was written");
    assert!(!latched(&home, ROOT));
}

#[test]
fn revoke_a_root_refuses_a_name() {
    for typed in ["root:bob", "ROOT:bob", "root:me/laptop", "root:"] {
        let error = parse(&[typed]).expect_err("a root takes a key, never a name");
        assert_eq!(error.exit_code(), 2, "{typed}");
        assert!(
            error.to_string().contains(&format!(
                "{typed} is not a root key; to see yours: swoosh status"
            )),
            "{error}"
        );
    }
    let error = parse(&["root"]).expect_err("`root` alone is the reserved name");
    assert_eq!(error.exit_code(), 2);
    assert!(!error.to_string().contains("not a root key"), "{error}");
}

#[tokio::test]
async fn revoke_a_root_on_the_pin_leaves_after_the_typed_prefix() {
    let home = device("root-pin", &[live(OWN, "desk"), live(LAPTOP, "laptop")]).await;
    let ran = revoke_root(&home, ROOT, &prefix(ROOT)).await;
    let err = ran.ok().to_owned();
    assert_eq!(
        ran.said,
        [format!(
            "this machine is me/desk, a device of {}; it leaves that root and can never join it again.",
            root_short(ROOT)
        )]
    );
    assert_eq!(
        err,
        format!(
            "left {} for good.\nto join a new root: swoosh join\n",
            root_short(ROOT)
        )
    );
    assert_eq!(ran.prompts, 0, "a device asks no passphrase");
    assert!(latched(&home, ROOT));
    assert_eq!(
        swoosh::standing::Standing::read(&home).await.unwrap(),
        swoosh::standing::Standing::Unpinned
    );
    for gone in [
        home.root_pub(),
        home.key_cert(),
        home.devices(),
        home.devices_conflict(),
        home.synced(),
        home.invited_by(),
    ] {
        assert!(!gone.exists(), "{} is gone", gone.display());
    }
}

#[tokio::test]
async fn revoke_a_root_latches_its_root_and_every_cap_under_it_is_refused() {
    let home = scratch("root-caps");
    let until = SystemTime::now() + Duration::from_secs(3600);
    let caps: Vec<Link> = [LAPTOP, PHONE]
        .into_iter()
        .map(|seed| {
            TestRoot::seeded(ALICE_ROOT)
                .device_badge(node(seed), until)
                .unwrap()
        })
        .collect();
    let revoked = swoosh::revoked::open(&home).unwrap();
    assert!(caps.iter().all(|cap| !revoked.is_revoked(cap.cap())));
    let _ = revoke_root(&home, ALICE_ROOT, &prefix(ALICE_ROOT))
        .await
        .ok()
        .to_owned();
    let revoked = swoosh::revoked::open(&home).unwrap();
    for cap in &caps {
        assert!(
            revoked.is_revoked(cap.cap()),
            "every cap under the root is refused"
        );
    }
}

#[tokio::test]
async fn revoke_a_root_on_the_holder_retires_the_root_and_frees_the_home_to_mint() {
    let home = scratch("root-retire");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = revoke_root(&home, ROOT, &prefix(ROOT)).await;
    let err = ran.ok().to_owned();
    assert_eq!(
        ran.said,
        [format!(
            "this machine keeps {}; this deletes it here and ends it for good.",
            root_short(ROOT)
        )]
    );
    assert_eq!(
        err,
        format!(
            "retired {}, your root, on this machine.\n\
             to make a new root: swoosh invite <name> <key>\n\
             tell your contacts; each of them runs: swoosh contact add <you> <new root key>\n",
            root_short(ROOT)
        )
    );
    assert_eq!(ran.prompts, 1, "one passphrase");
    assert!(latched(&home, ROOT));
    for gone in [
        home.root_key(),
        home.root_pub(),
        home.key_cert(),
        home.devices(),
        home.devices_conflict(),
        home.synced(),
        home.invited_by(),
    ] {
        assert!(!gone.exists(), "{} is gone", gone.display());
    }
    assert_eq!(
        swoosh::standing::Standing::revoked_root(&home)
            .await
            .unwrap(),
        None,
        "no revoked root is left"
    );
    let minted = invite(&home, &["tv", &node(0x44).to_string()]).await;
    let _ = minted.invite();
    assert!(
        matches!(
            swoosh::standing::Standing::read(&home).await.unwrap(),
            swoosh::standing::Standing::HoldsRoot { pin, .. } if pin != node(ROOT)
        ),
        "the next invite made a new root"
    );
}

#[tokio::test]
async fn revoke_a_root_on_the_holder_killed_after_the_latch_never_yields_a_mintable_root() {
    let home = scratch("root-killed");
    holds(&home, &[live(OWN, "desk")], Vec::new()).await;
    // Killed just after the latch: every file the root vouched for is still here.
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        &home,
        [nauthy::Revocation::Key(TestRoot::seeded(ROOT).verify_key())],
    )
    .unwrap();
    let before = snapshot(home.dir());
    assert_eq!(
        swoosh::standing::Standing::read(&home).await.unwrap(),
        swoosh::standing::Standing::Unpinned,
        "a revoked root.key reads as no root, never an unfinished mint"
    );
    let report = status(&home).await;
    assert!(
        report.contains(&format!(
            "a revoked root is still on this machine; to delete it: swoosh revoke root:{}",
            node(ROOT)
        )),
        "{report}"
    );
    assert!(snapshot(home.dir()) == before, "the reads wrote nothing");

    let ran = revoke_root(&home, ROOT, &prefix(ROOT)).await;
    let _ = ran.ok();
    assert_eq!(ran.prompts, 0, "the root is already revoked: no passphrase");
    assert!(!home.root_key().exists(), "running it again deletes it");
    assert!(!home.root_pub().exists());
    assert!(!home.devices().exists());
    assert!(!status(&home).await.contains("a revoked root"));
}

#[tokio::test]
async fn revoke_a_root_on_a_device_killed_after_the_latch_is_finished_by_running_it_again() {
    let home = device(
        "root-device-killed",
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
    )
    .await;
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        &home,
        [nauthy::Revocation::Key(TestRoot::seeded(ROOT).verify_key())],
    )
    .unwrap();
    let before = snapshot(home.dir());
    assert_eq!(
        swoosh::standing::Standing::read(&home).await.unwrap(),
        swoosh::standing::Standing::Unpinned
    );
    let _ = status(&home).await;
    assert!(snapshot(home.dir()) == before, "the read writes nothing");

    let ran = revoke_root(&home, ROOT, &prefix(ROOT)).await;
    let err = ran.ok().to_owned();
    assert!(
        err.starts_with(&format!("left {} for good.", root_short(ROOT))),
        "{err}"
    );
    for gone in [home.root_pub(), home.key_cert(), home.devices()] {
        assert!(!gone.exists(), "{} is gone", gone.display());
    }
}

#[tokio::test]
async fn revoke_a_root_refuses_this_machines_own_key() {
    let home = scratch("root-own-key");
    let before = snapshot(home.dir());
    let ran = revoke_root(&home, OWN, &prefix(OWN)).await;
    assert_eq!(ran.refusal(), "that is this machine's key, not a root.");
    assert!(ran.confirms.is_empty());
    assert!(snapshot(home.dir()) == before);
}

#[tokio::test]
async fn revoke_a_root_without_a_terminal_names_ssh_t() {
    for (kind, home, seed) in every_kind("root-no-terminal").await {
        let before = snapshot(home.dir());
        let ran = revoke_root_with(
            &home,
            seed,
            Some(&prefix(seed)),
            Counting::new([PASS]),
            false,
        )
        .await;
        assert_eq!(
            ran.refusal(),
            "this cannot be undone, so it needs a terminal: over swoosh ssh, add -t after --",
            "{kind}"
        );
        assert!(ran.confirms.is_empty(), "{kind}");
        assert!(snapshot(home.dir()) == before, "{kind}: nothing latched");
    }
}

#[test]
fn revoke_long_help_prints_the_recipe_exactly() {
    let mut cli = crate::Cli::command();
    cli.build();
    let mut revoke = cli
        .find_subcommand("revoke")
        .expect("revoke is a top-level verb")
        .clone();
    let long = revoke.render_long_help().to_string();
    let lines: Vec<&str> = long.lines().collect();
    let heading = lines
        .iter()
        .position(|line| *line == "To replace your root:")
        .unwrap_or_else(|| panic!("the heading: {long}"));
    assert_eq!(&lines[heading + 1..heading + 11], RECIPE_LINES, "{long}");
    let short = revoke.render_help().to_string();
    assert!(!short.contains("To replace your root:"), "{short}");
    for line in RECIPE_LINES {
        assert!(!short.contains(line), "-h holds none of them: {short}");
    }
}

#[tokio::test]
async fn revoke_a_root_on_the_holder_never_syncs() {
    let home = scratch("root-never-syncs");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = revoke_root(&home, ROOT, &prefix(ROOT)).await;
    let _ = ran.ok();
    let tape = ran.tape.text();
    assert!(
        !tape.contains("<exchange>"),
        "no exchange is dialed: {tape}"
    );
    assert!(!tape.contains("<offer>"), "nothing is offered: {tape}");
}

#[tokio::test]
async fn revoke_a_device_without_a_terminal_prints_one_partway_line() {
    let home = scratch("device-partway");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let tape = Tape::default();
    let typing = Typing::new(Counting::new([PASS]), false, None, &tape);
    let ran = run_typing(
        &home,
        &["me/laptop"],
        b"",
        typing,
        Devices::all(&tape),
        tape,
    )
    .await;
    assert_eq!(
        ran.refusal(),
        "me/laptop is blocked on this machine, not yet on your other devices; your root's passphrase \
         needs a terminal: over swoosh ssh, add -t after --"
    );
    assert!(ran.err.is_empty(), "no line before the error: {}", ran.err);
    assert!(blocks_key(&home, LAPTOP).await, "the block is written");
}

#[tokio::test]
async fn revoke_a_device_prints_revoked_after_the_root_commits() {
    let home = scratch("device-after-commit");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let ran = revoke(&home, &["me/laptop"]).await;
    let err = ran.ok().to_owned();
    let mut lines = err.lines();
    let reach = lines.next().unwrap();
    assert!(reach.starts_with("revoked me/laptop: "), "{err}");
    assert_eq!(
        lines.collect::<Vec<_>>(),
        [
            "me/laptop can never rejoin your devices with its current key.",
            "to add laptop again, first run this at its console: swoosh leave --new-key",
        ],
        "the reach line leads, and the two lines follow it"
    );
    assert!(
        ran.tape.at("<prompt>") < ran.tape.at(reach),
        "the first line follows the root step: {}",
        ran.tape.text()
    );
    assert!(
        kept_list(&home).is_revoked_key(&key(LAPTOP)),
        "the root committed its cut"
    );
}

/// Record a running `serve` in `home`'s `serve.lock`: this process's pid, which is alive.
fn serving(home: &Home) {
    std::fs::write(home.serve_lock(), format!("{}\n", std::process::id())).unwrap();
}

/// The lines a root's revoke prints while `serve` runs, for `root`.
fn sessions_end(root: &str) -> String {
    format!(
        "sessions from devices of {root} end now, yours too if you reached this machine as one.\n\
         sessions through links this machine made stay open.\n"
    )
}

/// A key one of your devices holds, or a contact's device, is never a root: the root form refuses it before
/// the terminal check and the prompt, naming the form that takes it, and writes nothing. Red when the root
/// form latches it as a root this machine does not know.
#[tokio::test]
async fn revoke_a_root_refuses_a_device_key_and_names_its_form() {
    let home = scratch("root-device-key");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let mut store = ContactsStore::open(&home).await.unwrap();
    store.contacts_mut().add(
        "alice".parse().unwrap(),
        Some("phone".parse().unwrap()),
        node(PHONE),
    );
    store.save(&swoosh::testkit::lock()).unwrap();
    let before = snapshot(home.dir());
    for (seed, line) in [
        (
            LAPTOP,
            "that is me/laptop's key, not a root; to revoke the device: swoosh revoke me/laptop",
        ),
        (
            PHONE,
            "that is alice/phone's key, not a root; to take back the links this machine gave it: swoosh \
             revoke alice/phone",
        ),
    ] {
        for terminal in [true, false] {
            let ran = revoke_root_with(
                &home,
                seed,
                Some(&prefix(seed)),
                Counting::new([PASS]),
                terminal,
            )
            .await;
            assert_eq!(ran.refusal(), line, "at a terminal: {terminal}");
            let usage = ran
                .result
                .as_ref()
                .err()
                .and_then(|error| error.downcast_ref::<Usage>());
            assert!(usage.is_none(), "exit 1, as the own-key refusal");
            assert!(ran.confirms.is_empty() && ran.said.is_empty(), "{line}");
            assert!(snapshot(home.dir()) == before, "nothing was written");
        }
    }
}

/// A root this machine keeps or is pinned to stays a root when a list of its devices also names its key as
/// `me/<name>`: a paste mistake upstream, or an update a thief signed. Each takes its own kind's arm, never
/// the device-key refusal. Red when the device-key check runs before the root is classified.
#[tokio::test]
async fn revoke_a_root_whose_key_is_also_a_device_row_takes_its_own_arm() {
    let rows = [live(OWN, "desk"), live(ROOT, "pasted")];
    let holder = scratch("root-also-row-holder");
    holds(&holder, &rows, Vec::new()).await;
    let device = device("root-also-row-device", &rows).await;
    for (what, home, prompts) in [("holder", holder, 1), ("device", device, 0)] {
        let ran = revoke_root(&home, ROOT, &prefix(ROOT)).await;
        let err = ran.ok().to_owned();
        assert!(!err.contains("not a root"), "{what}: {err}");
        assert_eq!(ran.confirms.len(), 1, "{what}: the prefix is asked");
        assert_eq!(ran.prompts, prompts, "{what}");
        assert!(latched(&home, ROOT), "{what}");
        assert!(!home.root_pub().exists(), "{what}: root.pub is gone");
        assert!(!home.root_key().exists(), "{what}: no root.key is left");
    }
}

/// The device arm latches the root before it leaves: a latch that fails leaves the membership whole, so the
/// rerun finds the pin again, never a home that left a root it still trusts. The latch is made to fail by a
/// `revoked` that reads fine but has no room for one more line: within a line of nauthy's 4 MiB cap, which
/// a write refuses to cross. Red when `leave` runs before the latch.
#[tokio::test]
async fn revoke_a_root_on_a_device_whose_latch_fails_keeps_its_membership() {
    use std::os::unix::fs::PermissionsExt as _;

    const CAP: usize = 4 << 20;
    let home = device(
        "root-device-latch-fails",
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
    )
    .await;
    let mut body = String::new();
    for id in 0_u64.. {
        let line = format!("id {id:016x}\n");
        if body.len() + line.len() > CAP {
            break;
        }
        body.push_str(&line);
    }
    let key_line = format!("key {}\n", TestRoot::seeded(ROOT).verify_key());
    assert!(
        CAP - body.len() < key_line.len(),
        "the latch's line cannot fit"
    );
    std::fs::write(home.revoked(), &body).unwrap();
    std::fs::set_permissions(home.revoked(), std::fs::Permissions::from_mode(0o600)).unwrap();
    let ran = revoke_root(&home, ROOT, &prefix(ROOT)).await;
    let refusal = ran.refusal();
    assert!(
        refusal.contains("is larger than a list of revocations can be"),
        "{refusal}"
    );
    assert!(!latched(&home, ROOT));
    for kept in [home.root_pub(), home.key_cert()] {
        assert!(kept.exists(), "{} survives", kept.display());
    }
}

/// A terminal that is there and fails to read the confirmation: what [`Prompt::confirm`] returns when the
/// tty was opened and its read failed.
struct BrokenTty;

impl Prompt for BrokenTty {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(&mut self, _asked: Question<'_>) -> eyre::Result<Passphrase> {
        eyre::bail!("no passphrase is asked before the prefix")
    }

    fn choose(&mut self, _asked: Question<'_>) -> eyre::Result<Choice> {
        eyre::bail!("no passphrase is chosen here")
    }

    fn say(&mut self, _line: &str) {}

    fn confirm(&mut self, _question: &str) -> eyre::Result<String> {
        Err(std::io::Error::other("the tty read failed").into())
    }
}

/// A confirmation that fails on an open terminal prints its own cause, never the missing-terminal line,
/// and writes nothing. Red when every confirm failure reads as no terminal.
#[tokio::test]
async fn revoke_a_root_whose_confirmation_fails_to_read_prints_the_cause() {
    let home = scratch("root-confirm-io");
    let before = snapshot(home.dir());
    let tape = Tape::default();
    let mut err = Stream {
        bytes: Vec::new(),
        tape: tape.clone(),
    };
    let target = format!("root:{}", node(STRANGER));
    let error = parse(&[&target])
        .unwrap()
        .block(
            &home,
            &b""[..],
            &mut BrokenTty,
            &Devices::all(&tape),
            &mut err,
        )
        .await
        .expect_err("the confirmation failed");
    assert_eq!(format!("{error:#}"), "the tty read failed");
    assert!(!latched(&home, STRANGER));
    assert!(snapshot(home.dir()) == before, "nothing was written");
}

/// The lines before the prompt are said where the person types, never on stderr, so a stderr sent elsewhere
/// never hides what the act ends. Red when they print on stderr.
#[tokio::test]
async fn revoke_a_root_says_what_this_machine_is_to_it_where_the_prompt_is() {
    for (kind, home, seed) in every_kind("root-tty").await {
        let ran = revoke_root(&home, seed, &prefix(seed)).await;
        let err = ran.ok().to_owned();
        assert!(!ran.said.is_empty(), "{kind}");
        for line in &ran.said {
            assert!(!err.contains(line.as_str()), "{kind}: {err}");
            assert!(
                ran.tape.at(&format!("<tty>{line}")) < ran.tape.at("<confirm>"),
                "{kind}"
            );
        }
    }
}

/// A root whose making stopped after `root.key` (no list) or whose restore did (its list beside it) is
/// retired as a made root: the holder's line, the prefix, its passphrase, the holder's lines, every file
/// gone. Never the `serve` line, since nothing was admitted under a root never pinned. Red when the half-made
/// root refuses after the prompt and names the mint, or the `serve` line prints for any holder.
#[tokio::test]
async fn revoke_a_half_made_root_retires_it_as_a_made_one() {
    let minted = scratch("root-half-minted");
    root_key_at(&minted.root_key());
    let restored = scratch("root-half-restored");
    root_key_at(&restored.root_key());
    held(&restored, &records(1, &[live(OWN, "desk")], Vec::new()));
    for (what, home) in [("mint", minted), ("restore", restored)] {
        assert!(
            matches!(
                swoosh::standing::Standing::read(&home).await.unwrap(),
                swoosh::standing::Standing::InterruptedMint { .. }
            ),
            "{what}"
        );
        serving(&home);
        let ran = revoke_root(&home, ROOT, &prefix(ROOT)).await;
        let err = ran.ok().to_owned();
        assert_eq!(
            ran.said,
            [format!(
                "this machine keeps {}; this deletes it here and ends it for good.",
                root_short(ROOT)
            )],
            "{what}"
        );
        assert_eq!(
            err,
            format!(
                "retired {}, your root, on this machine.\n\
                 to make a new root: swoosh invite <name> <key>\n\
                 tell your contacts; each of them runs: swoosh contact add <you> <new root key>\n",
                root_short(ROOT)
            ),
            "{what}"
        );
        assert_eq!(ran.prompts, 1, "{what}: its passphrase is asked");
        assert!(latched(&home, ROOT), "{what}");
        for gone in [home.root_key(), home.devices(), home.root_pub()] {
            assert!(!gone.exists(), "{what}: {} is gone", gone.display());
        }
        assert_eq!(
            swoosh::standing::Standing::read(&home).await.unwrap(),
            swoosh::standing::Standing::Unpinned,
            "{what}"
        );
    }
}

/// While `serve` runs, revoking the root this machine is pinned to says the sessions under it end, and
/// those through links this machine made do not; a root it was never pinned to, or one a stopped revoke
/// latched already, prints neither. Red when the lines are dropped, or printed for any kind.
#[tokio::test]
async fn revoke_a_root_names_the_sessions_it_ends_while_serve_runs() {
    let device = device("root-serve", &[live(OWN, "desk"), live(LAPTOP, "laptop")]).await;
    serving(&device);
    let ran = revoke_root(&device, ROOT, &prefix(ROOT)).await;
    assert!(
        ran.ok().ends_with(&sessions_end(&root_short(ROOT))),
        "{}",
        ran.err
    );

    let unknown = scratch("root-serve-unknown");
    serving(&unknown);
    let ran = revoke_root(&unknown, STRANGER, &prefix(STRANGER)).await;
    assert!(!ran.ok().contains("sessions"), "{}", ran.err);

    let latched_here = scratch("root-serve-latched");
    holds(&latched_here, &[live(OWN, "desk")], Vec::new()).await;
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        &latched_here,
        [nauthy::Revocation::Key(TestRoot::seeded(ROOT).verify_key())],
    )
    .unwrap();
    serving(&latched_here);
    let ran = revoke_root(&latched_here, ROOT, &prefix(ROOT)).await;
    assert!(!ran.ok().contains("sessions"), "{}", ran.err);
}

/// What this machine is to the root is read again under `home.lock`: a root kept here written while the
/// person typed stops a revoke that read the root as unknown, before its latch. Red when the re-check is
/// dropped.
#[tokio::test]
async fn revoke_a_root_whose_kind_moved_during_the_prompt_writes_nothing() {
    let home = scratch("root-kind-moved");
    let tape = Tape::default();
    let mut typing = Typing::new(Counting::new([PASS]), true, Some(&prefix(ROOT)), &tape);
    let key_path = home.root_key();
    typing.then = Some(Box::new(move || root_key_at(&key_path)));
    let target = format!("root:{}", node(ROOT));
    let ran = run_typing(&home, &[&target], b"", typing, Devices::all(&tape), tape).await;
    assert_eq!(ran.refusal(), swoosh::standing::CHANGED);
    assert!(!latched(&home, ROOT), "nothing latched");
}

/// Three wrong passphrases at the root step of `revoke me/<name>` leave the block written, and say so in
/// one line that names the rerun. Red when the third wrong passphrase prints its own refusal.
#[tokio::test]
async fn revoke_a_device_after_three_wrong_passphrases_prints_one_partway_line() {
    let home = scratch("device-wrong-three");
    holds(
        &home,
        &[live(OWN, "desk"), live(LAPTOP, "laptop")],
        Vec::new(),
    )
    .await;
    let tape = Tape::default();
    let wrong = Counting::new([
        "not it at all, sorry",
        "nor this one, either",
        "nor the third one",
    ]);
    let ran = run(&home, &["me/laptop"], b"", wrong, Devices::all(&tape), tape).await;
    assert_eq!(
        ran.refusal(),
        "me/laptop is blocked on this machine, not yet on your other devices; to finish, run it again: \
         swoosh revoke me/laptop"
    );
    assert_eq!(ran.prompts, 3, "three tries");
    assert!(!ran.err.contains("revoked"), "{}", ran.err);
    assert!(blocks_key(&home, LAPTOP).await, "the block is written");
}

/// Any other cause the root step stops on prints the partway sentence, then the cause's own line, as one
/// message: here a copy of your root that cannot be written. Red when the cause prints alone, with nothing
/// saying the block landed.
#[tokio::test]
async fn revoke_a_device_whose_root_step_stops_prints_the_partway_line_then_its_cause() {
    use std::os::unix::fs::PermissionsExt as _;

    let rows = [live(OWN, "desk"), live(LAPTOP, "laptop")];
    let home = device("partway-cause", &rows).await;
    let copy_dir = dir("partway-cause-copy");
    copy(&copy_dir, &records(1, &rows, Vec::new()));
    std::fs::set_permissions(&copy_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let ran = revoke(&home, &["me/laptop", "--root", copy_dir.to_str().unwrap()]).await;
    std::fs::set_permissions(&copy_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let refusal = ran.refusal();
    let (first, cause) = refusal.split_once('\n').expect("two lines");
    assert_eq!(
        first,
        "me/laptop is blocked on this machine, not yet on your other devices."
    );
    assert!(
        cause.starts_with("this copy of your root cannot be written ("),
        "{refusal}"
    );
    assert!(!ran.err.contains("revoked"), "{}", ran.err);
    assert!(blocks_key(&home, LAPTOP).await, "the block is written");
}

/// The recipe's first line, run on nas against the real `share`: the link it makes is bound to the key
/// `leave --new-key` made in the rescue home, so it admits that home and not desk's key, and it is sealed,
/// so no holder passes it on. Its last line, `revoke -` on nas with the link on stdin, ends it there.
#[tokio::test]
async fn the_recipe_link_is_bound_to_a_rescue_key() {
    let nas = scratch("recipe-nas");
    device_of(&nas, &live(OWN, "nas")).await;
    let rescue_dir = dir("recipe-rescue");
    swoosh::config::create_store_dir(&rescue_dir).unwrap();
    let rescue = Home::resolve(Some(rescue_dir)).unwrap();

    // Line 1's inner `$(…)`: a new key in its own home, printed on stdout.
    let made = "$(swoosh --home ~/.swoosh-rescue leave --new-key)";
    let (mut out, mut err) = (Vec::new(), Vec::new());
    super::super::leave::LeaveCmd { new_key: true }
        .leave(
            &rescue,
            &mut Counting::refusing(),
            SystemTime::now(),
            &mut out,
            &mut err,
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "leave --new-key on an empty home: {error:#}\n{}",
                String::from_utf8_lossy(&err)
            )
        });
    let rescue_key = String::from_utf8(out).unwrap().trim().to_owned();
    let rescue_key: NodeId = rescue_key.parse().expect("stdout is the new key alone");

    // Line 1's command on nas, as the recipe prints it, with the key in place of its `$(…)`.
    let line = RECIPE_LINES[0];
    let start = line.find("swoosh share ").expect("line 1 shares");
    let end = line.find(" > ~/nas.link)").expect("line 1 saves the link");
    let typed = &line[start..end];
    assert!(
        typed.contains(made),
        "line 1 makes the key in the rescue home: {line}"
    );
    let typed = typed.replace(made, &rescue_key.to_string());
    let cli = crate::Cli::try_parse_from(typed.split_whitespace()).expect("line 1 parses");
    let Some(crate::Command::Share(share)) = cli.command else {
        panic!("line 1 is a share: {typed}");
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    share
        .run(&nas, &b""[..], &mut out, &mut err)
        .await
        .unwrap_or_else(|error| panic!("{typed}: {error:#}"));
    let printed = String::from_utf8(out).unwrap();
    let link = swoosh::link::parse(printed.trim()).expect("stdout is the link alone");

    let nas_key = TestNode::seeded(OWN).verify_key();
    let service: Service = "ssh".parse().unwrap();
    let from = |key: NodeId| {
        nauthy::Request::now(Service::clone(&service)).bound_to(key.verify_key().unwrap())
    };
    link.cap()
        .verify_at_root_without_revocation(&from(rescue_key), nas_key)
        .expect("the link admits the rescue home's key, which lines 2 and 6 dial from");
    assert!(
        link.cap()
            .verify_at_root_without_revocation(&from(node(LAPTOP)), nas_key)
            .is_err(),
        "desk's own key is not admitted on it"
    );
    assert!(
        link.narrow(None, Some(Duration::from_secs(60))).is_err(),
        "the link is sealed"
    );
    let expected = (SystemTime::now() + Duration::from_secs(7 * DAY))
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ends = link
        .cap()
        .valid_until()
        .unwrap()
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(ends.abs_diff(expected) <= 5, "it lasts 7d");

    // Line 10's `revoke -` on nas, the link on stdin.
    let line = RECIPE_LINES[9];
    assert!(
        line.contains("swoosh ssh me/nas -- swoosh revoke - < ~/nas.link"),
        "line 10 revokes the link on nas: {line}"
    );
    let tape = Tape::default();
    let ran = run(
        &nas,
        &["-"],
        printed.as_bytes(),
        Counting::refusing(),
        Devices::all(&tape),
        tape,
    )
    .await;
    assert!(
        ran.ok().starts_with("revoked the link"),
        "line 10 runs and says what it did: {}",
        ran.err
    );
    assert!(
        swoosh::revoked::open(&nas).unwrap().is_revoked(link.cap()),
        "the rescue link is revoked on nas"
    );
}
