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
use nauthy::{Link, Revocations as _, Service};
use swoosh::contacts::ContactsStore;
use swoosh::grants::{Delegation, GrantKind, GrantRecord, Grants};
use swoosh::home::Home;
use swoosh::root::{Date, RootPlace};
use swoosh::roster::{Epoch, RosterDoc};
use swoosh::sync::{Answer, Dial, ExchangeError};
use swoosh::testkit::{Counting, TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;

use super::super::invite::invite_tests::{
    Asked, CI, DAY, LAPTOP, NAS, NINETY, OWN, PASS, PHONE, ROOT, Row, Stream, Tape, carrying, copy,
    device_of, due, held, holds, invite, kept, kept_list, key, live, node, now, records, revoked,
    row_of, scratch, signed, snapshot,
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
struct Ran {
    result: eyre::Result<()>,
    err: String,
    tape: Tape,
    prompts: usize,
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
    fn ok(&self) -> &str {
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
    let mut err = Stream {
        bytes: Vec::new(),
        tape: tape.clone(),
    };
    let mut prompt = Asked {
        inner: prompt,
        terminal: true,
        tape: tape.clone(),
    };
    let cmd = parse(args).unwrap();
    let result = match cmd.block(home, stdin, &mut err).await {
        Ok(Some(publish)) => publish.run(home, &mut prompt, &dial, &mut err).await,
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    Ran {
        result,
        err: String::from_utf8(err.bytes).unwrap(),
        tape,
        prompts: prompt.inner.events(),
    }
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
    let _ = ran.refusal();
    assert_eq!(
        ran.prompts, 1,
        "the passphrase was asked, and the ask ended"
    );
    let first = "revoked me/laptop: blocked here now. This key can never be your device again; laptop will \
                 need `swoosh leave --new-key` at its console.";
    assert!(
        ran.tape.at(first) < ran.tape.at("<prompt>"),
        "the first line prints before the prompt: {}",
        ran.tape.text()
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
    let root_key = format!("root:{}", node(ROOT));
    let error = parse(&[&root_key]).expect_err("a root key has no form yet");
    assert_eq!(error.exit_code(), 2, "a root key is an unknown shape");
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
    assert_eq!(usage.0, "stdin held no swoosh: link.");

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
            "and the links this machine gave it: blocked (only this machine admitted them).\n"
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
        "me/laptop is now listed under a key this revoke did not see, so your root did not revoke it",
        "the refusal names no command: running the revoke again would take the name's new key"
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

    let stored = swoosh::identity::inspect(&home).unwrap().into_stored();
    let out = super::super::status::report::Report::gather(&home, Some(&stored), now())
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
