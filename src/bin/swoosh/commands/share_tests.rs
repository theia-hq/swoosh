//! `share` over homes built on disk: a machine with its own key, the contacts it saved, and the ledger the
//! verb writes. Each run is in process, through the parser the binary uses, with stdin, stdout and stderr
//! captured.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Parser as _;
use nauthy::{CapError, Decision, Link, ProvenPeer, Service};
use swoosh::contacts::ContactsStore;
use swoosh::grants::{Delegation, GrantKind, GrantRecord, Grants};
use swoosh::home::{Home, HomeWrite, ProcessId, ServeLock};
use swoosh::node_client::ControlClient;
use swoosh::serve::control_codec::{
    DisabledList, LocalServiceSnapshot, Request, Response, ServiceMenu, StatusReply,
};
use swoosh::serve_toml::ServeToml;
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::ServiceCatalog;
use tokio::io::AsyncWriteExt as _;

use super::super::service_state::ShareTarget;
use super::{End, ONCE_ANYONE, ShareCmd, Span, Usage};

/// This machine's key.
const OWN: u8 = 0x11;
/// Bob's root.
const BOB_ROOT: u8 = 0x21;
/// Bob's laptop.
const BOB_LAPTOP: u8 = 0x22;
/// The root this machine is a device of.
const PIN: u8 = 0x31;

static SCRATCH_SEQ: AtomicU32 = AtomicU32::new(0);

/// A fresh home holding this machine's plain key.
async fn scratch(tag: &str) -> Home {
    let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("swoosh-share-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    swoosh::identity::write(&TestNode::seeded(OWN).seed(), &home)
        .await
        .unwrap();
    serving(
        &home,
        &["ssh=sshd:", "demo=echo:", "ping=ping:", "speed=speed:"],
    );
    home
}

/// Save bob's root, and his laptop as `bob/laptop`.
async fn with_bob(home: &Home) {
    let mut store = ContactsStore::open(home).await.unwrap();
    store
        .contacts_mut()
        .set_signet("bob".parse().unwrap(), TestRoot::seeded(BOB_ROOT).node_id());
    store.contacts_mut().add(
        "bob".parse().unwrap(),
        Some("laptop".parse().unwrap()),
        TestNode::seeded(BOB_LAPTOP).node_id(),
    );
    store.save(&swoosh::testkit::lock()).unwrap();
}

/// A file in `home`'s directory that does not exist yet.
fn path_in(home: &Home, name: &str) -> PathBuf {
    home.dir().join(name)
}

/// What one `share` did.
struct Ran {
    result: eyre::Result<()>,
    out: String,
    err: String,
}

impl Ran {
    fn refusal(&self) -> String {
        match &self.result {
            Ok(()) => panic!("share made a link: {}", self.out),
            Err(error) => format!("{error:#}"),
        }
    }

    fn made(&self) -> &str {
        if let Err(error) = &self.result {
            panic!("share refused: {error:#}\n{}", self.err);
        }
        self.out.trim()
    }

    fn link(&self) -> Link {
        swoosh::link::parse(self.made()).unwrap()
    }
}

/// The command `swoosh share <args>` parses to.
fn parse(args: &[&str]) -> Result<ShareCmd, clap::Error> {
    let cli = crate::Cli::try_parse_from(["swoosh", "share"].iter().chain(args).copied())?;
    match cli.command {
        Some(crate::Command::Share(cmd)) => Ok(cmd),
        other => panic!("share parses to share, not {other:?}"),
    }
}

/// `swoosh share <args>` on `home`, with `stdin` as its stdin.
async fn share_with(home: &Home, args: &[&str], stdin: &[u8]) -> Ran {
    let cmd = parse(args).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = cmd.run(home, stdin, &mut out, &mut err).await;
    Ran {
        result,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

async fn share(home: &Home, args: &[&str]) -> Ran {
    share_with(home, args, b"").await
}

async fn rows(home: &Home) -> Vec<GrantRecord> {
    Grants::at(home.links()).load().await.unwrap()
}

/// A file holding `link` as a person saves it, for a path argument.
fn saved(home: &Home, name: &str, link: &Link) -> String {
    let path = path_in(home, name);
    std::fs::write(
        &path,
        format!("{}\n", swoosh::link::Link::from(link.clone())),
    )
    .unwrap();
    path.display().to_string()
}

/// When `link` stops granting, in seconds from the epoch.
fn ends(link: &Link) -> u64 {
    link.cap()
        .valid_until()
        .unwrap()
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn from_now(span: Duration) -> u64 {
    (SystemTime::now() + span)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn share_without_who_refuses() {
    let home = scratch("no-who").await;
    let ran = share(&home, &["ssh"]).await;
    let error = ran.result.as_ref().expect_err("a bare share refuses");
    assert_eq!(
        error.downcast_ref::<Usage>().map(|usage| usage.0.as_str()),
        Some(
            "who is it for? swoosh share ssh <person>, <person>/<name>, <key>, or anyone (whoever \
             holds the link)"
        ),
        "a usage error, exit 2, naming the four kinds"
    );
    assert!(ran.out.is_empty(), "no link prints: {}", ran.out);
    assert!(rows(&home).await.is_empty(), "no row is written");
}

#[test]
fn share_with_empty_who_refuses() {
    for who in ["", " "] {
        let error = parse(&["ssh", who]).expect_err("an empty recipient refuses");
        assert_eq!(error.exit_code(), 2, "{who:?} is a usage error");
        assert!(
            error.to_string().contains("who is it for?"),
            "{who:?} names the four kinds: {error}"
        );
    }
}

#[tokio::test]
async fn share_person_without_root_refuses() {
    let home = scratch("no-root").await;
    let mut store = ContactsStore::open(&home).await.unwrap();
    store.contacts_mut().add(
        "bob".parse().unwrap(),
        Some("laptop".parse().unwrap()),
        TestNode::seeded(BOB_LAPTOP).node_id(),
    );
    store.save(&swoosh::testkit::lock()).unwrap();
    for who in ["bob", "carol"] {
        let ran = share(&home, &["ssh", who]).await;
        assert_eq!(
            ran.refusal(),
            format!("{who} has no root saved here: swoosh contact add {who} <root key>")
        );
        assert!(ran.out.is_empty(), "no link prints: {}", ran.out);
    }
    assert!(rows(&home).await.is_empty(), "no row is written");
}

#[tokio::test]
async fn share_bound_link_refuses() {
    let home = scratch("bound").await;
    let bound = TestNode::seeded(0x41)
        .bound_slip(
            &"ssh".parse().unwrap(),
            TestNode::seeded(BOB_LAPTOP).verify_key(),
            nauthy::Request::expires_in(Duration::from_secs(3600)),
        )
        .unwrap();
    let path = saved(&home, "bound.link", &bound);
    let ran = share(&home, &[&path]).await;
    assert_eq!(
        ran.refusal(),
        "this link cannot be copied: ask whoever made it for another"
    );
    assert!(ran.out.is_empty(), "no link prints: {}", ran.out);
}

#[tokio::test]
async fn share_save_writes_0600_and_refuses_an_existing_file() {
    let home = scratch("save").await;
    let file = path_in(&home, "x.link");
    let path = file.display().to_string();
    let ran = share(&home, &["demo", "anyone", "--save", &path]).await;
    assert_eq!(ran.made(), path, "stdout is the path alone");
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the file is private");
    let held = std::fs::read_to_string(&file).unwrap();
    assert!(
        held.starts_with("swoosh:"),
        "the file holds the printed form: {held}"
    );
    swoosh::link::parse(held.trim()).expect("the file holds the link");

    let again = share(&home, &["demo", "anyone", "--save", &path]).await;
    assert!(
        again.refusal().contains("exists already"),
        "{}",
        again.refusal()
    );
    assert!(again.out.is_empty(), "nothing prints: {}", again.out);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        held,
        "the file survives"
    );
    assert_eq!(
        rows(&home).await.len(),
        1,
        "the refused share writes no row"
    );
}

#[tokio::test]
async fn share_reads_a_link_from_a_path() {
    let home = scratch("path").await;
    let source = share(&home, &["demo", "anyone", "--expires", "2h"])
        .await
        .link();
    let path = saved(&home, "source.link", &source);
    let copy = share(&home, &[&path, "--expires", "1h"]).await.link();
    assert_eq!(
        copy.root(),
        source.root(),
        "the copy dials the same machine"
    );
    assert!(
        copy.cap().revocation_ids().len() > source.cap().revocation_ids().len(),
        "the copy is narrowed from the source"
    );
    assert!(ends(&copy) <= from_now(Duration::from_secs(3600)) + 1);

    let stdin = format!("{}\n", swoosh::link::Link::from(source.clone()));
    let piped = share_with(&home, &["-"], stdin.as_bytes()).await.link();
    assert_eq!(piped.root(), source.root(), "`-` reads the link from stdin");
}

#[tokio::test]
async fn share_link_copy_defaults_to_the_sources_remaining_time() {
    let home = scratch("copy").await;
    let source = share(&home, &["demo", "anyone", "--expires", "2h"])
        .await
        .link();
    let copy = share(&home, &[&saved(&home, "s.link", &source)]).await;
    assert!(
        ends(&source).abs_diff(ends(&copy.link())) <= 2,
        "the copy ends when its source does"
    );
    let first = copy.err.lines().next().unwrap();
    assert!(
        first.starts_with("the copy works until ") && first.ends_with(", when its link ends."),
        "a copy that ends with its link prints no span: {}",
        copy.err
    );
    assert!(
        copy.err
            .contains("anyone holding this link can use it: send it privately."),
        "{}",
        copy.err
    );

    let longer = share(
        &home,
        &[&saved(&home, "l.link", &source), "--expires", "3h"],
    )
    .await
    .link();
    assert!(
        ends(&longer) <= ends(&source),
        "a copy never outlives its source"
    );
}

#[tokio::test]
async fn share_link_with_a_recipient_is_a_usage_error() {
    let home = scratch("link-who").await;
    let source = share(&home, &["demo", "anyone"]).await.link();
    let ran = share(&home, &[&saved(&home, "s.link", &source), "bob/laptop"]).await;
    let error = ran.result.as_ref().expect_err("a link takes no recipient");
    assert!(error.downcast_ref::<Usage>().is_some(), "exit 2: {error:#}");
    assert!(ran.out.is_empty(), "no link prints: {}", ran.out);
}

#[tokio::test]
async fn share_to_your_own_root_as_a_person_is_refused() {
    let home = scratch("own-root").await;
    swoosh::config::write_signet(
        &swoosh::testkit::lock(),
        &home,
        TestRoot::seeded(PIN).node_id(),
    )
    .unwrap();
    let mut store = ContactsStore::open(&home).await.unwrap();
    store
        .contacts_mut()
        .set_signet("mine".parse().unwrap(), TestRoot::seeded(PIN).node_id());
    store
        .contacts_mut()
        .set_signet("twin".parse().unwrap(), TestNode::seeded(OWN).node_id());
    store.save(&swoosh::testkit::lock()).unwrap();

    let ran = share(&home, &["ssh", "mine"]).await;
    assert_eq!(
        ran.refusal(),
        "mine is saved with your own root: your devices already reach it."
    );
    let twin = share(&home, &["ssh", "twin"]).await;
    assert_eq!(
        twin.refusal(),
        "twin is saved with this machine's own key: your devices already reach it."
    );
    assert!(ran.out.is_empty() && twin.out.is_empty(), "no link prints");
    // This refusal comes once the key is read, after `--save`'s file was made, so the file goes with it.
    let file = path_in(&home, "twin.link");
    let saving = share(
        &home,
        &["ssh", "twin", "--save", &file.display().to_string()],
    )
    .await;
    assert_eq!(saving.refusal(), twin.refusal());
    assert!(!file.exists(), "the file made for the link is removed");
    assert!(rows(&home).await.is_empty(), "no row is written");
}

#[test]
fn on_is_not_a_flag() {
    let key = TestNode::seeded(BOB_LAPTOP).node_id().to_string();
    let error = parse(&["ssh", "--on", key.as_str()]).expect_err("--on is no flag");
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn share_with_your_own_devices_refuses() {
    for who in ["me", "me/laptop", "Me/laptop"] {
        let error = parse(&["ssh", who]).expect_err("your devices need no link");
        assert_eq!(error.exit_code(), 2, "{who}");
        assert!(
            error.to_string().contains("your devices already reach it."),
            "{who}: {error}"
        );
    }
}

/// The service form takes 1h to 365d, refused as a usage error (exit 2) with nothing written. The floor is
/// the service form's alone: a copy takes any span its source has left.
#[tokio::test]
async fn share_expires_is_one_hour_to_a_year() {
    let home = scratch("expires").await;
    for (span, ok) in [
        ("30m", false),
        ("59m", false),
        ("1h", true),
        ("365d", true),
        ("366d", false),
    ] {
        let ran = share(&home, &["demo", "anyone", "--expires", span]).await;
        if ok {
            ran.made();
            continue;
        }
        let error = ran.result.as_ref().expect_err(span);
        assert_eq!(
            error.downcast_ref::<Usage>().map(|usage| usage.0.as_str()),
            Some("a link's --expires is 1h to 365d"),
            "{span}: a usage error, exit 2"
        );
        assert!(
            ran.out.is_empty() && ran.err.is_empty(),
            "{span}: nothing prints"
        );
    }
    assert_eq!(rows(&home).await.len(), 2, "only the two shares made rows");

    let source = share(&home, &["demo", "anyone"]).await.link();
    let copy = share(
        &home,
        &[&saved(&home, "s.link", &source), "--expires", "30m"],
    )
    .await;
    assert!(
        ends(&copy.link()) <= from_now(Duration::from_secs(30 * 60)) + 1,
        "a copy takes a span under an hour"
    );
    assert!(
        copy.err.starts_with("the copy works until "),
        "{}",
        copy.err
    );
    assert!(
        copy.err.lines().next().unwrap().ends_with(" (30m)."),
        "it ends where --expires asked, and says so: {}",
        copy.err
    );
}

/// `--expires` takes one or more counts with units, largest first and each once, and prints back exactly
/// what was typed: `90m` is `90m`, never rounded to `1h`, and `1h30m` is `1h30m`.
#[test]
fn a_span_parses_its_grammar_and_prints_as_typed() {
    for (text, secs) in [
        ("90m", 5400),
        ("1h30m", 5400),
        ("2h", 7200),
        ("90d", 90 * 86_400),
        ("1d2h3m", 86_400 + 7200 + 180),
    ] {
        let span: Span = text.parse().unwrap();
        assert_eq!(span.duration(), Duration::from_secs(secs), "{text}");
        assert_eq!(span.to_string(), text, "{text} prints as typed");
    }
    for text in [
        "", "h", "90", "1h1h", "30m1h", "1x", "0h", "0h0m", "-1h", "1 h", "1H", "30s", "1m30s",
    ] {
        assert!(text.parse::<Span>().is_err(), "{text:?} is no span");
    }
    let error = parse(&["ssh", "anyone", "--expires", "1.5h"]).expect_err("no span");
    assert_eq!(error.exit_code(), 2);
    assert!(
        error
            .to_string()
            .contains("a span is a number and a unit, like 2h, 90d or 1h30m"),
        "swoosh's own line, no library text: {error}"
    );
}

#[tokio::test]
async fn an_issue_line_prints_the_span_as_typed() {
    let home = scratch("span").await;
    for (span, printed) in [("90m", " (90m)."), ("1h30m", " (1h30m)."), ("2d", " (2d).")] {
        let ran = share(&home, &["demo", "anyone", "--expires", span]).await;
        ran.made();
        let first = ran.err.lines().next().unwrap();
        assert!(first.ends_with(printed), "{span}: {first}");
    }
}

#[tokio::test]
async fn an_anyone_link_is_unsealed_and_a_bound_link_is_sealed() {
    let home = scratch("sealed").await;
    with_bob(&home).await;
    let key = TestNode::seeded(BOB_LAPTOP).node_id().to_string();
    let anyone = share(&home, &["demo", "anyone"]).await.link();
    anyone
        .narrow(None, Some(Duration::from_secs(60)))
        .expect("an anyone link narrows");
    for who in ["bob", "bob/laptop", key.as_str()] {
        let bound = share(&home, &["ssh", who]).await.link();
        assert!(
            matches!(
                bound.narrow(None, Some(Duration::from_secs(60))),
                Err(CapError::Attenuate(_))
            ),
            "{who}: a bound link is sealed"
        );
    }
    let kinds: Vec<(GrantKind, Delegation)> = rows(&home)
        .await
        .iter()
        .map(|row| (row.kind, row.delegation))
        .collect();
    assert_eq!(
        kinds,
        [
            (GrantKind::Bearer, Delegation::Delegable),
            (GrantKind::Fleet, Delegation::Sealed),
            (GrantKind::Device, Delegation::Sealed),
            (GrantKind::Device, Delegation::Sealed),
        ]
    );
}

#[tokio::test]
async fn share_with_a_person_binds_their_saved_root() {
    let home = scratch("person").await;
    with_bob(&home).await;
    let link = share(&home, &["ssh", "bob"]).await.link();
    let root = TestRoot::seeded(BOB_ROOT).verify_key();
    assert_eq!(link.cap().authority_bound_root().unwrap(), Some(root));
    let [row] = rows(&home).await.try_into().ok().unwrap();
    assert_eq!(row.holder, root.to_string(), "revoke bob finds the row");

    let laptop = share(&home, &["ssh", "bob/laptop"]).await.link();
    let request = nauthy::Request::now("ssh".parse().unwrap())
        .bound_to(TestNode::seeded(BOB_LAPTOP).verify_key());
    laptop
        .cap()
        .verify_at_root_without_revocation(&request, TestNode::seeded(OWN).verify_key())
        .expect("bob/laptop's link admits bob's laptop");
}

#[tokio::test]
async fn every_share_states_what_it_gives() {
    let home = scratch("gives").await;
    with_bob(&home).await;
    ServeToml::update(&swoosh::testkit::lock(), &home, |toml| {
        toml.services = Some(vec![
            "db=tcp:localhost:5432".to_owned(),
            "sock=unix:/run/db.sock".to_owned(),
            "news=proxy:https://news.example".to_owned(),
            "ssh=sshd:".to_owned(),
            "ping=ping:".to_owned(),
        ]);
    })
    .unwrap();
    let key = TestNode::seeded(BOB_LAPTOP).node_id().to_string();
    for (args, first) in [
        (
            vec!["ssh", "bob/laptop"],
            "bob/laptop can open a shell on this machine until ".to_owned(),
        ),
        (
            vec!["db", "bob"],
            "All of bob's machines can reach db (localhost:5432 on this machine) until ".to_owned(),
        ),
        (
            vec!["sock", "bob"],
            "All of bob's machines can reach sock (/run/db.sock on this machine) until ".to_owned(),
        ),
        (
            vec!["news", "bob"],
            "All of bob's machines can reach, through this machine, anything this machine can reach at \
             https://news.example, until "
                .to_owned(),
        ),
        // A key saved as a machine is named by its name.
        (
            vec!["ping", key.as_str()],
            "bob/laptop can use ping on this machine until ".to_owned(),
        ),
    ] {
        let ran = share(&home, &args).await;
        ran.made();
        let lines: Vec<&str> = ran.err.lines().collect();
        assert!(lines[0].starts_with(&first), "{args:?}: {}", ran.err);
        assert!(lines[0].ends_with(" (1h)."), "{args:?}: {}", ran.err);
        // Between them, the end as a clock time: `15:04`.
        let clock = &lines[0][first.len()..lines[0].len() - " (1h).".len()];
        assert!(
            clock.len() == 5
                && clock.as_bytes()[2] == b':'
                && clock
                    .chars()
                    .enumerate()
                    .all(|(at, c)| at == 2 || c.is_ascii_digit()),
            "{args:?}: the end is a clock time: {clock:?}"
        );
        let mut rest = vec![format!(
            "the link dials this machine: it works while this machine serves {}.",
            args[0]
        ), format!("this link is for the next bare `swoosh serve`; {} is not marked off in saved policy.", args[0])];
        // A shell shared with a person says what it reaches beyond this machine.
        if args[0] == "ssh" {
            rest.push("that shell can reach your other devices.".to_owned());
        }
        assert_eq!(lines[1..], rest, "{args:?}");
    }
    let anyone = share(&home, &["db", "anyone", "--expires", "7d"]).await;
    anyone.made();
    let lines: Vec<&str> = anyone.err.lines().collect();
    assert!(
        lines[0].starts_with("anyone can reach db (localhost:5432 on this machine) until ")
            && lines[0].ends_with(" (7d)."),
        "{}",
        anyone.err
    );
    // Past a day, the end is a date: `15 Oct 2026`.
    let date: Vec<&str> = lines[0]
        .trim_start_matches("anyone can reach db (localhost:5432 on this machine) until ")
        .trim_end_matches(" (7d).")
        .split(' ')
        .collect();
    assert!(
        matches!(date.as_slice(), [day, month, year]
            if day.parse::<u8>().is_ok_and(|day| (1..=31).contains(&day))
                && super::MONTHS.contains(month)
                && year.len() == 4 && year.parse::<u16>().is_ok()),
        "the end is a date: {date:?}"
    );
    assert_eq!(
        lines[3],
        "anyone holding this link can use it: send it privately."
    );
}

/// A stdout that refuses every write, as a closed pipe does.
struct Closed;

impl std::io::Write for Closed {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed pipe"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The row is on disk before the link prints: with a stdout that refuses the link, the share fails and its
/// row is there all the same, so a link that did print can always be revoked.
#[tokio::test]
async fn a_share_records_its_row_before_the_link_prints() {
    let home = scratch("row").await;
    let link = share(&home, &["demo", "anyone"]).await.link();
    let [row] = rows(&home).await.try_into().ok().unwrap();
    assert_eq!(Some(row.root_id), link.cap().root_revocation_id());
    assert_eq!(row.target, "demo".parse::<Service>().unwrap());
    assert_eq!(row.holder, swoosh::grants::ANYONE);

    let cmd = parse(&["demo", "anyone"]).unwrap();
    let mut err = Vec::new();
    let failed = cmd
        .run(&home, &b""[..], &mut Closed, &mut err)
        .await
        .expect_err("a stdout that refuses the link fails the share");
    assert!(format!("{failed:#}").contains("closed pipe"), "{failed:#}");
    assert_eq!(
        rows(&home).await.len(),
        2,
        "the row was written before the print"
    );
}

/// A `--save` that cannot make its file refuses before anything is signed or said: no file, no row, no line
/// on stderr, and swoosh's own words for why, never the system's.
#[tokio::test]
async fn a_refused_save_leaves_no_file_and_no_row() {
    let home = scratch("save-refused").await;
    let missing = path_in(&home, "no-such-dir").join("l.link");
    let path = missing.display().to_string();
    let ran = share(&home, &["demo", "anyone", "--save", &path]).await;
    assert_eq!(
        ran.refusal(),
        format!("could not make {path}: no such directory")
    );
    assert!(!missing.exists(), "no file is made");
    assert!(
        ran.out.is_empty() && ran.err.is_empty(),
        "nothing prints: {}",
        ran.err
    );
    assert!(rows(&home).await.is_empty(), "no row is written");

    let file = path_in(&home, "a-file");
    std::fs::write(&file, "").unwrap();
    let under_a_file = file.join("l.link").display().to_string();
    let ran = share(&home, &["demo", "anyone", "--save", &under_a_file]).await;
    assert_eq!(
        ran.refusal(),
        format!("could not make {under_a_file}: no such directory")
    );
    assert!(rows(&home).await.is_empty(), "no row is written");
}

/// A directory that takes no new file refuses `--save` before the key is read or a row is written: the file
/// is made first, so there is no row for a link nobody holds, no file, and no line. Root writes anywhere, so
/// the test has nothing to show there and skips.
#[tokio::test]
async fn a_save_into_an_unwritable_directory_leaves_no_file_and_no_row() {
    // SAFETY: `geteuid` reads the process's own id and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let home = scratch("save-unwritable").await;
    let dir = path_in(&home, "read-only");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let file = dir.join("l.link");
    let path = file.display().to_string();
    let ran = share(&home, &["demo", "anyone", "--save", &path]).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        ran.refusal(),
        format!("could not make {path}: permission denied")
    );
    assert!(!file.exists(), "no file is made");
    assert!(
        ran.out.is_empty() && ran.err.is_empty(),
        "nothing prints: {}",
        ran.err
    );
    assert!(rows(&home).await.is_empty(), "no row is written");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// An end prints as a clock time within a day and as a date past it, from a local time made by hand, so the
/// shape is checked with no time zone in play.
#[test]
fn an_end_prints_a_clock_time_or_a_date() {
    // SAFETY: `tm` is plain C data, so all-zero is a valid value; the fields read are set below.
    let mut local: libc::tm = unsafe { core::mem::zeroed() };
    local.tm_hour = 15;
    local.tm_min = 4;
    local.tm_mday = 15;
    local.tm_mon = 9;
    local.tm_year = 126;
    let at = |local: &libc::tm, within_a_day| {
        End {
            local,
            within_a_day,
        }
        .to_string()
    };
    assert_eq!(at(&local, true), "15:04");
    assert_eq!(at(&local, false), "15 Oct 2026");
    local.tm_hour = 9;
    local.tm_min = 0;
    assert_eq!(at(&local, true), "09:00", "padded to two digits");
}

/// A person whose root this machine revoked gets no link: this machine's gate would refuse every badge under
/// that root, so the link would print and never work.
#[tokio::test]
async fn share_to_a_person_whose_root_is_revoked_here_refuses() {
    let home = scratch("revoked-root").await;
    with_bob(&home).await;
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        &home,
        [nauthy::Revocation::Key(
            TestRoot::seeded(BOB_ROOT).verify_key(),
        )],
    )
    .unwrap();
    let ran = share(&home, &["ssh", "bob"]).await;
    assert_eq!(
        ran.refusal(),
        "bob's root is revoked here, so a link for bob would not work"
    );
    assert!(ran.out.is_empty() && ran.err.is_empty(), "nothing prints");
    assert!(rows(&home).await.is_empty(), "no row is written");
}

/// A root this machine revoked and has no name for gets no link either, and the refusal never prints its key.
#[tokio::test]
async fn share_to_a_revoked_unsaved_root_refuses_without_its_key() {
    let home = scratch("revoked-unsaved-root").await;
    let root = TestRoot::seeded(BOB_ROOT);
    swoosh::revoked::add(
        &swoosh::testkit::lock(),
        &home,
        [nauthy::Revocation::Key(root.verify_key())],
    )
    .unwrap();
    let ran = share(&home, &["ssh", &format!("root:{}", root.node_id())]).await;
    assert_eq!(
        ran.refusal(),
        "that root is revoked here, so a link for it would not work"
    );
    assert!(rows(&home).await.is_empty(), "no row is written");
}

/// A key typed as the recipient is one machine: the link it makes is bound to that key alone.
#[tokio::test]
async fn share_with_a_key_binds_that_one_machine() {
    let home = scratch("key").await;
    let laptop = TestNode::seeded(BOB_LAPTOP).node_id();
    let link = share(&home, &["ssh", &laptop.to_string()]).await.link();
    let own = TestNode::seeded(OWN).verify_key();
    let as_laptop =
        nauthy::Request::now("ssh".parse().unwrap()).bound_to(laptop.verify_key().unwrap());
    link.cap()
        .verify_at_root_without_revocation(&as_laptop, own)
        .expect("the key's machine is admitted");
    let as_other = nauthy::Request::now("ssh".parse().unwrap()).bound_to(
        NodeId::from_ed25519_secret(&[0x55; 32])
            .verify_key()
            .unwrap(),
    );
    assert!(
        link.cap()
            .verify_at_root_without_revocation(&as_other, own)
            .is_err(),
        "another machine is refused"
    );
}

/// Name `entries` in `home`'s `serve.toml`, as a bare `serve` would start them.
fn serving(home: &Home, entries: &[&str]) {
    ServeToml::update(&swoosh::testkit::lock(), home, |toml| {
        toml.services = Some(entries.iter().map(|&entry| entry.to_owned()).collect());
    })
    .unwrap();
}

/// A synthetic listener in this selected home's actual runtime namespace.
struct Live {
    task: tokio::task::JoinHandle<()>,
    socket: PathBuf,
}

impl Live {
    fn start(home: &Home, detail: Vec<u8>, issuer: NodeId) -> Self {
        let socket = home.control_socket().unwrap();
        swoosh::config::create_store_dir(socket.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::fs::write(home.serve_lock(), format!("{}\n", std::process::id())).unwrap();
        let status = StatusReply {
            node_id: issuer,
            pid: 1, // Deliberately not the authority used to compare the two exchanges.
            addr: None,
            uptime_secs: 0,
            menu: ServiceMenu {
                catalog: ServiceCatalog::decode(&0u32.to_be_bytes()).unwrap(),
                disabled: DisabledList::Known(vec![]),
            },
            warm: vec![],
        };
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let Ok(request) = Request::read(&mut stream).await else {
                    continue;
                };
                match request {
                    Request::LocalServiceDetail => stream.write_all(&detail).await.unwrap(),
                    Request::Status => Response::Status(status.clone())
                        .write(&mut stream)
                        .await
                        .unwrap(),
                    other => panic!("unexpected request: {other:?}"),
                }
            }
        });
        Self { task, socket }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(self.socket.parent().unwrap());
    }
}

fn detail(name: &str, target: &str, refused: bool) -> Vec<u8> {
    let mut payload = vec![0, 0, 1];
    for text in [name, target] {
        payload.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(text.as_bytes());
    }
    payload.push(u8::from(refused));
    frame(&payload)
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = b"SWC1\x09".to_vec();
    bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

async fn snapshot(mut bytes: &[u8]) -> LocalServiceSnapshot {
    match Response::read(&mut bytes).await.unwrap() {
        Response::LocalServiceDetail(result) => result.unwrap(),
        other => panic!("expected local service detail, got {other:?}"),
    }
}

/// Preflight refusals must not provision a key, touch a save path, or change the ledger/configuration.
async fn refuses_unchanged(home: &Home, service: &str) -> String {
    let paths = [home.key(), home.links(), home.serve_toml()];
    let before = paths.each_ref().map(|path| std::fs::read(path).ok());
    let save = path_in(home, "refused.link");
    let ran = share(home, &[service, "anyone", "--save", save.to_str().unwrap()]).await;
    let refusal = ran.refusal();
    assert!(ran.out.is_empty() && ran.err.is_empty());
    assert!(!save.exists());
    assert_eq!(
        before,
        paths.each_ref().map(|path| std::fs::read(path).ok())
    );
    refusal
}

/// Whether `home`'s `serve` gate admits `link` for `service` from the machine seeded `dialer`, now. A fresh
/// gate reads the ledger as it stands.
fn admits(gate: &nauthy::Gate, link: &Link, service: &str, dialer: u8) -> bool {
    matches!(
        gate.admit(
            ProvenPeer::from_handshake(TestNode::seeded(dialer).verify_key()),
            Some(link.cap()),
            &service.parse().unwrap(),
        ),
        Decision::Admit
    )
}

/// `home`'s `serve` gate, as the composition root builds it for a `serve` that binds `entries`.
async fn gate(home: &Home, entries: &[&str]) -> nauthy::Gate {
    swoosh::gate::anchored(
        home,
        TestNode::seeded(OWN).node_id(),
        swoosh::serve::BoundTargets::of(entries.iter().copied()),
    )
    .await
    .unwrap()
    .0
}

/// `share ssh anyone` without `--once` refuses, exit 1, before anything is minted or recorded, and says
/// both ways that work.
#[tokio::test]
async fn share_ssh_with_anyone_is_refused_and_mints_nothing() {
    let home = scratch("ssh-anyone").await;
    let ran = share(&home, &["ssh", "anyone"]).await;
    let error = ran
        .result
        .as_ref()
        .expect_err("an anyone link to a shell refuses");
    assert!(
        error.downcast_ref::<Usage>().is_none(),
        "exit 1, not a usage error"
    );
    assert_eq!(
        format!("error: {error:#}"),
        "error: ssh opens a shell on this machine; share it with a person: swoosh share ssh <person>\n\
         or make a link that works once: swoosh share ssh anyone --once"
    );
    assert!(ran.out.is_empty(), "no link prints: {}", ran.out);
    assert!(rows(&home).await.is_empty(), "no row is written");
}

/// The refusal is the engine's ceiling, not "runs code": every engine that must never face an open gate
/// refuses an `anyone` link, and a forward, a scoped proxy, a reflector or a name served by nothing does not.
#[tokio::test]
async fn an_anyone_link_to_an_engine_never_open_to_anyone_is_refused() {
    let home = scratch("never-public").await;
    serving(
        &home,
        &[
            "inbox=recv:",
            "web=recv:/srv/web",
            "news=proxy:https://news.example",
            "db=tcp:localhost:5432",
            "demo=echo:",
            "ping=ping:",
            "speed=speed:",
        ],
    );
    for service in ["ping", "speed", "inbox", "web"] {
        let ran = share(&home, &[service, "anyone"]).await;
        assert_eq!(
            ran.refusal(),
            format!(
                "whoever holds a link to anyone could use {service} any number of times; share it with a \
                 person: swoosh share {service} <person>\nor make a link that works once: swoosh share {service} \
                 anyone --once"
            ),
        );
        share(&home, &[service, "anyone", "--once"]).await.made();
    }
    for service in ["news", "db", "demo"] {
        share(&home, &[service, "anyone"]).await.made();
    }
}

/// `--once` names what a link to anyone gains, so with any other recipient, or on a copy of a link, it is a
/// usage error before anything is written.
#[tokio::test]
async fn once_with_a_bound_recipient_or_a_link_is_a_usage_error() {
    let home = scratch("once-who").await;
    with_bob(&home).await;
    let key = TestNode::seeded(BOB_LAPTOP).node_id().to_string();
    for who in ["bob", "bob/laptop", key.as_str()] {
        let ran = share(&home, &["ssh", who, "--once"]).await;
        let error = ran.result.as_ref().expect_err(who);
        assert_eq!(
            error.downcast_ref::<Usage>().map(|usage| usage.0.as_str()),
            Some(ONCE_ANYONE),
            "{who}: exit 2"
        );
    }
    assert!(rows(&home).await.is_empty(), "no row is written");
    let source = share(&home, &["demo", "anyone"]).await.link();
    let path = saved(&home, "s.link", &source);
    let stdin = format!("{}\n", swoosh::link::Link::from(source.clone()));
    for ran in [
        share(&home, &[&path, "--once"]).await,
        share_with(&home, &["-", "--once"], stdin.as_bytes()).await,
    ] {
        let error = ran.result.as_ref().expect_err("a copy is never once");
        assert_eq!(
            error.downcast_ref::<Usage>().map(|usage| usage.0.as_str()),
            Some(ONCE_ANYONE),
            "exit 2"
        );
        assert!(ran.out.is_empty(), "no link prints: {}", ran.out);
    }
}

/// A one-use link to a service that runs no code admits once, then refuses, whoever presents it; its
/// grant line carries ", once,".
#[tokio::test]
async fn once_on_a_service_that_runs_no_code_works_once() {
    let home = scratch("once-db").await;
    serving(&home, &["db=tcp:localhost:5432"]);
    let ran = share(&home, &["db", "anyone", "--once"]).await;
    let link = ran.link();
    let lines: Vec<&str> = ran.err.lines().collect();
    assert!(
        lines[0].starts_with("anyone can reach db (localhost:5432 on this machine), once, until ")
            && lines[0].ends_with(" (15m)."),
        "{}",
        ran.err
    );
    assert_eq!(
        lines[1..],
        [
            "the link dials this machine: it works while this machine serves db.",
            "this link is for the next bare `swoosh serve`; db is not marked off in saved policy.",
            "anyone holding this link can use it: send it privately.",
        ]
    );
    let gate = gate(&home, &["db=tcp:localhost:5432"]).await;
    assert!(admits(&gate, &link, "db", 0x51), "the first admission");
    assert!(!admits(&gate, &link, "db", 0x51), "the same holder again");
    assert!(!admits(&gate, &link, "db", 0x52), "anyone else after it");
}

/// `share ssh anyone --once` makes a sealed link the gate admits once, that ends in 15 minutes, and says
/// that the shell reaches your other devices; `--expires` may only shorten it.
#[tokio::test]
async fn an_explicit_shell_link_works_once_and_expires_in_15_minutes() {
    let home = scratch("once-ssh").await;
    let ran = share(&home, &["ssh", "anyone", "--once"]).await;
    let link = ran.link();
    assert!(
        ends(&link).abs_diff(from_now(Duration::from_secs(15 * 60))) <= 2,
        "it ends in 15 minutes"
    );
    let lines: Vec<&str> = ran.err.lines().collect();
    assert_eq!(lines.len(), 4, "{}", ran.err);
    assert!(
        lines[0].starts_with("anyone can open a shell on this machine, once, until ")
            && lines[0].ends_with(" (15m)."),
        "the end prints once, in the grant's line: {}",
        ran.err
    );
    assert_eq!(
        lines[1..],
        [
            "the link dials this machine: it works while this machine serves ssh.",
            "this link is for the next bare `swoosh serve`; ssh is not marked off in saved policy.",
            "that shell can reach your other devices: send the link privately.",
        ]
    );
    let [row] = rows(&home).await.try_into().ok().unwrap();
    assert_eq!(
        (row.kind, row.delegation),
        (GrantKind::Once, Delegation::Sealed)
    );

    let gate = gate(&home, &["ssh=sshd:"]).await;
    assert!(admits(&gate, &link, "ssh", 0x51), "the first admission");
    assert!(!admits(&gate, &link, "ssh", 0x51), "the second is refused");

    let shorter = share(&home, &["ssh", "anyone", "--once", "--expires", "5m"]).await;
    assert!(
        ends(&shorter.link()).abs_diff(from_now(Duration::from_secs(5 * 60))) <= 2,
        "--expires shortens it"
    );
    let longer = share(&home, &["ssh", "anyone", "--once", "--expires", "16m"]).await;
    let error = longer.result.as_ref().expect_err("longer than 15m refuses");
    assert_eq!(
        error.downcast_ref::<Usage>().map(|usage| usage.0.as_str()),
        Some("with --once, --expires is 15m at most"),
        "exit 2"
    );
    assert_eq!(
        rows(&home).await.len(),
        2,
        "the refused share writes no row"
    );
}

/// Complete R, not divergent or malformed P, supplies classification, disclosure and the target row.
#[tokio::test]
async fn live_targets_survive_saved_divergence_and_malformed_configuration() {
    for saved in ["services = [\"ssh=sshd:\"]", "services = ["] {
        let home = scratch("retarget").await;
        std::fs::write(home.serve_toml(), saved).unwrap();
        let _live = Live::start(
            &home,
            detail("ssh", "tcp:localhost:3000", false),
            TestNode::seeded(OWN).node_id(),
        );
        let ran = share(&home, &["ssh", "anyone"]).await;
        let link = ran.link();
        assert!(
            ran.err
                .starts_with("anyone can reach ssh (localhost:3000 on this machine) until ")
        );
        assert!(!ran.err.contains("shell"));
        assert_eq!(
            rows(&home).await[0].serves.as_ref().unwrap().as_str(),
            "tcp:localhost:3000"
        );
        assert!(admits(
            &gate(&home, &["ssh=tcp:localhost:3000"]).await,
            &link,
            "ssh",
            0x51
        ));
        assert!(!admits(
            &gate(&home, &["ssh=sshd:"]).await,
            &link,
            "ssh",
            0x51
        ));
        assert_eq!(std::fs::read_to_string(home.serve_toml()).unwrap(), saved);
    }
    let home = scratch("live-shell").await;
    serving(&home, &["ssh=tcp:localhost:3000"]);
    let _live = Live::start(
        &home,
        detail("ssh", "sshd:", false),
        TestNode::seeded(OWN).node_id(),
    );
    assert!(
        refuses_unchanged(&home, "ssh")
            .await
            .contains("opens a shell")
    );
}

#[tokio::test]
async fn missing_and_failed_live_detail_never_use_saved_targets_or_touch_keys() {
    for bytes in [
        frame(&[0, 0, 0]),
        frame(&[1]),
        frame(&[2, 1]),
        frame(&[2, 3]),
        frame(&[0, 0]),
        b"SWC1\x09\x20\x01".to_vec(),
        b"BAD1".to_vec(),
        detail("demo", "gopher:x", false),
    ] {
        let home = scratch("bad-detail").await;
        std::fs::write(home.key(), b"not a key").unwrap();
        let _live = Live::start(&home, bytes, TestNode::seeded(OWN).node_id());
        let refusal = refuses_unchanged(&home, "demo").await;
        assert!(!refusal.contains("key file"), "{refusal}");
    }
    let home = scratch("missing-live").await;
    let _live = Live::start(&home, frame(&[0, 0, 0]), TestNode::seeded(OWN).node_id());
    assert_eq!(
        refuses_unchanged(&home, "demo").await,
        "the running node does not list that service"
    );
}

#[tokio::test]
async fn only_initial_no_resident_and_actual_free_allow_next_start_shares() {
    let home = scratch("presence").await;
    let guard = HomeWrite::take(&home).await.unwrap();
    let held = ServeLock::take(&guard, &home).unwrap();
    drop(guard);
    for record in [
        String::new(),
        format!("{}\n", std::process::id()),
        "startup\n".to_owned(),
    ] {
        std::fs::write(home.serve_lock(), record).unwrap();
        assert_eq!(
            refuses_unchanged(&home, "demo").await,
            "cannot confirm that no node is serving this home"
        );
    }
    drop(held);
    std::fs::write(home.serve_lock(), "42\n").unwrap();
    share(&home, &["demo", "anyone"]).await.made(); // A stale PID is not a held flock.
    std::fs::remove_file(home.serve_lock()).unwrap();
    std::os::unix::fs::symlink(home.dir().join("absent"), home.serve_lock()).unwrap();
    refuses_unchanged(&home, "demo").await;
    std::fs::remove_file(home.serve_lock()).unwrap();
    std::fs::create_dir(home.serve_lock()).unwrap();
    refuses_unchanged(&home, "demo").await;
}

#[tokio::test]
async fn absent_defaults_explicit_empty_and_first_use_remain_distinct() {
    let home = scratch("defaults").await;
    std::fs::remove_file(home.serve_toml()).unwrap();
    std::fs::remove_file(home.key()).unwrap();
    assert_eq!(
        refuses_unchanged(&home, "ssh").await,
        "saved services do not list that service"
    );
    let key = TestNode::seeded(BOB_LAPTOP).node_id().to_string();
    let link = share(&home, &["ping", &key]).await.link();
    assert!(
        home.key().exists(),
        "valid next-start first use still provisions"
    );
    assert_eq!(
        link.root(),
        swoosh::identity::load(&home)
            .await
            .unwrap()
            .unwrap()
            .node_id()
            .verify_key()
            .unwrap()
    );
    assert_eq!(
        rows(&home).await[0].serves.as_ref().unwrap().as_str(),
        "ping:"
    );
    serving(&home, &[]);
    assert_eq!(
        refuses_unchanged(&home, "ping").await,
        "saved services do not list that service"
    );
}

#[tokio::test]
async fn off_retains_the_exact_target_without_enabling_a_route() {
    let home = scratch("off").await;
    ServeToml::update(&swoosh::testkit::lock(), &home, |toml| {
        toml.off.insert("demo".to_owned());
    })
    .unwrap();
    for live in [false, true] {
        let _resident = if live {
            Some(Live::start(
                &home,
                detail("demo", "echo:", true),
                TestNode::seeded(OWN).node_id(),
            ))
        } else {
            None
        };
        if live {
            ServeToml::update(&swoosh::testkit::lock(), &home, |toml| toml.off.clear()).unwrap();
        }
        let before = std::fs::read(home.serve_toml()).unwrap();
        let ran = share(&home, &["demo", "anyone"]).await;
        ran.made();
        assert!(ran.err.lines().any(|line| line == if live {
            "demo was reported unavailable; making this link does not enable it."
        } else {
            "this link is for the next bare `swoosh serve`; demo remains unavailable while marked off in saved policy. Making this link does not enable it."
        }));
        assert_eq!(
            rows(&home)
                .await
                .last()
                .unwrap()
                .serves
                .as_ref()
                .unwrap()
                .as_str(),
            "echo:"
        );
        assert_eq!(std::fs::read(home.serve_toml()).unwrap(), before);
    }
}

#[tokio::test]
async fn live_missing_or_foreign_identity_refuses_without_provision_or_fallback() {
    for missing in [false, true] {
        let home = scratch("issuer").await;
        if missing {
            std::fs::remove_file(home.key()).unwrap();
        }
        let issuer = TestNode::seeded(if missing { OWN } else { BOB_LAPTOP }).node_id();
        let _live = Live::start(&home, detail("demo", "echo:", false), issuer);
        let refusal = refuses_unchanged(&home, "demo").await;
        assert_eq!(
            refusal,
            if missing {
                "this home has no stored identity; cannot share from the running node"
            } else {
                "the running node's identity does not match this home"
            }
        );
    }
}

#[tokio::test]
async fn later_pid_key_and_home_changes_cannot_replace_the_selected_live_basis() {
    let home = scratch("changed").await;
    let bytes = detail("demo", "echo:", false);
    let _live = Live::start(&home, bytes.clone(), TestNode::seeded(OWN).node_id());
    let service = "demo".parse().unwrap();
    let client = || ControlClient::resolve(&home).unwrap();
    let pid = ProcessId::try_from(std::process::id()).unwrap();
    let other = ProcessId::try_from(if pid.get() == 42 { 43 } else { 42 }).unwrap();
    let old = ShareTarget::from_initial(
        &home,
        &service,
        Ok((client(), snapshot(&bytes).await, other)),
    )
    .await
    .unwrap();
    assert_eq!(
        old.issuer(&home).await.unwrap_err().to_string(),
        "the running node's PID no longer matches this home"
    );
    let target =
        ShareTarget::from_initial(&home, &service, Ok((client(), snapshot(&bytes).await, pid)))
            .await
            .unwrap();
    let issuer = target.issuer(&home).await.unwrap();
    let foreign = scratch("other-home").await;
    std::fs::remove_file(foreign.key()).unwrap();
    assert!(target.secret(&foreign, issuer).await.is_err());
    assert!(!foreign.key().exists());
    std::fs::write(home.serve_lock(), format!("{other}\n")).unwrap();
    assert!(
        target.issuer(&home).await.is_err(),
        "F2 rejects a changed record before status"
    );
    let guard = HomeWrite::take(&home).await.unwrap();
    assert!(
        target
            .recheck(&guard, &home, TestNode::seeded(OWN).node_id())
            .is_err()
    );
    std::fs::write(home.serve_lock(), format!("{pid}\n")).unwrap();
    let original = std::fs::read(home.key()).unwrap();
    std::fs::remove_file(home.key()).unwrap();
    assert!(
        target
            .recheck(&guard, &home, TestNode::seeded(OWN).node_id())
            .is_err()
    );
    drop(guard);
    swoosh::identity::write(&TestNode::seeded(BOB_LAPTOP).seed(), &home)
        .await
        .unwrap();
    assert!(target.secret(&home, issuer).await.is_err());
    let guard = HomeWrite::take(&home).await.unwrap();
    assert!(
        target
            .recheck(&guard, &home, TestNode::seeded(OWN).node_id())
            .is_err()
    );
    std::fs::write(home.key(), original).unwrap();
    target
        .recheck(&guard, &home, TestNode::seeded(OWN).node_id())
        .unwrap();
    assert!(!home.links().exists());
    assert_eq!(target.target.as_str(), "echo:");
    drop(guard);
    drop(_live);
    assert!(
        target.issuer(&home).await.is_err(),
        "later loss never selects Next"
    );
    assert!(!home.links().exists());
}

#[tokio::test]
async fn next_final_identity_missing_or_changed_has_no_running_node_claim() {
    let home = scratch("next-key-change").await;
    let target = ShareTarget::read(&home, &"demo".parse().unwrap())
        .await
        .unwrap();
    let issuer = target.issuer(&home).await.unwrap();
    assert!(issuer.is_none());
    let secret = target.secret(&home, issuer).await.unwrap();
    let guard = HomeWrite::take(&home).await.unwrap();
    target.recheck(&guard, &home, secret.node_id()).unwrap();
    std::fs::remove_file(home.key()).unwrap();
    assert_eq!(
        target
            .recheck(&guard, &home, secret.node_id())
            .unwrap_err()
            .to_string(),
        "the selected home's stored identity changed or is missing; cannot finish sharing"
    );
    drop(guard);
    swoosh::identity::write(&TestNode::seeded(BOB_LAPTOP).seed(), &home)
        .await
        .unwrap();
    let guard = HomeWrite::take(&home).await.unwrap();
    assert_eq!(
        target
            .recheck(&guard, &home, secret.node_id())
            .unwrap_err()
            .to_string(),
        "the selected home's stored identity changed or is missing; cannot finish sharing"
    );
    assert!(!home.links().exists());
    assert_eq!(target.target.as_str(), "echo:");
}

#[tokio::test]
async fn valid_first_use_may_leave_its_key_when_append_later_fails() {
    let home = scratch("first-append").await;
    std::fs::remove_file(home.key()).unwrap();
    std::fs::create_dir(home.links()).unwrap();
    let ran = share(&home, &["demo", "anyone"]).await;
    assert!(ran.result.is_err());
    assert!(ran.out.is_empty() && ran.err.is_empty());
    assert!(swoosh::identity::load(&home).await.unwrap().is_some());
    assert!(home.links().is_dir());
}

/// `share` folds a name in `serve.toml` as `serve` does, so `Web=sshd:` is the shell `serve` binds as `web`.
#[tokio::test]
async fn a_name_in_serve_toml_is_folded_as_serve_folds_it() {
    let home = scratch("folded").await;
    with_bob(&home).await;
    serving(&home, &["Web=sshd:"]);
    let ran = share(&home, &["web", "anyone"]).await;
    assert!(
        ran.refusal()
            .starts_with("web opens a shell on this machine;"),
        "{}",
        ran.refusal()
    );
    share(&home, &["web", "bob/laptop"]).await.made();
    let [row] = rows(&home).await.try_into().ok().unwrap();
    assert_eq!(
        row.serves.as_ref().map(ToString::to_string).as_deref(),
        Some("sshd:")
    );
}

/// A `share` that reads `serve.toml` before a named `serve ssh` writes it records the old target, and the
/// gate that start builds refuses the link.
#[tokio::test]
async fn a_share_during_a_named_start_is_refused_by_that_start() {
    let home = scratch("named-start").await;
    serving(&home, &["ssh=tcp:localhost:22"]);
    let link = share(&home, &["ssh", "anyone"]).await.link();
    let started = gate(&home, &["ssh=sshd:"]).await;
    assert!(
        !admits(&started, &link, "ssh", 0x51),
        "the shell that start binds refuses it"
    );
}

/// An `anyone` link to a target whose scheme swoosh does not know is refused: nothing can say what it gives.
#[tokio::test]
async fn an_anyone_link_to_an_unknown_scheme_is_refused() {
    let home = scratch("unknown-scheme").await;
    serving(&home, &["odd=gopher:x"]);
    with_bob(&home).await;
    for args in [
        &["odd", "anyone"][..],
        &["odd", "anyone", "--once"][..],
        &["odd", "bob"][..],
    ] {
        let ran = share(&home, args).await;
        assert_eq!(
            ran.refusal(),
            "\"gopher:x\" is not a target serve binds",
            "{args:?}"
        );
    }
    assert!(rows(&home).await.is_empty(), "no row is written");
}

/// A one-use link is sealed: it cannot be narrowed into a further link, offline or through `share <link>`.
#[tokio::test]
async fn an_explicit_shell_link_cannot_be_delegated() {
    let home = scratch("once-sealed").await;
    let link = share(&home, &["ssh", "anyone", "--once"]).await.link();
    assert!(
        matches!(
            link.narrow(None, Some(Duration::from_secs(60))),
            Err(CapError::Attenuate(_))
        ),
        "a one-use link is sealed"
    );
    let ran = share(&home, &[&saved(&home, "once.link", &link)]).await;
    assert_eq!(
        ran.refusal(),
        "this link cannot be copied: ask whoever made it for another"
    );
    assert!(ran.out.is_empty(), "no link prints: {}", ran.out);
}

/// A forward is no engine that must never face an open gate, so an `anyone` link to it is made as before.
#[tokio::test]
async fn share_a_forward_with_anyone_still_works() {
    let home = scratch("forward").await;
    serving(&home, &["db=tcp:localhost:5432"]);
    let link = share(&home, &["db", "anyone"]).await.link();
    link.narrow(None, Some(Duration::from_secs(60)))
        .expect("it is the delegable link it always was");
    let [row] = rows(&home).await.try_into().ok().unwrap();
    assert_eq!(row.kind, GrantKind::Bearer);
    assert_eq!(
        row.serves.as_ref().map(ToString::to_string).as_deref(),
        Some("tcp:localhost:5432"),
        "the row records the forward"
    );
}

/// The row of a shell shared with a device records `sshd:`, the target `ssh` stood for when it was made.
#[tokio::test]
async fn share_ssh_to_a_device_records_sshd() {
    let home = scratch("records-sshd").await;
    with_bob(&home).await;
    share(&home, &["ssh", "bob/laptop"]).await.made();
    let [row] = rows(&home).await.try_into().ok().unwrap();
    assert_eq!(
        row.serves.as_ref().map(ToString::to_string).as_deref(),
        Some("sshd:")
    );
}

/// Missing saved membership refuses even when the name has a constructor form.
#[tokio::test]
async fn a_name_not_served_never_constructs_a_sharing_target() {
    let home = scratch("records-none").await;
    with_bob(&home).await;
    serving(&home, &["db=tcp:localhost:5432"]);
    for name in ["demo", "ssh"] {
        for who in ["bob/laptop", "anyone"] {
            assert_eq!(
                share(&home, &[name, who]).await.refusal(),
                "saved services do not list that service"
            );
        }
    }
    assert!(rows(&home).await.is_empty());
}

/// The recipient keeps the kind its shape says: `root:ed01…` is a root, every machine of it; a bare key is one
/// machine. The link each makes, and the row each records, follow that kind.
#[tokio::test]
async fn share_keeps_the_kind_it_parsed() {
    let root = TestRoot::seeded(BOB_ROOT).node_id();
    let typed = format!("root:{root}");
    assert!(matches!(
        parse(&["db", &typed]).unwrap().who,
        Some(super::Recipient::Root(parsed)) if parsed.key() == root
    ));
    assert!(matches!(
        parse(&["db", &root.to_string()]).unwrap().who,
        Some(super::Recipient::Key(parsed)) if parsed == root
    ));

    let home = scratch("kind").await;
    serving(&home, &["db=tcp:localhost:5432"]);
    share(&home, &["db", &typed]).await.made();
    share(&home, &["db", &root.to_string()]).await.made();
    let kinds: Vec<GrantKind> = rows(&home).await.iter().map(|row| row.kind).collect();
    assert_eq!(kinds, [GrantKind::Fleet, GrantKind::Device]);
}

/// A link for a root's key admits a device that root vouches for, presenting its badge, and no device of
/// another root. Its line says it is for every machine of that root, the root alone under it; once the root is
/// saved for a person, the line names the person.
#[tokio::test]
async fn share_to_a_root_key_binds_every_machine_of_that_root() {
    let home = scratch("root-key").await;
    serving(&home, &["db=tcp:localhost:5432"]);
    let root = TestRoot::seeded(BOB_ROOT);
    let typed = format!("root:{}", root.node_id());
    let ran = share(&home, &["db", &typed]).await;
    let link = ran.link();
    let lines: Vec<&str> = ran.err.lines().collect();
    assert!(
        lines[0].starts_with(
            "Every machine of this root can reach db (localhost:5432 on this machine) until "
        ) && lines[0].ends_with(" (1h):"),
        "{}",
        ran.err
    );
    assert_eq!(lines[1], format!("  {typed}"));
    let [row] = rows(&home).await.try_into().ok().unwrap();
    assert_eq!(
        row.holder,
        root.node_id().to_string(),
        "the row holds the bare key"
    );

    let gate = gate(&home, &["db=tcp:localhost:5432"]).await;
    let until = SystemTime::now() + Duration::from_secs(3600);
    let device = TestNode::seeded(0x23);
    let badge = root.member_badge(device.verify_key(), until).unwrap();
    assert!(matches!(
        gate.admit_foreign(
            ProvenPeer::from_handshake(device.verify_key()),
            link.cap(),
            &badge,
            &"db".parse::<Service>().unwrap(),
        ),
        Decision::Admit
    ));
    let stranger = TestRoot::seeded(0x24)
        .member_badge(device.verify_key(), until)
        .unwrap();
    assert!(!matches!(
        gate.admit_foreign(
            ProvenPeer::from_handshake(device.verify_key()),
            link.cap(),
            &stranger,
            &"db".parse::<Service>().unwrap(),
        ),
        Decision::Admit
    ));

    with_bob(&home).await;
    let named = share(&home, &["db", &typed]).await;
    assert!(
        named.err.starts_with(
            "All of bob's machines can reach db (localhost:5432 on this machine) until "
        ),
        "{}",
        named.err
    );
}

/// A key no name here holds is said whole, alone under the line, so it can be compared.
#[tokio::test]
async fn a_share_to_an_unsaved_key_says_the_key_whole() {
    let home = scratch("unsaved-key").await;
    serving(&home, &["db=tcp:localhost:5432"]);
    let key = TestNode::seeded(0x25).node_id();
    let ran = share(&home, &["db", &key.to_string()]).await;
    ran.made();
    let lines: Vec<&str> = ran.err.lines().collect();
    assert!(
        lines[0].starts_with(
            "The machine with this key can reach db (localhost:5432 on this machine) until "
        ) && lines[0].ends_with(" (1h):"),
        "{}",
        ran.err
    );
    assert_eq!(lines[1], format!("  {key}"));
}
