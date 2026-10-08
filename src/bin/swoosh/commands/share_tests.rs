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
use nauthy::{CapError, Link, Service};
use swoosh::contacts::ContactsStore;
use swoosh::grants::{Delegation, GrantKind, GrantRecord, Grants};
use swoosh::home::Home;
use swoosh::serve_toml::ServeToml;
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;

use super::{BOUND, End, ShareCmd, Span, Usage};

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
    assert_eq!(ran.refusal(), BOUND);
    assert!(ran.out.is_empty(), "no link prints: {}", ran.out);
}

#[tokio::test]
async fn share_save_writes_0600_and_refuses_an_existing_file() {
    let home = scratch("save").await;
    let file = path_in(&home, "x.link");
    let path = file.display().to_string();
    let ran = share(&home, &["ssh", "anyone", "--save", &path]).await;
    assert_eq!(ran.made(), path, "stdout is the path alone");
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the file is private");
    let held = std::fs::read_to_string(&file).unwrap();
    assert!(
        held.starts_with("swoosh:"),
        "the file holds the printed form: {held}"
    );
    swoosh::link::parse(held.trim()).expect("the file holds the link");

    let again = share(&home, &["ssh", "anyone", "--save", &path]).await;
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
    let source = share(&home, &["ssh", "anyone", "--expires", "2h"])
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
    let source = share(&home, &["ssh", "anyone", "--expires", "2h"])
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
    let source = share(&home, &["ssh", "anyone"]).await.link();
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
        ("59m59s", false),
        ("1h", true),
        ("365d", true),
        ("366d", false),
    ] {
        let ran = share(&home, &["ssh", "anyone", "--expires", span]).await;
        match &ran.result {
            Ok(()) => assert!(ok, "{span} is refused"),
            Err(error) => {
                assert!(!ok, "{span}: {error:#}");
                assert_eq!(
                    error.downcast_ref::<Usage>().map(|usage| usage.0.as_str()),
                    Some("a link's --expires is 1h to 365d"),
                    "{span}: exit 2"
                );
                assert!(
                    ran.out.is_empty() && ran.err.is_empty(),
                    "{span}: nothing prints"
                );
            }
        }
    }
    assert_eq!(rows(&home).await.len(), 2, "only the two shares made rows");

    let source = share(&home, &["ssh", "anyone"]).await.link();
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
        ("1d2h3m4s", 86_400 + 7200 + 180 + 4),
    ] {
        let span: Span = text.parse().unwrap();
        assert_eq!(span.duration(), Duration::from_secs(secs), "{text}");
        assert_eq!(span.to_string(), text, "{text} prints as typed");
    }
    for text in [
        "", "h", "90", "1h1h", "30m1h", "1x", "0h", "0h0m", "-1h", "1 h", "1H",
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
        let ran = share(&home, &["ssh", "anyone", "--expires", span]).await;
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
    let anyone = share(&home, &["ssh", "anyone"]).await.link();
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
        toml.services = vec![
            "db=tcp:localhost:5432".to_owned(),
            "sock=unix:/run/db.sock".to_owned(),
            "news=fetch:https://news.example".to_owned(),
        ];
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
            "bob can reach db (localhost:5432 on this machine) until ".to_owned(),
        ),
        (
            vec!["sock", "bob"],
            "bob can reach sock (/run/db.sock on this machine) until ".to_owned(),
        ),
        (
            vec!["news", "bob"],
            "bob can reach, through this machine, anything this machine can reach at \
             https://news.example, until "
                .to_owned(),
        ),
        (
            vec!["ping", key.as_str()],
            format!("{key} can use ping on this machine until "),
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
        assert_eq!(
            lines[1..],
            [format!(
                "the link dials this machine: it works while this machine serves {}.",
                args[0]
            )],
            "{args:?}"
        );
    }
    let anyone = share(&home, &["ssh", "anyone", "--expires", "7d"]).await;
    anyone.made();
    let lines: Vec<&str> = anyone.err.lines().collect();
    assert!(
        lines[0].starts_with("anyone can open a shell on this machine until ")
            && lines[0].ends_with(" (7d)."),
        "{}",
        anyone.err
    );
    // Past a day, the end is a date: `15 Oct 2026`.
    let date: Vec<&str> = lines[0]
        .trim_start_matches("anyone can open a shell on this machine until ")
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
        lines[2],
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
    let link = share(&home, &["ssh", "anyone"]).await.link();
    let [row] = rows(&home).await.try_into().ok().unwrap();
    assert_eq!(Some(row.root_id), link.cap().root_revocation_id());
    assert_eq!(row.target, "ssh".parse::<Service>().unwrap());
    assert_eq!(row.holder, swoosh::grants::ANYONE);

    let cmd = parse(&["ssh", "anyone"]).unwrap();
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
    let ran = share(&home, &["ssh", "anyone", "--save", &path]).await;
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
    let ran = share(&home, &["ssh", "anyone", "--save", &under_a_file]).await;
    assert_eq!(
        ran.refusal(),
        format!("could not make {under_a_file}: no such directory")
    );
    assert!(rows(&home).await.is_empty(), "no row is written");
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
