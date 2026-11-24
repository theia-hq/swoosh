// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The device-list exchanges on the stream source: by own bind, over the run's sessions, presenting this
//! home's standing as it reads at each open; through a running `serve`, one Open per exchange.

use core::time::Duration;
use std::rc::Rc;

use bifrost::{NoDiscovery, Node, NodeId};
use clap::Parser as _;
use keystore::{KeyFile, Protection};
use swoosh::credential::Credential;
use swoosh::home::Home;
use swoosh::node_client::UidSocket;
use swoosh::peers::Peers;
use swoosh::serve::control_codec::OpenRefusal;
use swoosh::streams::{OwnBind, Resident, StreamSource};
use swoosh::sync::{Dial as _, SourceDial};
use swoosh::testkit::{Script, ScriptedPeer, TestNode, TestRoot};

use crate::commands::invite::invite_tests::{
    NAS, OWN, PASS, PHONE, ROOT, Row, copy, device_of, lapsed, live, node, records, root_key_at,
    scratch,
};
use crate::commands::through_serve::tests::{Answer, END, Heard, ROW_BOUND, Rig, Served, scripted};
use crate::{Cli, Outward, Verb};

/// What every exchange presents: this home's standing, never a slip.
const FAMILY: Credential = Credential::Family { present: None };

/// A pick-up that finds no renewal anywhere.
struct NoRenewal;

impl swoosh::renewal::Fetch for NoRenewal {
    async fn fetch(
        &self,
        _peer: NodeId,
    ) -> Result<Option<nauthy::Link>, swoosh::renewal::FetchError> {
        Ok(None)
    }
}

/// Make `home` a device of `ROOT` holding the list of [`siblings`] whose own standing ended five days
/// ago.
async fn a_lapsed_device(home: &Home) {
    a_device(home, false).await;
    device_of(home, &lapsed(OWN, "desk")).await;
}

/// `sync`'s body over `dial` and `source`, with no renewal anywhere: what it printed.
async fn synced(home: &Home, dial: &impl swoosh::sync::Dial, source: &impl StreamSource) -> String {
    let Outward::Sync(cmd) = outward(&["sync"]) else {
        unreachable!("sync parses as sync")
    };
    let mut out = Vec::new();
    cmd.exchange(home, dial, &NoRenewal, source, &mut out)
        .await
        .unwrap();
    String::from_utf8(out).unwrap()
}

/// The line `sync` prints when its pick-up found no renewal.
const MISSED: &str = "none of your devices had a renewal for this machine.";

/// A badge past its date is refused before it is sent, by own bind, and by the resident through
/// `serve`: on both paths the exchange reads it as not admitted, so `sync` reaches its pick-up and
/// prints its line.
#[tokio::test]
async fn a_dead_standing_still_reaches_the_pick_up() {
    // By own bind: no stream to `control.sync` carries the dead badge.
    let home = bare("dead-own");
    a_lapsed_device(&home).await;
    let wire = ScriptedPeer::new(node(NAS), [Script::Lists(Vec::new())]);
    let node_here = Node::new(wire.clone(), NoDiscovery);
    let peers = Peers::new(&node_here);
    let own = OwnBind::new(&peers, &home, node(OWN), &FAMILY);
    let dial = SourceDial::new(&own, &home);
    assert!(matches!(
        dial.exchange(node(NAS)).await,
        Err(swoosh::sync::ExchangeError::NotAdmitted)
    ));
    let printed = synced(&home, &dial, &own).await;
    assert!(printed.starts_with(MISSED), "{printed}");
    assert_eq!(wire.dials(), 0, "the dead badge reached no session");
    let _ = std::fs::remove_dir_all(home.dir());

    // Through `serve`: the resident's own refusal of the ended standing.
    let mut served = Served::new("dead-serve").await;
    a_lapsed_device(&served.home).await;
    let rig = Rig::default();
    let refused = (0..2)
        .map(|_| Answer::Refuse(OpenRefusal::StandingEnded))
        .collect();
    let resident = scripted(&mut served, refused, &rig);
    let source = Resident::new(Rc::new(UidSocket::resolve(&served.home).unwrap()));
    let printed = synced(
        &served.home,
        &SourceDial::new(&source, &served.home),
        &source,
    )
    .await;
    assert!(printed.starts_with(MISSED), "{printed}");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(heard.len(), 2, "one Open per device, each refused");
    all_exchanges(&heard);
}

/// By own bind, the exchange presents the badge the home stores, read at the open: after a join, after a
/// join that switched roots, and after a restore. A damaged home presents nothing.
#[tokio::test]
async fn an_own_bind_exchange_presents_the_badge_it_stored() {
    let presented = async |home: &Home| {
        let wire = ScriptedPeer::new(node(NAS), [Script::Lists(Vec::new())]);
        let node_here = Node::new(wire.clone(), NoDiscovery);
        let peers = Peers::new(&node_here);
        let own = OwnBind::new(&peers, home, node(OWN), &FAMILY);
        // The scripted peer speaks no exchange, so the body fails once the stream is admitted.
        let _ = SourceDial::new(&own, home).exchange(node(NAS)).await;
        let requests = wire.requests();
        assert_eq!(requests.len(), 1, "one stream");
        assert_eq!(requests[0].service, swoosh::serve::SYNC_SERVICE);
        requests[0].capability.clone()
    };

    // After a join: the pin and the standing it stored.
    let joined = scratch("stored-join");
    let desk = live(OWN, "desk");
    device_of(&joined, &desk).await;
    assert_eq!(
        presented(&joined).await.as_deref(),
        Some(desk.standing.as_str())
    );

    // After a join that moved this machine to another root: the new root's standing.
    let other = TestRoot::seeded(ROOT.wrapping_add(1));
    let moved = other
        .device_badge(
            node(OWN),
            std::time::SystemTime::now() + Duration::from_secs(80 * 24 * 60 * 60),
        )
        .unwrap();
    swoosh::config::write_signet(&swoosh::testkit::lock(), &joined, other.node_id()).unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), &joined, &moved).unwrap();
    assert_eq!(presented(&joined).await.as_deref(), Some(moved.as_str()));

    // After a restore, as `root restore` writes the home: the root kept here, beside the standing.
    let restored = bare("stored-restore");
    let _ = restoring(&restored, &mut Asked::default(), &[]).await;
    let stored = swoosh::config::load_badge(&restored).await.unwrap();
    assert!(stored.is_some(), "the restore stored a standing");
    assert_eq!(
        presented(&restored).await.as_deref(),
        stored.as_ref().map(nauthy::Link::as_str)
    );

    // A damaged home, pinned at its own key: nothing.
    swoosh::config::write_signet(&swoosh::testkit::lock(), &joined, node(OWN)).unwrap();
    assert_eq!(presented(&joined).await, None);

    let _ = std::fs::remove_dir_all(restored.dir().with_extension("copy"));
    for home in [joined, restored] {
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

// --- through `serve` ---

/// What one verb did through the scripted resident: its result, stderr, the Opens heard, and the
/// passphrases asked for, by key.
struct Routed {
    result: eyre::Result<()>,
    out: String,
    err: String,
    heard: Vec<Heard>,
    asked: Asked,
    /// Whether the verb's act was on the home when it ended.
    landed: bool,
}

/// A prompt that answers every passphrase and counts each by the key it opens.
#[derive(Default)]
pub(crate) struct Asked {
    root: usize,
    machine: usize,
}

impl swoosh::passphrase::Prompt for Asked {
    fn terminal(&self) -> bool {
        true
    }

    fn unlock(
        &mut self,
        asked: swoosh::passphrase::Asked<'_>,
    ) -> eyre::Result<keystore::Passphrase> {
        match asked {
            swoosh::passphrase::Asked::MachineKey => self.machine += 1,
            swoosh::passphrase::Asked::Root | swoosh::passphrase::Asked::Copy(_) => self.root += 1,
        }
        Ok(keystore::Passphrase::try_from(zeroize::Zeroizing::new(PASS.to_owned())).unwrap())
    }

    fn choose(
        &mut self,
        _asked: swoosh::passphrase::Asked<'_>,
    ) -> eyre::Result<swoosh::passphrase::Choice> {
        eyre::bail!("no passphrase is chosen here")
    }

    fn say(&mut self, _line: &str) {}
}

/// This machine's key, `OWN`, sealed under [`PASS`], so a read that opened it would ask. Sealed once
/// per process: the seal is slow by design.
fn sealed_machine_key(home: &Home) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    static SEALED: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let bytes = SEALED.get_or_init(|| {
        let scratch = bare("sealed-machine-key");
        swoosh::identity::make_machine_dir(&scratch).unwrap();
        let passphrase =
            keystore::Passphrase::try_from(zeroize::Zeroizing::new(PASS.to_owned())).unwrap();
        let mut seed = TestNode::seeded(OWN).seed();
        KeyFile::new(scratch.key())
            .write(
                &keystore::Secret::take(&mut seed),
                Protection::Passphrase(&passphrase),
            )
            .unwrap();
        let bytes = std::fs::read(scratch.key()).unwrap();
        let _ = std::fs::remove_dir_all(scratch.dir());
        bytes
    });
    swoosh::identity::make_machine_dir(home).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(home.key())
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// An empty home, holding nothing yet.
pub(crate) fn bare(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-exchange-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    Home::resolve(Some(dir)).unwrap()
}

/// The devices this machine's root lists beside it, `me/nas` and `me/phone`.
fn siblings() -> Vec<Row> {
    vec![live(OWN, "desk"), live(NAS, "nas"), live(PHONE, "phone")]
}

/// Make `home` `OWN`, its key sealed, a device of `ROOT` holding the list of [`siblings`], folded so
/// `me` names them; with the root kept here when `root` says so.
pub(crate) async fn a_device(home: &Home, root: bool) {
    a_device_of(home, root, &siblings()).await;
}

/// [`a_device`], holding the list of `rows`, this machine's own first.
async fn a_device_of(home: &Home, root: bool, rows: &[Row]) {
    sealed_machine_key(home);
    device_of(home, &rows[0]).await;
    if root {
        root_key_at(&home.root_key());
    }
    swoosh::roster::fold(
        &swoosh::home::HomeWrite::take(home).await.unwrap(),
        home,
        &TestRoot::seeded(ROOT).sign_update(&records(1, rows, Vec::new())),
    )
    .await
    .unwrap();
}

/// `argv` as the composition root splits it.
fn verb(argv: &[&str]) -> Verb {
    Cli::try_parse_from(core::iter::once("swoosh").chain(argv.iter().copied()))
        .unwrap()
        .command
        .unwrap()
        .split()
}

/// `argv`, a reaching verb, as the composition root dispatches it.
fn outward(argv: &[&str]) -> Outward {
    match verb(argv) {
        Verb::Outward(outward) => outward,
        _ => panic!("{argv:?} is no reaching verb"),
    }
}

/// `revoke <target>` on `home`, its block run first as the composition root runs it: the part your root
/// publishes, which offers the cut.
pub(crate) async fn revoking(home: &Home, target: &str, asked: &mut Asked) -> Outward {
    let Verb::Revoke(cmd) = verb(&["revoke", target]) else {
        panic!("revoke parses");
    };
    let publish = cmd
        .block(
            home,
            b"".as_slice(),
            asked,
            &crate::commands::revoke::Undialed,
            &mut Vec::new(),
        )
        .await
        .unwrap()
        .expect("a device's revoke publishes");
    Outward::Revoke(crate::commands::revoke::RevokeRoot {
        publish,
        reach: cmd.reach,
    })
}

/// `root restore` of a copy of `ROOT` listing [`siblings`] onto `home`, a machine that is none of its
/// devices yet, its local part run first: the exchange that brings the restored root up to date. `flags`
/// follow the verb as typed.
pub(crate) async fn restoring(home: &Home, asked: &mut Asked, flags: &[&str]) -> Outward {
    sealed_machine_key(home);
    let dir = home.dir().with_extension("copy");
    let _ = std::fs::remove_dir_all(&dir);
    copy(&dir, &records(1, &siblings()[1..], Vec::new()));
    let argv = [&["root", "restore", dir.to_str().unwrap()][..], flags].concat();
    let Verb::RootRestore(cmd) = verb(&argv) else {
        panic!("root restore parses");
    };
    let restored = cmd.restore(home, asked).await.unwrap();
    Outward::RootRestore(Box::new(restored))
}

/// Run `verb` through the scripted resident on `served`, answering each Open with the next of
/// `answers`, then stop it: what the verb did.
async fn routed(served: &mut Served, answers: Vec<Answer>, verb: Outward, asked: Asked) -> Routed {
    let rig = Rig::default();
    let resident = scripted(served, answers, &rig);
    let mut asked = asked;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (socket, _) = crate::commands::through_serve::serve(&served.home)
        .await
        .unwrap()
        .expect("serve answers");
    let hints =
        crate::commands::through_serve::hints(swoosh::reaching::Reaching::reach_args(&verb))
            .unwrap();
    let result = tokio::time::timeout(
        ROW_BOUND * 6,
        crate::exchange_through_serve(
            verb,
            &served.home,
            socket,
            hints,
            &mut asked,
            &mut out,
            &mut err,
        ),
    )
    .await
    .expect("the verb ends");
    rig.stop.cancel();
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    Routed {
        result,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
        heard,
        asked,
        landed: false,
    }
}

/// Every Open heard is one exchange: `control.sync`, on Main, with no slip.
fn all_exchanges(heard: &[Heard]) {
    for open in heard {
        assert_eq!(open.service, swoosh::serve::SYNC_SERVICE);
        assert_eq!(open.lane, swoosh::serve::control_codec::OpenLane::Main);
        assert_eq!(open.slip, None, "an exchange carries no slip");
    }
}

/// Answers enough for any one verb's Opens here: each attaches and ends at once, so no exchange runs.
fn attaching() -> Vec<Answer> {
    (0..12).map(|_| Answer::Attach).collect()
}

/// One exchange verb through the scripted resident, every Open attaching: `sync`, `invite`, `revoke`
/// or `root restore`, by `name`.
async fn ride(name: &str) -> Routed {
    ride_with(name, attaching()).await
}

/// [`ride`], the resident answering each Open with the next of `answers`.
async fn ride_with(name: &str, answers: Vec<Answer>) -> Routed {
    // Rows run at once: each run gets a home of its own.
    static RUNS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let run = RUNS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut served = Served::new(&format!("ride-{name}-{run}")).await;
    let mut asked = Asked::default();
    let tv = node(0x44);
    let verb = match name {
        "sync" => {
            a_device(&served.home, false).await;
            outward(&["sync"])
        }
        "invite" => {
            a_device(&served.home, true).await;
            outward(&["invite", "tv", &tv.to_string()])
        }
        "revoke" => {
            a_device(&served.home, true).await;
            revoking(&served.home, "me/phone", &mut asked).await
        }
        "restore" => restoring(&served.home, &mut asked, &[]).await,
        _ => unreachable!("no such verb here"),
    };
    let mut ran = routed(&mut served, answers, verb, asked).await;
    let home = &served.home;
    // What the route itself wrote, after the local part: the update the root cut. `root restore`'s
    // route writes nothing of its own when no device answers; its finishing line is what it leaves.
    let held = swoosh::roster::held(home, TestRoot::seeded(ROOT).verify_key());
    ran.landed = match name {
        "invite" => held.is_some_and(|list| {
            list.members()
                .iter()
                .any(|member| member.node == TestNode::seeded(0x44).verify_key())
        }),
        "revoke" => held.is_some_and(|list| {
            list.members()
                .iter()
                .all(|member| member.node != TestNode::seeded(PHONE).verify_key())
        }),
        _ => true,
    };
    ran
}

/// With `serve` answering, `sync`, `invite` and `revoke` bind nothing and unlock no machine key: every
/// exchange and offer is an Open for `control.sync` on Main, with no slip, each on a control connection
/// of its own.
#[tokio::test]
async fn the_exchange_verbs_ride_the_resident() {
    for name in ["sync", "invite", "revoke"] {
        let ran = ride(name).await;
        assert!(
            !ran.heard.is_empty(),
            "{name} made an exchange: {:?} {}",
            ran.result,
            ran.err
        );
        all_exchanges(&ran.heard);
        assert!(ran.result.is_ok(), "{name}: {:?} {}", ran.result, ran.err);
        assert_eq!(ran.asked.machine, 0, "{name} unlocked no machine key");
    }
}

/// `root restore`'s exchange rides the resident the same way, and the root's own prompt is asked once.
#[tokio::test]
async fn root_restore_rides_the_resident() {
    let ran = ride("restore").await;
    assert!(ran.result.is_ok(), "{:?} {}", ran.result, ran.err);
    assert!(!ran.heard.is_empty(), "the restore exchanged");
    all_exchanges(&ran.heard);
    assert_eq!(ran.asked.root, 1, "the copy's passphrase, once");
}

/// Through `serve`, `invite`, `revoke` and `root restore` unlock no machine key, and the root once.
#[tokio::test]
async fn invite_through_serve_unlocks_no_machine_key() {
    for name in ["invite", "revoke", "restore"] {
        let ran = ride(name).await;
        assert_eq!(ran.asked.machine, 0, "{name}: no machine key");
        assert_eq!(
            ran.asked.root, 1,
            "{name}: the root, once: {:?}",
            ran.result
        );
    }
}

/// After `join` writes its standing, its pull is one Open for `control.sync` on Main to the machine that
/// made the invite, with no slip.
#[tokio::test]
async fn join_pull_rides_the_resident_with_no_slip() {
    let mut served = Served::new("join-pull").await;
    a_device(&served.home, false).await;
    let Verb::Join(join) = verb(&["join"]) else {
        panic!("join parses");
    };
    let pull = Outward::Join(crate::commands::join::JoinPull {
        from: node(NAS),
        reach: join.reach,
    });
    let ran = routed(&mut served, attaching(), pull, Asked::default()).await;
    assert!(ran.result.is_ok(), "the pull is never a failure");
    assert_eq!(ran.heard.len(), 1, "one Open");
    all_exchanges(&ran.heard);
    assert_eq!(ran.heard[0].peer, node(NAS));
}

/// The stale-list exchange over the resident is one Open for `control.sync` on Main.
#[tokio::test]
async fn the_stale_exchange_rides_the_resident() {
    let mut served = Served::new("stale").await;
    a_device(&served.home, false).await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![Answer::Attach], &rig);
    let source = Resident::new(Rc::new(UidSocket::resolve(&served.home).unwrap()));
    let _ = swoosh::sync::once(&SourceDial::new(&source, &served.home), node(NAS)).await;
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(heard.len(), 1, "one Open");
    all_exchanges(&heard);
    assert_eq!(heard[0].peer, node(NAS));
}

/// Through `serve`, a `sync` refused for an ended standing reaches its pick-up as an Open for
/// `control.renewal` on Main with no slip, whose upload ends with End before the answer is read: the
/// resident answers only once it has read the End.
#[tokio::test]
async fn a_due_sync_through_serve_reaches_its_pick_up() {
    let mut served = Served::new("due-sync").await;
    a_lapsed_device(&served.home).await;
    let answers = vec![
        Answer::Refuse(OpenRefusal::StandingEnded),
        Answer::Refuse(OpenRefusal::StandingEnded),
        // The miss, one byte, sent only after the client's End.
        Answer::AfterEnd(vec![0x00]),
        Answer::AfterEnd(vec![0x00]),
    ];
    let ran = routed(&mut served, answers, outward(&["sync"]), Asked::default()).await;
    assert!(ran.result.is_ok(), "{:?} {}", ran.result, ran.err);
    assert!(ran.out.starts_with(MISSED), "{}", ran.out);
    let pick_ups: Vec<&Heard> = ran
        .heard
        .iter()
        .filter(|open| open.service == swoosh::serve::RENEWAL_SERVICE)
        .collect();
    assert_eq!(pick_ups.len(), 2, "each device asked");
    for open in pick_ups {
        assert_eq!(open.lane, swoosh::serve::control_codec::OpenLane::Main);
        assert_eq!(open.slip, None);
        assert_eq!(open.upload, END, "the empty upload ended with End");
    }
}

/// `sync --peer <key>=<addr>` through `serve` with an ended standing: the pick-up's Open to that machine
/// carries the address, as the exchange's does, and no other machine's Open does.
#[tokio::test]
async fn a_hinted_pick_up_through_serve_carries_its_address() {
    let mut served = Served::new("hinted-pick-up").await;
    a_lapsed_device(&served.home).await;
    let answers = vec![
        Answer::Refuse(OpenRefusal::StandingEnded),
        Answer::Refuse(OpenRefusal::StandingEnded),
        Answer::AfterEnd(vec![0x00]),
        Answer::AfterEnd(vec![0x00]),
    ];
    let hint = format!("{}=127.0.0.1:4433", node(NAS));
    let ran = routed(
        &mut served,
        answers,
        outward(&["sync", "--peer", &hint]),
        Asked::default(),
    )
    .await;
    assert!(ran.result.is_ok(), "{:?} {}", ran.result, ran.err);
    let addr: core::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let pick_up = ran
        .heard
        .iter()
        .find(|open| open.service == swoosh::serve::RENEWAL_SERVICE && open.peer == node(NAS))
        .expect("nas's pick-up");
    assert_eq!(pick_up.hints, vec![addr]);
    for open in ran.heard.iter().filter(|open| open.peer != node(NAS)) {
        assert!(open.hints.is_empty(), "another machine's Open carries none");
    }
}

/// An unrooted saved machine, `alice/laptop`, for the root sweep to ask.
async fn an_unrooted_contact(home: &Home) -> NodeId {
    let alice = TestNode::seeded(0x51).node_id();
    let home_lock = swoosh::home::HomeWrite::take(home).await.unwrap();
    let mut store = swoosh::contacts::ContactsStore::open(home).await.unwrap();
    store
        .contacts_mut()
        .save(&"alice/laptop".parse().unwrap(), alice)
        .unwrap();
    store.save(&home_lock).unwrap();
    alice
}

/// Through `serve`, a `sync` that meets another version prints its rows, then the version line, exit 1,
/// and opens nothing more, its root sweep included. A root act says the same after its own lines.
#[tokio::test]
async fn serve_gone_ends_sync_after_its_rows() {
    let mut served = Served::new("gone-skew").await;
    a_device(&served.home, false).await;
    an_unrooted_contact(&served.home).await;
    let ran = routed(
        &mut served,
        vec![Answer::Version, Answer::Attach, Answer::Attach],
        outward(&["sync"]),
        Asked::default(),
    )
    .await;
    let error = ran.result.expect_err("exit 1");
    assert!(
        error.is::<crate::commands::through_serve::Skew>(),
        "{error:#}"
    );
    assert_eq!(
        ran.out, "no device answered; your devices get it at their next sync.\n",
        "the rows came first"
    );
    assert_eq!(
        ran.heard.len(),
        1,
        "no Open after the first met another version"
    );
}

/// A one-device `sync` whose `serve` stops while its exchange is attached ends with the stopped line
/// naming that device, exit 1, and opens nothing after.
#[tokio::test]
async fn serve_dies_inside_an_attached_exchange_is_named() {
    let mut served = Served::new("dies-inside").await;
    a_device_of(&served.home, false, &[live(OWN, "desk"), live(NAS, "nas")]).await;
    an_unrooted_contact(&served.home).await;
    let ran = routed(
        &mut served,
        vec![Answer::Stop, Answer::Attach],
        outward(&["sync"]),
        Asked::default(),
    )
    .await;
    let error = format!("{:#}", ran.result.expect_err("exit 1"));
    assert!(
        error.starts_with("swoosh serve stopped here and ended the connection to me/nas\n"),
        "{error}"
    );
    assert_eq!(ran.heard.len(), 1, "no Open after the cut");
}

/// What each root act's own last line says once it has landed, before the line that says where `serve`
/// went.
fn reach_line(name: &str) -> &'static str {
    match name {
        "revoke" => "revoked me/phone",
        "invite" => "me/tv runs 90d from now",
        "restore" => "restored root:",
        _ => unreachable!("no such root act here"),
    }
}

/// With `serve` of another version, or one that stalled (it takes connects and replies to nothing),
/// `revoke`, `invite` and `root restore` still make their cut and print their own lines, then end with
/// the line that says why, exit 1.
#[tokio::test]
async fn a_root_act_against_a_skewed_or_wedged_resident_ends_with_its_line() {
    for (name, wedged) in [
        ("revoke", false),
        ("invite", false),
        ("restore", false),
        ("revoke", true),
        ("invite", true),
        ("restore", true),
    ] {
        let answers = if wedged {
            vec![Answer::Wedge]
        } else {
            (0..12).map(|_| Answer::Version).collect()
        };
        let ran = ride_with(name, answers).await;
        let error = ran.result.expect_err("exit 1");
        if wedged {
            assert!(
                error.is::<crate::commands::through_serve::Unresponsive>(),
                "{name}: {error:#}"
            );
        } else {
            assert!(
                error.is::<crate::commands::through_serve::Skew>(),
                "{name}: {error:#}"
            );
        }
        assert!(
            ran.err.contains(reach_line(name)),
            "{name}: its own lines came first: {}",
            ran.err
        );
        assert!(ran.landed, "{name}: the route's own write landed");
    }
}

/// A healthy `serve` whose one device never answers its Open: the run ends on that device's no-answer,
/// exit 0, and says nothing of `serve`.
#[tokio::test]
async fn a_slow_device_through_a_healthy_serve_is_no_answer() {
    let mut served = Served::new("slow-device").await;
    a_device_of(&served.home, false, &[live(OWN, "desk"), live(NAS, "nas")]).await;
    let ran = routed(
        &mut served,
        vec![Answer::Stall],
        outward(&["sync"]),
        Asked::default(),
    )
    .await;
    assert!(ran.result.is_ok(), "{:?}", ran.result);
    assert_eq!(
        ran.out,
        "no device answered; your devices get it at their next sync.\n"
    );
}

/// A root act whose `serve` stops while its exchange with a device is attached ends, after its own lines,
/// with the stopped line naming that device and no advice to run the act again, exit 1.
#[tokio::test]
async fn a_root_acts_stopped_serve_names_the_device_it_cut() {
    let ran = ride_with("invite", vec![Answer::Attach, Answer::Stop]).await;
    let error = format!("{:#}", ran.result.expect_err("exit 1"));
    let cut = if ran.heard[1].peer == node(NAS) {
        "me/nas"
    } else {
        "me/phone"
    };
    assert_eq!(
        error,
        format!(
            "swoosh serve stopped here and ended the connection to {cut}\n  Commands here connect \
             through it while it runs.\n  Start it again; it asks your devices as it starts."
        )
    );
    assert!(ran.err.contains(reach_line("invite")), "{}", ran.err);
}

/// `sync --peer <key>=<addr>`: the Open to that machine carries the address and no other Open does. More
/// addresses for one machine than one Open carries are the usage line, before anything is opened.
#[tokio::test]
async fn peer_hints_ride_each_exchange_through_serve() {
    let mut served = Served::new("hints").await;
    a_device(&served.home, false).await;
    let hint = format!("{}=127.0.0.1:4433", node(NAS));
    let ran = routed(
        &mut served,
        attaching(),
        outward(&["sync", "--peer", &hint]),
        Asked::default(),
    )
    .await;
    let addr: core::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
    for open in &ran.heard {
        let expected = if open.peer == node(NAS) {
            vec![addr]
        } else {
            Vec::new()
        };
        assert_eq!(open.hints, expected, "hints ride their own machine's Opens");
    }
    assert!(ran.heard.iter().any(|open| open.peer == node(NAS)));

    let crowded: Vec<String> = (0..17)
        .map(|port| format!("{}=127.0.0.1:{}", node(NAS), 4000 + port))
        .collect();
    let mut argv = vec!["sync"];
    for hint in &crowded {
        argv.extend(["--peer", hint.as_str()]);
    }
    let error = crate::commands::through_serve::hints(swoosh::reaching::Reaching::reach_args(
        &outward(&argv),
    ))
    .expect_err("a usage error");
    assert_eq!(
        error.to_string(),
        format!(
            "--peer or SWOOSH_PEER gives more than 16 addresses for {}",
            node(NAS)
        )
    );
}

/// Through `serve`, `sync` asks each saved machine of a person with no root saved which root vouches for
/// it: one Open for `lookup.root` on Main with no slip, per machine.
#[tokio::test]
async fn sync_asks_the_roots_through_the_source() {
    let mut served = Served::new("roots").await;
    a_device(&served.home, false).await;
    let alice = an_unrooted_contact(&served.home).await;
    let ran = routed(
        &mut served,
        attaching(),
        outward(&["sync"]),
        Asked::default(),
    )
    .await;
    assert!(ran.result.is_ok(), "{:?} {}", ran.result, ran.err);
    let lookups: Vec<&Heard> = ran
        .heard
        .iter()
        .filter(|open| open.service == swoosh::serve::LOOKUP_ROOT_SERVICE)
        .collect();
    assert_eq!(lookups.len(), 1, "one ask, for the one unrooted machine");
    assert_eq!(lookups[0].peer, alice);
    assert_eq!(
        lookups[0].lane,
        swoosh::serve::control_codec::OpenLane::Main
    );
    assert_eq!(lookups[0].slip, None);
}

/// With `serve` answering, `sync --relay` refuses with the moot line before any Open. The local verbs'
/// refusal before their act runs in the binary: `tests/exchange_route.rs`.
#[tokio::test]
async fn a_reach_flag_refuses_an_exchange_verb_before_it_writes() {
    let mut served = Served::new("moot-sync").await;
    a_device(&served.home, false).await;
    let ran = routed(
        &mut served,
        attaching(),
        outward(&["sync", "--relay", "https://relay.example.com"]),
        Asked::default(),
    )
    .await;
    let error = ran.result.expect_err("exit 1");
    assert!(
        error.is::<crate::commands::through_serve::Moot>(),
        "{error:#}"
    );
    assert!(ran.heard.is_empty(), "no Open");
}
