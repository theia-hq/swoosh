//! `send` over its source, on both paths: by own bind each file is a stream on the run's own Bulk session,
//! through `serve` each is one Open on Bulk, and the lines a stream that was not opened prints are each
//! path's own.
//!
//! The sender's own lines also render a hostile file name through the shared escaper, so a newline in a
//! name cannot forge a second line on this terminal and an ESC cannot drive it. The name is not the only
//! surface: the skip line prints the whole error chain beside the escaped prefix, so a path-bearing
//! context built with a raw `Path::display` (the `stat`/`read` walk and the no-file-name error) would
//! leak the bytes the prefix escaped.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use bifrost::{Discovery, NoDiscovery, Node, NodeId, Transport};
use clap::Parser as _;
use swoosh::contacts::Contacts;
use swoosh::credential::Credential;
use swoosh::home::Home;
use swoosh::learn::Admitted;
use swoosh::peer::Machine;
use swoosh::peers::{Hints, Peers};
use swoosh::reach::Diagnosis;
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::streams::{Ask, OwnBind, Resident, StreamSource as _};
use swoosh::testkit::{HostilePeer, Script, ScriptedPeer};

use super::{MAX_INFLIGHT, Route, SEND_LANE, SendCmd, collect_files, file_name};
use crate::commands::machine;
use crate::commands::through_serve::tests::{
    Answer, Heard, ROW_BOUND, Rig, Served, book, machine as typed, nas, nas_slip, resident_key,
    scripted,
};
use crate::commands::through_serve::{self, Dial, ThisMachine};

#[derive(clap::Parser)]
struct Wrap {
    #[command(flatten)]
    send: SendCmd,
}

/// `send` as `argv` (the paths, then the machine) parses.
fn send(argv: &[&str]) -> SendCmd {
    Wrap::try_parse_from(["x"].iter().chain(argv)).unwrap().send
}

/// `n` small files in a scratch directory of their own: the directory, and each file's path.
fn files(tag: &str, n: usize) -> (PathBuf, Vec<String>) {
    let dir = std::env::temp_dir().join(format!("swoosh-send-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let paths = (0..n)
        .map(|at| {
            let path = dir.join(format!("f{at}.txt"));
            std::fs::write(&path, format!("file {at}")).unwrap();
            path.to_str().unwrap().to_owned()
        })
        .collect();
    (dir, paths)
}

/// A home with nothing in it: a standing that reads as none, so a stream presents nothing.
fn empty_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-send-home-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Home::resolve(Some(dir)).unwrap()
}

/// A run that presents this home's standing, for a stream a row holds beside the run's.
const FAMILY: Credential = Credential::Family { present: None };

/// The names `out`'s `sent` lines give, in the order they were sent.
fn sent_names(out: &str) -> Vec<&str> {
    out.lines()
        .filter_map(|line| line.strip_prefix("sent "))
        .filter_map(|line| line.split(" (").next())
        .collect()
}

/// The file each of `err`'s `skip` lines names, and the rest of its first line.
fn skips(err: &str) -> Vec<(&str, &str)> {
    err.lines()
        .filter_map(|line| line.strip_prefix("skip "))
        .filter_map(|line| line.split_once(": "))
        .collect()
}

/// A home whose standing is a device badge for the machine `this`, so a stream presents a real one:
/// the home, and the badge.
fn device_home(tag: &str, this: NodeId) -> (Home, nauthy::Link) {
    let dir = std::env::temp_dir().join(format!("swoosh-send-device-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let root = swoosh::testkit::TestRoot::seeded(0x70);
    swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).unwrap();
    let until = std::time::SystemTime::now() + core::time::Duration::from_secs(30 * 24 * 60 * 60);
    let badge = root.device_badge(this, until).unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
    (home, badge)
}

/// What a run printed and how it ended.
struct Ran {
    ended: eyre::Result<()>,
    out: String,
    err: String,
}

/// An Open the scripted resident attaches, answering a transfer's frame with the receiver's ack.
fn ack() -> Answer {
    Answer::Exchange(vec![1])
}

/// Run `cmd` to `machine` by own bind over `peers`, from `home` as `this`, its root question unheard.
async fn by_own_bind<T: Transport, D: Discovery>(
    cmd: &SendCmd,
    peers: &Peers<'_, T, D>,
    home: &Home,
    this: NodeId,
    machine: &Machine,
) -> Ran {
    let bound = swoosh::transport::Bound {
        local: false,
        reach: swoosh::transport::Reach::default(),
    };
    let route = Route::Own {
        peer: &cmd.peer,
        bound: &bound,
        this,
    };
    let ask = Ask {
        peer: machine.key(),
        hints: Hints::NONE,
        service: cmd.service.clone(),
        lane: SEND_LANE,
        slip: cmd.peer.self_present(),
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let ended = cmd
        .run_send(
            OwnBind::new(peers, home, this, &cmd.credential()),
            &route,
            machine,
            ask,
            Admitted::unheard(),
            &Cell::new(false),
            &mut out,
            &mut err,
        )
        .await;
    Ran {
        ended,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// Run `cmd` to `machine` through the `serve` at `home`, presenting `slip`, its root question unheard.
async fn through(
    cmd: &SendCmd,
    home: &Home,
    machine: &Machine,
    slip: Option<nauthy::Link>,
    contacts: &Contacts,
) -> Ran {
    let (socket, _) = through_serve::serve(home).await.unwrap().unwrap();
    through_socket(cmd, Rc::new(socket), machine, slip, contacts).await
}

/// [`through`], on a socket already resolved.
async fn through_socket(
    cmd: &SendCmd,
    socket: Rc<swoosh::node_client::UidSocket>,
    machine: &Machine,
    slip: Option<nauthy::Link>,
    contacts: &Contacts,
) -> Ran {
    let dial = Dial {
        machine,
        service: &cmd.service,
        contacts,
    };
    let ask = swoosh::streams::Ask {
        peer: machine.key(),
        hints: swoosh::peers::Hints::NONE,
        service: cmd.service.clone(),
        lane: SEND_LANE,
        slip,
    };
    let resident = Resident::new(Rc::clone(&socket));
    let route = Route::Serve {
        dial: &dial,
        socket: &socket,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let ended = tokio::time::timeout(
        ROW_BOUND,
        cmd.run_send(
            &resident,
            &route,
            machine,
            ask,
            Admitted::unheard(),
            &Cell::new(false),
            &mut out,
            &mut err,
        ),
    )
    .await
    .expect("the run ended");
    Ran {
        ended,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// The Opens the scripted resident heard for files, the follow-up and the lookup left out.
fn file_opens(heard: &[Heard]) -> Vec<&Heard> {
    heard.iter().filter(|open| open.service == "recv").collect()
}

/// With `serve` answering, `send` reads no key and binds nothing: its run takes no node, and the home's
/// key is one no read could load, so a run that read it would fail. Every file is one Open.
#[tokio::test]
async fn send_through_serve_binds_nothing_and_reads_no_key() {
    let mut served = Served::new("send-nokey").await;
    std::fs::create_dir_all(served.home.key().parent().unwrap()).unwrap();
    std::fs::write(served.home.key(), b"not a key").unwrap();
    let rig = Rig::default();
    let resident = scripted(&mut served, (0..3).map(|_| ack()).collect(), &rig);
    let (dir, paths) = files("nokey", 3);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");

    // As the dialing route runs it: the warning, the exchange and the lookup beside it read the home too.
    let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
    let outward = crate::Outward::Send(cmd);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let ended = tokio::time::timeout(
        ROW_BOUND,
        crate::dial_through_serve(
            crate::Dialing::of(&outward).unwrap(),
            crate::Beside::of(&outward, &served.home, Some(&peer)),
            crate::ThroughServe {
                machine: &peer,
                slip: None,
                socket,
                hints: std::collections::HashMap::new(),
                contacts: &contacts,
            },
            crate::commands::learning::Asking::NoTerminal,
            // Never opened: `send` has no bridge.
            crate::commands::connect::stdio,
            &mut out,
            &mut err,
        ),
    )
    .await
    .expect("the run ended");
    let _ = std::fs::remove_dir_all(dir);
    assert!(
        ended.is_ok(),
        "not a run through serve that sent: {}",
        String::from_utf8_lossy(&err)
    );
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), 3);
}

/// By own bind, N files are N streams on one Bulk session of the run's own: a Main session already held
/// to the machine carries none of them. Through `serve`, N files are N Opens, each on Bulk, each on a
/// control connection of its own, and each presenting the link typed as the machine.
#[tokio::test]
async fn send_opens_one_bulk_stream_per_file_on_both_paths() {
    let (dir, paths) = files("bulk", 3);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");

    let scripted_peer = ScriptedPeer::new(
        nas(),
        [
            Script::Holds,
            Script::Says(vec![1]),
            Script::Says(vec![1]),
            Script::Says(vec![1]),
        ],
    );
    let node = Node::new(scripted_peer.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let home = empty_home("bulk");
    let held = OwnBind::new(&peers, &home, node.node_id(), &FAMILY)
        .open(&Ask {
            peer: nas(),
            hints: Hints::NONE,
            service: "recv".parse().unwrap(),
            lane: OpenLane::Main,
            slip: None,
        })
        .await
        .expect("the Main stream opened");
    // The verb's own entry, as the composition root dispatches it.
    let bound = swoosh::transport::Bound {
        local: false,
        reach: swoosh::transport::Reach::default(),
    };
    let ctx = swoosh::reaching::ReachCtx {
        contacts: &contacts,
        machine: Some(&peer),
        bound: &bound,
        present: None,
        membership: None,
        home: &home,
        admitted: Admitted::unheard(),
    };
    let ended = swoosh::reaching::Reaching::run(cmd, &node, ctx, &peers).await;
    drop(held);
    assert!(ended.is_ok(), "{ended:?}");
    assert_eq!(scripted_peer.requests().len(), 4);
    assert_eq!(
        scripted_peer.dials(),
        2,
        "the held Main session and one Bulk session for every file"
    );

    let _ = std::fs::remove_dir_all(dir);

    // More files than one window holds, so some open only after others attached.
    let many = MAX_INFLIGHT + 2;
    let (dir, paths) = files("bulk-serve", many);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let mut served = Served::new("send-bulk").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, (0..many).map(|_| ack()).collect(), &rig);
    let slip = nas_slip();
    let ran = through(&cmd, &served.home, &peer, Some(slip.clone()), &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    assert!(ran.ended.is_ok(), "{:?}: {}", ran.ended, ran.err);
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    let opens = file_opens(&heard);
    assert_eq!(
        opens.len(),
        many,
        "one Open, and one control connection, per file"
    );
    for open in opens {
        assert_eq!(open.lane, OpenLane::Bulk);
        assert_eq!(open.slip.as_deref(), Some(slip.as_str()));
    }
}

/// The line a run to `me/nas` ends with when `serve` is gone.
const SERVE_STOPPED: &str = "swoosh serve stopped here and ended the connection to me/nas\n  Commands here \
                             connect through it while it runs.\n  Run this command again to reconnect.";

/// The line a run to `me/nas` ends with when `serve` is gone after a file printed `sent`, files left.
const STOPPED_AFTER_SENT: &str = "swoosh serve stopped here and ended the connection to me/nas\n  Commands \
                                  here connect through it while it runs.\n  Run this command again to \
                                  reconnect, without the files already marked `sent`.";

/// A row of [`send_ends_on_a_refusal_every_file_would_repeat`]: its tag, the resident's answer to every
/// Open, and the line the run ends with.
type Case = (&'static str, fn() -> Answer, String);

/// Through `serve`, an outcome every later stream would repeat, met by the first file of more than one
/// window's worth, ends the run with its line and opens no file past the window: the machine's
/// `NotAdmitted` (asked why first), an ended standing, the machine being this one (exit 2 through the
/// root's mapping), `serve`'s Error reply (its home unread), `serve` gone, another version answering,
/// and a slip that addresses another machine. By own bind, a home that cannot be read ends it too.
#[tokio::test]
async fn send_ends_on_a_refusal_every_file_would_repeat() {
    let (dir, paths) = files("ends", MAX_INFLIGHT + 1);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let recv = "recv".parse().unwrap();

    let refused = machine::refused(&peer, &recv, Some(Diagnosis::NotYours));
    let ended = through_serve::StandingEnded(Some(resident_key()));
    let cases: [Case; 5] = [
        (
            "na",
            || Answer::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
            format!("{refused:#}"),
        ),
        (
            "se",
            || Answer::Refuse(OpenRefusal::StandingEnded),
            ended.to_string(),
        ),
        (
            "nh",
            || Answer::Refuse(OpenRefusal::NotHere),
            "me/nas is this machine".to_owned(),
        ),
        (
            "sk",
            || Answer::Version,
            "swoosh serve on this machine is a different version\n  Restart it with this version."
                .to_owned(),
        ),
        (
            "he",
            || Answer::Error("this machine's home or badge could not be read"),
            // The reply as the resident's Error line prints it, escaped.
            r"this machine\'s home or badge could not be read".to_owned(),
        ),
    ];
    for (tag, answer, line) in cases {
        let mut served = Served::new(&format!("send-ends-{tag}")).await;
        let rig = Rig::default();
        let resident = scripted(
            &mut served,
            (0..=MAX_INFLIGHT + 1).map(|_| answer()).collect(),
            &rig,
        );
        let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
        rig.stop.cancel();
        let report = ran.ended.expect_err("the run ended non-zero");
        assert_eq!(format!("{report:#}"), line, "{tag}");
        assert_eq!(
            report.is::<ThisMachine>(),
            tag == "nh",
            "{tag}: exit 2 only for this machine"
        );
        assert!(!ran.err.contains("skip "), "{tag}: {}", ran.err);
        let heard = tokio::time::timeout(ROW_BOUND, resident)
            .await
            .unwrap()
            .unwrap();
        assert!(
            file_opens(&heard).len() <= MAX_INFLIGHT,
            "{tag}: a file past the first window opened"
        );
    }

    // Another version answering once this run's Opens attached is a restarted `serve`: the run's is gone,
    // after files printed `sent`.
    let mut served = Served::new("send-ends-restarted").await;
    let rig = Rig::default();
    let resident = scripted(
        &mut served,
        (0..MAX_INFLIGHT)
            .map(|_| ack())
            .chain([Answer::Version])
            .collect(),
        &rig,
    );
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    rig.stop.cancel();
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(format!("{report:#}"), STOPPED_AFTER_SENT);
    assert!(!ran.err.contains("skip "), "{}", ran.err);
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), MAX_INFLIGHT + 1);

    // `serve` gone before the first Open: its lock free and its socket unlinked.
    let mut served = Served::new("send-ends-gone").await;
    let (socket, _) = through_serve::serve(&served.home).await.unwrap().unwrap();
    drop(served.listener());
    drop(served.lock());
    let ran = through_socket(&cmd, Rc::new(socket), &peer, None, &contacts).await;
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(format!("{report:#}"), SERVE_STOPPED);
    assert!(!ran.err.contains("skip "), "{}", ran.err);

    // A slip for another machine: no Open is sent, and the run ends on the malformed request's line.
    let mut served = Served::new("send-ends-malformed").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![ack()], &rig);
    let other = swoosh::testkit::TestNode::seeded(0x64)
        .slip(
            &"recv".parse().unwrap(),
            std::time::SystemTime::now() + core::time::Duration::from_secs(3600),
        )
        .unwrap()
        .link()
        .unwrap();
    let ran = through(&cmd, &served.home, &peer, Some(other), &contacts).await;
    rig.stop.cancel();
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(
        format!("{report:#}"),
        "open request slip does not address its peer"
    );
    assert_eq!(ran.err, "", "no skip line");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert!(file_opens(&heard).is_empty());

    // By own bind, a home whose revocations cannot be read once the run's up-front read has passed:
    // every open would read it again, so the first ends the run and nothing reaches the machine.
    let scripted_peer = ScriptedPeer::new(nas(), (0..=MAX_INFLIGHT).map(|_| Script::Says(vec![1])));
    let node = Node::new(scripted_peer.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let home = empty_home("ends-home");
    std::fs::create_dir_all(home.revoked()).unwrap();
    let ran = by_own_bind(&cmd, &peers, &home, node.node_id(), &peer).await;
    let _ = std::fs::remove_dir_all(dir);
    let report = ran.ended.expect_err("the run ended non-zero");
    assert!(
        format!("{report:#}").starts_with("could not read the revocations on this machine"),
        "{report:#}"
    );
    assert_eq!(ran.err, "", "no skip line");
    assert!(scripted_peer.requests().is_empty());
    assert_eq!(scripted_peer.dials(), 0);
}

/// A machine not reached before any file was admitted ends the run with its one line, on both paths,
/// for a failed dial and for one out of time: never a `skip` per file and a count, and through `serve`
/// no Open past the first window.
#[tokio::test]
async fn send_ends_when_the_machine_is_unreached_before_any_file() {
    let (dir, paths) = files("unreached", MAX_INFLIGHT + 1);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");

    let cases: [Case; 2] = [
        (
            "ur",
            || {
                Answer::Refuse(OpenRefusal::Unreachable(bifrost::RefusalDetail::bounded(
                    "no route",
                )))
            },
            "connect to peer: no route".to_owned(),
        ),
        (
            "to",
            || Answer::Refuse(OpenRefusal::Timeout),
            "connect to peer: timed out".to_owned(),
        ),
    ];
    for (tag, answer, line) in cases {
        let mut served = Served::new(&format!("send-unreached-{tag}")).await;
        let rig = Rig::default();
        let resident = scripted(
            &mut served,
            (0..=MAX_INFLIGHT + 1).map(|_| answer()).collect(),
            &rig,
        );
        let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
        rig.stop.cancel();
        let report = ran.ended.expect_err("the run ended non-zero");
        assert_eq!(format!("{report:#}"), line, "{tag}");
        assert_eq!(ran.err, "", "{tag}: no skip line");
        let heard = tokio::time::timeout(ROW_BOUND, resident)
            .await
            .unwrap()
            .unwrap();
        assert!(
            file_opens(&heard).len() <= MAX_INFLIGHT,
            "{tag}: a file past the first window opened"
        );
    }

    // By own bind: every dial fails.
    let at = HostilePeer::node_id().to_string();
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push(&at);
    let hostile = send(&argv);
    let machine = hostile.peer.machine(&Contacts::default()).unwrap();
    let node = Node::new(HostilePeer::Unreachable("closed by peer"), NoDiscovery);
    let peers = Peers::new(&node);
    let home = empty_home("unreached");
    let ran = by_own_bind(&hostile, &peers, &home, node.node_id(), &machine).await;
    let report = ran.ended.expect_err("the run ended non-zero");
    assert!(
        format!("{report:#}").starts_with(&format!(
            "could not reach {}: connect to peer: closed by peer",
            hostile.peer
        )),
        "{report:#}"
    );
    assert_eq!(ran.err, "", "no skip line");

    // By own bind: the machine takes every request and answers none, so each open runs out of time.
    // Last, on a paused clock, so the deadline passes at once and no socket case above shares it.
    tokio::time::pause();
    let scripted_peer = ScriptedPeer::new(nas(), (0..=MAX_INFLIGHT).map(|_| Script::Silent));
    let node = Node::new(scripted_peer.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let ran = by_own_bind(&cmd, &peers, &home, node.node_id(), &peer).await;
    let _ = std::fs::remove_dir_all(dir);
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(
        format!("{report:#}"),
        "the machine did not answer the request to open a stream in time"
    );
    assert_eq!(ran.err, "", "no skip line");
    assert!(scripted_peer.requests().len() <= MAX_INFLIGHT);
}

/// `serve` stopping before it answers an Open ends the run with its own line, not a `skip` per file:
/// the cut finds no `serve` and its lock free. A cut while `serve` still answers is that file's alone.
#[tokio::test]
async fn send_ends_when_serve_stops_before_an_open_is_answered() {
    let contacts = book();
    let peer = typed(&contacts, "me/nas");

    // One file: with more, a later file's connect can find `serve` gone first and hide the cut.
    let (dir, paths) = files("vanish", 1);
    let cmd = send(&[paths[0].as_str(), "me/nas"]);
    let mut served = Served::new("send-vanish").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![Answer::Vanish], &rig);
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(format!("{report:#}"), SERVE_STOPPED);
    assert_eq!(ran.err, "", "no skip line");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), 1);

    // `serve` still up: one answer is left unspent, so it holds its socket and lock through the ask.
    let (dir, paths) = files("hangup", 2);
    let cmd = send(&[paths[0].as_str(), paths[1].as_str(), "me/nas"]);
    let mut served = Served::new("send-hangup").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![Answer::Hangup, ack(), ack()], &rig);
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    rig.stop.cancel();
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(
        format!(
            "{:#}",
            ran.ended.expect_err("a skipped file ends the run non-zero")
        ),
        "1 item(s) could not be sent"
    );
    let sent = sent_names(&ran.out);
    assert_eq!(sent.len(), 1, "{}", ran.out);
    let skipped = skips(&ran.err);
    assert_eq!(skipped.len(), 1, "{}", ran.err);
    let (name, line) = skipped[0];
    assert!(!sent.contains(&name), "{name} was sent and skipped");
    assert_eq!(line, "connection lost");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), 2);
}

/// Through `serve`, a run that ends on `serve` stopping after a file printed `sent` says to leave the
/// sent files out of the rerun, since a bare rerun would send them again. Before any `sent` line, the
/// run's line is `serve` stopping's own, unchanged.
#[tokio::test]
async fn a_serve_stopped_after_a_sent_file_ends_without_resending() {
    let contacts = book();
    let peer = typed(&contacts, "me/nas");

    // One window's worth answered, then `serve` stops, before the last file's Open: that file opens only
    // once one of the window printed `sent`.
    let (dir, paths) = files("stopped-after-sent", MAX_INFLIGHT + 1);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let mut served = Served::new("send-stopped-after-sent").await;
    let rig = Rig::default();
    let resident = scripted(
        &mut served,
        (0..MAX_INFLIGHT).map(|_| ack()).collect(),
        &rig,
    );
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(format!("{report:#}"), STOPPED_AFTER_SENT);
    assert!(!report.is::<ThisMachine>(), "exit 1, not a usage error");
    // The run ends at the first file to meet the stop; the files still in flight print nothing.
    assert!(!sent_names(&ran.out).is_empty(), "{}", ran.out);
    assert_eq!(ran.err, "", "no skip line");
    tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();

    // `serve` stops before any file printed `sent`: the line is unchanged.
    let (dir, paths) = files("stopped-before-sent", 1);
    let cmd = send(&[paths[0].as_str(), "me/nas"]);
    let mut served = Served::new("send-stopped-before-sent").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![Answer::Vanish], &rig);
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(format!("{report:#}"), SERVE_STOPPED);
    assert!(sent_names(&ran.out).is_empty(), "{}", ran.out);
    tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
}

/// Through `serve`, `serve` stopping while a file's stream is attached ends the run on its own line, as
/// a stop before an open does: after a `sent` line, the line says to leave the sent files out of the
/// rerun, and no `N item(s)` line follows. Before any `sent` line, the line is `serve` stopping's own.
#[tokio::test]
async fn a_serve_stopped_mid_transfer_ends_without_resending() {
    let contacts = book();
    let peer = typed(&contacts, "me/nas");

    // One window's worth answered, then `serve` attaches the last file and stops under it: that file
    // opens only once one of the window printed `sent`.
    let (dir, paths) = files("cut-after-sent", MAX_INFLIGHT + 1);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let mut served = Served::new("send-cut-after-sent").await;
    let rig = Rig::default();
    let resident = scripted(
        &mut served,
        (0..MAX_INFLIGHT)
            .map(|_| ack())
            .chain([Answer::Stop])
            .collect(),
        &rig,
    );
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(format!("{report:#}"), STOPPED_AFTER_SENT);
    assert!(!report.is::<ThisMachine>(), "exit 1, not a usage error");
    assert!(!sent_names(&ran.out).is_empty(), "{}", ran.out);
    assert_eq!(ran.err, "", "no skip line");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), MAX_INFLIGHT + 1);

    // `serve` attaches the only file and stops under it, before any `sent`: the line is unchanged.
    let (dir, paths) = files("cut-before-sent", 1);
    let cmd = send(&[paths[0].as_str(), "me/nas"]);
    let mut served = Served::new("send-cut-before-sent").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![Answer::Stop], &rig);
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    let report = ran.ended.expect_err("the run ended non-zero");
    assert_eq!(format!("{report:#}"), SERVE_STOPPED);
    assert!(sent_names(&ran.out).is_empty(), "{}", ran.out);
    assert_eq!(ran.err, "", "no skip line");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), 1);
}

/// Through `serve`, a stream cut mid-transfer while `serve` still answers is that file's alone: its
/// `skip` line names it, the other file is sent, and the run ends on the count, never a `serve` line.
#[tokio::test]
async fn a_cut_transfer_with_serve_answering_skips_its_file() {
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let (dir, paths) = files("cut-answering", 2);
    let cmd = send(&[paths[0].as_str(), paths[1].as_str(), "me/nas"]);
    let mut served = Served::new("send-cut-answering").await;
    let rig = Rig::default();
    // One answer is left unspent, so the resident holds its socket and lock and answers the status ask.
    let resident = scripted(&mut served, vec![Answer::Cut, ack(), ack()], &rig);
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    rig.stop.cancel();
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(
        format!(
            "{:#}",
            ran.ended.expect_err("a skipped file ends the run non-zero")
        ),
        "1 item(s) could not be sent"
    );
    let sent = sent_names(&ran.out);
    assert_eq!(sent.len(), 1, "{}", ran.out);
    let skipped = skips(&ran.err);
    assert_eq!(skipped.len(), 1, "{}", ran.err);
    let (name, _) = skipped[0];
    assert!(!sent.contains(&name), "{name} was sent and skipped");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), 2);
}

/// A machine reached once and then not is a path that dropped: the file whose open met it is skipped,
/// by name, and the files after it still go.
#[tokio::test]
async fn send_skips_an_unreached_file_after_one_was_admitted() {
    // One window, then two more: the window's files are admitted before the next file opens.
    let many = MAX_INFLIGHT + 2;
    let (dir, paths) = files("unreached-after", many);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let mut served = Served::new("send-unreached-after").await;
    let rig = Rig::default();
    let resident = scripted(
        &mut served,
        (0..MAX_INFLIGHT)
            .map(|_| ack())
            .chain([
                Answer::Refuse(OpenRefusal::Unreachable(bifrost::RefusalDetail::bounded(
                    "no route",
                ))),
                ack(),
            ])
            .collect(),
        &rig,
    );
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(
        format!(
            "{:#}",
            ran.ended.expect_err("a skipped file ends the run non-zero")
        ),
        "1 item(s) could not be sent"
    );
    let sent = sent_names(&ran.out);
    assert_eq!(sent.len(), many - 1, "{}", ran.out);
    let skipped = skips(&ran.err);
    assert_eq!(skipped.len(), 1, "{}", ran.err);
    let (name, line) = skipped[0];
    assert!(!sent.contains(&name), "{name} was sent and skipped");
    assert_eq!(line, "connect to peer: no route");
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), many);
}

/// Each skip line names its file: `serve` busy for two files of three prints two skips naming two
/// different files, neither of them the one sent; and a transfer that fails after its open names its
/// file too.
#[tokio::test]
async fn send_skip_lines_name_their_file() {
    let (dir, paths) = files("named", 3);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let mut served = Served::new("send-named").await;
    let rig = Rig::default();
    let resident = scripted(
        &mut served,
        vec![
            Answer::Refuse(OpenRefusal::Busy),
            ack(),
            Answer::Refuse(OpenRefusal::Busy),
        ],
        &rig,
    );
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(
        format!(
            "{:#}",
            ran.ended.expect_err("a skipped file ends the run non-zero")
        ),
        "2 item(s) could not be sent"
    );
    let sent = sent_names(&ran.out);
    assert_eq!(sent.len(), 1, "{}", ran.out);
    let mut named: Vec<&str> = skips(&ran.err).into_iter().map(|(name, _)| name).collect();
    assert_eq!(named.len(), 2, "{}", ran.err);
    named.extend(&sent);
    named.sort_unstable();
    assert_eq!(named, ["f0.txt", "f1.txt", "f2.txt"], "{}", ran.err);
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), 3);

    // By own bind, a stream that opened and then failed names its file too.
    let (dir, paths) = files("named-failed", 1);
    let cmd = send(&[paths[0].as_str(), "me/nas"]);
    let scripted_peer = ScriptedPeer::new(nas(), [Script::Ends]);
    let node = Node::new(scripted_peer, NoDiscovery);
    let peers = Peers::new(&node);
    let home = empty_home("named-failed");
    let ran = by_own_bind(&cmd, &peers, &home, node.node_id(), &peer).await;
    let _ = std::fs::remove_dir_all(dir);
    assert!(ran.ended.is_err(), "a failed transfer is a skip");
    let named: Vec<&str> = skips(&ran.err).into_iter().map(|(name, _)| name).collect();
    assert_eq!(named, ["f0.txt"], "{}", ran.err);
}

/// A file whose own name carries a carriage return, an ESC CSI sequence and a bidi override, and whose
/// stream is refused, names itself in its skip line with each escaped once: no raw byte reaches the
/// terminal, and no escape is escaped again.
#[tokio::test]
async fn a_hostile_file_name_prints_escaped_once_in_a_skip() {
    let dir = std::env::temp_dir().join(format!("swoosh-send-hostile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a\rb\u{1b}[2Kc\u{202e}.txt");
    std::fs::write(&path, b"a").unwrap();
    let at = HostilePeer::node_id().to_string();
    let cmd = send(&[path.to_str().unwrap(), &at]);
    let peer = cmd.peer.machine(&Contacts::default()).unwrap();
    let node = Node::new(HostilePeer::RefusesStreams("no"), NoDiscovery);
    let peers = Peers::new(&node);
    let home = empty_home("hostile-name");

    let ran = by_own_bind(&cmd, &peers, &home, node.node_id(), &peer).await;
    let _ = std::fs::remove_dir_all(dir);
    assert!(ran.ended.is_err(), "a refused stream is a skip");
    assert_eq!(
        ran.err,
        "skip a\\rb\\u{1b}[2Kc\\u{202e}.txt: stream refused: unavailable: no\n"
    );
}

/// An `anyone` link typed as the machine presents alone by own bind: it reads nothing of this home, so
/// a home whose revocations cannot be read, or whose root key is loose, still sends every file, and
/// every open presents the link with nothing beside it. Driven through the verb's own entry, so it is the
/// credential the run binds with that decides.
#[tokio::test]
async fn an_anyone_send_by_own_bind_presents_the_link_alone() {
    use std::os::unix::fs::PermissionsExt as _;

    let (dir, paths) = files("anyone", 2);
    let link = swoosh::testkit::TestNode::seeded(0x61)
        .slip(
            &"recv".parse().unwrap(),
            std::time::SystemTime::now() + core::time::Duration::from_secs(3600),
        )
        .unwrap()
        .link()
        .unwrap();
    let typed_link = format!("{}{}", swoosh::link::PREFIX, link.as_str());
    let contacts = Contacts::default();
    let bound = swoosh::transport::Bound {
        local: false,
        reach: swoosh::transport::Reach::default(),
    };
    let unreadable = [
        (
            "revoked",
            (|home: &Home| std::fs::create_dir_all(home.revoked()).unwrap()) as fn(&Home),
        ),
        ("loose", |home: &Home| {
            std::fs::write(home.root_key(), b"not a key").unwrap();
            std::fs::set_permissions(home.root_key(), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }),
    ];
    for (tag, spoil) in unreadable {
        let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
        argv.push(&typed_link);
        let cmd = send(&argv);
        let peer = cmd.peer.machine(&contacts).unwrap();
        let scripted_peer =
            ScriptedPeer::new(nas(), [Script::Says(vec![1]), Script::Says(vec![1])]);
        let node = Node::new(scripted_peer.clone(), NoDiscovery);
        let peers = Peers::new(&node);
        let home = empty_home(&format!("anyone-{tag}"));
        spoil(&home);
        let ctx = swoosh::reaching::ReachCtx {
            contacts: &contacts,
            machine: Some(&peer),
            bound: &bound,
            present: None,
            membership: None,
            home: &home,
            admitted: Admitted::unheard(),
        };
        let ended = swoosh::reaching::Reaching::run(cmd, &node, ctx, &peers).await;
        assert!(ended.is_ok(), "{tag}: {ended:?}");
        let slots: Vec<_> = scripted_peer
            .requests()
            .into_iter()
            .map(|request| (request.capability, request.membership))
            .collect();
        assert_eq!(
            slots,
            [
                (Some(link.as_str().to_owned()), None),
                (Some(link.as_str().to_owned()), None)
            ],
            "{tag}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// A stream that fails alone skips its file and the run goes on: `serve` busy for one file of three
/// prints one `skip` naming that file with the busy line, sends the other two, and ends counting one.
#[tokio::test]
async fn send_skips_a_file_whose_open_fails_alone() {
    let (dir, paths) = files("skip", 3);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let mut served = Served::new("send-skip").await;
    let rig = Rig::default();
    let resident = scripted(
        &mut served,
        vec![ack(), Answer::Refuse(OpenRefusal::Busy), ack()],
        &rig,
    );
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(
        format!(
            "{:#}",
            ran.ended.expect_err("a skipped file ends the run non-zero")
        ),
        "1 item(s) could not be sent"
    );
    let sent = sent_names(&ran.out);
    assert_eq!(sent.len(), 2, "{}", ran.out);
    let skipped = ["f0.txt", "f1.txt", "f2.txt"]
        .into_iter()
        .find(|name| !sent.contains(name))
        .unwrap();
    assert_eq!(
        ran.err,
        format!(
            "skip {skipped}: too many connections open through swoosh serve on this machine\n  Close \
             one, or wait for one to end, then try again.\n"
        )
    );
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file_opens(&heard).len(), 3);
}

/// The root question waits for the first admitted file and is asked once, on Main, presenting nothing,
/// on both paths: never when no file is admitted, and once however many are.
#[tokio::test]
async fn the_lookup_asks_after_the_first_admitted_file() {
    let (dir, paths) = files("lookup", 2);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("bob/nas");
    let cmd = send(&argv);
    let mut contacts = Contacts::default();
    contacts.save(&"bob/nas".parse().unwrap(), nas()).unwrap();
    let peer = typed(&contacts, "bob/nas");
    let bound = swoosh::transport::Bound {
        local: false,
        reach: swoosh::transport::Reach::default(),
    };

    // By own bind: the files are refused, so nothing is asked; admitted, the question rides a Main
    // session of its own beside the files' Bulk one.
    for (admits, lookups, dials) in [(false, 0, 1), (true, 1, 2)] {
        let script = if admits {
            // Any of the three may be the question's: it reads no answer it knows and asks nothing more.
            vec![Script::Says(vec![1]); 3]
        } else {
            vec![]
        };
        let scripted_peer = ScriptedPeer::new(nas(), script);
        let node = Node::new(scripted_peer.clone(), NoDiscovery);
        let peers = Peers::new(&node);
        let home = empty_home("lookup");
        let route = Route::Own {
            peer: &cmd.peer,
            bound: &bound,
            this: node.node_id(),
        };
        let ask = Ask {
            peer: nas(),
            hints: Hints::NONE,
            service: cmd.service.clone(),
            lane: SEND_LANE,
            slip: None,
        };
        let (admitted, lookup) = crate::lookup(swoosh::learn::Asked::of(&peer));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let sent = Cell::new(false);
        let (ended, _shown) = tokio::join!(
            cmd.run_send(
                OwnBind::new(&peers, &home, node.node_id(), &cmd.credential()),
                &route,
                &peer,
                ask,
                admitted,
                &sent,
                &mut out,
                &mut err,
            ),
            lookup
        );
        assert_eq!(ended.is_ok(), admits);
        let requests = scripted_peer.requests();
        let asked: Vec<_> = requests
            .iter()
            .filter(|request| request.service == "lookup.root")
            .collect();
        assert_eq!(asked.len(), lookups, "admitted: {admits}");
        assert!(asked.iter().all(|request| request.capability.is_none()));
        assert_eq!(scripted_peer.dials(), dials, "admitted: {admits}");
    }

    // Through `serve`: the files present the link typed as the machine, the question nothing.
    for (answers, lookups) in [
        (
            vec![Answer::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted))],
            0,
        ),
        (vec![ack(), ack(), Answer::Exchange(Vec::new())], 1),
    ] {
        let mut served = Served::new(&format!("send-lookup-{lookups}")).await;
        let rig = Rig::default();
        let resident = scripted(&mut served, answers, &rig);
        let (socket, _) = through_serve::serve(&served.home).await.unwrap().unwrap();
        let socket = Rc::new(socket);
        let dial = Dial {
            machine: &peer,
            service: &cmd.service,
            contacts: &contacts,
        };
        let ask = swoosh::streams::Ask {
            peer: peer.key(),
            hints: swoosh::peers::Hints::NONE,
            service: cmd.service.clone(),
            lane: SEND_LANE,
            slip: Some(nas_slip()),
        };
        let resident_source = Resident::new(Rc::clone(&socket));
        let route = Route::Serve {
            dial: &dial,
            socket: &socket,
        };
        let (admitted, lookup) = crate::lookup(swoosh::learn::Asked::of(&peer));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let sent = Cell::new(false);
        let _ = tokio::time::timeout(ROW_BOUND, async {
            tokio::join!(
                cmd.run_send(
                    &resident_source,
                    &route,
                    &peer,
                    ask,
                    admitted,
                    &sent,
                    &mut out,
                    &mut err
                ),
                lookup
            )
        })
        .await
        .expect("the run ended");
        rig.stop.cancel();
        let heard = tokio::time::timeout(ROW_BOUND, resident)
            .await
            .unwrap()
            .unwrap();
        let asked: Vec<_> = heard
            .iter()
            .filter(|open| open.service == "lookup.root")
            .collect();
        assert_eq!(asked.len(), lookups);
        for open in asked {
            assert_eq!((open.lane, open.slip.as_deref()), (OpenLane::Main, None));
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// One of your devices refusing the file is asked why through the same source, on Main: by own bind the
/// question rides a Main session the run already holds, presenting what the file did, so it makes no
/// connection of its own; through `serve` it is one Open for `control.services` on Main.
#[tokio::test]
async fn send_follow_up_rides_the_source_on_main() {
    let (dir, paths) = files("follow", 1);
    let cmd = send(&[paths[0].as_str(), "me/nas"]);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let recv = "recv".parse().unwrap();

    let scripted_peer = ScriptedPeer::new(
        nas(),
        [
            Script::Holds,
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Script::Lists(vec!["recv"]),
        ],
    );
    let node = Node::new(scripted_peer.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let (home, badge) = device_home("follow", node.node_id());
    let held = OwnBind::new(&peers, &home, node.node_id(), &FAMILY)
        .open(&Ask {
            peer: nas(),
            hints: Hints::NONE,
            service: "ping".parse().unwrap(),
            lane: OpenLane::Main,
            slip: None,
        })
        .await
        .expect("the Main stream opened");
    let ran = by_own_bind(&cmd, &peers, &home, node.node_id(), &peer).await;
    drop(held);
    let report = ran.ended.expect_err("a refused send exits non-zero");
    assert_eq!(
        format!("{report:#}"),
        format!(
            "{:#}",
            machine::refused(&peer, &recv, Some(Diagnosis::Listed))
        )
    );
    let requests = scripted_peer.requests();
    let services: Vec<&str> = requests
        .iter()
        .map(|request| request.service.as_str())
        .collect();
    assert_eq!(services, ["ping", "recv", "control.services"]);
    assert_eq!(
        requests[1].capability.as_deref(),
        Some(badge.as_str()),
        "the file presents this home's badge"
    );
    assert_eq!(
        (&requests[2].capability, &requests[2].membership),
        (&requests[1].capability, &requests[1].membership),
        "the follow-up presents what the file did"
    );
    assert_eq!(
        scripted_peer.dials(),
        2,
        "the held Main session carried the follow-up"
    );

    let mut served = Served::new("send-follow").await;
    let rig = Rig::default();
    let resident = scripted(
        &mut served,
        vec![
            Answer::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
            Answer::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
        ],
        &rig,
    );
    let ran = through(&cmd, &served.home, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(
        format!(
            "{:#}",
            ran.ended.expect_err("a refused send exits non-zero")
        ),
        format!(
            "{:#}",
            machine::refused(&peer, &recv, Some(Diagnosis::NotYours))
        )
    );
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .unwrap()
        .unwrap();
    let asked: Vec<_> = heard
        .iter()
        .map(|open| (open.service.as_str(), open.lane))
        .collect();
    assert_eq!(
        asked,
        [
            ("recv", OpenLane::Bulk),
            ("control.services", OpenLane::Main)
        ]
    );
}

/// The operator's exact hostile name for the skip shape (`missing\nname\u{1b}[31m.txt`): a path that
/// cannot be stat'ed is skipped, and the WHOLE line, error chain included, must render escaped. The
/// skip line names the path, escaped, so the `stat` context names none and carries none of its bytes.
#[tokio::test]
async fn a_hostile_missing_path_renders_escaped_in_the_skip_error() {
    let path = std::env::temp_dir().join("missing\nname\u{1b}[31m.txt");
    let error = collect_files(&path)
        .await
        .expect_err("a path that does not exist is a skip");

    let message = format!("{error:#}");
    assert!(
        message.starts_with("stat: ") && !message.contains("missing"),
        "the stat context names no path: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC rides the error chain onto the skip line: {message:?}"
    );
}

/// The other skip shape the directory walk builds: an unreadable directory is wrapped as
/// `read <path>`, and that context renders escaped too.
#[cfg(unix)]
#[tokio::test]
async fn a_hostile_unreadable_directory_renders_escaped_in_the_read_error() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!(
        "swoosh-send-{}-no-read\nname\u{1b}[31m.txt",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("the hostile directory is created");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000))
        .expect("the directory is closed");
    let result = collect_files(&dir).await;
    // Reopen and remove first, so the asserts (and a failed one) leave no unreadable tree behind.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is reopened");
    let _ = std::fs::remove_dir_all(&dir);

    // Root ignores mode 000, so the walk succeeds and this environment cannot exercise the shape.
    let Err(error) = result else {
        return;
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("read ") && message.contains(r"no-read\nname\u{1b}[31m.txt"),
        "the read context renders the path escaped: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC rides the error chain onto the skip line: {message:?}"
    );
}

/// A path with no final component is a hard error rather than a silent misname, and its one
/// path-bearing message renders escaped like every other.
#[test]
fn a_hostile_path_with_no_file_name_renders_escaped() {
    let error = file_name(Path::new("evil\nname\u{1b}[31m/.."))
        .expect_err("a path with no final component has no file name");

    let message = format!("{error:#}");
    assert!(
        message.contains(r"path has no file name: evil\nname\u{1b}[31m/.."),
        "the no-file-name error renders the path escaped: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC reaches the skip line: {message:?}"
    );
}

/// A receiver that refuses the stream sends its own detail, and the skip line prints it: a carriage
/// return, an ESC CSI sequence and a bidi override there print as escapes, so the refusal cannot erase
/// the skip line and draw a `sent` line in its place. Driven by own bind over a peer that refuses every
/// stream, so it is the stream's own error path this pins, not the renderer alone.
#[tokio::test]
async fn a_hostile_refusal_prints_escaped() {
    let path = std::env::temp_dir().join(format!("swoosh-send-{}-refused.txt", std::process::id()));
    std::fs::write(&path, b"a").expect("write the file to send");
    let at = HostilePeer::node_id().to_string();
    let cmd = send(&[path.to_str().unwrap(), &at]);
    let peer = cmd.peer.machine(&Contacts::default()).unwrap();
    let node = Node::new(
        HostilePeer::RefusesStreams("no\r\u{1b}[2Ksent a.txt (1 bytes)\u{202e}"),
        NoDiscovery,
    );
    let peers = Peers::new(&node);
    let home = empty_home("refused");

    let ran = by_own_bind(&cmd, &peers, &home, node.node_id(), &peer).await;
    let _ = std::fs::remove_file(&path);
    assert!(ran.ended.is_err(), "a refused stream is a skip");
    assert_eq!(
        ran.err,
        format!(
            "skip swoosh-send-{}-refused.txt: stream refused: unavailable: \
             no\\r\\u{{1b}}[2Ksent a.txt (1 bytes)\\u{{202e}}\n",
            std::process::id()
        )
    );
}

/// A peer that closes the dial gives a reason, and the run ends with the connect chain that carries it:
/// a carriage return, an ESC CSI sequence and a bidi override there print as escapes, so the reason
/// cannot erase the error and draw a `sent` line in its place. Driven by own bind over a transport whose
/// dial fails with that reason, so it is `send`'s own dial this pins.
#[tokio::test]
async fn a_hostile_connect_failure_prints_escaped() {
    let at = HostilePeer::node_id().to_string();
    let cmd = send(&["/etc/hosts", &at]);
    let peer = cmd.peer.machine(&Contacts::default()).unwrap();
    let node = Node::new(
        HostilePeer::Unreachable("closed by peer: no\r\u{1b}[2Ksent hosts (1 bytes)\u{202e}"),
        NoDiscovery,
    );
    let peers = Peers::new(&node);
    let home = empty_home("connect-failure");

    let ran = by_own_bind(&cmd, &peers, &home, node.node_id(), &peer).await;
    let error = format!(
        "{:#}",
        ran.ended.expect_err("an unreached machine ends the run")
    );
    assert!(
        error.starts_with(&format!(
            "could not reach {}: connect to peer: closed by peer: \
             no\\r\\u{{1b}}[2Ksent hosts (1 bytes)\\u{{202e}}",
            cmd.peer
        )),
        "{error}"
    );
    assert!(
        !error.contains('\r') && !error.contains('\u{1b}'),
        "{error:?}"
    );
    assert_eq!(ran.err, "", "no skip line");
}

/// A send one of your devices refuses ends with the one dial refusal, after asking the device why: never a
/// `skip` for the file and an item count.
#[tokio::test]
async fn a_refused_send_to_your_device_ends_with_one_refusal() {
    let (dir, paths) = files("refused-device", 1);
    let cmd = send(&[paths[0].as_str(), "me/nas"]);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let scripted_peer = ScriptedPeer::new(
        nas(),
        [
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Script::Lists(vec!["ping"]),
        ],
    );
    let node = Node::new(scripted_peer.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let home = empty_home("refused-device");

    let ran = by_own_bind(&cmd, &peers, &home, node.node_id(), &peer).await;
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(
        format!(
            "{:#}",
            ran.ended.expect_err("a refused send exits non-zero")
        ),
        "me/nas does not serve recv\n  Only nas can add it; on nas, run:\n    swoosh service add recv:<dir>"
    );
    assert!(!ran.err.contains("skip "), "{}", ran.err);
    let asked: Vec<String> = scripted_peer
        .requests()
        .into_iter()
        .map(|request| request.service)
        .collect();
    assert_eq!(asked, ["recv", "control.services"]);
}

/// A `serve` that takes an Open and then answers nothing, a status included, has stalled: every file would
/// stall on it. The first file to confirm it ends the run with the stall's two lines, once and with no
/// `skip` before them. What follows the stall, and what was sent before it, are pinned by
/// `a_stalled_serve_ends_a_send_of_many_files_once`.
#[tokio::test]
async fn a_stalled_serve_ends_a_send_once() {
    tokio::time::pause();
    let (dir, paths) = files("wedged", 3);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let mut served = Served::new("send-wedged").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![Answer::Wedge], &rig);
    let socket = Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
    let source = swoosh::streams::Tracked::new(
        Resident::new(Rc::clone(&socket)),
        std::collections::HashMap::new(),
    );
    let dial = Dial {
        machine: &peer,
        service: &cmd.service,
        contacts: &contacts,
    };
    let route = Route::Serve {
        dial: &dial,
        socket: &socket,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let ended = tokio::time::timeout(
        core::time::Duration::from_secs(600),
        cmd.through(
            &source,
            &route,
            &peer,
            Admitted::unheard(),
            &Cell::new(false),
            &mut out,
            &mut err,
        ),
    )
    .await
    .expect("the run ended");
    rig.stop.cancel();
    let _ = std::fs::remove_dir_all(dir);
    let report = ended.expect_err("a stalled serve ends the run non-zero");
    assert!(report.is::<through_serve::Unresponsive>(), "{report:#}");
    assert_eq!(String::from_utf8(err).unwrap(), "", "no skip line");
    assert!(sent_names(&String::from_utf8(out).unwrap()).is_empty());
    let heard = resident.await.unwrap();
    assert_eq!(file_opens(&heard).len(), 1, "no Open after the stall");
}

/// A live `serve` that refuses a connect while it holds its lock skips each file with the cut's line,
/// never that `serve` is not running.
#[tokio::test]
async fn a_refused_connect_under_a_held_lock_is_a_cut_for_send() {
    let mut served = Served::new("send-refused-held").await;
    drop(served.listener());
    let (dir, paths) = files("refused-held", 1);
    let cmd = send(&[paths[0].as_str(), "me/nas"]);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let socket = Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
    let ran = through_socket(&cmd, socket, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    assert!(ran.ended.is_err());
    let skipped = skips(&ran.err);
    assert_eq!(skipped.len(), 1, "{}", ran.err);
    assert_eq!(skipped[0].1, "connection lost");
}

/// A control socket that stops passing the trust check, here a `serve.lock` that names another process,
/// fails it again at every later connect: the run ends on the first file's open with that one line,
/// never a `skip` per file.
#[tokio::test]
async fn an_untrusted_socket_ends_a_send_once() {
    let mut served = Served::new("send-untrusted").await;
    let _listener = served.listener();
    let socket = Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
    // The resolve's path checks passed; the connect's own check reads the pid `serve.lock` records.
    std::fs::write(served.home.serve_lock(), "1\n").unwrap();
    let (dir, paths) = files("untrusted", 3);
    let mut argv: Vec<&str> = paths.iter().map(String::as_str).collect();
    argv.push("me/nas");
    let cmd = send(&argv);
    let contacts = book();
    let peer = typed(&contacts, "me/nas");
    let ran = through_socket(&cmd, socket, &peer, None, &contacts).await;
    let _ = std::fs::remove_dir_all(dir);
    let report = format!("{:#}", ran.ended.expect_err("the run ended non-zero"));
    assert!(
        report.starts_with("refusing to trust the control path "),
        "{report}"
    );
    assert!(!report.contains("could not be sent"), "{report}");
    assert_eq!(ran.err, "", "no skip line");
    assert_eq!(
        ran.out,
        format!("sending to {}...\n", peer.key()),
        "nothing sent"
    );
}
