// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The dialing verbs through a running `serve`, as the composition root's dialing route runs them: the
//! stale-list exchange beside the verb's stream and the root question after it are each one Open there,
//! and neither prints a line of its own.

use core::time::Duration;
use std::time::SystemTime;

use clap::Parser as _;
use swoosh::contacts::ContactsStore;
use swoosh::home::Home;
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::testkit::{TestNode, TestRoot};

use crate::commands::invite::invite_tests::{NAS, node};
use crate::commands::through_serve::tests::{
    Answer, Event, Heard, ROW_BOUND, Reply, Rig, Served, on_a_big_stack, routed, scripted,
};
use crate::{Cli, Verb};

/// The machine saved as `bob/nas`.
const BOB_NAS: u8 = 0x71;
/// The root bob's machine shows.
const BOB_ROOT: u8 = 0x72;
/// The root saved here as bob's, which the one his machine shows is not.
const SAVED_ROOT: u8 = 0x73;

/// The `--peer` address typed for `me/nas` in every run here.
const NAS_HINT: &str = "127.0.0.1:4000";

/// What a run printed and how it ended: its error as the composition root prints it, and what a
/// bridge's stream wrote to its stdout.
#[derive(Debug, PartialEq, Eq)]
struct Printed {
    ok: bool,
    error: Option<String>,
    out: String,
    err: String,
    down: String,
}

/// What a bridge in these rows reads from stdin: these bytes, then its end.
const UP: &[u8] = b"up";

/// Run `argv` from `home` through its `serve` as the dialing route runs it.
async fn dialed(home: &Home, argv: &[&str]) -> Printed {
    let mut err = Vec::new();
    let mut printed = dialed_to(home, argv, ROW_BOUND, &mut err).await;
    printed.err = String::from_utf8(err).unwrap();
    printed
}

/// [`dialed`], within `bound`, its stderr to `err`.
async fn dialed_to(
    home: &Home,
    argv: &[&str],
    bound: Duration,
    err: &mut impl crate::screen::Paint,
) -> Printed {
    let mut out = Vec::new();
    let mut printed = dialed_out(home, argv, bound, &mut out, err).await;
    printed.out = String::from_utf8(out).unwrap();
    printed
}

/// [`dialed_to`], its stdout to `out`, which a row can read as the run goes.
async fn dialed_out(
    home: &Home,
    argv: &[&str],
    bound: Duration,
    out: &mut impl std::io::Write,
    err: &mut impl crate::screen::Paint,
) -> Printed {
    let outward = match Cli::try_parse_from(core::iter::once("swoosh").chain(argv.iter().copied()))
        .unwrap()
        .command
        .unwrap()
        .split()
    {
        Verb::Outward(outward) => outward,
        // `stop` resolves its machine against the list of your devices first, as the composition root
        // does, and only another of your devices goes on.
        Verb::Stop(cmd) => crate::Outward::Stop(cmd.run_local(home, None).await.unwrap().unwrap()),
        _ => panic!("{argv:?} is a reaching verb"),
    };
    let contacts = ContactsStore::open(home).await.unwrap().contacts().clone();
    let machine = swoosh::reaching::Reaching::dialed(&outward)
        .unwrap()
        .machine(&contacts)
        .unwrap();
    let hints =
        crate::commands::through_serve::hints(swoosh::reaching::Reaching::reach_args(&outward))
            .unwrap();
    // The decision's one probe, as the composition root makes it.
    let (socket, this) = crate::commands::through_serve::tests::answering_as(home).await;
    let mut down = Vec::new();
    let (stdin, input) = tokio::sync::mpsc::channel(1);
    stdin.try_send(Ok(UP.to_vec())).unwrap();
    drop(stdin);
    let stdio = || {
        let input = crate::commands::connect::Stdin {
            chunks: input,
            kind: crate::commands::connect::StdinKind::Piped,
        };
        Ok((input, &mut down))
    };
    let beside = crate::Beside::of(&outward, home, Some(&machine));
    let ended = tokio::time::timeout(
        bound,
        crate::dial_through_serve(
            crate::decision::tests::dialing(outward),
            beside,
            crate::ThroughServe {
                machine: &machine,
                slip: None,
                socket,
                this,
                hints,
                contacts: &contacts,
            },
            crate::commands::learning::Asking::NoTerminal,
            stdio,
            out,
            err,
        ),
    )
    .await
    .expect("the run ended");
    Printed {
        ok: ended.is_ok(),
        error: ended.err().map(|report| format!("{report:#}")),
        out: String::new(),
        err: String::new(),
        down: String::from_utf8(down).unwrap(),
    }
}

/// Every Open the resident heard, in order.
fn opens(events: &[Event]) -> Vec<&Heard> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Open(heard) => Some(heard),
            Event::Status => None,
        })
        .collect()
}

/// How many status asks the resident heard.
fn statuses(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, Event::Status))
        .count()
}

/// A file to send, in a directory of its own for `tag`.
fn a_file(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("swoosh-dialroute-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("note.txt");
    std::fs::write(&file, b"hello").unwrap();
    file.to_str().unwrap().to_owned()
}

/// A `serve`d home that is one of your devices, beside `me/nas`, its last exchange stale or just now.
async fn a_device(tag: &str, stale: bool) -> Served {
    let served = Served::new(tag).await;
    crate::exchange_tests::a_device(&served.home, false).await;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let then = if stale { now - 2 * 3600 } else { now };
    std::fs::write(served.home.synced(), format!("{then}\n")).unwrap();
    served
}

/// A `serve`d home that is no device, holding `bob/nas` with another root saved as bob's.
async fn bobs_contact(tag: &str) -> Served {
    let served = Served::new(tag).await;
    let mut store = ContactsStore::open(&served.home).await.unwrap();
    let contacts = store.contacts_mut();
    contacts.add(
        "bob".parse().unwrap(),
        Some("nas".parse().unwrap()),
        TestNode::seeded(BOB_NAS).node_id(),
    );
    contacts
        .learn(
            &"bob".parse().unwrap(),
            TestRoot::seeded(SAVED_ROOT).node_id(),
            "nas".parse().unwrap(),
        )
        .unwrap();
    store.save(&swoosh::testkit::lock()).unwrap();
    served
}

/// The root route's hit: bob's machine's standing under [`BOB_ROOT`].
fn bobs_standing() -> Vec<u8> {
    let standing = TestRoot::seeded(BOB_ROOT)
        .device_badge(
            TestNode::seeded(BOB_NAS).node_id(),
            SystemTime::now() + Duration::from_secs(3600),
        )
        .unwrap();
    let text = standing.as_str().as_bytes();
    let mut answer = vec![0x01];
    answer.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
    answer.extend_from_slice(text);
    answer
}

/// A refusal the verb prints its own line for, with no status ask after it.
fn unavailable() -> Reply {
    Reply::Refuse(OpenRefusal::Peer(PeerRefusal::Unavailable(
        bifrost::RefusalDetail::bounded("off"),
    )))
}

/// The four dialing verbs, to `machine`, with `extra` after each.
fn the_four(machine: &str, file: &str, extra: &[&str]) -> Vec<Vec<String>> {
    let verbs: [&[&str]; 4] = [
        &["ping", machine, "-c", "1"],
        &["speed", machine, "-n", "1024"],
        &["status", machine],
        &["send", file, machine],
    ];
    verbs
        .iter()
        .map(|verb| {
            verb.iter()
                .chain(extra)
                .map(|word| (*word).to_owned())
                .collect()
        })
        .collect()
}

fn words(argv: &[String]) -> Vec<&str> {
    argv.iter().map(String::as_str).collect()
}

/// With `serve` answering and a stale list, each dialing verb makes the beside-exchange with its device
/// as one Open on Main, with no slip and the `--peer` addresses typed for it, and prints as it does with
/// a fresh list, which makes none.
#[test]
fn dialing_verbs_through_serve_make_the_stale_exchange() {
    on_a_big_stack(async || {
        let hint = format!("{}={NAS_HINT}", node(NAS));
        let file = a_file("exchange");
        for argv in the_four("me/nas", &file, &["--peer", &hint]) {
            let mut printed = Vec::new();
            for stale in [true, false] {
                let mut served = a_device(&format!("exch-{}-{stale}", argv[0]), stale).await;
                let rig = Rig::default();
                let resident = routed(
                    &mut served,
                    |service| match service {
                        "control.sync" => Reply::Refuse(OpenRefusal::Busy),
                        _ => unavailable(),
                    },
                    &rig,
                );
                printed.push(dialed(&served.home, &words(&argv)).await);
                rig.stop.cancel();
                let events = resident.await.unwrap();
                let syncs: Vec<&Heard> = opens(&events)
                    .into_iter()
                    .filter(|open| open.service == "control.sync")
                    .collect();
                if !stale {
                    assert!(syncs.is_empty(), "{argv:?}: no exchange on a fresh list");
                    continue;
                }
                let [sync] = syncs.as_slice() else {
                    panic!("{argv:?}: {} exchanges, not one", syncs.len());
                };
                assert_eq!(sync.peer, node(NAS), "{argv:?}");
                assert_eq!(sync.lane, OpenLane::Main, "{argv:?}");
                assert_eq!(sync.slip, None, "{argv:?}");
                assert_eq!(sync.hints, vec![NAS_HINT.parse().unwrap()], "{argv:?}");
                // The verb's own Opens carry them too.
                let own: Vec<&Heard> = opens(&events)
                    .into_iter()
                    .filter(|open| open.service != "control.sync")
                    .collect();
                assert!(!own.is_empty(), "{argv:?}");
                for open in own {
                    assert_eq!(
                        open.hints,
                        vec![NAS_HINT.parse().unwrap()],
                        "{argv:?}: {}",
                        open.service
                    );
                }
            }
            assert_eq!(
                printed[0], printed[1],
                "{argv:?}: the exchange printed nothing"
            );
        }
    });
}

/// With `serve` answering and a stale list, `forward … -` makes the beside-exchange with its device as
/// one Open on Main beside the bridge's own, each carrying the `--peer` addresses typed for it, and its
/// stdout carries only the stream's bytes; with a fresh list it makes none, and the run is the same. So
/// do `forward <port>` and `proxy`, their Opens on Bulk.
#[test]
fn forward_and_proxy_through_serve_make_the_stale_exchange() {
    on_a_big_stack(async || {
        let hint = format!("{}={NAS_HINT}", node(NAS));
        let argv = ["forward", "me/nas", "ssh", "-", "--peer", &hint];
        let mut printed = Vec::new();
        for stale in [true, false] {
            let mut served = a_device(&format!("exch-forward-{stale}"), stale).await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                |service| match service {
                    "control.sync" => Reply::Refuse(OpenRefusal::Busy),
                    _ => Reply::Exchange(b"down".to_vec()),
                },
                &rig,
            );
            printed.push(dialed(&served.home, &argv).await);
            rig.stop.cancel();
            let events = resident.await.unwrap();
            let heard = opens(&events);
            assert_eq!(
                heard
                    .iter()
                    .filter(|open| open.service == "control.sync")
                    .count(),
                usize::from(stale),
                "{stale}: the exchange"
            );
            for open in heard {
                assert_eq!(open.lane, OpenLane::Main, "{stale}: {}", open.service);
                assert_eq!(
                    open.hints,
                    vec![NAS_HINT.parse().unwrap()],
                    "{stale}: {}",
                    open.service
                );
            }
        }
        let bridged = &printed[0];
        assert!(bridged.ok, "{bridged:?}");
        assert_eq!((bridged.down.as_str(), bridged.out.as_str()), ("down", ""));
        assert_eq!(printed[0], printed[1], "the exchange printed nothing");

        // `forward <port>`: its admission and pipes ride Bulk beside the exchange on Main, and a later
        // pipe refused ends the run, once the exchange was heard.
        let mut printed = Vec::new();
        for stale in [true, false] {
            let port = std::net::TcpListener::bind(("127.0.0.1", 0))
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let port_text = port.to_string();
            let argv = ["forward", "me/nas", "ssh", &port_text, "--peer", &hint];
            let mut served = a_device(&format!("exch-port-{stale}"), stale).await;
            let rig = Rig::default();
            let synced = std::sync::Arc::new(tokio::sync::Notify::new());
            let heard_sync = std::sync::Arc::clone(&synced);
            let mut admitted = false;
            let resident = routed(
                &mut served,
                move |service| match service {
                    "control.sync" => {
                        heard_sync.notify_one();
                        Reply::Refuse(OpenRefusal::Busy)
                    }
                    "ssh" if !admitted => {
                        admitted = true;
                        Reply::Exchange(Vec::new())
                    }
                    _ => Reply::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
                },
                &rig,
            );
            let pipe = async {
                if stale {
                    synced.notified().await;
                }
                // The port is bound once the admission is made.
                loop {
                    if let Ok(mut pipe) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await
                    {
                        use tokio::io::AsyncReadExt as _;
                        let _ = pipe.read_to_end(&mut Vec::new()).await;
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            let (ran, ()) = tokio::join!(dialed(&served.home, &argv), pipe);
            printed.push(ran);
            rig.stop.cancel();
            let events = resident.await.unwrap();
            let heard = opens(&events);
            assert_eq!(
                heard
                    .iter()
                    .filter(|open| open.service == "control.sync")
                    .count(),
                usize::from(stale),
                "{stale}: the exchange"
            );
            for open in heard {
                let lane = match open.service.as_str() {
                    "ssh" => OpenLane::Bulk,
                    _ => OpenLane::Main,
                };
                assert_eq!(open.lane, lane, "{stale}: {}", open.service);
                assert_eq!(
                    open.hints,
                    vec![NAS_HINT.parse().unwrap()],
                    "{stale}: {}",
                    open.service
                );
            }
        }
        let ported = &printed[0];
        assert_eq!(
            ported.error.as_deref(),
            Some("me/nas refused ssh\n  nas does not count this machine as one of your devices."),
            "{ported:?}"
        );
        assert_eq!(ported.out, "");
        assert_eq!(printed[0], printed[1], "the exchange printed nothing");

        // `proxy`: its admission and requests ride Bulk beside the exchange on Main, its stdout is the URL
        // alone, and a later request refused ends the run, once the exchange was heard.
        let argv = ["proxy", "me/nas", "http://example.com/x", "--peer", &hint];
        let mut printed = Vec::new();
        for stale in [true, false] {
            let mut served = a_device(&format!("exch-proxy-{stale}"), stale).await;
            let rig = Rig::default();
            let synced = std::sync::Arc::new(tokio::sync::Notify::new());
            let heard_sync = std::sync::Arc::clone(&synced);
            let mut admitted = false;
            let resident = routed(
                &mut served,
                move |service| match service {
                    "control.sync" => {
                        heard_sync.notify_one();
                        Reply::Refuse(OpenRefusal::Busy)
                    }
                    "proxy" if !admitted => {
                        admitted = true;
                        Reply::Exchange(Vec::new())
                    }
                    _ => Reply::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
                },
                &rig,
            );
            let url = Shared::default();
            let request = async {
                if stale {
                    synced.notified().await;
                }
                // The URL prints once the admission is made.
                let printed = loop {
                    if let Some(line) = url.line() {
                        break line;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                };
                let (addr, path) = printed
                    .strip_prefix("http://")
                    .and_then(|rest| rest.split_once('/'))
                    .unwrap();
                let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
                let head = format!("GET /{path} HTTP/1.1\r\nHost: {addr}\r\n\r\n");
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                client.write_all(head.as_bytes()).await.unwrap();
                let mut response = Vec::new();
                let _ = client.read_to_end(&mut response).await;
                String::from_utf8(response).unwrap()
            };
            let (mut out, mut err) = (url.clone(), Vec::new());
            let (ran, response) = tokio::join!(
                dialed_out(&served.home, &argv, ROW_BOUND, &mut out, &mut err),
                request
            );
            assert!(
                response.starts_with("HTTP/1.1 403 Forbidden"),
                "{stale}: {response}"
            );
            let out = url.text();
            assert!(
                out.starts_with("http://127.0.0.1:") && out.lines().count() == 1,
                "{stale}: {out}"
            );
            printed.push(ran);
            rig.stop.cancel();
            let events = resident.await.unwrap();
            let heard = opens(&events);
            assert_eq!(
                heard
                    .iter()
                    .filter(|open| open.service == "control.sync")
                    .count(),
                usize::from(stale),
                "{stale}: the exchange"
            );
            for open in heard {
                let lane = match open.service.as_str() {
                    "proxy" => OpenLane::Bulk,
                    _ => OpenLane::Main,
                };
                assert_eq!(open.lane, lane, "{stale}: {}", open.service);
                assert_eq!(
                    open.hints,
                    vec![NAS_HINT.parse().unwrap()],
                    "{stale}: {}",
                    open.service
                );
            }
        }
        let proxied = &printed[0];
        assert_eq!(
            proxied.error.as_deref(),
            Some("me/nas refused proxy\n  nas does not count this machine as one of your devices."),
            "{proxied:?}"
        );
        assert_eq!(printed[0], printed[1], "the exchange printed nothing");
    });
}

/// Through `serve`, a bridge whose stream ended clean, its upload landed, exits 0 with nothing on stderr
/// though the exchange beside it met `serve` gone: exit 0 says the far side holds every byte, and a
/// `serve` that went after a clean session is not that session's failure.
#[test]
fn a_clean_bridge_exits_0_when_serve_went_beside() {
    on_a_big_stack(async || {
        let mut served = a_device("beside-bridge", true).await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |service| match service {
                "control.sync" => Reply::VersionAfterHeld,
                _ => Reply::AfterVersion(Box::new(Reply::Exchange(b"down".to_vec()))),
            },
            &rig,
        );
        let printed = dialed(&served.home, &["forward", "me/nas", "ssh", "-"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        let ssh = opens(&events)
            .into_iter()
            .find(|open| open.service == "ssh");
        assert!(ssh.is_some_and(|open| {
            open.upload
                .ends_with(&crate::commands::through_serve::tests::END)
        }));
        assert!(printed.ok, "{printed:?}");
        assert_eq!((printed.err.as_str(), printed.down.as_str()), ("", "down"));
    });
}

/// To a contact's machine through `serve`, each dialing verb asks the root route once, on Main with no
/// slip, only once its own stream attached, and the root it showed is told after the run.
#[test]
fn probe_verbs_through_serve_ask_the_lookup() {
    on_a_big_stack(async || {
        let file = a_file("lookup");
        for argv in the_four("bob/nas", &file, &[]) {
            for attaches in [true, false] {
                let mut served = bobs_contact(&format!("lookup-{}-{attaches}", argv[0])).await;
                let rig = Rig::default();
                let resident = routed(
                    &mut served,
                    move |service| match service {
                        "lookup.root" => Reply::Exchange(bobs_standing()),
                        _ if !attaches => unavailable(),
                        "recv" => Reply::Exchange(vec![1]),
                        _ => Reply::Observed,
                    },
                    &rig,
                );
                let printed = dialed(&served.home, &words(&argv)).await;
                rig.stop.cancel();
                let events = resident.await.unwrap();
                let heard = opens(&events);
                let lookups: Vec<usize> = heard
                    .iter()
                    .enumerate()
                    .filter(|(_, open)| open.service == "lookup.root")
                    .map(|(at, _)| at)
                    .collect();
                let told = "warning: bob/nas is vouched for by a different root";
                if !attaches {
                    assert!(lookups.is_empty(), "{argv:?}: asked with nothing attached");
                    assert!(!printed.err.contains(told), "{argv:?}: {}", printed.err);
                    continue;
                }
                let [at] = lookups.as_slice() else {
                    panic!("{argv:?}: {} lookups, not one", lookups.len());
                };
                assert!(*at > 0, "{argv:?}: asked before the verb's own Open");
                assert_eq!(heard[*at].lane, OpenLane::Main, "{argv:?}");
                assert_eq!(heard[*at].slip, None, "{argv:?}");
                assert_eq!(heard[*at].peer, TestNode::seeded(BOB_NAS).node_id());
                assert_eq!(
                    printed.err.matches(told).count(),
                    1,
                    "{argv:?}: {}",
                    printed.err
                );
                let tail = printed.err.rfind(told).unwrap();
                assert!(
                    printed.err[tail..].ends_with(&format!(
                        "swoosh contact add bob {}\n",
                        swoosh::root_key::RootKey::from(TestRoot::seeded(BOB_ROOT).node_id())
                    )),
                    "{argv:?}: told last, after the run: {}",
                    printed.err
                );
            }
        }
    });
}

/// The line another version of `serve` ends a run with, once.
fn assert_skew_once(error: Option<String>) {
    let error = error.unwrap_or_default();
    assert!(
        error.starts_with("swoosh serve on this machine is a different version"),
        "{error}"
    );
    assert_eq!(error.matches("different version").count(), 1, "{error}");
}

/// Through `serve`, an Open beside the verb prints nothing and asks `serve` nothing: an exchange dropped
/// unanswered when the verb ends, a lookup that runs past its deadline, and either meeting another
/// version of `serve`. One that meets `serve` gone or of another version ends the run with that line
/// once, after the verb's own. The only status ask is the warning's, before the first Open.
#[test]
fn beside_opens_print_nothing_of_their_own() {
    on_a_big_stack(async || {
        // The exchange: dropped unanswered, or met by another version, beside a refused ping.
        let mut baseline = None;
        for exchange in ["none", "stall", "version"] {
            let mut served = a_device(&format!("beside-exch-{exchange}"), exchange != "none").await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                move |service| match (service, exchange) {
                    ("control.sync", "stall") => Reply::Stall,
                    ("control.sync", _) => Reply::Version,
                    _ => unavailable(),
                },
                &rig,
            );
            let printed = dialed(&served.home, &["ping", "me/nas", "-c", "1"]).await;
            rig.stop.cancel();
            let events = resident.await.unwrap();
            assert_eq!(statuses(&events), 1, "{exchange}: the probe alone");
            assert_eq!(
                opens(&events)
                    .iter()
                    .any(|open| open.service == "control.sync"),
                exchange != "none",
                "{exchange}: the exchange was made"
            );
            assert!(
                matches!(events[0], Event::Status),
                "{exchange}: asked first"
            );
            match &baseline {
                None => baseline = Some(printed),
                Some(baseline) => assert_eq!(&printed, baseline, "{exchange}"),
            }
        }

        // The exchange met by another version while a ping whose stream attached runs: the ping's lines are
        // its own, as with no exchange at all, and the version's line ends the run after them, once.
        let mut baseline: Option<Printed> = None;
        for exchange in ["none", "version"] {
            let mut served =
                a_device(&format!("beside-attached-{exchange}"), exchange != "none").await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                move |service| match (service, exchange) {
                    ("control.sync", _) => Reply::VersionAfterHeld,
                    (_, "none") => Reply::Observed,
                    _ => Reply::AfterVersion(Box::new(Reply::Observed)),
                },
                &rig,
            );
            let printed = dialed(&served.home, &["ping", "me/nas", "-c", "1"]).await;
            rig.stop.cancel();
            let events = resident.await.unwrap();
            assert!(
                opens(&events).iter().any(|open| open.service == "ping"),
                "{exchange}: the ping attached"
            );
            match &baseline {
                None => {
                    assert!(printed.ok, "{printed:?}");
                    baseline = Some(printed);
                }
                Some(baseline) => {
                    assert_eq!(
                        (&printed.out, &printed.err),
                        (&baseline.out, &baseline.err),
                        "{exchange}"
                    );
                    assert!(!printed.ok, "{printed:?}");
                    assert_skew_once(printed.error);
                }
            }
        }

        // The exchange cut before its reply: the cut is asked about once, as any cut is (`serve` may have
        // gone), so a second status ask follows the probe's; the ping's lines are still its own.
        let mut served = a_device("beside-hangup", true).await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |service| match service {
                "control.sync" => Reply::Hangup,
                _ => unavailable(),
            },
            &rig,
        );
        let printed = dialed(&served.home, &["ping", "me/nas", "-c", "1"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        assert_eq!(statuses(&events), 2, "the probe and the cut's ask");
        let mut fresh = a_device("beside-hangup-fresh", false).await;
        let rig = Rig::default();
        let resident = routed(&mut fresh, |_| unavailable(), &rig);
        let baseline = dialed(&fresh.home, &["ping", "me/nas", "-c", "1"]).await;
        rig.stop.cancel();
        resident.await.unwrap();
        assert_eq!(printed, baseline, "the cut exchange printed nothing");

        // `send` beside an exchange met by another version, its reply read after the one file's Open was
        // sent: the file is sent, then the record ends the run with that line, once.
        let file = a_file("beside-skew");
        let mut served = a_device("beside-skew", true).await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |service| match service {
                "control.sync" => Reply::VersionAfterHeld,
                _ => Reply::AfterVersion(Box::new(Reply::Exchange(vec![1]))),
            },
            &rig,
        );
        let printed = dialed(&served.home, &["send", &file, "me/nas"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        assert!(
            printed.out.ends_with("sent note.txt (5 bytes)\n"),
            "{printed:?}"
        );
        assert!(!printed.ok, "{printed:?}");
        assert_skew_once(printed.error);
        let mut heard: Vec<_> = opens(&events)
            .iter()
            .map(|open| open.service.clone())
            .collect();
        heard.sort();
        assert_eq!(heard, ["control.sync", "recv"], "no Open after the record");

        // And read before the last files' Opens: more files than `send` keeps in flight (16), so the last
        // is opened only once one is sent, which the resident holds until the record is made. That file
        // is never sent an Open; its record ends the run with the line, once.
        let dir = std::env::temp_dir().join(format!(
            "swoosh-dialroute-beside-skew-many-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let files = 17;
        for at in 0..files {
            std::fs::write(dir.join(format!("note-{at}.txt")), b"hello").unwrap();
        }
        let mut served = a_device("beside-skew-many", true).await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |service| match service {
                "control.sync" => Reply::VersionAfterHeld,
                _ => Reply::AfterVersion(Box::new(Reply::Exchange(vec![1]))),
            },
            &rig,
        );
        let printed = dialed(&served.home, &["send", dir.to_str().unwrap(), "me/nas"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        assert!(!printed.ok, "{printed:?}");
        assert_skew_once(printed.error);
        let sent = opens(&events)
            .iter()
            .filter(|open| open.service == "recv")
            .count();
        assert!(
            sent < files,
            "{sent} of {files}: no file's Open after the record"
        );

        // The lookup: past its deadline, or met by another version, after `send`'s file attached. The file
        // is sent either way; another version after an attach is a restarted `serve`, so the run's is
        // gone, and that line ends the run, once, after the file's.
        let file = a_file("beside-lookup");
        let mut baseline: Option<Printed> = None;
        for lookup in ["miss", "stall", "version"] {
            let mut served = bobs_contact(&format!("beside-lookup-{lookup}")).await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                move |service| match (service, lookup) {
                    ("lookup.root", "miss") => Reply::Exchange(vec![0x00]),
                    ("lookup.root", "stall") => Reply::Stall,
                    ("lookup.root", _) => Reply::Version,
                    _ => Reply::Exchange(vec![1]),
                },
                &rig,
            );
            let printed = dialed(&served.home, &["send", &file, "bob/nas"]).await;
            rig.stop.cancel();
            let events = resident.await.unwrap();
            assert_eq!(printed.ok, lookup != "version", "{lookup}: {printed:?}");
            assert_eq!(statuses(&events), 1, "{lookup}: the probe alone");
            assert!(
                opens(&events)
                    .iter()
                    .any(|open| open.service == "lookup.root"),
                "{lookup}: the lookup was asked"
            );
            match &baseline {
                None => baseline = Some(printed),
                Some(baseline) if lookup == "version" => {
                    assert_eq!(
                        (&printed.out, &printed.err),
                        (&baseline.out, &baseline.err),
                        "{lookup}"
                    );
                    let error = printed.error.unwrap_or_default();
                    assert!(
                        error.starts_with("swoosh serve stopped here and ended the connection"),
                        "{error}"
                    );
                    assert_eq!(error.matches("serve stopped").count(), 1, "{error}");
                }
                Some(baseline) => assert_eq!(&printed, baseline, "{lookup}"),
            }
        }
    });
}

/// Through `serve`, a `send` whose every file printed `sent`, then whose lookup beside it met another
/// version (a restarted `serve`, so the run's is gone), ends saying every file was sent and advises no
/// rerun, which would send them all again. It still exits non-zero.
#[test]
fn a_serve_gone_beside_a_whole_send_ends_without_resending() {
    on_a_big_stack(async || {
        let file = a_file("whole-send");
        let mut served = bobs_contact("whole-send").await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |service| match service {
                "lookup.root" => Reply::Version,
                _ => Reply::Exchange(vec![1]),
            },
            &rig,
        );
        let printed = dialed(&served.home, &["send", &file, "bob/nas"]).await;
        rig.stop.cancel();
        resident.await.unwrap();
        assert!(
            printed.out.ends_with("sent note.txt (5 bytes)\n"),
            "{printed:?}"
        );
        assert!(!printed.ok, "{printed:?}");
        assert_eq!(
            printed.error.as_deref(),
            Some(
                "swoosh serve stopped here and ended the connection to bob/nas\n  Commands here \
                 connect through it while it runs.\n  Every file was marked `sent`."
            )
        );
    });
}

/// A stderr the resident can read as it hears an Open, or a stdout a row reads as the run goes.
#[derive(Clone, Default)]
struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

/// A test writer, so plain: it never shows style.
impl crate::screen::Paint for Shared {}

impl std::io::Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    /// The first whole line written, if one has been.
    fn line(&self) -> Option<String> {
        self.text()
            .split_once('\n')
            .map(|(line, _)| line.to_owned())
    }
}

/// Through `serve`, a badge inside the warning window warns once, written before the first Open reaches
/// `serve`, when `serve` runs as this machine's key. A `serve` that says it runs as another key reads no
/// standing of its own here, so nothing warns: the key is `serve`'s, never read from this machine's files.
#[test]
fn the_warning_prints_before_the_first_open() {
    use crate::commands::invite::invite_tests::{OWN, ROOT};

    on_a_big_stack(async || {
        let warning = "warning: this device's standing expires in";
        let file = a_file("warn-order");
        for argv in the_four("me/nas", &file, &[]) {
            for (key, warns) in [(node(OWN), true), (node(NAS), false)] {
                let mut served = a_device(&format!("warn-{}-{warns}", argv[0]), false).await;
                let until = SystemTime::now() + Duration::from_secs(3 * 24 * 3600);
                let badge = TestRoot::seeded(ROOT)
                    .device_badge(node(OWN), until)
                    .unwrap();
                swoosh::config::write_badge(&swoosh::testkit::lock(), &served.home, &badge)
                    .unwrap();
                let err = Shared::default();
                let first = std::sync::Arc::new(std::sync::Mutex::new(None));
                let rig = Rig {
                    key: Some(key),
                    heard: Some({
                        let (err, first) = (err.clone(), std::sync::Arc::clone(&first));
                        std::sync::Arc::new(move || {
                            first
                                .lock()
                                .unwrap()
                                .get_or_insert_with(|| err.text().contains(warning));
                        })
                    }),
                    ..Rig::default()
                };
                let resident = routed(&mut served, |_| unavailable(), &rig);
                let _ = dialed_to(&served.home, &words(&argv), ROW_BOUND, &mut err.clone()).await;
                rig.stop.cancel();
                resident.await.unwrap();
                let printed = err.text();
                assert_eq!(
                    printed.matches(warning).count(),
                    usize::from(warns),
                    "{argv:?} {warns}: {printed}"
                );
                assert_eq!(
                    *first.lock().unwrap(),
                    Some(warns),
                    "{argv:?} {warns}: written before the first Open: {printed}"
                );
            }
        }
    });
}

/// More files than run at once, to a `serve` that takes every Open and answers nothing more, a status
/// included: the run ends on the first stall it confirms, with the stall's line once and no `skip`, and no
/// file's Open follows the asks that confirmed it. A file sent before the stall stays sent. The run is
/// bounded by the Open's own wait and the bounded asks.
#[test]
fn a_stalled_serve_ends_a_send_of_many_files_once() {
    on_a_big_stack(async || {
        tokio::time::pause();
        let dir =
            std::env::temp_dir().join(format!("swoosh-dialroute-many-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for at in 0..=crate::commands::send::MAX_INFLIGHT {
            std::fs::write(dir.join(format!("f{at:02}")), b"hello").unwrap();
        }
        for sends_first in [false, true] {
            let mut served = bobs_contact(&format!("many-{sends_first}")).await;
            // Wedged by the first Open, unless a file is sent first.
            let rig = Rig::default();
            let mut acked = !sends_first;
            let resident = routed(
                &mut served,
                move |service| match service {
                    "recv" if !acked => {
                        acked = true;
                        Reply::Exchange(vec![1])
                    }
                    _ => Reply::Wedge,
                },
                &rig,
            );
            let started = tokio::time::Instant::now();
            let printed = dialed_to(
                &served.home,
                &["send", dir.to_str().unwrap(), "bob/nas"],
                Duration::from_secs(600),
                &mut Vec::new(),
            )
            .await;
            let took = started.elapsed();
            rig.stop.cancel();
            let events = resident.await.unwrap();
            assert!(!printed.ok, "{sends_first}");
            let error = printed.error.unwrap();
            assert!(
                error.starts_with("swoosh serve did not answer here\n  Restart it."),
                "{error}"
            );
            assert_eq!(error.matches("did not answer").count(), 1, "{error}");
            assert_eq!(
                printed
                    .out
                    .lines()
                    .filter(|line| line.starts_with("sent "))
                    .count(),
                usize::from(sends_first),
                "{}",
                printed.out
            );
            let recv = opens(&events)
                .iter()
                .filter(|open| open.service == "recv")
                .count();
            let most = crate::commands::send::MAX_INFLIGHT + usize::from(sends_first);
            assert_eq!(
                recv, most,
                "{sends_first}: every file in flight, and no more"
            );
            // After the first status ask that follows an Open, no Open.
            let asked = events
                .iter()
                .position(|event| matches!(event, Event::Open(_)))
                .and_then(|first| {
                    events[first..]
                        .iter()
                        .position(|event| matches!(event, Event::Status))
                        .map(|at| first + at)
                })
                .expect("a status was asked after the Opens");
            assert!(
                !events[asked..]
                    .iter()
                    .any(|event| matches!(event, Event::Open(_))),
                "{sends_first}: an Open after the stall was asked about"
            );
            assert!(took < Duration::from_secs(65), "{sends_first}: {took:?}");
        }
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// A device's answer to a list request on `control.serve`: `Done`, then its list of what it serves,
/// naming `entries`.
pub(crate) fn list_answer(entries: &[&str]) -> Vec<u8> {
    let gate = nauthy::Gate::rooted(
        TestRoot::seeded(7).verify_key(),
        nauthy::Denylist::load(std::env::temp_dir().join("swoosh-dialroute-no-revocations"))
            .unwrap(),
    );
    let mut router = tightbeam::tunnel::Router::new(gate);
    for entry in entries {
        router = swoosh::serve::bind_entry(router, entry, [0u8; 32], &[]).unwrap();
    }
    let mut answer = vec![swoosh::serve::control::Answer::Done.encode()];
    answer.extend(
        router
            .catalog(Some(swoosh::serve::CONTROL_SERVE_SERVICE.parse().unwrap()))
            .encode()
            .unwrap(),
    );
    answer
}

/// Through `serve`, `ping` and `speed` refused `NotAdmitted` by one of your devices ask it why: one
/// `control.serve` Open on Main carrying a list request and its End, apart from the verb's own (Isolated
/// for `speed`), and the refusal carries the diagnosis. To a contact's machine there is no follow-up.
#[test]
fn a_refused_ping_through_serve_names_the_cause() {
    on_a_big_stack(async || {
        for (argv, lane, error) in [
            (
                &["ping", "me/nas", "-c", "1"][..],
                OpenLane::Main,
                "me/nas refused ping\n  ping was turned off or removed on nas, or nas is too busy to \
                 take it now.\n  On nas, run this to see which:\n    swoosh status",
            ),
            (
                &["speed", "me/nas", "-n", "1024"],
                OpenLane::Isolated,
                "me/nas does not serve speed\n  Only nas can add it; on nas, run:\n    swoosh \
                 service add speed",
            ),
        ] {
            let mut served = a_device(&format!("refused-cause-{}", argv[0]), false).await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                |service| match service {
                    "control.serve" => Reply::Exchange(list_answer(&["ping"])),
                    _ => Reply::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
                },
                &rig,
            );
            let printed = dialed(&served.home, argv).await;
            rig.stop.cancel();
            let events = resident.await.unwrap();
            assert_eq!(printed.error.as_deref(), Some(error), "{argv:?}");
            assert!(printed.out.is_empty(), "{argv:?}");
            let heard: Vec<_> = opens(&events)
                .iter()
                .map(|open| (open.service.as_str(), open.lane))
                .collect();
            assert_eq!(
                heard,
                [(argv[0], lane), ("control.serve", OpenLane::Main)],
                "{argv:?}"
            );
            let [why] = opens_of(&events, "control.serve")[..] else {
                panic!("one follow-up: {argv:?}");
            };
            let mut upload = crate::commands::through_serve::tests::data(&[
                swoosh::serve::control::Request::List.encode(),
            ]);
            upload.extend_from_slice(&crate::commands::through_serve::tests::END);
            assert_eq!(
                why.upload, upload,
                "the follow-up asks for the list: {argv:?}"
            );
        }

        // To a contact's machine: the refusal alone, no follow-up.
        let mut served = bobs_contact("refused-contact").await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |_| Reply::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
            &rig,
        );
        let printed = dialed(&served.home, &["ping", "bob/nas", "-c", "1"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        assert!(printed.error.is_some());
        assert!(
            !opens(&events)
                .iter()
                .any(|open| open.service == "control.serve"),
            "no follow-up to a contact"
        );
    });
}

/// One row of a stop through `serve`: how the resident answers an Open, and the line the run ends with.
type StopRow = (fn() -> Reply, &'static str);

/// The device's `Done` to the stop, sent once its request has arrived.
fn ack() -> Reply {
    Reply::Answer(vec![swoosh::serve::control::Answer::Done.encode()])
}

/// Every Open of `service` the resident heard.
fn opens_of<'e>(events: &'e [Event], service: &str) -> Vec<&'e Heard> {
    opens(events)
        .into_iter()
        .filter(|open| open.service == service)
        .collect()
}

/// Through `serve`, `stop me/nas` is one Open of `control.serve` on a connection of its own, with no slip:
/// attached, then its one request, then `Done`, gives the stopped lines, exit 0. Its upload is the request
/// and then its End, after the answer: the device answers only a request that arrived, and drops a stream
/// whose End came first. An own bind, Main, a slip, an unflushed request or an End before the answer would
/// each show here.
#[test]
fn stop_rides_the_resident() {
    on_a_big_stack(async || {
        let mut served = a_device("stop-rides", false).await;
        let rig = Rig::default();
        let resident = routed(&mut served, |_| ack(), &rig);
        let printed = dialed(&served.home, &["stop", "me/nas"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        let [stop] = opens(&events)[..] else {
            panic!("one Open, the stop's: {printed:?}");
        };
        assert_eq!(stop.service, "control.serve");
        assert_eq!(stop.peer, node(NAS));
        assert_eq!(stop.lane, OpenLane::Isolated);
        assert_eq!(stop.slip, None);
        let mut upload = crate::commands::through_serve::tests::data(&[
            swoosh::serve::control::Request::Stop.encode(),
        ]);
        upload.extend_from_slice(&crate::commands::through_serve::tests::END);
        assert_eq!(stop.upload, upload);
        assert!(printed.ok, "{printed:?}");
        let short: String = node(NAS).to_string().chars().take(12).collect();
        assert_eq!(
            printed.err,
            format!(
                "Stopped me/nas ({short}\u{2026}).\nIt serves again when swoosh serve next runs on nas.\n"
            )
        );
    });
}

/// Through `serve`, a stop to a device still in its first sync round is answered `NotYet`: the two lines
/// that say so, exit 1. Read it as a stop or an unknown reply and the person is told the wrong thing.
#[test]
fn stop_in_the_first_round_prints_not_yet_through_serve() {
    on_a_big_stack(async || {
        let mut served = a_device("stop-not-yet", false).await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |_| Reply::Answer(vec![swoosh::serve::control::Answer::NotYet.encode()]),
            &rig,
        );
        let printed = dialed(&served.home, &["stop", "me/nas"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        assert_eq!(opens_of(&events, "control.serve").len(), 1);
        assert!(!printed.ok, "{printed:?}");
        assert_eq!(
            printed.error.as_deref(),
            Some(
                "me/nas has just started; it cannot be stopped from here yet\n  nas is still syncing \
                 with your devices. Try again in a minute."
            )
        );
    });
}

/// Through `serve`, a stop whose Open came back `Broken` or `Timeout` stopped nothing and says so at once:
/// the request rides only an attached stream, so it never left. One Open, never a probe.
#[test]
fn a_failed_stop_open_stopped_nothing_through_serve() {
    on_a_big_stack(async || {
        let refusals = [
            OpenRefusal::Broken(bifrost::RefusalDetail::bounded("cut")),
            OpenRefusal::Timeout,
        ];
        for (at, refusal) in refusals.into_iter().enumerate() {
            let mut served = a_device(&format!("stop-failed-{at}"), false).await;
            let rig = Rig::default();
            let stopped = refusal.clone();
            let resident = routed(
                &mut served,
                move |service| match service {
                    "control.serve" => Reply::Refuse(stopped.clone()),
                    _ => Reply::Exchange(Vec::new()),
                },
                &rig,
            );
            let printed = dialed(&served.home, &["stop", "me/nas"]).await;
            rig.stop.cancel();
            let events = resident.await.unwrap();
            assert_eq!(
                printed.error.as_deref(),
                Some("could not stop me/nas\n  Nothing was stopped."),
                "{refusal:?}"
            );
            assert_eq!(opens(&events).len(), 1, "{refusal:?}: one Open, no probe");
        }
    });
}

/// Through `serve`, each row of the stop's open table: a dial that never connected, a dial timeout
/// included, says nothing was stopped; the device's refusal is the refused line alone; and what `serve`
/// says of itself is its own line, never that nothing was stopped.
#[test]
fn one_open_table_for_stop_through_serve() {
    on_a_big_stack(async || {
        let unreachable = "could not reach me/nas: it is offline or not running swoosh serve\n  \
                           Nothing was stopped.";
        let rows: [StopRow; 6] = [
            (
                || {
                    Reply::Refuse(OpenRefusal::Unreachable(bifrost::RefusalDetail::bounded(
                        "timed out",
                    )))
                },
                unreachable,
            ),
            (
                || Reply::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
                "me/nas refused: only your own devices can stop it",
            ),
            (
                || Reply::Refuse(OpenRefusal::Busy),
                "too many connections open through swoosh serve on this machine\n  Close one, or \
                 wait for one to end, then try again.",
            ),
            // Its remedy names the key `serve` runs as, which follows.
            (
                || Reply::Refuse(OpenRefusal::StandingEnded),
                "this device's standing has ended, so a machine that admits only your devices will \
                 refuse this dial\n  Renew it where your root is kept:\n    swoosh invite <name> ",
            ),
            (
                || Reply::Version,
                "swoosh serve on this machine is a different version\n  Restart it with this version.",
            ),
            (|| Reply::Hangup, "connection lost"),
        ];
        for (at, (reply, line)) in rows.into_iter().enumerate() {
            let mut served = a_device(&format!("stop-table-{at}"), false).await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                move |service| match service {
                    "control.serve" => reply(),
                    _ => unavailable(),
                },
                &rig,
            );
            let printed = dialed(&served.home, &["stop", "me/nas"]).await;
            rig.stop.cancel();
            let events = resident.await.unwrap();
            let error = printed.error.unwrap_or_default();
            assert!(error.starts_with(line), "row {at}: {error}");
            assert_eq!(
                at == 0,
                error.contains("Nothing was stopped."),
                "row {at}: {error}"
            );
            assert_eq!(opens(&events).len(), 1, "row {at}: one Open");
        }
        // `serve` stopped under the stop's Open: its own line, which makes no claim about the device.
        let mut served = a_device("stop-table-gone", false).await;
        let rig = Rig::default();
        let resident = scripted(&mut served, vec![Answer::Vanish], &rig);
        let printed = dialed(&served.home, &["stop", "me/nas"]).await;
        let heard = resident.await.unwrap();
        assert_eq!(heard.len(), 1);
        assert_eq!(
            printed.error.as_deref(),
            Some(
                "swoosh serve stopped here and ended the connection to me/nas\n  Commands here \
                 connect through it while it runs.\n  Run this command again to reconnect."
            )
        );
        // The resident's own error comes before it reaches out, so no stop left: the route's line, the
        // reason as the resident gave it.
        let mut served = a_device("stop-table-error", false).await;
        let rig = Rig::default();
        let resident = scripted(&mut served, vec![Answer::Error("disk full")], &rig);
        let printed = dialed(&served.home, &["stop", "me/nas"]).await;
        let heard = resident.await.unwrap();
        assert_eq!(heard.len(), 1, "one Open");
        assert_eq!(heard[0].service, "control.serve");
        assert_eq!(printed.error.as_deref(), Some("disk full"));
    });
}

/// Through `serve`, a stop whose `Done` was read exits 0 with its stopped lines and no `serve` line, though
/// the exchange beside it met `serve` of another version: `Done` proves the stop, and a `serve` that
/// went beside it is not that stop's failure.
#[test]
fn a_stop_exits_0_when_serve_went_beside() {
    on_a_big_stack(async || {
        let mut served = a_device("stop-beside", true).await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |service| match service {
                "control.sync" => Reply::VersionAfterHeld,
                // Sent without reading the request: `AfterVersion` waits on another Open's reply, and only
                // the exit code is in question here.
                _ => Reply::AfterVersion(Box::new(Reply::Exchange(vec![
                    swoosh::serve::control::Answer::Done.encode(),
                ]))),
            },
            &rig,
        );
        let printed = dialed(&served.home, &["stop", "me/nas"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        assert_eq!(opens_of(&events, "control.sync").len(), 1);
        assert_eq!(printed.error, None, "{printed:?}");
        let short: String = node(NAS).to_string().chars().take(12).collect();
        assert_eq!(
            printed.err,
            format!(
                "Stopped me/nas ({short}\u{2026}).\nIt serves again when swoosh serve next runs on nas.\n"
            )
        );
    });
}
