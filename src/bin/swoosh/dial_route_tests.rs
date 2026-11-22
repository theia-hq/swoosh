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
use swoosh::node_client::UidSocket;
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::testkit::{TestNode, TestRoot};

use crate::commands::invite::invite_tests::{NAS, node};
use crate::commands::through_serve::tests::{
    Event, Heard, ROW_BOUND, Reply, Rig, Served, on_a_big_stack, routed,
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

/// What a run printed and how it ended: its error as the composition root prints it.
#[derive(Debug, PartialEq, Eq)]
struct Printed {
    ok: bool,
    error: Option<String>,
    out: String,
    err: String,
}

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
    err: &mut impl std::io::Write,
) -> Printed {
    let Verb::Outward(outward) =
        Cli::try_parse_from(core::iter::once("swoosh").chain(argv.iter().copied()))
            .unwrap()
            .command
            .unwrap()
            .split()
    else {
        panic!("{argv:?} is a reaching verb");
    };
    let contacts = ContactsStore::open(home).await.unwrap().contacts().clone();
    let machine = swoosh::reaching::Reaching::dialed(&outward)
        .unwrap()
        .machine(&contacts)
        .unwrap();
    let hints =
        crate::commands::through_serve::hints(swoosh::reaching::Reaching::reach_args(&outward))
            .unwrap();
    let socket = UidSocket::resolve(home).unwrap();
    let mut out = Vec::new();
    let ended = tokio::time::timeout(
        bound,
        crate::dial_through_serve(
            outward, home, &machine, None, socket, hints, &contacts, &mut out, err,
        ),
    )
    .await
    .expect("the run ended");
    Printed {
        ok: ended.is_ok(),
        error: ended.err().map(|report| format!("{report:#}")),
        out: String::from_utf8(out).unwrap(),
        err: String::new(),
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
            }
            assert_eq!(
                printed[0], printed[1],
                "{argv:?}: the exchange printed nothing"
            );
        }
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

/// Through `serve`, an Open beside the verb prints nothing and asks `serve` nothing: an exchange dropped
/// unanswered when the verb ends, a lookup that runs past its deadline, and either meeting another
/// version of `serve`.
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
            assert_eq!(statuses(&events), 0, "{exchange}: no status ask");
            assert_eq!(
                opens(&events)
                    .iter()
                    .any(|open| open.service == "control.sync"),
                exchange != "none",
                "{exchange}: the exchange was made"
            );
            match &baseline {
                None => baseline = Some(printed),
                Some(baseline) => assert_eq!(&printed, baseline, "{exchange}"),
            }
        }

        // The exchange met by another version beside a ping whose stream attached: the ping's lines are its
        // own, as with no exchange at all.
        let mut baseline = None;
        for exchange in ["none", "version"] {
            let mut served =
                a_device(&format!("beside-attached-{exchange}"), exchange != "none").await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                |service| match service {
                    "control.sync" => Reply::Version,
                    _ => Reply::Observed,
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
                None => baseline = Some(printed),
                Some(baseline) => assert_eq!(&printed, baseline, "{exchange}"),
            }
        }

        // The exchange cut before its reply: the cut is asked about once, as any cut is (`serve` may have
        // gone), so one status ask follows; the ping's lines are still its own.
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
        assert_eq!(statuses(&events), 1, "the cut's ask alone");
        let mut fresh = a_device("beside-hangup-fresh", false).await;
        let rig = Rig::default();
        let resident = routed(&mut fresh, |_| unavailable(), &rig);
        let baseline = dialed(&fresh.home, &["ping", "me/nas", "-c", "1"]).await;
        rig.stop.cancel();
        resident.await.unwrap();
        assert_eq!(printed, baseline, "the cut exchange printed nothing");

        // `send` beside an exchange met by another version: the record ends the run with that line once,
        // and no file's Open is sent.
        let file = a_file("beside-skew");
        let mut served = a_device("beside-skew", true).await;
        let rig = Rig::default();
        let resident = routed(
            &mut served,
            |service| match service {
                "control.sync" => Reply::Version,
                _ => Reply::Exchange(vec![1]),
            },
            &rig,
        );
        let printed = dialed(&served.home, &["send", &file, "me/nas"]).await;
        rig.stop.cancel();
        let events = resident.await.unwrap();
        let error = printed.error.unwrap_or_default();
        assert!(
            error.starts_with("swoosh serve on this machine is a different version"),
            "{error}"
        );
        assert_eq!(error.matches("different version").count(), 1, "{error}");
        assert!(
            !opens(&events).iter().any(|open| open.service == "recv"),
            "no file's Open after the record"
        );

        // The lookup: past its deadline, or met by another version, after `send`'s file attached.
        let file = a_file("beside-lookup");
        let mut baseline = None;
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
            assert!(printed.ok, "{lookup}: {printed:?}");
            assert_eq!(statuses(&events), 0, "{lookup}: no status ask");
            assert!(
                opens(&events)
                    .iter()
                    .any(|open| open.service == "lookup.root"),
                "{lookup}: the lookup was asked"
            );
            match &baseline {
                None => baseline = Some(printed),
                Some(baseline) => assert_eq!(&printed, baseline, "{lookup}"),
            }
        }
    });
}
