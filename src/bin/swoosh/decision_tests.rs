// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The one decision of a run's path, over the verb as the composition root holds it: which verbs ride a
//! `serve` answering here, and that the socket is asked at most once, and never for a verb that binds its
//! own whatever runs.

use core::time::Duration;
use std::time::SystemTime;

use clap::Parser as _;
use swoosh::home::Home;
use swoosh::serve::control_codec::{OpenRefusal, Request, Response};
use swoosh::testkit::{TestNode, TestRoot};

use super::{Decision, Rides, decide};
use crate::commands::through_serve::tests::Served;
use crate::exchange_tests::{Asked, a_device, bare, restoring, revoking};
use crate::{Cli, Dialing, Outward, Verb};

/// The key that signs the links typed as the machine here.
const ISSUER: u8 = 0x91;

/// `outward`'s dialing verb, as the dialing route takes it: a row that drives that route needs one.
pub(crate) fn dialing(outward: &Outward) -> Dialing<'_> {
    match outward.rides() {
        Rides::Dials { dialing, .. } => dialing,
        Rides::Never | Rides::Exchanges => panic!("not a dialing verb that rides serve"),
    }
}

/// `argv`, parsed and split as the composition root splits it.
fn verb(argv: &[&str]) -> Verb {
    Cli::try_parse_from(core::iter::once("swoosh").chain(argv.iter().copied()))
        .unwrap()
        .command
        .unwrap()
        .split()
}

/// `argv`, a reaching verb that needs no home to split.
fn outward(argv: &[&str]) -> Outward {
    match verb(argv) {
        Verb::Outward(outward) => outward,
        _ => panic!("{argv:?} is no reaching verb"),
    }
}

/// `stop me/nas` from `home`, one of your devices, resolved as the composition root resolves it.
async fn stop(home: &Home) -> Outward {
    let Verb::Stop(cmd) = verb(&["stop", "me/nas"]) else {
        panic!("stop parses");
    };
    Outward::Stop(cmd.run_local(home, None).await.unwrap().unwrap())
}

/// `join`'s first exchange, with `flags` typed on the `join`.
fn joining(flags: &[&str]) -> Outward {
    let Outward::Ping(ping) = outward(&[&["ping", "me/nas"][..], flags].concat()) else {
        panic!("ping parses");
    };
    Outward::Join(crate::commands::join::JoinPull {
        from: TestNode::seeded(ISSUER).node_id(),
        reach: ping.reach,
    })
}

/// A link for `ping` from [`ISSUER`] that admits anyone holding it, as `swoosh share ping anyone` prints.
fn anyone_link() -> String {
    let link = TestRoot::seeded(ISSUER)
        .slip(
            &swoosh::reach::PING_SERVICE.parse().unwrap(),
            SystemTime::now() + Duration::from_secs(3600),
        )
        .unwrap()
        .seal()
        .unwrap()
        .link()
        .unwrap();
    swoosh::link::Link::from(link).to_string()
}

/// A link for `ping` from [`ISSUER`] that admits only `TestNode::seeded(0x92)`'s key.
fn bound_link() -> String {
    let link = TestRoot::seeded(ISSUER)
        .bound_slip(
            &swoosh::reach::PING_SERVICE.parse().unwrap(),
            TestNode::seeded(0x92).verify_key(),
            SystemTime::now() + Duration::from_secs(3600),
        )
        .unwrap();
    swoosh::link::Link::from(link).to_string()
}

/// Every reaching verb, each with the arm it rides: `None` for [`Rides::Never`], `Some(true)` for a
/// dialing verb, `Some(false)` for an exchange verb. Built from `scratch`'s homes, which it keeps.
async fn every_verb(scratch: &[Home; 4]) -> Vec<(&'static str, Outward, Option<bool>)> {
    let [device, root, restored, flagged] = scratch;
    a_device(device, false).await;
    a_device(root, true).await;
    let revoke = |flagged: bool| async move {
        let mut asked = Asked::default();
        let mut revoke = revoking(root, "me/phone", &mut asked).await;
        if let Outward::Revoke(publish) = &mut revoke {
            publish.reach.local = flagged;
        }
        revoke
    };
    let anyone = anyone_link();
    let bound = bound_link();
    let tv = TestNode::seeded(0x44).node_id().to_string();
    let mut verbs = vec![
        ("serve", outward(&["serve"]), None),
        ("ping", outward(&["ping", "me/nas"]), Some(true)),
        ("speed", outward(&["speed", "me/nas"]), Some(true)),
        ("status", outward(&["status", "me/nas"]), Some(true)),
        ("send", outward(&["send", "note.txt", "me/nas"]), Some(true)),
        (
            "forward -",
            outward(&["forward", "me/nas", "ssh", "-"]),
            Some(true),
        ),
        (
            "forward port",
            outward(&["forward", "me/nas", "ssh", "5432"]),
            Some(true),
        ),
        (
            "forward unix:",
            outward(&["forward", "me/nas", "ssh", "unix:/x"]),
            Some(true),
        ),
        (
            "proxy",
            outward(&["proxy", "me/nas", "http://example.com/x"]),
            Some(true),
        ),
        ("stop", stop(device).await, Some(true)),
        ("ping <bound link>", outward(&["ping", &bound]), Some(true)),
        ("ping <anyone link>", outward(&["ping", &anyone]), None),
        (
            "forward <anyone link>",
            outward(&["forward", &anyone, "ping", "-"]),
            None,
        ),
        ("sync", outward(&["sync"]), Some(false)),
        ("invite", outward(&["invite", "tv", &tv]), Some(false)),
        ("join", joining(&[]), Some(false)),
        ("join --local", joining(&["--local"]), None),
        ("revoke", revoke(false).await, Some(false)),
        ("revoke --local", revoke(true).await, None),
    ];
    verbs.push((
        "root restore",
        restoring(restored, &mut Asked::default(), &[]).await,
        Some(false),
    ));
    verbs.push((
        "root restore --local",
        restoring(flagged, &mut Asked::default(), &["--local"]).await,
        None,
    ));
    for home in [restored, flagged] {
        let _ = std::fs::remove_dir_all(home.dir().with_extension("copy"));
    }
    verbs
}

/// The homes [`every_verb`] builds its verbs from, for `tag`.
fn scratch(tag: &str) -> [Home; 4] {
    ["device", "root", "restored", "flagged"].map(|name| bare(&format!("decision-{tag}-{name}")))
}

/// Each verb rides the arm its streams need: `serve` and a verb typed with an `anyone` link never ride;
/// every family dialing verb does, every `forward` end included, with the link typed as the machine as
/// its slip; the exchange verbs exchange through `serve`, the three root acts only with no reach flag.
#[tokio::test]
async fn rides_names_every_verb() {
    let scratch = scratch("rides");
    for (name, verb, arm) in every_verb(&scratch).await {
        match (verb.rides(), arm) {
            (Rides::Never, None) | (Rides::Exchanges, Some(false)) => {}
            (Rides::Dials { slip, .. }, Some(true)) => {
                // Only the link typed as the machine travels as the slip.
                assert_eq!(slip.is_some(), name.contains("link"), "{name}");
            }
            (rides, arm) => panic!(
                "{name}: rides {}, expected {arm:?}",
                match rides {
                    Rides::Never => "never",
                    Rides::Dials { .. } => "dials",
                    Rides::Exchanges => "exchanges",
                }
            ),
        }
    }
    for home in scratch {
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// A resident on `served`'s socket that tells, for each connection in the order it took them, whether it
/// closed before a request: a probe. Each request is refused as busy.
fn counting(served: &mut Served) -> tokio::sync::mpsc::UnboundedReceiver<bool> {
    let listener = served.listener();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let (tell, told) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = listener.accept().await.unwrap();
            let probe = Request::read(&mut conn).await.is_err();
            if !probe {
                let _ = Response::OpenRefusal(OpenRefusal::Busy)
                    .write(&mut conn)
                    .await;
            }
            if tell.send(probe).is_err() {
                break;
            }
        }
    });
    told
}

/// The probes `home`'s resident took since the last ask: a status sent behind them marks the end, since
/// one resident takes its connections in the order they were made.
async fn probes(home: &Home, told: &mut tokio::sync::mpsc::UnboundedReceiver<bool>) -> usize {
    use swoosh::node_client::NodeClient as _;

    let _refused = swoosh::node_client::UidSocket::resolve(home)
        .unwrap()
        .status()
        .await;
    let mut probes = 0;
    while tokio::time::timeout(Duration::from_secs(5), told.recv())
        .await
        .unwrap()
        .unwrap()
    {
        probes += 1;
    }
    probes
}

/// With `serve` answering, each riding verb's decision asks its socket once, with a connection that
/// carries no request, and rides it. `serve`, a verb typed with an `anyone` link and a root act with a
/// reach flag bind their own without asking at all.
#[tokio::test]
async fn the_decision_is_made_once() {
    let scratch = scratch("once");
    let mut served = Served::new("decision-once").await;
    let mut told = counting(&mut served);
    for (name, verb, arm) in every_verb(&scratch).await {
        let decision = decide(&verb, &served.home).await.unwrap();
        assert_eq!(
            probes(&served.home, &mut told).await,
            usize::from(arm.is_some()),
            "{name}"
        );
        match (decision, arm) {
            (Decision::Own, None)
            | (Decision::Dials { .. }, Some(true))
            | (Decision::Exchanges { .. }, Some(false)) => {}
            (_, arm) => panic!("{name}: the wrong path for {arm:?}"),
        }
    }
    for home in scratch {
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// A socket file no listener holds, as a `serve` that crashed leaves it: the connect is refused, which
/// reads as nothing answering, so the run binds its own.
#[tokio::test]
async fn a_stale_socket_binds_its_own() {
    let mut served = Served::new("decision-stale").await;
    // The socket file stays and its lock stays held; nothing accepts on it.
    drop(served.listener());
    let ping = outward(&["ping", "me/nas"]);
    assert!(matches!(
        decide(&ping, &served.home).await.unwrap(),
        Decision::Own
    ));
}
