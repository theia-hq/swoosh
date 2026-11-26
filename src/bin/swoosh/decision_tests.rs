// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The one decision of a run's path, over the verb as the composition root holds it: which verbs ride a
//! `serve` answering here, and that the socket is asked at most once, and never for a verb that binds its
//! own whatever runs.

use core::time::Duration;
use std::time::SystemTime;

use bifrost::{Discovery, Node, Transport};
use clap::Parser as _;
use swoosh::contacts::Contacts;
use swoosh::home::Home;
use swoosh::learn::Admitted;
use swoosh::peer::Machine;
use swoosh::peers::Peers;
use swoosh::serve::control_codec::{OpenRefusal, Request, Response};
use swoosh::testkit::{TestNode, TestRoot};

use super::{Decision, Rides, decide};
use crate::commands::through_serve::tests::{Served, book, resident_key};
use crate::exchange_tests::{Asked, a_device, bare, restoring, revoking};
use crate::{Cli, Dialing, Outward, Run, Verb};

/// The key that signs the links typed as the machine here.
const ISSUER: u8 = 0x91;

/// `outward`'s dialing verb, as either path takes it: a row that drives one needs one.
pub(crate) fn dialing(outward: Outward) -> Dialing {
    match outward.split() {
        Run::Dials(dialing) => dialing,
        Run::Serve(_) | Run::Exchanges(_) => panic!("not a dialing verb"),
    }
}

/// Run `dialing` to `machine` over its own bind on `node`, from `home`, as the composition root runs it,
/// its route naming a bind with no flags.
pub(crate) async fn by_own_bind<'s, 'n: 's, T: Transport, D: Discovery>(
    dialing: &Dialing,
    node: &Node<T, D>,
    peers: &'s Peers<'n, T, D>,
    home: &'s Home,
    machine: &Machine,
    contacts: &Contacts,
    admitted: Admitted<'s>,
) -> eyre::Result<()>
where
    T::Session: 'static,
    <T::Session as bifrost::Session>::Write: Send + 'static,
    <T::Session as bifrost::Session>::Read: Send + 'static,
{
    let bound = swoosh::transport::Bound {
        local: false,
        reach: swoosh::transport::Reach::default(),
    };
    dialing
        .by_own_bind(node, peers, home, &bound, machine, contacts, admitted)
        .await
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

/// The machine `outward` dials, resolved from [`book`] as the composition root resolves it, if it dials
/// one.
fn machine_of(outward: &Outward) -> Option<Machine> {
    swoosh::reaching::Reaching::dialed(outward).map(|peer| peer.machine(&book()).unwrap())
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
        match (verb.split().rides(), arm) {
            (Rides::Never(_), None) | (Rides::Exchanges(_), Some(false)) => {}
            (Rides::Dials(_, slip), Some(true)) => {
                // Only the link typed as the machine travels as the slip.
                assert_eq!(slip.is_some(), name.contains("link"), "{name}");
            }
            (rides, arm) => panic!(
                "{name}: rides {}, expected {arm:?}",
                match rides {
                    Rides::Never(_) => "never",
                    Rides::Dials(..) => "dials",
                    Rides::Exchanges(_) => "exchanges",
                }
            ),
        }
    }
    for home in scratch {
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// What one connection to [`counting`]'s resident carried.
#[derive(Debug, PartialEq, Eq)]
enum Carried {
    /// A `Status`, answered as [`resident_key`]: a probe.
    Status,
    /// An Open, refused as busy.
    Open,
    /// Nothing: the connection closed before a request.
    Nothing,
}

/// A resident on `served`'s socket that tells, for each connection in the order it took them, what it
/// carried. A status is answered as [`resident_key`], and an Open is refused as busy.
fn counting(served: &mut Served) -> tokio::sync::mpsc::UnboundedReceiver<Carried> {
    let listener = served.listener();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let (tell, told) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = listener.accept().await.unwrap();
            let carried = match Request::read(&mut conn).await {
                Ok(asked @ (Request::Status | Request::Whoami)) => {
                    let answer =
                        crate::commands::through_serve::tests::answer_of(&asked, resident_key());
                    let _ = answer.write(&mut conn).await;
                    Carried::Status
                }
                Ok(_) => {
                    let _ = Response::OpenRefusal(OpenRefusal::Busy)
                        .write(&mut conn)
                        .await;
                    Carried::Open
                }
                Err(_) => Carried::Nothing,
            };
            if tell.send(carried).is_err() {
                break;
            }
        }
    });
    told
}

/// The probes `home`'s resident took since the last ask, each a `Whoami`: a connection closed with no
/// request, made here, marks the end, since one resident takes its connections in the order they were
/// made. Anything else it took is no probe, and fails the row.
async fn probes(home: &Home, told: &mut tokio::sync::mpsc::UnboundedReceiver<Carried>) -> usize {
    drop(
        swoosh::node_client::UidSocket::resolve(home)
            .unwrap()
            .connected()
            .await
            .unwrap(),
    );
    let mut probes = 0;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), told.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Carried::Status => probes += 1,
            Carried::Nothing => return probes,
            Carried::Open => panic!("the decision opened nothing"),
        }
    }
}

/// With `serve` answering, each riding verb's decision asks its socket once, with one `Whoami` and
/// nothing else, and rides it. `serve`, a verb typed with an `anyone` link and a root act with a reach
/// flag bind their own without asking at all.
#[tokio::test]
async fn the_decision_is_made_once() {
    let scratch = scratch("once");
    let mut served = Served::new("decision-once").await;
    let mut told = counting(&mut served);
    for (name, verb, arm) in every_verb(&scratch).await {
        let machine = machine_of(&verb);
        let decision = decide(verb.split(), &served.home, machine.as_ref())
            .await
            .unwrap();
        assert_eq!(
            probes(&served.home, &mut told).await,
            usize::from(arm.is_some()),
            "{name}"
        );
        match (decision, arm) {
            (Decision::Own(_), None)
            | (Decision::Dials { .. }, Some(true))
            | (Decision::Exchanges { .. }, Some(false)) => {}
            (_, arm) => panic!("{name}: the wrong path for {arm:?}"),
        }
    }
    for home in scratch {
        let _ = std::fs::remove_dir_all(home.dir());
    }
}

/// A socket file no listener holds and a free `serve.lock`, as a `serve` that crashed leaves them: the
/// connect is refused and no `serve` holds the lock, so the run binds its own.
#[tokio::test]
async fn a_stale_socket_binds_its_own() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut served = Served::new("decision-stale").await;
    drop(served.listener());
    // Freeing the lock unlinks the socket and its leaf, as a clean stop does; a crash leaves the file.
    drop(served.lock());
    let socket = served.home.control_socket().unwrap();
    let leaf = socket.parent().unwrap();
    std::fs::create_dir_all(leaf).unwrap();
    std::fs::set_permissions(leaf, std::fs::Permissions::from_mode(0o700)).unwrap();
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    assert!(socket.exists(), "the socket file stays with no listener");
    let ping = outward(&["ping", "me/nas"]);
    let machine = machine_of(&ping);
    assert!(matches!(
        decide(ping.split(), &served.home, machine.as_ref())
            .await
            .unwrap(),
        Decision::Own(_)
    ));
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir(leaf);
}

/// A `serve` that holds the lock but answers nowhere is an error for every riding verb, never an own
/// bind; for `revoke`, `root restore` and `join`, whose act has landed by the decision, it is the error
/// that says what landed first: for `revoke`, only this machine's block, and the rerun that finishes it.
#[tokio::test]
async fn a_held_unreachable_serve_after_a_landed_act_says_it_landed() {
    let scratch = scratch("landed");
    let mut served = Served::new("decision-landed").await;
    // The socket file stays and the lock stays held; nothing accepts on it.
    drop(served.listener());
    for (name, verb, arm) in every_verb(&scratch).await {
        let Some(_) = arm else { continue };
        let machine = machine_of(&verb);
        let Err(report) = decide(verb.split(), &served.home, machine.as_ref()).await else {
            panic!("{name}: a held lock with no answer is no own bind");
        };
        let landed = ["revoke", "root restore", "join"].contains(&name);
        assert_eq!(
            report.is::<crate::commands::through_serve::ActLanded>(),
            landed,
            "{name}"
        );
        let line = format!("error: {report:#}\n");
        assert!(
            line.starts_with(
                "error: swoosh serve is running for this home, but this command cannot reach it\n"
            ),
            "{name}: {line}"
        );
        // As the composition root prints it: the landed act's line first, on its own, then the error.
        let mut err = Vec::new();
        let left = crate::landed_then(report, &mut err);
        let err = String::from_utf8(err).unwrap();
        match landed {
            true => {
                assert!(
                    left.is::<crate::commands::through_serve::Reported>(),
                    "{name}"
                );
                let said = match name {
                    "revoke" => {
                        "me/phone is blocked on this machine, not yet on your other devices\nto \
                         finish, run it again: swoosh revoke me/phone"
                    }
                    _ => "The change is made and saved here. Your devices have not been told yet.",
                };
                assert_eq!(err, format!("{said}\n{line}"), "{name}");
            }
            false => {
                assert_eq!(err, "", "{name}");
                assert_eq!(format!("error: {left:#}\n"), line, "{name}");
            }
        }
    }
    for home in scratch {
        let _ = std::fs::remove_dir_all(home.dir());
    }
}
