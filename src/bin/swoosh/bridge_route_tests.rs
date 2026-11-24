// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `forward <machine> <service> -`, the bridge `swoosh ssh` runs, as one body on both paths: its stream
//! on the run's `Peers` by own bind, what an open that gave no stream prints, the follow-up a refusal
//! asks, and a connection that ends under it while stdin idles.

use core::cell::RefCell;
use std::rc::Rc;

use clap::Parser as _;
use swoosh::credential::Credential;
use swoosh::peer::Machine;
use swoosh::peers::{DialFailure, OpenError, Peers};
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::streams::{OwnBind, Resident, Tracked, Unopened};
use swoosh::testkit::{Script, ScriptedPeer};
use tokio::io::{self, DuplexStream};
use tokio::sync::mpsc;

use crate::commands::connect::{Download, Output, Stdin, StdinKind};
use crate::commands::forward::ForwardCmd;
use crate::commands::route::Route;
use crate::commands::through_serve::Dial;
use crate::commands::through_serve::tests::{
    Answer, Event, ROW_BOUND, Reply, Rig, Served, book, empty_home, machine, nas, on_a_big_stack,
    routed, scripted,
};
use crate::probe_route_tests::{Meets, asked, bound, device_home};

// A source that opens nothing still names a download half the bridge could wait on.
impl Download for DuplexStream {
    fn landed(&mut self) -> impl Future<Output = io::Result<()>> {
        core::future::pending()
    }
}

/// What a source's every open meets.
type Meet = fn() -> Option<Unopened>;

/// `forward <typed> ssh -`, parsed as the binary parses it.
fn bridge(typed: &str) -> ForwardCmd {
    let Some(crate::Command::Forward(cmd)) =
        crate::Cli::try_parse_from(["swoosh", "forward", typed, "ssh", "-"])
            .unwrap()
            .command
    else {
        panic!("a bridge is a `forward`");
    };
    cmd
}

/// A piped stdin that carries `up`, then ends once the returned sender drops.
fn stdin(up: &[u8]) -> (mpsc::Sender<io::Result<Vec<u8>>>, Stdin) {
    let (sender, chunks) = mpsc::channel(1);
    if !up.is_empty() {
        sender.try_send(Ok(up.to_vec())).unwrap();
    }
    let stdin = Stdin {
        chunks,
        kind: StdinKind::Piped,
    };
    (sender, stdin)
}

/// An output that drops what it is given, and says when the bridge closed it: the download was whole.
struct Closed(Rc<tokio::sync::Notify>);

impl io::AsyncWrite for Closed {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<io::Result<usize>> {
        core::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }
}

impl Output for Closed {
    fn close(&mut self) -> io::Result<()> {
        self.0.notify_one();
        Ok(())
    }
}

/// `cmd` by own bind over `peers` from `home` as `this`, to `machine`, its stdin `input`.
async fn by_own_bind<T: bifrost::Transport, D: bifrost::Discovery>(
    cmd: &ForwardCmd,
    peers: &Peers<'_, T, D>,
    home: &swoosh::home::Home,
    this: bifrost::NodeId,
    machine: &Machine,
    input: Stdin,
    output: impl Output,
) -> eyre::Result<()> {
    let bound = bound();
    let route = Route::Own {
        peer: &cmd.peer,
        bound: &bound,
        this,
    };
    let own = OwnBind::new(peers, home, this, &Credential::Family { present: None });
    cmd.bridge(own, &route, machine, || Ok((input, output)))
        .await
}

/// `cmd` through the `serve` at `home`, as the dialing route runs its stream, to `machine`.
async fn through(
    cmd: &ForwardCmd,
    home: &swoosh::home::Home,
    machine: &Machine,
    contacts: &swoosh::contacts::Contacts,
    input: Stdin,
    output: impl Output,
) -> eyre::Result<()> {
    let socket = Rc::new(swoosh::node_client::UidSocket::resolve(home).unwrap());
    let source = Tracked::new(
        Resident::new(Rc::clone(&socket)),
        std::collections::HashMap::new(),
    );
    let dial = Dial {
        machine,
        service: &cmd.service,
        contacts,
    };
    let route = Route::Serve {
        dial: &dial,
        socket: &socket,
    };
    cmd.bridge(&source, &route, machine, || Ok((input, output)))
        .await
}

/// By own bind, `forward … -` opens one stream through the run's `Peers` on Main, presenting the stored
/// badge, with no connection of its own: the stale exchange beside it rides the same held session.
#[tokio::test]
async fn the_bridge_own_bind_rides_main() {
    let this = nas();
    let peer = ScriptedPeer::new(this, [Script::Ends]);
    let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
    let peers = Peers::new(&node);
    let (home, badge) = device_home("bridge-main", this);
    let contacts = book();
    let machine = machine(&contacts, "me/nas");
    let (_, input) = stdin(b"");
    by_own_bind(
        &bridge("me/nas"),
        &peers,
        &home,
        this,
        &machine,
        input,
        io::sink(),
    )
    .await
    .unwrap();
    assert_eq!(asked(&peer), ["ssh"]);
    assert_eq!(peer.dials(), 1, "one connection");
    let presented = peer.requests().pop().unwrap().capability;
    assert_eq!(presented.as_deref(), Some(badge.as_str()));
    let own = OwnBind::new(&peers, &home, this, &Credential::Family { present: None });
    let _ = swoosh::sync::Dial::exchange(&swoosh::sync::SourceDial::new(&own, &home), this).await;
    assert_eq!(asked(&peer), ["ssh", "control.sync"]);
    assert_eq!(
        peer.dials(),
        1,
        "the exchange rode the bridge's Main session"
    );
}

/// While stdin idles after the download's end, a connection that ends with no word that the upload
/// landed ends the bridge at once, exit 1: by own bind the held session's close, which the read half
/// hears, and through `serve` the resident's close, `serve`'s own line when it went.
#[test]
fn the_bridge_ends_at_a_cut_on_both_paths() {
    on_a_big_stack(async || {
        let contacts = book();
        let machine = machine(&contacts, "me/nas");
        let peer = ScriptedPeer::new(nas(), [Script::Ends]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = Peers::new(&node);
        let home = empty_home("bridge-cut");
        let closed = Rc::new(tokio::sync::Notify::new());
        let (_idle, input) = stdin(b"");
        let output = Closed(Rc::clone(&closed));
        let cmd = bridge("me/nas");
        let run = by_own_bind(&cmd, &peers, &home, nas(), &machine, input, output);
        let cut = async {
            closed.notified().await;
            peer.cut();
            core::future::pending::<()>().await;
        };
        let ended = tokio::time::timeout(ROW_BOUND, async {
            tokio::select! {
                ended = run => ended,
                () = cut => unreachable!(),
            }
        })
        .await
        .expect("the closed session ended the run though stdin idles");
        assert_eq!(format!("{:#}", ended.unwrap_err()), "connection lost");

        for (index, (answer, line)) in [
            (Answer::EndThenCut, "connection lost"),
            (
                Answer::EndThenStop,
                "swoosh serve stopped here and ended the connection to me/nas",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            // Tagged by index: the line holds spaces and a `/`, which would nest the home's directory.
            let mut served = Served::new(&format!("bridge-cut-{index}")).await;
            let rig = Rig::default();
            // A spare answer keeps the resident up after the first, until the row stops it.
            let resident = scripted(&mut served, vec![answer, Answer::Hangup], &rig);
            let (_idle, input) = stdin(b"");
            let ended = tokio::time::timeout(
                ROW_BOUND,
                through(&cmd, &served.home, &machine, &contacts, input, io::sink()),
            )
            .await
            .expect("the resident's close ended the run though stdin idles");
            rig.stop.cancel();
            resident.await.unwrap();
            let error = format!("{:#}", ended.unwrap_err());
            assert!(error.starts_with(line), "{error}");
        }
    });
}

/// `NotAdmitted` from one of your devices asks it why, one `control.services` stream on Main through the
/// path the refused stream took, and names the cause on both paths; a contact's machine is asked
/// nothing.
#[test]
fn a_refused_bridge_names_the_cause_on_both_paths() {
    on_a_big_stack(async || {
        let mut contacts = book();
        let bob = bifrost::NodeId::from_ed25519_secret(&[0x71; 32]);
        contacts.save(&"bob/nas".parse().unwrap(), bob).unwrap();
        let does_not_serve = "me/nas does not serve ssh\n  Only nas can add it; on nas, run:\n    swoosh service add ssh";
        let not_shared = "bob/nas refused ssh\n  It does not serve ssh, or its owner has not shared ssh with you.";
        for (typed, line, follow_up) in [
            ("me/nas", does_not_serve, true),
            ("bob/nas", not_shared, false),
        ] {
            let machine = machine(&contacts, typed);
            let refused = Script::Refuse(bifrost::Refusal::NotAdmitted);
            let peer = ScriptedPeer::new(machine.key(), [refused, Script::Lists(vec!["ping"])]);
            let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
            let peers = Peers::new(&node);
            let home = empty_home(&format!("bridge-refused-{follow_up}"));
            let (_, input) = stdin(b"");
            let ended = by_own_bind(
                &bridge(typed),
                &peers,
                &home,
                nas(),
                &machine,
                input,
                io::sink(),
            )
            .await;
            assert_eq!(format!("{:#}", ended.unwrap_err()), line, "{typed}");
            let expected: &[&str] = if follow_up {
                &["ssh", "control.services"]
            } else {
                &["ssh"]
            };
            assert_eq!(asked(&peer), expected, "{typed}");
            assert_eq!(
                peer.dials(),
                1,
                "{typed}: the follow-up rode the refused stream's session"
            );
        }

        let not_yours =
            "me/nas refused ssh\n  nas does not count this machine as one of your devices.";
        for (typed, line, follow_up) in
            [("me/nas", not_yours, true), ("bob/nas", not_shared, false)]
        {
            let machine = machine(&contacts, typed);
            let mut served = Served::new(&format!("bridge-refused-serve-{follow_up}")).await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                |_| Reply::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
                &rig,
            );
            let (_, input) = stdin(b"");
            let ended = through(
                &bridge(typed),
                &served.home,
                &machine,
                &contacts,
                input,
                io::sink(),
            )
            .await;
            rig.stop.cancel();
            let events = resident.await.unwrap();
            assert_eq!(format!("{:#}", ended.unwrap_err()), line, "{typed}");
            let opens: Vec<(&str, OpenLane)> = events
                .iter()
                .filter_map(|event| match event {
                    Event::Open(heard) => Some((heard.service.as_str(), heard.lane)),
                    Event::Status => None,
                })
                .collect();
            let mut expected = vec![("ssh", OpenLane::Main)];
            if follow_up {
                expected.push(("control.services", OpenLane::Main));
            }
            assert_eq!(opens, expected, "{typed}");
        }
    });
}

/// Each way an open gives no stream prints one line on both paths, except the rows whose line names the
/// path: what the own bind meets before it reaches anything (its dial, its deadline) has no counterpart
/// through `serve`, and an unreachable machine by own bind carries the bind's hint.
#[test]
fn one_open_table_for_the_bridge() {
    on_a_big_stack(async || {
        let served = Served::new("bridge-table").await;
        let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
        let contacts = book();
        let machine = machine(&contacts, "me/nas");
        let cmd = bridge("me/nas");
        let bound = bound();
        let own = Route::Own {
            peer: &cmd.peer,
            bound: &bound,
            this: nas(),
        };
        let dial = Dial {
            machine: &machine,
            service: &cmd.service,
            contacts: &contacts,
        };
        let serve = Route::Serve {
            dial: &dial,
            socket: &socket,
        };
        let met = async |meets: Meet, route: &Route<'_>| {
            let opened = RefCell::new(Vec::new());
            let source = Meets {
                meets,
                opened: &opened,
            };
            let never = || -> eyre::Result<(Stdin, io::Sink)> { panic!("nothing was admitted") };
            let ended = cmd.bridge(source, route, &machine, never).await;
            format!("{:#}", ended.unwrap_err())
        };
        let table: [(Meet, &str); 9] = [
            (
                || {
                    Some(Unopened::Refused(OpenRefusal::Unreachable(
                        bifrost::RefusalDetail::bounded("busy"),
                    )))
                },
                "connect to peer: busy",
            ),
            (
                || Some(Unopened::Refused(OpenRefusal::Timeout)),
                "connect to peer: timed out",
            ),
            (
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::Unavailable(bifrost::RefusalDetail::bounded("busy")),
                    )))
                },
                "stream refused: unavailable: busy",
            ),
            (
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::BadRequest(bifrost::RefusalDetail::bounded("busy")),
                    )))
                },
                "stream refused: bad request: busy",
            ),
            (
                || {
                    Some(Unopened::Refused(OpenRefusal::Broken(
                        bifrost::RefusalDetail::bounded("busy"),
                    )))
                },
                "stream: busy",
            ),
            (
                || {
                    Some(Unopened::Refused(OpenRefusal::PeerUnreadable(
                        bifrost::RefusalDetail::bounded("busy"),
                    )))
                },
                "stream: busy",
            ),
            (
                || Some(Unopened::Refused(OpenRefusal::Busy)),
                "too many connections open through swoosh serve on this machine\n  Close one, or wait for one to end, then try again.",
            ),
            (
                || Some(Unopened::Refused(OpenRefusal::NotHere)),
                "me/nas is this machine",
            ),
            (
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::NotAdmitted,
                    )))
                },
                "me/nas refused ssh\n  nas does not count this machine as one of your devices.",
            ),
        ];
        for (meets, line) in table {
            let by_own = met(meets, &own).await;
            assert_eq!(by_own, met(meets, &serve).await, "one line on both paths");
            assert_eq!(by_own, line);
        }

        // The own bind's own outcomes: its dial reached nothing, which names the machine, or its open's
        // deadline passed.
        assert_eq!(
            met(
                || Some(Unopened::Own(OpenError::Unreachable(DialFailure::TimedOut))),
                &own
            )
            .await,
            "could not reach me/nas: timed out after 10s with no response"
        );
        assert_eq!(
            met(|| Some(Unopened::Own(OpenError::Timeout)), &own).await,
            "the machine did not answer the request to open a stream in time"
        );
        let local = swoosh::transport::Bound {
            local: true,
            reach: swoosh::transport::Reach::default(),
        };
        let own_local = Route::Own {
            peer: &cmd.peer,
            bound: &local,
            this: nas(),
        };
        let hinted = met(
            || Some(Unopened::Own(OpenError::Unreachable(DialFailure::TimedOut))),
            &own_local,
        )
        .await;
        assert!(hinted.contains("With --local or SWOOSH_LOCAL"), "{hinted}");
    });
}
