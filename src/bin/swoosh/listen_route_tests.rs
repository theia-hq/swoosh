// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `forward <machine> <service> <port>` as one listener on both paths: what a pipe's open that gave no
//! stream does to the run, a connection cut under it, a badge that lapses between pipes, and how its
//! admission ends.

use core::cell::RefCell;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use std::rc::Rc;
use std::sync::Arc;

use bifrost::RefusalDetail;
use swoosh::peer::Machine;
use swoosh::peers::{DialFailure, OpenError, Peers};
use swoosh::serve::control_codec::{ControlError, MalformedOpen, OpenRefusal, PeerRefusal};
use swoosh::streams::{Ask, Opened, Resident, StreamSource, Tracked, Unopened};
use swoosh::testkit::{Script, TestRoot};
use tokio::io::{self, DuplexStream};
use tokio::sync::Notify;

use crate::commands::connect::tests::{client, listening, nas, port_forward, ported};
use crate::commands::connect::{Listener, PipeFailures};
use crate::commands::route::Route;
use crate::commands::through_serve::Dial;
use crate::commands::through_serve::tests::{
    Answer, END, Heard, ROW_BOUND, Reply, Rig, Served, book, machine, on_a_big_stack, routed,
    scripted,
};
use crate::probe_route_tests::{Meets, bound, device_home};

/// What a listener's run did: the line it ended with, `None` while it still listens, and its stderr.
type Ran = (Option<String>, String);

/// The port's listener for `me/nas`'s `ssh` over `source`, worded by `route`, already admitted, while
/// `clients` connect, for at most `within`: the line the run ended with, `None` when `clients` finished
/// with the port still listening, and what the run wrote to stderr.
async fn listened(
    source: &impl StreamSource<Read: crate::commands::connect::Download>,
    route: &Route<'_>,
    within: core::time::Duration,
    clients: impl AsyncFnOnce(core::net::SocketAddr),
) -> Ran {
    let contacts = book();
    let machine = machine(&contacts, "me/nas");
    let ask = listening(&machine);
    let listener = Listener {
        source,
        ask: &ask,
        route,
        machine: &machine,
    };
    let local = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let at = local.local_addr().unwrap();
    let mut err = Vec::new();
    let ended = {
        let failures = PipeFailures::new(&machine, &mut err);
        tokio::time::timeout(within, async {
            tokio::select! {
                // The run's end first: a client that saw its pipe end may finish in the same poll.
                biased;
                ended = listener.forward(local, &failures) => Some(format!("{ended:#}")),
                () = clients(at) => None,
            }
        })
        .await
        .expect("the run ended, or its clients finished")
    };
    (ended, String::from_utf8(err).unwrap())
}

/// `me/nas`'s `ssh` through the `serve` at `served`, as the dialing route runs a port: the run's one
/// tracked source over the resident, its admission made first.
async fn through_serve(
    served: &Served,
    within: core::time::Duration,
    clients: impl AsyncFnOnce(core::net::SocketAddr),
) -> Ran {
    admitted(served, async |source, route| {
        listened(source, route, within, clients).await
    })
    .await
}

/// `run` over the port's listener through the `serve` at `served`, once its admission is made: the run's
/// one tracked source over the resident, and its route.
async fn admitted<R>(
    served: &Served,
    run: impl AsyncFnOnce(&Tracked<Resident>, &Route<'_>) -> R,
) -> R {
    let contacts = book();
    let machine = machine(&contacts, "me/nas");
    let cmd = port_forward("me/nas");
    let socket = Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
    let source = Tracked::new(
        Resident::new(Rc::clone(&socket)),
        std::collections::HashMap::new(),
    );
    let dial = Dial {
        machine: &machine,
        service: &cmd.service,
        contacts: &contacts,
    };
    let route = Route::Serve {
        dial: &dial,
        socket: &socket,
    };
    let ask = listening(&machine);
    Listener {
        source: &source,
        ask: &ask,
        route: &route,
        machine: &machine,
    }
    .admit()
    .await
    .unwrap();
    run(&source, &route).await
}

/// What a row's source meets at every open.
pub(crate) type Meet = fn() -> Option<Unopened>;

/// What a row's open does to the run.
#[derive(Clone, Copy)]
pub(crate) enum Then {
    /// The run ends: its line starts so, by own bind and through `serve`.
    Ends {
        own: &'static str,
        serve: &'static str,
    },
    /// That pipe alone fails, warning with this clause, and the port listens on.
    Warns(&'static str),
}

/// A detail the machine gave.
fn down() -> RefusalDetail {
    RefusalDetail::bounded("down")
}

/// Each way a listener pipe's open gives no stream, as a source meets it, and what it does to the run of
/// `me/nas`'s `ssh`: the line it ends with on each path, or the warning's clause.
pub(crate) fn table() -> [(Meet, Then); 22] {
    let not_yours = "me/nas refused ssh\n  nas does not count this machine as one of your devices.";
    let ended =
        "this device's membership badge has ended, so a family-gated peer will refuse this dial; ";
    [
        (
            || {
                Some(Unopened::Refused(OpenRefusal::Peer(
                    PeerRefusal::NotAdmitted,
                )))
            },
            Then::Ends {
                own: not_yours,
                serve: not_yours,
            },
        ),
        (
            || Some(Unopened::Refused(OpenRefusal::StandingEnded)),
            Then::Ends {
                own: ended,
                serve: ended,
            },
        ),
        (
            || Some(Unopened::Refused(OpenRefusal::NotHere)),
            Then::Ends {
                own: "me/nas is this machine",
                serve: "me/nas is this machine",
            },
        ),
        (
            || Some(Unopened::Malformed(MalformedOpen::HintCount)),
            Then::Ends {
                own: "open request has too many hints",
                serve: "open request has too many hints",
            },
        ),
        (
            || {
                Some(Unopened::Control(ControlError::Untrusted {
                    path: "/tmp/swoosh.sock".into(),
                }))
            },
            Then::Ends {
                own: "connection lost",
                serve: "swoosh serve's socket is not private to you\n  /tmp/swoosh.sock is not yours alone.",
            },
        ),
        (
            || {
                Some(Unopened::Control(ControlError::Unattributed {
                    path: "/tmp/swoosh.sock".into(),
                    pid: 4242.try_into().unwrap(),
                }))
            },
            Then::Ends {
                own: "connection lost",
                serve: "another process is answering swoosh serve's socket\n  Process 4242 answers at \
                        /tmp/swoosh.sock.",
            },
        ),
        (
            || Some(Unopened::ServeGone),
            Then::Ends {
                own: "connection lost",
                serve: "swoosh serve stopped here and ended the connection to me/nas",
            },
        ),
        (
            || Some(Unopened::Skew),
            Then::Ends {
                own: "swoosh serve on this machine is a different version",
                serve: "swoosh serve on this machine is a different version",
            },
        ),
        (
            || Some(Unopened::Refused(OpenRefusal::Busy)),
            Then::Warns("too many connections here"),
        ),
        (
            || Some(Unopened::Refused(OpenRefusal::Unreachable(down()))),
            Then::Warns("unreachable"),
        ),
        (
            || Some(Unopened::Refused(OpenRefusal::Timeout)),
            Then::Warns("unreachable"),
        ),
        (
            || Some(Unopened::Refused(OpenRefusal::Broken(down()))),
            Then::Warns("interrupted (down)"),
        ),
        (
            || Some(Unopened::Refused(OpenRefusal::PeerUnreadable(down()))),
            Then::Warns("interrupted"),
        ),
        (
            || {
                Some(Unopened::Refused(OpenRefusal::Peer(
                    PeerRefusal::Unavailable(down()),
                )))
            },
            Then::Warns("reached, but refused (unavailable: down)"),
        ),
        (
            || {
                Some(Unopened::Refused(OpenRefusal::Peer(
                    PeerRefusal::BadRequest(down()),
                )))
            },
            Then::Warns("reached, but refused (bad request: down)"),
        ),
        (
            || Some(Unopened::Own(OpenError::Busy)),
            Then::Warns("too many connections here"),
        ),
        (
            || Some(Unopened::Own(OpenError::Timeout)),
            Then::Warns("unreachable"),
        ),
        (
            || Some(Unopened::Own(OpenError::Unreachable(DialFailure::TimedOut))),
            Then::Warns("unreachable"),
        ),
        (
            || {
                Some(Unopened::Own(OpenError::Open(bifrost::Error::Stream(
                    "closed".into(),
                ))))
            },
            Then::Warns("interrupted"),
        ),
        (
            || Some(Unopened::Home(eyre::eyre!("unreadable"))),
            Then::Warns("interrupted"),
        ),
        (
            || Some(Unopened::ServeError("disk full".to_owned())),
            Then::Warns("interrupted"),
        ),
        (
            || {
                Some(Unopened::Control(ControlError::Timeout {
                    phase: "response read",
                }))
            },
            Then::Warns("interrupted"),
        ),
    ]
}

/// Each way a later pipe's open gives no stream ends the run where the table says, on both paths, with
/// the line it names: every outcome every later open would repeat ends it, a malformed Open and a
/// control socket that cannot be trusted among them; every other warns once and keeps listening.
#[test]
fn one_ending_table_on_both_paths() {
    on_a_big_stack(async || {
        let mut served = Served::new("listen-table").await;
        let rig = Rig::default();
        // Answers status, so `serve` here is neither stalled nor gone; no Open reaches it.
        let resident = routed(&mut served, |_| Reply::Stall, &rig);
        let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
        let contacts = book();
        let machine = machine(&contacts, "me/nas");
        let cmd = port_forward("me/nas");
        let bound = bound();
        let own = Route::Own {
            peer: &cmd.peer,
            bound: &bound,
            this: crate::commands::through_serve::tests::nas(),
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
        let table = table();
        for (at, (meets, then)) in table.into_iter().enumerate() {
            for (path, route) in [("own", &own), ("serve", &serve)] {
                let opened = RefCell::new(Vec::new());
                let source = Meets {
                    meets,
                    opened: &opened,
                };
                let ends = matches!(then, Then::Ends { .. });
                let (ran, err) = listened(&source, route, ROW_BOUND, async |local| {
                    client(local).await;
                    if ends {
                        core::future::pending::<()>().await;
                    }
                    // A second connection is opened too: the port still listens after the first.
                    client(local).await;
                })
                .await;
                match then {
                    Then::Ends { own, serve } => {
                        let line = ran.unwrap_or_else(|| panic!("row {at} {path}: listening"));
                        let expected = if path == "own" { own } else { serve };
                        assert!(line.starts_with(expected), "row {at} {path}: {line}");
                        assert_eq!(err, "", "row {at} {path}: no warning first");
                    }
                    Then::Warns(clause) => {
                        assert_eq!(ran, None, "row {at} {path}: ended");
                        assert_eq!(opened.borrow().len(), 2, "row {at} {path}: both pipes");
                        let warning = crate::commands::through_serve::tests::warning(clause);
                        assert_eq!(err, warning, "row {at} {path}: one warning");
                    }
                }
            }
        }
        rig.stop.cancel();
        resident.await.unwrap();
    });
}

/// Through `serve`, a later pipe's Open that gets no reply ends the run with `Unresponsive` when `serve`
/// then fails a status too; when it answers status, the pipe alone fails, warning `interrupted`, and the
/// port listens on. The pipe's open is asked directly: a paused clock would outrun a local connection.
#[test]
fn a_confirmed_stall_ends_a_listener() {
    on_a_big_stack(async || {
        tokio::time::pause();
        let contacts = book();
        let machine = machine(&contacts, "me/nas");
        let ask = listening(&machine);
        // A spare answer keeps the slow resident serving status until the row's stop.
        for (tag, answer, stalled) in [
            ("wedged", Answer::Wedge, true),
            ("slow", Answer::Stall, false),
        ] {
            let mut served = Served::new(&format!("listen-stall-{tag}")).await;
            let rig = Rig::default();
            let resident = scripted(
                &mut served,
                vec![Answer::Attach, answer, Answer::Hangup],
                &rig,
            );
            let mut err = Vec::new();
            let over = admitted(&served, async |source, route| {
                let listener = Listener {
                    source,
                    ask: &ask,
                    route,
                    machine: &machine,
                };
                let failures = PipeFailures::new(&machine, &mut err);
                match listener.open(&failures).await {
                    Ok(Some(_)) => panic!("{tag}: no stream attaches"),
                    Ok(None) => None,
                    Err(over) => Some(format!("{:#}", listener.ending(over).await)),
                }
            })
            .await;
            rig.stop.cancel();
            let _ = resident.await;
            let err = String::from_utf8(err).unwrap();
            if stalled {
                assert_eq!(
                    over.as_deref(),
                    Some("swoosh serve on this machine did not answer\n  Restart it."),
                    "{tag}"
                );
                assert_eq!(err, "", "{tag}");
            } else {
                assert_eq!(over, None, "{tag}: listening");
                assert_eq!(
                    err,
                    crate::commands::through_serve::tests::warning("interrupted"),
                    "{tag}"
                );
            }
        }
    });
}

/// The services a scripted resident's Opens asked for, in order.
fn services(heard: &[Heard]) -> Vec<&str> {
    heard.iter().map(|open| open.service.as_str()).collect()
}

/// A cut under a live pipe leaves the port up on both paths: the pipe goes to the log alone, the next
/// connection redials and carries, presenting the badge read at that open, and when the gate then
/// refuses, the run ends at that connection on its first refusal, with the dial refusal and its cause.
#[test]
fn a_host_cut_leaves_a_listener_up_on_both_paths() {
    on_a_big_stack(async || {
        let does_not_serve = "me/nas does not serve ssh\n  Only nas can add it; on nas, run:\n    swoosh service add ssh";
        let peer = nas(vec![
            Script::Holds,
            Script::Holds,
            Script::Holds,
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Script::Lists(vec!["ping"]),
        ]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = Peers::new(&node);
        let (home, badge) = device_home("listen-cut", crate::commands::through_serve::tests::nas());
        let (ran, err) = ported(&node, &peers, &home, async |local| {
            let _first = tokio::net::TcpStream::connect(local).await.unwrap();
            while peer.requests().len() < 2 {
                tokio::time::sleep(core::time::Duration::from_millis(10)).await;
            }
            // The admission's and the first pipe's held session.
            peer.cut_nth(0);
            let _second = tokio::net::TcpStream::connect(local).await.unwrap();
            while peer.requests().len() < 3 {
                tokio::time::sleep(core::time::Duration::from_millis(10)).await;
            }
            assert_eq!(peer.dials(), 2, "the next pipe redialed");
            client(local).await;
            core::future::pending().await
        })
        .await;
        let ran = ran.map(|ended| format!("{ended:#}"));
        assert_eq!(ran.as_deref(), Some(does_not_serve));
        assert_eq!(err, "");
        let requests = peer.requests();
        let asked: Vec<&str> = requests.iter().map(|r| r.service.as_str()).collect();
        assert_eq!(
            asked,
            ["ssh", "ssh", "ssh", "ssh", "control.services"],
            "one refused pipe, then the follow-up"
        );
        assert_eq!(requests[2].capability.as_deref(), Some(badge.as_str()));

        let mut served = Served::new("listen-cut").await;
        let rig = Rig::default();
        let not_admitted = || Answer::Refuse(OpenRefusal::Peer(PeerRefusal::NotAdmitted));
        let resident = scripted(
            &mut served,
            vec![
                Answer::Attach,
                Answer::Cut,
                Answer::Attach,
                not_admitted(),
                not_admitted(),
            ],
            &rig,
        );
        let (ran, err) = through_serve(&served, ROW_BOUND, async |local| {
            client(local).await;
            client(local).await;
            client(local).await;
            core::future::pending().await
        })
        .await;
        rig.stop.cancel();
        let heard = resident.await.unwrap();
        assert_eq!(
            ran.as_deref(),
            Some("me/nas refused ssh\n  nas does not count this machine as one of your devices.")
        );
        assert_eq!(err, "");
        assert_eq!(
            services(&heard),
            ["ssh", "ssh", "ssh", "ssh", "control.services"]
        );
    });
}

/// By own bind each pipe presents the badge as the home holds it at that open: one renewed since the
/// last pipe carries, and one past its date and not renewed ends the run at that pipe with the dead-badge
/// line, the badge never presented.
#[tokio::test]
async fn a_lapsed_badge_ends_a_listener_at_its_next_pipe_by_own_bind() {
    let this = crate::commands::through_serve::tests::nas();
    let root = TestRoot::seeded(0x70);
    let day = core::time::Duration::from_secs(24 * 60 * 60);
    for renewed in [true, false] {
        let peer = nas(vec![Script::Holds, Script::Holds, Script::Holds]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = Peers::new(&node);
        let (home, _) = device_home(&format!("listen-lapse-{renewed}"), this);
        let until = if renewed {
            std::time::SystemTime::now() + 60 * day
        } else {
            std::time::SystemTime::now() - day
        };
        let next = root.device_badge(this, until).unwrap();
        let (ran, err) = ported(&node, &peers, &home, async |local| {
            let _first = tokio::net::TcpStream::connect(local).await.unwrap();
            while peer.requests().len() < 2 {
                tokio::time::sleep(core::time::Duration::from_millis(10)).await;
            }
            swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &next).unwrap();
            let _second = tokio::net::TcpStream::connect(local).await.unwrap();
            if renewed {
                while peer.requests().len() < 3 {
                    tokio::time::sleep(core::time::Duration::from_millis(10)).await;
                }
            } else {
                core::future::pending::<()>().await;
            }
        })
        .await;
        let requests = peer.requests();
        if renewed {
            assert!(ran.is_none(), "listening: {ran:?}");
            assert_eq!(requests[2].capability.as_deref(), Some(next.as_str()));
        } else {
            let line = format!("{:#}", ran.expect("the run ended"));
            assert!(
                line.starts_with("this device's membership badge has ended"),
                "{line}"
            );
            assert_eq!(requests.len(), 2, "the lapsed badge was never presented");
        }
        assert_eq!(err, "");
    }
}

/// An upload half that notes whether it was ended with End.
struct Noted {
    write: DuplexStream,
    ended: Arc<AtomicBool>,
}

impl io::AsyncWrite for Noted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ended.store(true, Ordering::SeqCst);
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

impl bifrost::WriteEnd for Noted {
    fn abort(&mut self) {}
    fn delivered(self) -> impl Future<Output = io::Result<()>> + Send + 'static {
        core::future::pending()
    }
}

/// A source whose every open attaches, its upload half noting its End.
struct Admits(Arc<AtomicBool>);

impl StreamSource for Admits {
    type Write = Noted;
    type Read = DuplexStream;

    async fn open(&self, _ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        let (write, _far) = io::duplex(64);
        let (_near, read) = io::duplex(64);
        Ok(Opened {
            info: bifrost::ConnInfo::default(),
            write: Noted {
                write,
                ended: Arc::clone(&self.0),
            },
            read,
        })
    }
}

/// A port's admission stream ends with End on both paths, so the far side reads a clean end of an empty
/// upload, never a reset: the one admission over any source, and through `serve` the resident reads End
/// alone.
#[test]
fn a_port_admission_ends_with_end_on_both_paths() {
    on_a_big_stack(async || {
        let contacts = book();
        let machine: Machine = machine(&contacts, "me/nas");
        let cmd = port_forward("me/nas");
        let bound = bound();
        let route = Route::Own {
            peer: &cmd.peer,
            bound: &bound,
            this: crate::commands::through_serve::tests::nas(),
        };
        let ended = Arc::new(AtomicBool::new(false));
        let ask = listening(&machine);
        Listener {
            source: &Admits(Arc::clone(&ended)),
            ask: &ask,
            route: &route,
            machine: &machine,
        }
        .admit()
        .await
        .unwrap();
        assert!(ended.load(Ordering::SeqCst), "the admission ended with End");

        let mut served = Served::new("listen-admit").await;
        let rig = Rig::default();
        let resident = scripted(&mut served, vec![Answer::Attach], &rig);
        let (ran, _) = through_serve(&served, ROW_BOUND, async |_| {}).await;
        assert_eq!(ran, None);
        let heard = tokio::time::timeout(ROW_BOUND, resident)
            .await
            .expect("the admission stream closed")
            .unwrap();
        let [admission] = heard.as_slice() else {
            panic!("{} Opens, not the one admission", heard.len());
        };
        assert_eq!(
            admission.upload, END,
            "the admission stream ends with End alone"
        );
    });
}

/// A source whose `ssh` opens are refused `NotAdmitted`, noting each open's service, and whose follow-up,
/// any other service, says it is asking on `asking`, then waits for `answer` before it is refused too.
struct AsksLate<'a> {
    opened: &'a RefCell<Vec<String>>,
    asking: &'a Notify,
    answer: &'a Notify,
}

impl StreamSource for AsksLate<'_> {
    type Write = Noted;
    type Read = DuplexStream;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        self.opened
            .borrow_mut()
            .push(ask.service.as_str().to_owned());
        if ask.service.as_str() != "ssh" {
            // `notify_one` keeps its permit, so the row hears it whether or not it waits yet.
            self.asking.notify_one();
            self.answer.notified().await;
        }
        Err(Unopened::Refused(OpenRefusal::Peer(
            PeerRefusal::NotAdmitted,
        )))
    }
}

/// A refusal every later pipe would repeat closes the port before the one question it asks: while one of
/// your devices is asked why, a new local connection is refused by this computer and opens no stream, so a
/// client that retries adds no refused opens at the machine and no second question.
#[test]
fn a_port_closes_before_its_ending_asks_why() {
    on_a_big_stack(async || {
        let cmd = port_forward("me/nas");
        let bound = bound();
        let route = Route::Own {
            peer: &cmd.peer,
            bound: &bound,
            this: crate::commands::through_serve::tests::nas(),
        };
        let opened = RefCell::new(Vec::new());
        let (asking, answer) = (Notify::new(), Notify::new());
        let source = AsksLate {
            opened: &opened,
            asking: &asking,
            answer: &answer,
        };
        let (ran, err) = listened(&source, &route, ROW_BOUND, async |local| {
            // Held, not read to its end: a port still up would hold this pipe through the question.
            let _first = tokio::net::TcpStream::connect(local).await.unwrap();
            asking.notified().await;
            assert!(
                tokio::net::TcpStream::connect(local).await.is_err(),
                "the port closed before the question"
            );
            assert_eq!(*opened.borrow(), ["ssh", "control.services"]);
            answer.notify_one();
            core::future::pending::<()>().await;
        })
        .await;
        let line = ran.expect("the run ended");
        assert!(
            line.starts_with(
                "me/nas refused ssh\n  nas does not count this machine as one of your devices."
            ),
            "{line}"
        );
        assert_eq!(err, "", "no warning first");
    });
}
