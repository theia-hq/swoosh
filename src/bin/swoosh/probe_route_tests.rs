// Setup helpers here panic on failed setup, which is the intent; exempt this test file from the unwrap lints.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `ping`, `status <machine>` and `speed` as one body on both paths: what an open that gave no stream
//! prints, by own bind and through `serve`; the own bind's stream on the run's `Peers`, its path read from
//! the session it rides; and what runs beside the verb, which prints nothing of its own.

use core::cell::RefCell;
use core::time::Duration;

use swoosh::credential::Credential;
use swoosh::learn::Admitted;
use swoosh::observation::Observer;
use swoosh::peers::{DialFailure, Hints, OpenError, Peers};
use swoosh::serve::control_codec::{OpenLane, OpenRefusal, PeerRefusal};
use swoosh::streams::{
    Ask, Observing, OneStream, Opened, OwnBind, Resident, StreamSource, Tracked, Unopened,
};
use swoosh::testkit::{Script, ScriptedPeer, TestWrite};
use tokio::io::DuplexStream;

use crate::commands::route::Route;
use crate::commands::through_serve::Dial;
use crate::commands::through_serve::tests::{
    Dialing, Events, Ran, Reply, Rig, Served, book, empty_home, machine, nas, on_a_big_stack,
    routed,
};

/// A source whose every open meets what `meets` gives, or never answers when it gives nothing, noting
/// each open's service.
#[derive(Clone, Copy)]
struct Meets<'a> {
    meets: fn() -> Option<Unopened>,
    opened: &'a RefCell<Vec<String>>,
}

impl StreamSource for Meets<'_> {
    type Write = TestWrite<DuplexStream>;
    type Read = DuplexStream;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        self.opened
            .borrow_mut()
            .push(ask.service.as_str().to_owned());
        match (self.meets)() {
            Some(unopened) => Err(unopened),
            None => core::future::pending().await,
        }
    }
}

impl Observing for Meets<'_> {
    type Session = OneStream<TestWrite<DuplexStream>, DuplexStream>;
    type Follow = Observer<Events>;

    async fn observed(&self, ask: &Ask) -> Result<(Self::Session, Self::Follow), Unopened> {
        match self.open(ask).await {
            Ok(_) => unreachable!("a source that meets an outcome opens nothing"),
            Err(unopened) => Err(unopened),
        }
    }
}

/// The run's bind as the own bind's lines read it: the default reach, so an unreachable machine's line
/// carries no hint.
fn bound() -> swoosh::transport::Bound {
    swoosh::transport::Bound {
        local: false,
        reach: swoosh::transport::Reach::default(),
    }
}

/// `argv`'s one body to `me/nas`, over a source whose open meets `meets`, as `route` words it.
async fn meeting(argv: &[&str], meets: fn() -> Option<Unopened>, route: &Route<'_>) -> Printed {
    let opened = RefCell::new(Vec::new());
    let source = Meets {
        meets,
        opened: &opened,
    };
    let contacts = book();
    let machine = machine(&contacts, "me/nas");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let ended = match Dialing::of(argv) {
        Dialing::Ping(cmd) => {
            cmd.probe(
                source,
                route,
                &machine,
                Admitted::unheard(),
                &mut out,
                &mut err,
            )
            .await
        }
        Dialing::Status(cmd) => {
            cmd.probe(
                source,
                route,
                &machine,
                Admitted::unheard(),
                &mut out,
                &mut err,
            )
            .await
        }
        Dialing::Speed(cmd) => {
            cmd.measure(
                source,
                route,
                &machine,
                Admitted::unheard(),
                &mut out,
                &mut err,
            )
            .await
        }
    };
    Printed {
        out: String::from_utf8(out).unwrap(),
        error: ended.err().map(|report| format!("{report:#}")),
    }
}

/// A dialing verb with no reach flag set, for the flags a [`Dial`] reads.
fn no_reach_flags() -> crate::commands::ping::PingCmd {
    let Dialing::Ping(cmd) = Dialing::of(&["ping", "me/nas"]) else {
        unreachable!("ping parses as ping")
    };
    cmd
}

/// What a run printed on stdout, and its error as the composition root prints it.
#[derive(Debug, PartialEq, Eq)]
struct Printed {
    out: String,
    error: Option<String>,
}

/// One row of the open table: the verb, what its open meets, then its stdout and its error.
type Row = (
    &'static [&'static str],
    fn() -> Option<Unopened>,
    &'static str,
    &'static str,
);

fn detail() -> bifrost::RefusalDetail {
    bifrost::RefusalDetail::bounded("busy")
}

/// Each way an open gives no stream prints one line on both paths, except the rows whose line names the
/// path: what the own bind meets before it reaches anything (its dial, its deadline) has no counterpart
/// through `serve`, so it is pinned by its own words beside the resident's.
#[test]
fn one_open_table_for_the_probe_verbs() {
    on_a_big_stack(async || {
        let served = Served::new("open-table").await;
        let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
        let contacts = book();
        let peer: swoosh::peer::Peer = "me/nas".parse().unwrap();
        let bound = bound();
        let own = Route::Own {
            peer: &peer,
            bound: &bound,
            this: nas(),
        };
        let table: [Row; 17] = [
            (
                &["ping", "me/nas"],
                || Some(Unopened::Refused(OpenRefusal::Unreachable(detail()))),
                "me/nas: unreachable\n",
                "could not reach me/nas",
            ),
            (
                &["ping", "me/nas"],
                || Some(Unopened::Refused(OpenRefusal::Timeout)),
                "me/nas: unreachable\n",
                "could not reach me/nas",
            ),
            (
                &["ping", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::Unavailable(detail()),
                    )))
                },
                "me/nas: reached, but refused (unavailable: busy)\n",
                "me/nas: reached, but refused",
            ),
            (
                &["ping", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::BadRequest(detail()),
                    )))
                },
                "me/nas: reached, but refused (bad request: busy)\n",
                "me/nas: reached, but refused",
            ),
            (
                &["ping", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Broken(
                        bifrost::RefusalDetail::bounded("reset\r"),
                    )))
                },
                "me/nas: reached, but the probe failed (reset\\r)\n",
                "me/nas: reached, but the probe failed",
            ),
            (
                &["ping", "me/nas"],
                || Some(Unopened::Refused(OpenRefusal::PeerUnreadable(detail()))),
                "me/nas: reached, but the probe failed (busy)\n",
                "me/nas: reached, but the probe failed",
            ),
            (
                &["ping", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::NotAdmitted,
                    )))
                },
                "",
                "me/nas refused ping\n  nas does not count this machine as one of your devices.",
            ),
            (
                &["status", "me/nas"],
                || Some(Unopened::Refused(OpenRefusal::Unreachable(detail()))),
                "me/nas: unreachable\n",
                "could not reach me/nas",
            ),
            (
                &["status", "me/nas"],
                || Some(Unopened::Refused(OpenRefusal::Timeout)),
                "me/nas: unreachable\n",
                "could not reach me/nas",
            ),
            (
                &["status", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::NotAdmitted,
                    )))
                },
                "me/nas: reached, but nas does not count this machine as one of your devices\n",
                "me/nas: reached, but refused",
            ),
            (
                &["status", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::BadRequest(detail()),
                    )))
                },
                "me/nas: reached, but refused (bad request: busy)\n",
                "me/nas: reached, but refused",
            ),
            (
                &["status", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Broken(
                        bifrost::RefusalDetail::bounded("reset\r"),
                    )))
                },
                "me/nas: reached, but the probe failed (reset\\r)\n",
                "me/nas: reached, but the probe failed",
            ),
            (
                &["status", "me/nas"],
                || Some(Unopened::Refused(OpenRefusal::PeerUnreadable(detail()))),
                "me/nas: reached, but the probe failed (busy)\n",
                "me/nas: reached, but the probe failed",
            ),
            (
                &["speed", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::NotAdmitted,
                    )))
                },
                "",
                "me/nas refused speed\n  nas does not count this machine as one of your devices.",
            ),
            (
                &["speed", "me/nas"],
                || {
                    Some(Unopened::Refused(OpenRefusal::Peer(
                        PeerRefusal::Unavailable(detail()),
                    )))
                },
                "",
                "stream refused: unavailable: busy",
            ),
            (
                &["speed", "me/nas"],
                || Some(Unopened::Refused(OpenRefusal::Broken(detail()))),
                "",
                "stream: busy",
            ),
            (
                &["speed", "me/nas"],
                || Some(Unopened::Refused(OpenRefusal::Busy)),
                "",
                "too many connections open through swoosh serve on this machine\n  Close one, or wait for one to end, then try again.",
            ),
        ];
        for (argv, meets, out, error) in table {
            let service = match argv[0] {
                "speed" => swoosh::reach::SPEED_SERVICE,
                "status" => swoosh::serve::CONTROL_SERVICES_SERVICE,
                _ => swoosh::reach::PING_SERVICE,
            }
            .parse()
            .unwrap();
            let machine = machine(&contacts, "me/nas");
            let reach = no_reach_flags();
            let dial = Dial {
                machine: &machine,
                service: &service,
                slip: None,
                reach: &reach.reach,
                contacts: &contacts,
            };
            let serve = Route::Serve {
                dial: &dial,
                socket: &socket,
            };
            let by_own = meeting(argv, meets, &own).await;
            let through = meeting(argv, meets, &serve).await;
            assert_eq!(by_own, through, "{argv:?}: one line on both paths");
            assert_eq!(by_own.out, out, "{argv:?}");
            assert_eq!(by_own.error.as_deref(), Some(error), "{argv:?}");
        }

        // The own bind's own outcomes: its dial reached nothing, or its open's deadline passed. `ping` and
        // `status` print the resident's unreachable line for both; `speed` keeps the own bind's words.
        for argv in [&["ping", "me/nas"][..], &["status", "me/nas"]] {
            for meets in [
                (|| Some(Unopened::Own(OpenError::Unreachable(DialFailure::TimedOut))))
                    as fn() -> Option<Unopened>,
                || Some(Unopened::Own(OpenError::Timeout)),
            ] {
                let printed = meeting(argv, meets, &own).await;
                assert_eq!(printed.out, "me/nas: unreachable\n", "{argv:?}");
                assert_eq!(printed.error.as_deref(), Some("could not reach me/nas"));
            }
        }
        // By own bind an unreachable machine's error carries the bind's hint; through `serve` it never does.
        let local = swoosh::transport::Bound {
            local: true,
            reach: swoosh::transport::Reach::default(),
        };
        let own_local = Route::Own {
            peer: &peer,
            bound: &local,
            this: nas(),
        };
        let hinted = meeting(
            &["ping", "me/nas"],
            || Some(Unopened::Refused(OpenRefusal::Timeout)),
            &own_local,
        )
        .await;
        assert!(
            hinted
                .error
                .as_deref()
                .is_some_and(|error| error.contains("With --local or SWOOSH_LOCAL")),
            "{hinted:?}"
        );
        let speed = meeting(
            &["speed", "me/nas"],
            || Some(Unopened::Own(OpenError::Unreachable(DialFailure::TimedOut))),
            &own,
        )
        .await;
        assert_eq!(
            speed.error.as_deref(),
            Some("could not reach me/nas: timed out after 10s with no response")
        );
    });
}

/// Run `argv` by own bind to `me/nas` over `peer`, from a home holding nothing.
async fn by_own_bind(argv: &[&str], peer: &ScriptedPeer, tag: &str) -> Ran {
    let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
    let peers = Peers::new(&node);
    let home = empty_home(tag);
    let contacts = book();
    let machine = machine(&contacts, "me/nas");
    Dialing::of(argv)
        .by_own_bind(&peers, &home, node.node_id(), &machine)
        .await
}

/// The services `peer`'s gate was asked, in order.
fn asked(peer: &ScriptedPeer) -> Vec<String> {
    peer.requests()
        .into_iter()
        .map(|request| request.service)
        .collect()
}

/// By own bind, `ping` and `status <machine>` each open one stream through the run's `Peers` on Main,
/// one connection, presenting the stored badge: `status` asks one of your devices `control.services`,
/// `ping` asks `ping`. The stale exchange beside a run to your device, presenting this home's standing
/// as the composition root's own bind does, rides that same held session.
#[tokio::test(start_paused = true)]
async fn ping_and_status_own_bind_ride_main() {
    let this = nas();
    for (argv, service) in [
        (&["ping", "me/nas", "-c", "1"][..], "ping"),
        (&["status", "me/nas"], "control.services"),
        (&["status", "bob/nas"], "ping"),
    ] {
        let peer = ScriptedPeer::new(this, [Script::Lists(vec!["ping"])]);
        let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
        let peers = Peers::new(&node);
        let (home, badge) = device_home(&format!("ride-main-{}-{service}", argv[0]), this);
        // `bob/nas`, a contact's machine, at the same key in a book of its own.
        let contacts = match argv[1] {
            "bob/nas" => {
                let mut contacts = swoosh::contacts::Contacts::default();
                contacts.save(&"bob/nas".parse().unwrap(), this).unwrap();
                contacts
            }
            _ => book(),
        };
        let machine = machine(&contacts, argv[1]);
        let _ = Dialing::of(argv)
            .by_own_bind(&peers, &home, this, &machine)
            .await;
        assert_eq!(asked(&peer), [service], "{argv:?}");
        assert_eq!(peer.dials(), 1, "{argv:?}: one connection");
        let presented = peer.requests().pop().unwrap().capability;
        assert_eq!(presented.as_deref(), Some(badge.as_str()), "{argv:?}");
        // The stream rode a held session: what runs beside it rides the same one.
        let own = OwnBind::new(&peers, &home, this, &Credential::Family { present: None });
        let beside = match argv[1] {
            "me/nas" => {
                use swoosh::sync::Dial as _;
                let _ = swoosh::sync::SourceDial::new(&own, &home)
                    .exchange(this)
                    .await;
                "control.sync"
            }
            _ => {
                let _ = own.open(&ask(service, OpenLane::Main)).await;
                service
            }
        };
        assert_eq!(peer.dials(), 1, "{argv:?}: the run's session was held");
        let request = peer.requests().pop().unwrap();
        assert_eq!(request.service, beside, "{argv:?}");
        assert_eq!(
            request.capability.as_deref(),
            Some(badge.as_str()),
            "{argv:?}"
        );
    }
}

/// A home whose standing is a device badge for the machine `this`: the home, and the badge.
fn device_home(tag: &str, this: bifrost::NodeId) -> (swoosh::home::Home, nauthy::Link) {
    let dir =
        std::env::temp_dir().join(format!("swoosh-probe-device-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = swoosh::home::Home::resolve(Some(dir)).unwrap();
    let root = swoosh::testkit::TestRoot::seeded(0x70);
    swoosh::config::write_signet(&swoosh::testkit::lock(), &home, root.node_id()).unwrap();
    let until = std::time::SystemTime::now() + Duration::from_secs(30 * 24 * 60 * 60);
    let badge = root.device_badge(this, until).unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
    (home, badge)
}

/// An ask to `me/nas` for `service` on `lane`.
fn ask(service: &str, lane: OpenLane) -> Ask {
    Ask {
        peer: nas(),
        hints: Hints::NONE,
        service: service.parse().unwrap(),
        lane,
        slip: None,
    }
}

/// By own bind, `ping` refused `NotAdmitted` by one of your devices asks `control.services` on the held
/// Main session the refused stream took: one connection in all.
#[tokio::test]
async fn the_follow_up_rides_the_verbs_session() {
    let peer = ScriptedPeer::new(
        nas(),
        [
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Script::Lists(vec!["ping"]),
        ],
    );
    let ran = by_own_bind(&["ping", "me/nas"], &peer, "follow-up-session").await;
    assert!(ran.ended.is_err());
    assert_eq!(asked(&peer), ["ping", "control.services"]);
    assert_eq!(
        peer.dials(),
        1,
        "the follow-up rode the refused stream's session"
    );
}

/// A writer that keeps each line it is given with the paused clock's time since `start`.
struct Timed {
    start: tokio::time::Instant,
    lines: std::rc::Rc<RefCell<Vec<(Duration, String)>>>,
    pending: String,
}

impl std::io::Write for Timed {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.pending.push_str(core::str::from_utf8(bytes).unwrap());
        while let Some(at) = self.pending.find('\n') {
            let line: String = self.pending.drain(..=at).collect();
            self.lines
                .borrow_mut()
                .push((self.start.elapsed(), line.trim_end().to_owned()));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// By own bind, under `-v`, a held session whose path moves mid-run prints the path in force once,
/// first, then one line at the moment of the move, between the probe lines it fell between, not on a
/// sampling clock; the block after the run carries the path the session reads then. Each probe here
/// waits out its 10 s bound, so the first ends at 10 s and the second at 21 s, and the move at 15.5 s
/// falls between them, off any whole-second sample.
#[tokio::test(start_paused = true)]
async fn ping_v_prints_changes_from_the_held_session() {
    let peer = ScriptedPeer::new(nas(), [Script::Holds]);
    let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
    let peers = Peers::new(&node);
    let home = empty_home("ping-v-moves");
    let contacts = book();
    let machine = machine(&contacts, "me/nas");
    let bound = bound();
    let Dialing::Ping(cmd) = Dialing::of(&["ping", "me/nas", "-v", "-c", "2", "-i", "1"]) else {
        unreachable!()
    };
    let route = Route::Own {
        peer: &cmd.peer,
        bound: &bound,
        this: nas(),
    };
    let lines = std::rc::Rc::default();
    let mut out = Timed {
        start: tokio::time::Instant::now(),
        lines: std::rc::Rc::clone(&lines),
        pending: String::new(),
    };
    let own = OwnBind::new(&peers, &home, nas(), &Credential::Family { present: None });
    let moved = async {
        tokio::time::sleep(Duration::from_millis(15_500)).await;
        peer.set_path(
            0,
            crate::commands::through_serve::tests::reading(bifrost::Path::Direct),
        );
    };
    let mut err = Vec::new();
    let run = cmd.probe(
        own,
        &route,
        &machine,
        Admitted::unheard(),
        &mut out,
        &mut err,
    );
    let (_, ()) = tokio::join!(run, moved);
    let lines = lines.borrow();
    let live: Vec<_> = lines.iter().take(4).cloned().collect();
    assert_eq!(
        live,
        [
            (Duration::ZERO, "me/nas, path: unknown".to_owned()),
            (Duration::from_secs(10), "me/nas, seq 0 lost".to_owned()),
            (
                Duration::from_millis(15_500),
                "me/nas, path: direct".to_owned()
            ),
            (Duration::from_secs(21), "me/nas, seq 1 lost".to_owned()),
        ],
        "the move printed when it happened, between its probe lines: {lines:?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|(_, line)| line.contains(", path: "))
            .count(),
        2,
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|(_, line)| line == "  path: direct"),
        "the block reads the path after the run: {lines:?}"
    );
}

/// A source that counts every open and observed open that reaches it, past whatever wraps it.
struct Reached<'a, S> {
    source: S,
    reached: &'a core::cell::Cell<usize>,
}

impl<S: StreamSource> StreamSource for Reached<'_, S> {
    type Write = S::Write;
    type Read = S::Read;

    async fn open(&self, ask: &Ask) -> Result<Opened<Self::Write, Self::Read>, Unopened> {
        self.reached.set(self.reached.get() + 1);
        self.source.open(ask).await
    }

    async fn gone(&self, peer: bifrost::NodeId) -> bool {
        self.source.gone(peer).await
    }

    async fn stalled(&self) -> bool {
        self.source.stalled().await
    }
}

impl<S: Observing> Observing for Reached<'_, S> {
    type Session = S::Session;
    type Follow = S::Follow;

    async fn observed(&self, ask: &Ask) -> Result<(Self::Session, Self::Follow), Unopened> {
        self.reached.set(self.reached.get() + 1);
        self.source.observed(ask).await
    }
}

/// Through `serve`, an exchange beside the verb that met `serve` gone, or another version, before the
/// verb's Open: the verb prints that line once and asks the socket for nothing of its own.
#[test]
fn a_gone_met_beside_is_the_verbs_line_once() {
    on_a_big_stack(async || {
        for gone in ["version", "stopped"] {
            let mut served = Served::new(&format!("gone-beside-{gone}")).await;
            let rig = Rig::default();
            let resident = routed(
                &mut served,
                |service| match service {
                    "control.sync" => Reply::Version,
                    _ => Reply::Observed,
                },
                &rig,
            );
            let socket =
                std::rc::Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
            let mut resident = Some(resident);
            let mut heard = None;
            if gone == "stopped" {
                rig.stop.cancel();
                heard = Some(resident.take().unwrap().await.unwrap());
            }
            let reached = core::cell::Cell::new(0);
            let source = Tracked::new(
                Reached {
                    source: Resident::new(std::rc::Rc::clone(&socket)),
                    reached: &reached,
                },
                std::collections::HashMap::new(),
            );
            // The exchange's Open, first, as the beside exchange makes it.
            let met = source.open(&ask("control.sync", OpenLane::Main)).await;
            assert!(met.is_err(), "{gone}");
            assert_eq!(reached.get(), 1, "{gone}");
            let contacts = book();
            let machine = machine(&contacts, "me/nas");
            let reach = no_reach_flags();
            let service = swoosh::reach::PING_SERVICE.parse().unwrap();
            let dial = Dial {
                machine: &machine,
                service: &service,
                slip: None,
                reach: &reach.reach,
                contacts: &contacts,
            };
            let route = Route::Serve {
                dial: &dial,
                socket: &socket,
            };
            let Dialing::Ping(cmd) = Dialing::of(&["ping", "me/nas", "-c", "1"]) else {
                unreachable!()
            };
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let ended = cmd
                .probe(
                    &source,
                    &route,
                    &machine,
                    Admitted::unheard(),
                    &mut out,
                    &mut err,
                )
                .await;
            let error = format!("{:#}", ended.expect_err("exit 1"));
            let line = match gone {
                "version" => "swoosh serve on this machine is a different version",
                _ => "swoosh serve stopped here and ended the connection to me/nas",
            };
            assert!(error.starts_with(line), "{gone}: {error}");
            assert_eq!(error.matches(line).count(), 1, "{gone}: once");
            assert!(out.is_empty(), "{gone}");
            // Nothing past the record: the verb's open, its follow-up and its stopped ask never reach
            // the socket, so a stopped `serve` is not asked again either.
            assert_eq!(reached.get(), 1, "{gone}: no open after the record");
            let events = match (heard, resident) {
                (Some(events), _) => events,
                (None, Some(resident)) => {
                    rig.stop.cancel();
                    resident.await.unwrap()
                }
                (None, None) => unreachable!("a resident is awaited once"),
            };
            let pings = events
                .iter()
                .filter(|event| {
                    matches!(event, crate::commands::through_serve::tests::Event::Open(heard) if heard.service == "ping")
                })
                .count();
            assert_eq!(pings, 0, "{gone}: no Open after the record");
        }
    });
}

/// What runs beside a verb ends with it and prints nothing: an exchange that meets `serve` gone, or
/// reaches its own deadline while the verb still runs, leaves the verb's result as the run's.
#[tokio::test(start_paused = true)]
async fn the_exchange_beside_leaves_the_verbs_result() {
    let served = Served::new("beside-result").await;
    crate::exchange_tests::a_device(&served.home, false).await;
    let stale = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 2 * 3600;
    std::fs::write(served.home.synced(), format!("{stale}\n")).unwrap();
    let contacts = swoosh::contacts::ContactsStore::open(&served.home)
        .await
        .unwrap()
        .contacts()
        .clone();
    let machine = machine(&contacts, "me/nas");
    for (meets, verb_takes) in [
        (
            (|| Some(Unopened::ServeGone)) as fn() -> Option<Unopened>,
            1,
        ),
        // Past `sync::EACH`, so the exchange's own deadline ends it first.
        (|| None, 6),
    ] {
        let opened = RefCell::new(Vec::new());
        let source = Meets {
            meets,
            opened: &opened,
        };
        let beside = crate::Beside {
            home: &served.home,
            machine: Some(&machine),
            exchanges: true,
            asks_root: false,
        };
        let started = tokio::time::Instant::now();
        let (ended, shown) = crate::run_verb(
            beside,
            &swoosh::sync::SourceDial::new(&source, &served.home),
            async |_admitted| {
                tokio::time::sleep(Duration::from_secs(verb_takes)).await;
                Err(eyre::eyre!("the verb's own line"))
            },
        )
        .await;
        assert_eq!(opened.into_inner(), ["control.sync"], "{verb_takes}");
        assert!(shown.is_none());
        assert_eq!(
            format!("{:#}", ended.expect_err("the verb's exit")),
            "the verb's own line"
        );
        assert_eq!(started.elapsed(), Duration::from_secs(verb_takes));
    }
}

/// A control socket that cannot be trusted at an Open's connect keeps its own error through `serve`,
/// never a cut's `connection lost` or `serve`'s stopped line.
#[test]
fn an_untrusted_socket_at_an_open_keeps_its_own_line() {
    on_a_big_stack(async || {
        let served = Served::new("untrusted-open").await;
        let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
        let contacts = book();
        let machine = machine(&contacts, "me/nas");
        let reach = no_reach_flags();
        let service = swoosh::reach::PING_SERVICE.parse().unwrap();
        let dial = Dial {
            machine: &machine,
            service: &service,
            slip: None,
            reach: &reach.reach,
            contacts: &contacts,
        };
        let untrusted = swoosh::serve::control_codec::ControlError::Untrusted {
            path: served.home.dir().join("serve.sock"),
        };
        let line = untrusted.to_string();
        let unattached = dial.unopened(Unopened::Control(untrusted), &socket).await;
        let report = dial.unattached(unattached, &socket).await;
        assert_eq!(format!("{report:#}"), line);
    });
}
