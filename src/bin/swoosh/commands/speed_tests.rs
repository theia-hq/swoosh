//! The refusal render: after admission the typed code chooses the phrase, never the detail prose, so a
//! rate-limited or busy run does not read as a missing service (the render table in
//! `notes/design/typed-refusal-and-errors.md`); and the peer's detail prints escaped.

use bifrost::RefusalDetail;
use measure::{MethodRefusal, Refusal};

use super::{failed_line, log_path, observed_run, path_line, print_path, refusal_line, title};

/// A method refusal carrying `detail`.
fn method(code: MethodRefusal, detail: &str) -> Refusal {
    Refusal::Method {
        code,
        detail: RefusalDetail::bounded(detail),
    }
}

/// Each `MethodRefusal` code renders its own line: a missing method names the method, a rate limit or a
/// busy service reports the bound that stopped the run.
#[test]
fn a_method_refusal_renders_its_typed_code() {
    assert_eq!(
        refusal_line(
            "alice",
            &method(MethodRefusal::WrongMethod, "this service speaks ping")
        ),
        "alice does not serve `speed`: this service speaks ping"
    );
    assert_eq!(
        refusal_line(
            "alice",
            &method(MethodRefusal::RateLimited, "over the byte cap")
        ),
        "alice is rate limited: over the byte cap"
    );
    assert_eq!(
        refusal_line("alice", &method(MethodRefusal::Busy, "one run at a time")),
        "alice is busy: one run at a time"
    );
}

/// A peer's detail holding a carriage return, an ESC CSI sequence and a bidi override prints as escapes on
/// one line, whether the peer refused the dial or the method.
#[test]
fn a_hostile_refusal_prints_escaped() {
    let hostile = "no\r\u{1b}[2Kalice: 900 MiB/s\u{202e}";
    let escaped = r"no\r\u{1b}[2Kalice: 900 MiB/s\u{202e}";
    let dial = Refusal::Stream(bifrost::Refusal::Unavailable {
        detail: RefusalDetail::bounded(hostile),
    });
    let refused_the_method = method(MethodRefusal::Busy, hostile);
    for (refusal, line) in [
        (
            dial,
            format!("alice: reached, but refused: unavailable: {escaped}"),
        ),
        (refused_the_method, format!("alice is busy: {escaped}")),
    ] {
        let printed = refusal_line("alice", &refusal);
        assert_eq!(printed, line);
        assert!(
            !printed.contains(['\r', '\n', '\u{1b}', '\u{202e}']),
            "no raw byte of the peer's reaches the line: {printed:?}"
        );
    }
}

/// A run that was reached and then broke prints its cause chain, and a cause can be the peer's own text
/// (the reason it gave for closing the connection). A carriage return, an ESC CSI sequence and a bidi
/// override there print as escapes, on one line, with the chain's words as they were.
#[test]
fn a_hostile_failure_cause_prints_escaped() {
    let reason = "closed by peer: no\r\u{1b}[2Ksent a.txt (1 bytes)\u{202e}";
    let error = measure::ProtocolError::Io(std::io::Error::other(reason));
    let printed = failed_line(&error);
    assert!(
        printed.ends_with(r"closed by peer: no\r\u{1b}[2Ksent a.txt (1 bytes)\u{202e}"),
        "the peer's reason prints escaped at the end of the chain: {printed:?}"
    );
    assert!(
        !printed.contains(['\r', '\n', '\u{1b}', '\u{202e}']),
        "no raw byte of the peer's reaches the line: {printed:?}"
    );
}

/// `speed` to one of your devices that refuses it prints the dial refusal once, as the error, after asking
/// the device why over a second connection to it: never the generic refusal line.
#[tokio::test]
async fn a_refused_speed_to_your_device_names_the_cause() {
    use clap::Parser as _;
    use swoosh::testkit::{Script, ScriptedPeer};
    use swoosh::transport;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        speed: super::SpeedCmd,
    }

    let key = bifrost::NodeId::from_ed25519_secret(&[0x69; 32]);
    let mut contacts = swoosh::contacts::Contacts::default();
    contacts
        .save(&"me/nas".parse().expect("a device"), key)
        .expect("the name is free");
    let cmd = Wrap::try_parse_from(["x", "me/nas"])
        .expect("speed parses")
        .speed;
    let machine = cmd.peer.machine(&contacts).expect("one machine");
    let peer = ScriptedPeer::new(
        key,
        [
            Script::Refuse(bifrost::Refusal::NotAdmitted),
            Script::Lists(vec!["ping"]),
        ],
    );
    let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
    let bound = transport::Bound {
        local: false,
        reach: transport::Reach::default(),
    };
    let peers = swoosh::peers::Peers::new(&node);
    let error = cmd
        .run_speed(
            &node,
            &peers,
            &machine,
            &bound,
            None,
            None,
            swoosh::learn::Admitted::unheard(),
        )
        .await
        .expect_err("a refused speed test exits non-zero");
    assert_eq!(
        format!("{error:#}"),
        "me/nas does not serve speed\n  Only nas can add it; on nas, run:\n    swoosh service add speed"
    );
    let asked: Vec<String> = peer
        .requests()
        .into_iter()
        .map(|request| request.service)
        .collect();
    assert_eq!(asked, ["speed", "control.services"]);
    assert_eq!(peer.dials(), 2, "its own connection, then the follow-up's");
}

/// `speed` takes its connection from the run's owner as an isolated one, so the owner's per-peer cap
/// holds it: with four isolated connections to the machine live, it is refused before it dials.
#[tokio::test]
async fn speed_opens_isolated() {
    use clap::Parser as _;
    use swoosh::testkit::ScriptedPeer;
    use swoosh::transport;

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        speed: super::SpeedCmd,
    }

    let key = bifrost::NodeId::from_ed25519_secret(&[0x69; 32]);
    let mut contacts = swoosh::contacts::Contacts::default();
    contacts
        .save(&"me/nas".parse().expect("a device"), key)
        .expect("the name is free");
    let cmd = Wrap::try_parse_from(["x", "me/nas"])
        .expect("speed parses")
        .speed;
    let machine = cmd.peer.machine(&contacts).expect("one machine");
    let peer = ScriptedPeer::new(key, []);
    let node = bifrost::Node::new(peer.clone(), bifrost::NoDiscovery);
    let peers = swoosh::peers::Peers::new(&node);
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(
            peers
                .isolated(key, swoosh::peers::Hints::NONE)
                .await
                .expect("below the cap"),
        );
    }
    let bound = transport::Bound {
        local: false,
        reach: transport::Reach::default(),
    };
    let error = cmd
        .run_speed(
            &node,
            &peers,
            &machine,
            &bound,
            None,
            None,
            swoosh::learn::Admitted::unheard(),
        )
        .await
        .expect_err("a fifth isolated connection is refused");
    assert_eq!(
        format!("{error:#}"),
        "too many streams open to this machine; try again when one closes"
    );
    assert_eq!(peer.dials(), 4, "refused before it dials");
    assert!(peer.requests().is_empty());
}

/// The words for a path, as a run prints them.
fn direct() -> bifrost::ConnInfo {
    bifrost::ConnInfo {
        path: bifrost::Path::Direct,
        rtt: None,
        remote: None,
    }
}

fn relayed() -> bifrost::ConnInfo {
    bifrost::ConnInfo {
        path: bifrost::Path::Relayed(bifrost::Relay::from(
            url::Url::parse("https://relay.example/").unwrap(),
        )),
        rtt: None,
        remote: None,
    }
}

/// `speed`'s part of the no-transport rule, on both paths: the title and the path row name the machine,
/// the mode and the path, never the transport that carried the run.
#[test]
fn default_output_names_no_transport() {
    for (mode, title_line) in [
        (measure::Mode::Down, "speed test to me/nas (down)"),
        (measure::Mode::Up, "speed test to me/nas (up)"),
        (measure::Mode::Bidir, "speed test to me/nas (bidir)"),
    ] {
        assert_eq!(title("me/nas", mode), title_line);
    }
    for (info, row) in [
        (direct(), "path: direct"),
        (relayed(), "path: relayed through relay.example"),
        (bifrost::ConnInfo::default(), "path: unknown"),
    ] {
        assert_eq!(path_line(&info), row);
    }
    let lines = [title("me/nas", measure::Mode::Down), path_line(&direct())];
    for line in lines {
        assert!(!line.contains("via"), "{line}");
        assert!(!line.contains(swoosh::transport::FAST_PATH), "{line}");
    }
}

/// What a run through `serve` prints of `observed`: its stdout and its stderr.
fn printed(observed: swoosh::observation::Observed) -> (String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    print_path(observed, &mut out, &mut err).unwrap();
    (
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// Through `serve` the path row comes from the Finish after the run. When the Finish fails there is no
/// row and stderr warns once; a sample that failed earlier is never printed.
#[test]
fn the_path_row_through_serve_is_the_finishs_or_a_warning() {
    use swoosh::observation::{ObservationError, Observed};

    assert_eq!(
        printed(Observed {
            last: Ok(direct()),
            earlier: None,
        }),
        ("path: direct\n".to_owned(), String::new())
    );
    assert_eq!(
        printed(Observed {
            last: Err(ObservationError::Unavailable),
            earlier: None,
        }),
        (
            String::new(),
            "warning: could not read the path of this run\n".to_owned()
        )
    );
    // An earlier failure beside a good Finish: the row, and nothing on stderr.
    assert_eq!(
        printed(Observed {
            last: Ok(relayed()),
            earlier: Some(ObservationError::Unavailable),
        }),
        (
            "path: relayed through relay.example\n".to_owned(),
            String::new()
        )
    );
    // A failed run prints only its own error: its observation goes to the log.
    log_path(Observed {
        last: Err(ObservationError::Unavailable),
        earlier: Some(ObservationError::Unavailable),
    });
}

/// A resident that answers every query with a sample and keeps the actions it was asked.
#[derive(Default)]
struct Recorded(core::cell::RefCell<Vec<swoosh::serve::control_codec::PathAction>>);

impl swoosh::observation::PathSource for Recorded {
    fn path(
        &self,
        request: swoosh::serve::control_codec::PathRequest,
    ) -> impl Future<
        Output = Result<
            swoosh::serve::control_codec::PathReply,
            swoosh::serve::control_codec::ControlError,
        >,
    > {
        self.0.borrow_mut().push(request.action);
        core::future::ready(Ok(
            swoosh::serve::control_codec::PathReply::Sample(direct()),
        ))
    }
}

/// An observed Open's reference, read from an Attached as the client reads one.
async fn reference() -> swoosh::serve::control_codec::PathRef {
    use swoosh::serve::control_codec::Response;

    let mut frame = b"SWC1\x06\x00\x1c\x01".to_vec();
    frame.extend_from_slice(&[7; 16]);
    frame.extend_from_slice(&1_u64.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0]);
    match Response::read_open(&mut frame.as_slice()).await.unwrap() {
        Response::Attached(attached) => attached.reference.unwrap(),
        other => panic!("not attached: {other:?}"),
    }
}

/// A session whose one stream open fails with `error`, the way a refused or broken run ends.
struct Failing(core::cell::RefCell<Option<bifrost::Error>>);

impl bifrost::Session for Failing {
    type Write = swoosh::testkit::TestWrite<tokio::io::DuplexStream>;
    type Read = tokio::io::DuplexStream;

    fn peer(&self) -> bifrost::NodeId {
        bifrost::NodeId::from_ed25519_secret(&[0x69; 32])
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(self.0.borrow_mut().take().unwrap_or(bifrost::Error::Closed))
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        Err(bifrost::Error::Closed)
    }

    async fn wait_closed(&self) {
        core::future::pending().await
    }

    fn close(&self) {}

    fn path_changes(&self) -> bifrost::PathChanges {
        bifrost::PathChanges::fixed(bifrost::Path::Unknown)
    }
}

/// A run through `serve` that is refused, or that breaks, still Finishes its receipt, so the resident
/// lets the reference go at once rather than at the end of its retention.
#[tokio::test(start_paused = true)]
async fn a_refused_or_broken_run_still_finishes_its_receipt() {
    use swoosh::observation::{Observer, Receipt};
    use swoosh::serve::control_codec::PathAction;

    for (error, refused) in [
        (bifrost::Error::Refused(bifrost::Refusal::NotAdmitted), true),
        (bifrost::Error::Closed, false),
    ] {
        let source = std::rc::Rc::new(Recorded::default());
        let observer = Observer::new(
            Receipt::new(reference().await, std::rc::Rc::clone(&source)),
            bifrost::ConnInfo::default(),
        );
        let session = Failing(core::cell::RefCell::new(Some(error)));
        let (outcome, observed) = observed_run(
            measure::Mode::Down,
            measure::Limit::ByBytes(1),
            &session,
            observer,
        )
        .await;
        assert_eq!(
            matches!(outcome, Err(measure::ProtocolError::Refused(_))),
            refused
        );
        assert!(outcome.is_err());
        assert_eq!(observed.last.unwrap(), direct());
        assert_eq!(*source.0.borrow(), [PathAction::Finish]);
    }
}
