//! The lines `forward <machine> <service> -` prints when it runs through `serve`, pinned to their ruled
//! words, and the stand-ins the observed verbs' tests run against.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::rc::Rc;

use bifrost::{ConnInfo, NodeId, RefusalDetail};
use swoosh::contacts::Contacts;
use swoosh::node_client::NodeClient;
use swoosh::observation::{Observer, PathSource, Receipt};
use swoosh::peer::{Machine as PeerMachine, Peer};
use swoosh::serve::control_codec::{
    ControlError, DisabledList, OpenRefusal, PathRef, PathReply, PathRequest, PeerRefusal, Request,
    Response, ServiceMenu, StatusReply,
};
use swoosh::testkit::{control_frame, control_header};
use swoosh::transport::ReachArgs;

use super::{Busy, Dial, Moot, Skew, StandingEnded, ThisMachine};

/// A stream the resident attached, as the socket gives its halves.
type Stream = swoosh::streams::Opened<
    swoosh::serve::control_codec::OpenWrite,
    swoosh::serve::control_codec::OpenRead,
>;
use crate::commands::connect::{ConnectionLost, Machine};

/// The key of `me/nas`.
pub(crate) fn nas() -> NodeId {
    NodeId::from_ed25519_secret(&[0x61; 32])
}

pub(crate) fn book() -> Contacts {
    let mut contacts = Contacts::default();
    contacts.save(&"me/nas".parse().unwrap(), nas()).unwrap();
    contacts
}

pub(crate) fn machine(contacts: &Contacts, typed: &str) -> PeerMachine {
    typed.parse::<Peer>().unwrap().machine(contacts).unwrap()
}

/// A home with nothing in it, under `tag`: a standing that reads as none, so a stream by own bind
/// presents nothing.
pub(crate) fn empty_home(tag: &str) -> swoosh::home::Home {
    let dir = std::env::temp_dir().join(format!("swoosh-probe-home-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    swoosh::home::Home::resolve(Some(dir)).unwrap()
}

/// A dialing verb with one stream, parsed as the binary parses it.
#[derive(clap::Parser)]
pub(crate) enum Dialing {
    Ping(crate::commands::ping::PingCmd),
    Status(crate::commands::status::StatusCmd),
    Speed(crate::commands::speed::SpeedCmd),
}

/// What a dialing verb's run through `serve` ended with, and what it printed.
pub(crate) struct Ran {
    pub(crate) ended: eyre::Result<()>,
    pub(crate) out: String,
    pub(crate) err: String,
}

impl Dialing {
    /// `argv` (after a program name) as a verb.
    pub(crate) fn of(argv: &[&str]) -> Self {
        use clap::Parser as _;

        Self::try_parse_from(core::iter::once("x").chain(argv.iter().copied())).unwrap()
    }

    /// Run the verb through the `serve` at `home` as the dialing route runs its stream, to `machine`,
    /// with no hints, no slip and no question asked.
    pub(crate) async fn through(
        &self,
        home: &swoosh::home::Home,
        machine: &PeerMachine,
        contacts: &Contacts,
    ) -> Ran {
        use swoosh::streams::{Resident, Tracked};

        let socket = Rc::new(swoosh::node_client::UidSocket::resolve(home).unwrap());
        let source = Tracked::new(
            Resident::new(Rc::clone(&socket)),
            std::collections::HashMap::new(),
        );
        let service = match self {
            Self::Ping(_) => swoosh::reach::PING_SERVICE.parse().unwrap(),
            Self::Status(_) => crate::commands::status::StatusCmd::service(machine).unwrap(),
            Self::Speed(_) => swoosh::reach::SPEED_SERVICE.parse().unwrap(),
        };
        let dial = Dial {
            machine,
            service: &service,
            contacts,
        };
        let route = crate::commands::route::Route::Serve {
            dial: &dial,
            socket: &socket,
        };
        self.run(&source, &route, machine).await
    }

    /// Run the verb by own bind over `peers`, from `home` as `this`, to `machine`, with no question
    /// asked.
    pub(crate) async fn by_own_bind<T: bifrost::Transport, D: bifrost::Discovery>(
        &self,
        peers: &swoosh::peers::Peers<'_, T, D>,
        home: &swoosh::home::Home,
        this: NodeId,
        machine: &PeerMachine,
    ) -> Ran {
        let (peer, service) = match self {
            Self::Ping(cmd) => (&cmd.peer, swoosh::reach::PING_SERVICE),
            Self::Status(cmd) => (cmd.peer.as_ref().unwrap(), swoosh::reach::PING_SERVICE),
            Self::Speed(cmd) => (&cmd.peer, swoosh::reach::SPEED_SERVICE),
        };
        let bound = swoosh::transport::Bound {
            local: false,
            reach: swoosh::transport::Reach::default(),
        };
        let route = crate::commands::route::Route::Own {
            bound: &bound,
            this,
        };
        let credential = swoosh::credential::Credential::dialing(peer, service);
        let own = swoosh::streams::OwnBind::new(peers, home, this, &credential);
        self.run(own, &route, machine).await
    }

    /// The verb's one body over `source`, as `route` words it.
    async fn run(
        &self,
        source: impl swoosh::streams::Observing + Copy,
        route: &crate::commands::route::Route<'_>,
        machine: &PeerMachine,
    ) -> Ran {
        use swoosh::learn::Admitted;

        let (mut out, mut err) = (Vec::new(), Vec::new());
        let ended = match self {
            Self::Ping(cmd) => {
                cmd.probe(
                    source,
                    route,
                    machine,
                    Admitted::unheard(),
                    &mut out,
                    &mut err,
                )
                .await
            }
            Self::Status(cmd) => {
                cmd.probe(
                    source,
                    route,
                    machine,
                    Admitted::unheard(),
                    &mut out,
                    &mut err,
                )
                .await
            }
            Self::Speed(cmd) => {
                cmd.measure(
                    source,
                    route,
                    machine,
                    Admitted::unheard(),
                    &mut out,
                    &mut err,
                )
                .await
            }
        };
        let (out, err) = (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        );
        // Every run here is held to the screen law on the bytes a person would see: what it printed, and
        // a refusal as the composition root prints it. A `Reported` one is already on `err`.
        for captured in [&out, &err] {
            if let Err(breach) = crate::screen::law::holds(captured) {
                panic!("{breach}\n{captured}");
            }
        }
        if let Err(report) = &ended
            && !report.is::<super::Reported>()
        {
            let lines = crate::error_lines(report, &Vec::new());
            if let Err(breach) = crate::screen::law::read(&lines) {
                panic!("{breach}\n{lines}");
            }
        }
        Ran { ended, out, err }
    }
}

/// What a run through `serve` did, in order: each line it wrote to stderr, as `stderr: <line>`, and each
/// query on its receipt, as `Sample` or `Finish`. A query reads the next of the replies it was given, or
/// `Unavailable` once they run out.
#[derive(Clone, Default)]
pub(crate) struct Events {
    log: Rc<RefCell<Vec<String>>>,
    replies: Rc<RefCell<VecDeque<PathReply>>>,
    /// What this writer has written and not yet ended by a newline.
    pending: Rc<RefCell<String>>,
    /// Whether this writer stands for stdout rather than stderr.
    stdout: bool,
    /// Whether the resident takes every query and never answers it.
    stall: bool,
    /// How long the resident takes to answer each query.
    delay: core::time::Duration,
}

impl Events {
    /// A resident that answers the queries with `replies`, in order.
    pub(crate) fn answering(replies: impl IntoIterator<Item = PathReply>) -> Self {
        Self {
            replies: Rc::new(RefCell::new(replies.into_iter().collect())),
            ..Self::default()
        }
    }

    /// This resident, answering each query only `delay` after it starts.
    pub(crate) fn slow(self, delay: core::time::Duration) -> Self {
        Self { delay, ..self }
    }

    /// A writer into the same log that stands for stdout: its lines read `stdout: <line>`.
    pub(crate) fn stdout(&self) -> Self {
        Self {
            pending: Rc::default(),
            stdout: true,
            ..self.clone()
        }
    }

    /// A resident that takes every query and never answers it.
    pub(crate) fn stalling() -> Self {
        Self {
            stall: true,
            ..Self::default()
        }
    }

    /// An observer of an Open that attached reading `attached`, its queries answered here.
    pub(crate) async fn observer(&self, attached: ConnInfo) -> Observer<Self> {
        Observer::new(
            Receipt::new(reference().await, Rc::new(self.clone())),
            attached,
        )
    }

    /// What happened so far.
    pub(crate) fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
}

impl PathSource for Events {
    async fn path(&self, request: PathRequest) -> Result<PathReply, ControlError> {
        self.log.borrow_mut().push(format!("{:?}", request.action));
        if self.stall {
            return core::future::pending().await;
        }
        tokio::time::sleep(self.delay).await;
        let reply = self.replies.borrow_mut().pop_front();
        Ok(reply.unwrap_or(PathReply::Unavailable))
    }
}

/// A test writer, so plain: it never shows style.
impl crate::screen::Paint for Events {}

impl std::io::Write for Events {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut pending = self.pending.borrow_mut();
        pending.push_str(&String::from_utf8_lossy(buf));
        while let Some(end) = pending.find('\n') {
            let line: String = pending.drain(..=end).collect();
            let stream = if self.stdout { "stdout" } else { "stderr" };
            self.log
                .borrow_mut()
                .push(format!("{stream}: {}", line.trim_end()));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A stdout whose every write fails, as a closed pipe's does.
pub(crate) struct Unwritable;

/// A test writer, so plain: it never shows style.
impl crate::screen::Paint for Unwritable {}

impl std::io::Write for Unwritable {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(tokio::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(tokio::io::ErrorKind::BrokenPipe.into())
    }
}

/// An observed Open's reference, read from an Attached as the client reads one.
async fn reference() -> PathRef {
    use swoosh::serve::control_codec::Response;

    let mut frame = control_frame(b"\x06\x00\x1c\x01");
    frame.extend_from_slice(&[7; 16]);
    frame.extend_from_slice(&1_u64.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0]);
    match Response::read_open(&mut frame.as_slice()).await.unwrap() {
        Response::Attached(attached) => attached.reference.unwrap(),
        other => panic!("not attached: {other:?}"),
    }
}

/// A path reading of `path`.
pub(crate) fn reading(path: bifrost::Path) -> ConnInfo {
    ConnInfo {
        path,
        rtt: None,
        remote: None,
    }
}

/// A relayed path, through `relay.example`.
pub(crate) fn relayed() -> bifrost::Path {
    bifrost::Path::Relayed(bifrost::Relay::from(
        url::Url::parse("https://relay.example/").unwrap(),
    ))
}

/// How `report` prints at the composition root.
fn printed(report: &eyre::Report) -> String {
    format!("error: {report:#}\n")
}

/// The reach flags `argv` sets on a `forward`, read as clap reads them.
fn reach(argv: &[&str]) -> ReachArgs {
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct Forward {
        #[command(flatten)]
        reach: ReachArgs,
    }
    Forward::parse_from(argv).reach
}

#[test]
fn a_reach_flag_while_serve_runs_names_the_first_set() {
    let line = |argv: &[&str]| Moot::first(&reach(argv)).map(|moot| printed(&moot.into()));
    assert_eq!(line(&["forward"]), None);
    assert_eq!(
        line(&["forward", "--resolver", "https://dns.example", "--local"]).unwrap(),
        "error: --local or SWOOSH_LOCAL does not apply while swoosh serve runs here\n  Commands \
         here connect through swoosh serve.\n  Set it on swoosh serve, or stop swoosh serve and run \
         this command again.\n"
    );
    assert!(
        line(&["forward", "--resolver", "https://dns.example"])
            .unwrap()
            .starts_with("error: --resolver or SWOOSH_RESOLVER does not apply")
    );
    assert!(
        line(&[
            "forward",
            "--relay",
            "https://relay.example",
            "--resolver",
            "https://dns.example"
        ])
        .unwrap()
        .starts_with("error: --relay or SWOOSH_RELAY does not apply")
    );
}

#[test]
fn serve_lines_keep_their_ruled_words() {
    assert_eq!(
        printed(&Busy.into()),
        "error: too many connections open through swoosh serve on this machine\n  Close one, or \
         wait for one to end, then try again.\n"
    );
    assert_eq!(
        printed(&Skew.into()),
        "error: swoosh serve on this machine is a different version\n  Restart it with this \
         version.\n"
    );
}

/// The two lines a cut prints: `serve`'s own when it is gone, else the own bind's. Which one is
/// [`UidSocket::gone`](swoosh::node_client::UidSocket::gone)'s call, held by
/// `send_ends_when_serve_stops_before_an_open_is_answered` against a resident that went and one still up.
#[test]
fn a_cut_names_serve_only_when_it_is_gone_and_otherwise_is_connection_lost() {
    let contacts = book();
    let named = Machine::of(&contacts, nas());
    let stopped: eyre::Report = super::ServeStopped(named.to_string()).into();
    assert_eq!(
        printed(&stopped),
        "error: swoosh serve stopped here and ended the connection to me/nas\n  Commands here \
         connect through it while it runs.\n  Run this command again to reconnect.\n"
    );
    let lost: eyre::Report = ConnectionLost.into();
    assert_eq!(printed(&lost), "error: connection lost\n");
}

#[test]
fn this_machine_prints_as_it_was_typed() {
    let contacts = book();
    assert_eq!(
        ThisMachine::of(&machine(&contacts, "me/nas")).to_string(),
        "me/nas is this machine"
    );
    assert_eq!(
        ThisMachine::of(&machine(&Contacts::default(), &nas().to_string())).to_string(),
        "that key is this machine's"
    );
}

/// The status a `serve` running as `node_id` answers.
pub(crate) fn status_of(node_id: NodeId) -> StatusReply {
    StatusReply {
        node_id,
        pid: 1,
        reach: swoosh::testkit::loopback_reach(),
        uptime_secs: 0,
        menu: ServiceMenu {
            catalog: tightbeam::tunnel::ServiceCatalog::decode(&0_u32.to_be_bytes()).unwrap(),
            disabled: DisabledList::Known(Vec::new()),
        },
        warm: Vec::new(),
    }
}

/// What a `serve` running as `node_id` answers `asked`, a `Whoami` (the probe) or a `Status` (an ask after
/// an Open went unanswered): the same `serve` either way.
pub(crate) fn answer_of(asked: &Request, node_id: NodeId) -> Response {
    match asked {
        Request::Whoami => Response::Whoami { node_id },
        _ => Response::Status(status_of(node_id)),
    }
}

/// A `serve` that answers status as the machine `this`, or not at all, and nothing else.
struct Serve(Option<NodeId>);

impl NodeClient for Serve {
    async fn services(&self) -> Result<ServiceMenu, ControlError> {
        Err(ControlError::NoResident)
    }

    async fn status(&self) -> Result<StatusReply, ControlError> {
        self.0.map(status_of).ok_or(ControlError::NoResident)
    }

    async fn stop(&self) -> Result<(), ControlError> {
        Err(ControlError::NoResident)
    }
}

#[tokio::test]
async fn an_ended_standing_names_the_own_binds_remedy_when_serve_says_who_it_is() {
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ssh".parse().unwrap();
    let pipe = Dial {
        machine: &peer,
        service: &service,
        contacts: &contacts,
    };
    let this = NodeId::from_ed25519_secret(&[0x62; 32]);
    let head = "error: this device's standing has ended, so a machine that admits only your devices \
                will refuse this dial";
    let named = pipe
        .refused(OpenRefusal::StandingEnded, &Serve(Some(this)))
        .await;
    assert!(named.is::<StandingEnded>());
    assert_eq!(
        printed(&named),
        format!("{head}\n{}\n", swoosh::badge::remedy(this))
    );
    // `serve`'s status cannot be read: the head alone, never a remedy keyed to a guess.
    let alone = pipe.refused(OpenRefusal::StandingEnded, &Serve(None)).await;
    assert_eq!(printed(&alone), format!("{head}\n"));
}

#[tokio::test]
async fn a_refusal_through_serve_prints_the_own_binds_line() {
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ssh".parse().unwrap();
    let pipe = Dial {
        machine: &peer,
        service: &service,
        contacts: &contacts,
    };
    // The dial refusal for one of your devices, with no cause asked: the same head the own bind prints
    // when it cannot tell.
    assert_eq!(
        printed(
            &pipe
                .refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted), &Serve(None))
                .await
        ),
        printed(&crate::commands::machine::refused(&peer, &service, None))
    );
    assert!(
        pipe.refused(OpenRefusal::Busy, &Serve(None))
            .await
            .is::<Busy>()
    );
    assert!(
        pipe.refused(OpenRefusal::NotHere, &Serve(None))
            .await
            .is::<ThisMachine>()
    );
    // Peer text is escaped, as every peer word in an error chain is.
    let hostile = RefusalDetail::try_from("no\u{1b}[2K").unwrap();
    let line = printed(
        &pipe
            .refused(
                OpenRefusal::Peer(PeerRefusal::Unavailable(hostile)),
                &Serve(None),
            )
            .await,
    );
    assert!(!line.contains('\u{1b}'), "{line}");
}

/// A machine's refusal in wide glyphs, through `serve`, the path most dials take: the `error:` line is cut
/// to its room, counted at two columns for every scalar that is not ASCII, so the reason cannot wrap and
/// start a forged line of its own.
#[tokio::test]
async fn a_wide_refusal_through_serve_cannot_forge_a_line() {
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ssh".parse().unwrap();
    let pipe = Dial {
        machine: &peer,
        service: &service,
        contacts: &contacts,
    };
    let forged = "error: me/boss refused ssh";
    let wide = format!("{}{forged}", "\u{6587}\u{4ef6}".repeat(40));
    let wide = RefusalDetail::bounded(&wide);
    for refusal in [
        OpenRefusal::Peer(PeerRefusal::Unavailable(wide.clone())),
        OpenRefusal::Unreachable(wide.clone()),
        OpenRefusal::Broken(wide),
    ] {
        let line = printed(&pipe.refused(refusal, &Serve(None)).await);
        assert!(columns_at_most(&line) < 80, "{line}");
        assert!(!line.contains(forged), "{line}");
    }
}

/// A dial that timed out, which the resident reports as Unreachable with the words `timed out`, prints
/// what a `Timeout` prints, on both paths: only `stop` tells the two apart.
#[tokio::test]
async fn a_dial_timeout_prints_as_a_timeout_on_both_paths() {
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ssh".parse().unwrap();
    let pipe = Dial {
        machine: &peer,
        service: &service,
        contacts: &contacts,
    };
    use swoosh::streams::Unopened::Refused;

    let dial_timeout = || OpenRefusal::Unreachable(RefusalDetail::bounded("timed out"));
    assert_eq!(
        printed(&pipe.refused(dial_timeout(), &Serve(None)).await),
        printed(&pipe.refused(OpenRefusal::Timeout, &Serve(None)).await)
    );
    let bound = crate::probe_route_tests::bound();
    let own = crate::commands::route::Route::Own {
        bound: &bound,
        this: resident_key(),
    };
    assert_eq!(
        printed(&own.line(Refused(dial_timeout()), &peer).await),
        printed(&own.line(Refused(OpenRefusal::Timeout), &peer).await)
    );
}

/// A home with this process recorded as its `serve` and the control socket bound, as `serve` binds it:
/// a verb run here finds a resident, and the test answers as that resident.
pub(crate) struct Served {
    pub(crate) home: swoosh::home::Home,
    dir: std::path::PathBuf,
    listener: Option<std::os::unix::net::UnixListener>,
    lock: Option<swoosh::serve::InstanceLock>,
}

impl Served {
    pub(crate) async fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("swoosh-ts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let home = swoosh::home::Home::resolve(Some(dir.clone())).unwrap();
        let root = swoosh::home::runtime_root().unwrap();
        // Other tests in this binary build their socket's leaf with `create_dir_all`, which leaves a fresh
        // shared root at the umask's mode; `acquire_single` rightly refuses a loosened root it did not make.
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (lock, listener) = swoosh::serve::acquire_single(&home, &root).await.unwrap();
        Self {
            home,
            dir,
            listener: Some(listener),
            lock: Some(lock),
        }
    }

    /// The bound socket, as the resident takes it.
    pub(crate) fn listener(&mut self) -> std::os::unix::net::UnixListener {
        self.listener.take().unwrap()
    }

    /// The held `serve.lock`, for a resident that stops: dropping it unlinks the socket and frees the
    /// lock, as `serve` exiting does.
    pub(crate) fn lock(&mut self) -> swoosh::serve::InstanceLock {
        self.lock.take().unwrap()
    }
}

/// The socket of the `serve` the probe found answering at `home`.
pub(crate) async fn answering(home: &swoosh::home::Home) -> swoosh::node_client::UidSocket {
    answering_as(home).await.0
}

/// [`answering`], with the key the `serve` said it runs as.
pub(crate) async fn answering_as(
    home: &swoosh::home::Home,
) -> (swoosh::node_client::UidSocket, NodeId) {
    match super::serve(home).await.unwrap() {
        super::Found::Answering { socket, this } => (socket, this),
        super::Found::Absent => panic!("serve answers"),
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Open `me/nas`'s `ssh` through the `serve` at `served`, the test answering as the resident with an
/// Attached reading `info`. Returns the stream and the resident's end of its connection.
async fn attached(
    served: &mut Served,
    info: bifrost::ConnInfo,
) -> (Stream, tokio::net::UnixStream) {
    use swoosh::serve::control_codec::{Attached, Observation, OpenLane, Request, Response};

    let listener = served.listener();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let ask = swoosh::streams::Ask {
        lane: OpenLane::Main,
        ..crate::commands::connect::tests::listening(&peer)
    };
    // One connection, the Open's own: a probe first would be the connection the resident takes.
    let connected = swoosh::node_client::UidSocket::resolve(&served.home)
        .unwrap()
        .connected()
        .await
        .unwrap();
    let resident = async {
        let (mut conn, _) = listener.accept().await.unwrap();
        Request::read(&mut conn).await.unwrap();
        Response::Attached(Attached::from(info))
            .write(&mut conn)
            .await
            .unwrap();
        conn
    };
    let (attached, conn) = tokio::join!(
        swoosh::streams::Resident::attach(connected, &ask, Observation::Unobserved),
        resident
    );
    let (stream, _reference) = attached.unwrap();
    (stream, conn)
}

fn direct() -> bifrost::ConnInfo {
    bifrost::ConnInfo {
        path: bifrost::Path::Direct,
        rtt: None,
        remote: None,
    }
}

/// Through `serve`, `delivered` writes no End and never resolves: the word that the peer holds the upload
/// is Landed, on the read half. It holds the half while it waits, so the direction closes, without End,
/// only once the caller drops the wait.
#[tokio::test]
async fn delivered_through_serve_writes_no_end_and_waits_for_its_caller() {
    use bifrost::{Session as _, WriteEnd as _};
    use tokio::io::AsyncReadExt as _;

    let mut served = Served::new("delivered").await;
    let (stream, mut conn) = attached(&mut served, direct()).await;
    let session = swoosh::streams::OneStream::new(
        nas(),
        swoosh::streams::Opened {
            info: stream.info,
            write: swoosh::streams::Upload::from(stream.write),
            read: stream.read,
        },
        (),
    );
    let (upload, _download) = session.open_bi().await.unwrap();
    let mut delivered = Box::pin(upload.delivered());
    assert!(futures::poll!(delivered.as_mut()).is_pending());
    tokio::task::yield_now().await;
    let mut buf = [0; 16];
    assert!(
        matches!(conn.try_read(&mut buf), Err(error) if error.kind() == tokio::io::ErrorKind::WouldBlock),
        "the resident heard something"
    );
    drop(delivered);
    let mut rest = Vec::new();
    conn.read_to_end(&mut rest).await.unwrap();
    assert!(
        rest.is_empty(),
        "an End or Data reached the resident: {rest:?}"
    );
}

/// `serve` gave one stream: `OneStream` hands it out once and refuses every other, and reports the
/// machine asked for and the path as the stream attached.
#[tokio::test]
async fn one_stream_hands_out_its_stream_once() {
    use bifrost::Session as _;

    let mut served = Served::new("onestream").await;
    let (stream, _conn) = attached(&mut served, direct()).await;
    let session = swoosh::streams::OneStream::new(
        nas(),
        swoosh::streams::Opened {
            info: stream.info,
            write: swoosh::streams::Upload::from(stream.write),
            read: stream.read,
        },
        (),
    );
    assert_eq!(session.peer(), nas());
    assert_eq!(session.conn_info(), direct());
    assert!(matches!(
        session.accept_bi().await,
        Err(bifrost::Error::Closed)
    ));
    assert!(session.open_bi().await.is_ok());
    assert!(matches!(
        session.open_bi().await,
        Err(bifrost::Error::Closed)
    ));
}

/// A pick-up that finds no renewal: this home has no standing to renew.
struct NoRenewal;

impl swoosh::renewal::Fetch for NoRenewal {
    async fn fetch(
        &self,
        _peer: NodeId,
    ) -> Result<Option<nauthy::Link>, swoosh::renewal::FetchError> {
        Ok(None)
    }
}

/// Drive `runs` on an 8 MiB thread, as the gated measure proof is: over mem both ends' transfer buffers
/// share one thread's stack.
pub(crate) fn on_a_big_stack(runs: impl AsyncFnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(runs()));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// A machine serving `public` to anyone, so a dial presenting nothing is admitted, and this machine's
/// `serve` on a fresh home's socket: `runs` gets the home and a book naming the machine `name`, and the
/// resident answers while it runs.
async fn through_the_resident(
    tag: &str,
    public: &'static [&'static str],
    name: &str,
    runs: impl AsyncFnOnce(&swoosh::home::Home, &Contacts),
) {
    use bifrost::{NoDiscovery, Node};
    use bifrost_mem::MemTransport;
    use tightbeam::tunnel::{self, CancellationToken, Router};

    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let denylist =
        std::env::temp_dir().join(format!("swoosh-ts-deny-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&denylist);
    let denylist = nauthy::Denylist::load(denylist).unwrap();
    tokio::task::spawn_local(async move {
        let public: Vec<nauthy::Service> = public
            .iter()
            .map(|service| service.parse().unwrap())
            .collect();
        let gate = tunnel::resolve_gate(Some(host_id), denylist).unwrap();
        swoosh::serve::diagnostics(Router::new(gate), &public)
            .unwrap()
            .expose()
            .unwrap()
            .run(&host, CancellationToken::new())
            .await;
    });

    let mut served = Served::new(tag).await;
    let listener = served.listener();
    let node = Node::new(MemTransport::bind(), NoDiscovery);
    let peers = swoosh::peers::Peers::new(&node);
    let renewal = swoosh::renewal::OpenRenewal::new(&served.home, &NoRenewal);
    let opener =
        swoosh::serve::Opener::new(&peers, &renewal, &served.home, node.node_id()).unwrap();
    let resident = std::sync::Arc::new(swoosh::serve::Resident::new(
        node.node_id(),
        swoosh::testkit::loopback_source(),
        tightbeam::tunnel::ServiceCatalog::decode(&0_u32.to_be_bytes()).unwrap(),
        swoosh::serve_toml::LiveServeToml::load(&served.home).unwrap(),
        CancellationToken::new(),
        std::sync::Arc::default(),
    ));

    let mut contacts = Contacts::default();
    contacts.save(&name.parse().unwrap(), host_id).unwrap();
    tokio::select! {
        ended = resident.serve(listener, &opener) => panic!("the resident stopped: {ended:?}"),
        () = runs(&served.home, &contacts) => {}
    }
}

/// `speed` through a running `serve`, end to end: the verb's Open reaches the real resident on this
/// home's socket, the resident dials the machine on a connection of its own, measure's responder there
/// answers each mode, and the run's Finish reads the path through the same socket.
#[test]
fn speed_runs_through_the_resident_against_measures_responder() {
    on_a_big_stack(async || {
        through_the_resident("speed", &["speed"], "me/nas", async |home, contacts| {
            // Byte-bounded runs end on the count, so only a time-bounded upload waits on the verb's End
            // for its reply: that leg runs a real 50 ms window, since measure reads the wall clock.
            for argv in [
                ["--down", "-n", "262144"],
                ["--up", "-n", "262144"],
                ["--bidir", "-n", "262144"],
                ["--up", "-t", "0.05"],
            ] {
                let cmd = Dialing::of(&[&["speed", "me/nas"][..], &argv].concat());
                let machine = machine(contacts, "me/nas");
                let ran = tokio::time::timeout(
                    core::time::Duration::from_secs(10),
                    cmd.through(home, &machine, contacts),
                )
                .await
                .expect("the run never ended");
                assert!(ran.ended.is_ok(), "not a run through serve that measured");
            }
        })
        .await;
    });
}

/// `ping` and `status <machine>` through a running `serve`, end to end: each verb's one observed Open
/// rides the resident's held session to the machine, measure's responder answers its probes there, and
/// the run's Finish reads the path through the same socket.
#[test]
fn ping_and_status_run_through_the_resident_on_its_held_session() {
    on_a_big_stack(async || {
        through_the_resident("ping", &["ping"], "bob/nas", async |home, contacts| {
            for argv in [
                &["ping", "bob/nas", "-c", "2", "-i", "0.05"][..],
                &["ping", "bob/nas", "-v", "-c", "1"],
                &["status", "bob/nas"],
            ] {
                // The open `ping` route admits one run a second per caller, and every run here is the
                // resident's, so each waits out the last one's.
                tokio::time::sleep(core::time::Duration::from_millis(1100)).await;
                let machine = machine(contacts, "bob/nas");
                let ran = tokio::time::timeout(
                    core::time::Duration::from_secs(10),
                    Dialing::of(argv).through(home, &machine, contacts),
                )
                .await
                .expect("the run never ended");
                assert!(
                    ran.ended.is_ok(),
                    "not a run through serve that answered: {argv:?}"
                );
            }
        })
        .await;
    });
}

/// `ping` and `status <machine>` through `serve` make one Open each, observed, on the held Main session,
/// for the service the probe names: `control.serve` for one of your devices.
#[tokio::test]
async fn ping_and_status_open_once_observed_on_main() {
    use swoosh::serve::control_codec::{Observation, OpenLane, Request, Response};

    for (argv, service) in [
        (["ping", "me/nas"], "ping"),
        (["status", "me/nas"], "control.serve"),
    ] {
        let mut served = Served::new(&format!("open-{}", argv[0])).await;
        let listener = served.listener();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::UnixListener::from_std(listener).unwrap();
        let contacts = book();
        let peer = machine(&contacts, "me/nas");
        let resident = async {
            let (mut conn, _) = listener.accept().await.unwrap();
            let Request::Open(open) = Request::read(&mut conn).await.unwrap() else {
                panic!("not an Open");
            };
            Response::OpenRefusal(OpenRefusal::Busy)
                .write(&mut conn)
                .await
                .unwrap();
            (open.lane(), open.observation(), open.service().to_string())
        };
        let cmd = Dialing::of(&argv);
        let run = cmd.through(&served.home, &peer, &contacts);
        let (ran, asked) = tokio::time::timeout(core::time::Duration::from_secs(10), async {
            tokio::join!(run, resident)
        })
        .await
        .expect("the Open was answered");
        let Err(busy) = ran.ended else {
            panic!("not a run through serve that ended in its refusal");
        };
        assert!(busy.is::<Busy>(), "{busy:#}");
        assert_eq!(
            asked,
            (OpenLane::Main, Observation::Observed, service.to_owned())
        );
    }
}

/// An Open the resident refused reaches `ping` and `status <machine>` typed, so each prints the own
/// bind's outcome: an unreachable machine reads `could not reach`, with no reach hint.
#[tokio::test]
async fn an_unreachable_open_reaches_ping_and_status_as_their_own_line() {
    use swoosh::serve::control_codec::{Request, Response};

    for argv in [["ping", "me/nas"], ["status", "me/nas"]] {
        let mut served = Served::new(&format!("unreached-{}", argv[0])).await;
        let listener = served.listener();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::UnixListener::from_std(listener).unwrap();
        let contacts = book();
        let peer = machine(&contacts, "me/nas");
        let resident = async {
            let (mut conn, _) = listener.accept().await.unwrap();
            Request::read(&mut conn).await.unwrap();
            Response::OpenRefusal(OpenRefusal::Unreachable(RefusalDetail::bounded("no route")))
                .write(&mut conn)
                .await
                .unwrap();
        };
        let cmd = Dialing::of(&argv);
        let run = cmd.through(&served.home, &peer, &contacts);
        let (ran, ()) = tokio::time::timeout(core::time::Duration::from_secs(10), async {
            tokio::join!(run, resident)
        })
        .await
        .expect("the Open was answered");
        let Err(unreached) = ran.ended else {
            panic!("not a run through serve that ended unreached");
        };
        assert_eq!(printed(&unreached), "error: could not reach me/nas\n");
    }
}

/// Asking whether `serve` went after a run broke takes at most a second: a resident that accepts and
/// stalls is there, so the answer is that it did not, and the run's own line stands.
#[tokio::test]
async fn asking_a_stalled_serve_whether_it_went_is_bounded_and_says_no() {
    let mut served = Served::new("stalled").await;
    let listener = served.listener();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ping".parse().unwrap();
    let dial = Dial {
        machine: &peer,
        service: &service,
        contacts: &contacts,
    };
    let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
    // Every connection is taken and held, and nothing is ever answered.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            held.push(conn);
        }
    });
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let stopped = tokio::time::timeout(core::time::Duration::from_secs(60), dial.stopped(&socket))
        .await
        .expect("the ask ends");
    assert!(stopped.is_none(), "a stalled serve is not a stopped one");
    // The timer's own granularity may add a millisecond.
    let bound = core::time::Duration::from_secs(1);
    assert!(
        (bound..bound + core::time::Duration::from_millis(50)).contains(&started.elapsed()),
        "{:?}",
        started.elapsed()
    );
}

/// An End frame as the resident reads one: the magic, tag 11 and an empty body (`serve/socket/splice.rs`).
pub(crate) const END: [u8; 7] = control_header(0x0b, 0);

/// A Landed frame: tag 12, empty, toward the client only.
const LANDED: [u8; 7] = control_header(0x0c, 0);

/// `bytes` as one Data frame, tag 10 (at most a frame's 8 KiB).
pub(crate) fn data(bytes: &[u8]) -> Vec<u8> {
    let mut frame = control_frame(b"\x0a");
    frame.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(bytes);
    frame
}

/// The key the scripted resident's status names, so an ended standing's remedy has one to name.
pub(crate) fn resident_key() -> NodeId {
    NodeId::from_ed25519_secret(&[0x77; 32])
}

/// How the scripted resident answers one Open.
pub(crate) enum Answer {
    /// Attach, end the download with End, and keep what the client uploads until it hangs up.
    Attach,
    /// Attach, send these bytes and End, and answer the client's End with Landed.
    Exchange(Vec<u8>),
    /// Attach, read the client's upload to its End, and only then send these bytes and End: a client
    /// that reads before it ends its upload waits forever.
    AfterEnd(Vec<u8>),
    /// Attach, then drop the connection with no End: a cut, the resident still up.
    Cut,
    /// Attach, send these bytes with no End, and drop the connection once the row's `cut` fires: a cut
    /// mid-download, the resident still up.
    SaysThenCut(Vec<u8>),
    /// Attach, end the download with End, then drop the connection with no Landed, the resident still
    /// up.
    EndThenCut,
    /// Attach, end the download with End, then stop with no Landed: the socket and the lock go before the
    /// connection does.
    EndThenStop,
    /// Attach, then stop: the socket and the lock go before the connection does, as when `serve` exits
    /// under a pipe.
    Stop,
    /// Attach, then stop accepting and cut the connection while the lock stays held, as a live `serve`
    /// whose accept queue is full refuses connects, until the row's `stop`.
    Deaf,
    /// Reply as a `serve` of another control version.
    Version,
    /// Reply with the resident's own error, this reason.
    Error(&'static str),
    /// Hear the Open and drop its connection with no reply, the resident still up.
    Hangup,
    /// Hear the Open and never reply to it, still serving every other connection: a resident whose
    /// machine is slow to answer.
    Stall,
    /// Hear the Open and never reply, serving nothing more until the row's `stop`, its listener and lock
    /// kept: a stalled resident, whose kernel still takes connects.
    Wedge,
    /// Hear the Open, then stop with no reply: the socket and the lock go before the connection does.
    Vanish,
    /// Refuse it so.
    Refuse(OpenRefusal),
}

/// One Open the scripted resident heard: what it asked for, and what an attached one uploaded.
pub(crate) struct Heard {
    pub(crate) peer: NodeId,
    pub(crate) hints: Vec<core::net::SocketAddr>,
    pub(crate) service: String,
    pub(crate) lane: swoosh::serve::control_codec::OpenLane,
    pub(crate) observation: swoosh::serve::control_codec::Observation,
    pub(crate) slip: Option<String>,
    pub(crate) upload: Vec<u8>,
}

/// What a row holds of its scripted resident: `stop` ends it (it stops on its own once its answers run
/// out, unless it went deaf), and `landed` is told each time it answers an upload's End with Landed. A
/// [`routed`] resident orders its held replies by the other two: `held` once it hears an Open whose reply
/// waits ([`Reply::AfterVersion`]), `versioned` once a client hung up on its [`Reply::VersionAfterHeld`].
#[derive(Default)]
pub(crate) struct Rig {
    pub(crate) stop: tightbeam::tunnel::CancellationToken,
    pub(crate) landed: std::sync::Arc<tokio::sync::Notify>,
    pub(crate) held: tightbeam::tunnel::CancellationToken,
    pub(crate) versioned: tightbeam::tunnel::CancellationToken,
    /// The key a [`routed`] resident's status names, [`resident_key`] when unset.
    pub(crate) key: Option<NodeId>,
    /// Told each time a [`routed`] resident hears an Open, before it replies.
    pub(crate) heard: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// Whether a [`routed`] resident starts as [`Reply::Wedge`] leaves it, answering nothing.
    pub(crate) wedged: bool,
    /// Fired by a row to cut a [`scripted`] resident's [`Answer::SaysThenCut`] connection.
    pub(crate) cut: tightbeam::tunnel::CancellationToken,
}

/// A resident on `served`'s socket that reads one request per connection and answers each Open with the
/// next of `answers`, then stops, its lock freed and its socket gone, once they run out. A status ask
/// is answered as [`resident_key`]. Resolves to the Opens it heard, once every attached one's client
/// has hung up.
pub(crate) fn scripted(
    served: &mut Served,
    answers: Vec<Answer>,
    rig: &Rig,
) -> tokio::task::JoinHandle<Vec<Heard>> {
    use swoosh::serve::control_codec::{Attached, Request, Response};
    use tokio::io::AsyncWriteExt as _;

    let listener = served.listener();
    listener.set_nonblocking(true).unwrap();
    let mut listener = Some(tokio::net::UnixListener::from_std(listener).unwrap());
    let mut lock = Some(served.lock());
    let stop = rig.stop.clone();
    let cut = rig.cut.clone();
    let landed = std::sync::Arc::clone(&rig.landed);
    tokio::spawn(async move {
        let mut answers = VecDeque::from(answers);
        let mut heard = Vec::new();
        let mut held = Vec::new();
        let mut deaf = false;
        while let Some(accepting) = listener.as_ref().filter(|_| !answers.is_empty()) {
            let (mut conn, _) = tokio::select! {
                accepted = accepting.accept() => accepted.unwrap(),
                () = stop.cancelled() => break,
            };
            let open = match Request::read(&mut conn).await {
                Ok(Request::Open(open)) => open,
                Ok(asked @ (Request::Status | Request::Whoami)) => {
                    let _ = answer_of(&asked, resident_key()).write(&mut conn).await;
                    continue;
                }
                _ => continue,
            };
            heard.push(Heard {
                peer: open.peer(),
                hints: open.hints().as_slice().to_vec(),
                service: open.service().to_string(),
                lane: open.lane(),
                observation: open.observation(),
                slip: open.slip().map(|slip| slip.as_str().to_owned()),
                upload: Vec::new(),
            });
            let at = heard.len() - 1;
            match answers.pop_front().unwrap() {
                // A client that gave up on its Open has closed the connection: nothing reads the reply.
                Answer::Refuse(refusal) => {
                    let _ = Response::OpenRefusal(refusal).write(&mut conn).await;
                }
                // Another control version's magic: the client reads no further.
                Answer::Version => {
                    let _ = conn.write_all(b"SWC9").await;
                }
                Answer::Hangup => drop(conn),
                Answer::Stall => held.push((at, tokio::spawn(hold_silent(conn)))),
                Answer::Wedge => {
                    stop.cancelled().await;
                    drop(conn);
                    break;
                }
                Answer::Vanish => {
                    listener = None;
                    lock = None;
                    drop(conn);
                }
                // As a refusal: a client whose run already ended reads no reply.
                Answer::Error(reason) => {
                    let _ = Response::Error(reason.to_owned()).write(&mut conn).await;
                }
                attach => {
                    Response::Attached(Attached::from(direct()))
                        .write(&mut conn)
                        .await
                        .unwrap();
                    match attach {
                        Answer::Attach => held.push((at, tokio::spawn(hold(conn, None, None)))),
                        Answer::Exchange(download) => {
                            let landed = Some(std::sync::Arc::clone(&landed));
                            held.push((at, tokio::spawn(hold(conn, Some(download), landed))));
                        }
                        Answer::AfterEnd(download) => {
                            held.push((at, tokio::spawn(answer_after_end(conn, download))));
                        }
                        Answer::Stop => {
                            listener = None;
                            lock = None;
                            drop(conn);
                        }
                        Answer::EndThenCut => {
                            let _ = conn.write_all(&END).await;
                            drop(conn);
                        }
                        Answer::SaysThenCut(download) => {
                            let _ = conn.write_all(&data(&download)).await;
                            let cut = cut.clone();
                            held.push((
                                at,
                                tokio::spawn(async move {
                                    cut.cancelled().await;
                                    drop(conn);
                                    Vec::new()
                                }),
                            ));
                        }
                        Answer::EndThenStop => {
                            let _ = conn.write_all(&END).await;
                            listener = None;
                            lock = None;
                            drop(conn);
                        }
                        Answer::Deaf => {
                            listener = None;
                            deaf = true;
                            drop(conn);
                        }
                        _ => drop(conn),
                    }
                }
            }
        }
        drop(listener);
        if deaf {
            stop.cancelled().await;
        }
        drop(lock);
        for (at, holder) in held {
            heard[at].upload = holder.await.unwrap();
        }
        heard
    })
}

/// What a [`routed`] resident heard, in the order it heard it.
pub(crate) enum Event {
    /// A status ask, answered as [`resident_key`].
    Status,
    /// An Open, and what it uploaded once its client hung up.
    Open(Heard),
}

/// How a [`routed`] resident answers an Open.
pub(crate) enum Reply {
    /// Refuse it so.
    Refuse(OpenRefusal),
    /// Attach with a reference to sample its path by, end the download with End, and hold the
    /// connection until the client hangs up: an observed Open that attached.
    Observed,
    /// Attach, send these bytes and End, and answer the client's End with Landed.
    Exchange(Vec<u8>),
    /// Attach, read the client's one-frame request, then send these bytes and End and answer the client's
    /// End with Landed, as [`Exchange`](Self::Exchange) does. A client that ends its upload before the
    /// answer leaves gets no answer: the connection drops, as a node's teardown would drop it.
    Answer(Vec<u8>),
    /// Reply as a `serve` of another control version.
    Version,
    /// Hear the Open and never reply, still serving every other connection.
    Stall,
    /// Hear the Open and drop its connection with no reply, still serving.
    Hangup,
    /// Reply as a `serve` of another control version only once an Open held by [`AfterVersion`] is
    /// heard, so that Open was sent before the client read this reply.
    ///
    /// [`AfterVersion`]: Self::AfterVersion
    VersionAfterHeld,
    /// Hear the Open, and answer it as the inner [`Observed`] or [`Exchange`] only once a client hung up
    /// on a [`VersionAfterHeld`] reply: the client had read it, so its record is made, while this Open's
    /// run is still under way.
    ///
    /// [`Observed`]: Self::Observed
    /// [`Exchange`]: Self::Exchange
    /// [`VersionAfterHeld`]: Self::VersionAfterHeld
    AfterVersion(Box<Reply>),
    /// Hear the Open and never reply, and from then on take every connection and answer nothing on it,
    /// a status included, its lock kept: a stalled resident whose kernel still takes connects.
    Wedge,
}

/// A resident on `served`'s socket that answers each Open by its service, as `reply` says, and every
/// status ask as [`resident_key`], until `rig.stop`; its lock is held until then. A Path ask is dropped
/// unanswered. Resolves to what it heard, in order, once every held client has hung up.
pub(crate) fn routed(
    served: &mut Served,
    mut reply: impl FnMut(&str) -> Reply + Send + 'static,
    rig: &Rig,
) -> tokio::task::JoinHandle<Vec<Event>> {
    use swoosh::serve::control_codec::{Attached, Request, Response};
    use tokio::io::AsyncWriteExt as _;

    let listener = served.listener();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let lock = served.lock();
    let stop = rig.stop.clone();
    let landed = std::sync::Arc::clone(&rig.landed);
    let (held_heard, versioned) = (rig.held.clone(), rig.versioned.clone());
    let key = rig.key.unwrap_or_else(resident_key);
    let told = rig.heard.clone();
    let wedged_from_start = rig.wedged;
    tokio::spawn(async move {
        let mut events = Vec::new();
        let mut held = Vec::new();
        let mut wedged = wedged_from_start;
        loop {
            let (mut conn, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                () = stop.cancelled() => break,
            };
            let open = match Request::read(&mut conn).await {
                Ok(Request::Open(open)) => open,
                Ok(asked @ (Request::Status | Request::Whoami)) => {
                    events.push(Event::Status);
                    if wedged {
                        held.push((None, tokio::spawn(hold_silent(conn))));
                    } else {
                        let _ = answer_of(&asked, key).write(&mut conn).await;
                    }
                    continue;
                }
                _ => continue,
            };
            if let Some(told) = &told {
                told();
            }
            let service = open.service().to_string();
            events.push(Event::Open(Heard {
                peer: open.peer(),
                hints: open.hints().as_slice().to_vec(),
                service: service.clone(),
                lane: open.lane(),
                observation: open.observation(),
                slip: open.slip().map(|slip| slip.as_str().to_owned()),
                upload: Vec::new(),
            }));
            let at = Some(events.len() - 1);
            if wedged {
                held.push((at, tokio::spawn(hold_silent(conn))));
                continue;
            }
            match reply(&service) {
                Reply::Refuse(refusal) => {
                    let _ = Response::OpenRefusal(refusal).write(&mut conn).await;
                }
                Reply::Version => {
                    let _ = conn.write_all(b"SWC9").await;
                }
                Reply::Stall => held.push((at, tokio::spawn(hold_silent(conn)))),
                Reply::Hangup => drop(conn),
                Reply::Wedge => {
                    wedged = true;
                    held.push((at, tokio::spawn(hold_silent(conn))));
                }
                Reply::Observed => {
                    let attached = Attached {
                        reference: Some(reference().await),
                        info: direct(),
                    };
                    if Response::Attached(attached).write(&mut conn).await.is_ok() {
                        held.push((at, tokio::spawn(hold(conn, None, None))));
                    }
                }
                Reply::Exchange(download) => {
                    if Response::Attached(Attached::from(direct()))
                        .write(&mut conn)
                        .await
                        .is_ok()
                    {
                        let landed = Some(std::sync::Arc::clone(&landed));
                        held.push((at, tokio::spawn(hold(conn, Some(download), landed))));
                    }
                }
                Reply::Answer(download) => {
                    if Response::Attached(Attached::from(direct()))
                        .write(&mut conn)
                        .await
                        .is_ok()
                    {
                        let landed = std::sync::Arc::clone(&landed);
                        held.push((at, tokio::spawn(answer_request(conn, download, landed))));
                    }
                }
                // Spawned, so the resident hears the Open it waits on. Each wait also ends at `stop`, so a
                // client that never sends the other Open fails its row rather than hanging it.
                Reply::VersionAfterHeld => {
                    let (heard, versioned, stop) =
                        (held_heard.clone(), versioned.clone(), stop.clone());
                    held.push((
                        at,
                        tokio::spawn(async move {
                            use tokio::io::AsyncReadExt as _;
                            tokio::select! {
                                () = heard.cancelled() => {}
                                () = stop.cancelled() => return Vec::new(),
                            }
                            let _ = conn.write_all(b"SWC9").await;
                            // The client hangs up once it has read the reply, and records it then.
                            let mut sent = Vec::new();
                            let _ = conn.read_to_end(&mut sent).await;
                            versioned.cancel();
                            sent
                        }),
                    ));
                }
                Reply::AfterVersion(reply) => {
                    held_heard.cancel();
                    let (versioned, stop) = (versioned.clone(), stop.clone());
                    let landed = std::sync::Arc::clone(&landed);
                    held.push((
                        at,
                        tokio::spawn(async move {
                            tokio::select! {
                                () = versioned.cancelled() => {}
                                () = stop.cancelled() => return Vec::new(),
                            }
                            let (reference, download, landed) = match *reply {
                                Reply::Observed => (Some(reference().await), None, None),
                                Reply::Exchange(download) => (None, Some(download), Some(landed)),
                                _ => panic!("only an attaching reply waits on another's version"),
                            };
                            let attached = Attached {
                                reference,
                                info: direct(),
                            };
                            match Response::Attached(attached).write(&mut conn).await {
                                Ok(()) => hold(conn, download, landed).await,
                                Err(_) => Vec::new(),
                            }
                        }),
                    ));
                }
            }
        }
        drop(listener);
        drop(lock);
        for (at, holder) in held {
            let upload = holder.await.unwrap();
            if let Some(Event::Open(heard)) = at.map(|at| &mut events[at]) {
                heard.upload = upload;
            }
        }
        events
    })
}

/// Hold one attached connection as the resident: send `download` and End (End alone when there is no
/// download), keep every frame the client uploads, and, for an exchange, answer its End with Landed and
/// tell `landed`. Returns the upload's raw frames once the client hangs up.
async fn hold(
    mut conn: tokio::net::UnixStream,
    download: Option<Vec<u8>>,
    landed: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> Vec<u8> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut sent = download.as_deref().map(data).unwrap_or_default();
    sent.extend_from_slice(&END);
    let _ = conn.write_all(&sent).await;
    let mut upload = Vec::new();
    if let Some(landed) = landed {
        let mut header = [0; 7];
        while conn.read_exact(&mut header).await.is_ok() {
            upload.extend_from_slice(&header);
            if header == END {
                let _ = conn.write_all(&LANDED).await;
                landed.notify_one();
                break;
            }
            let mut body = vec![0; usize::from(u16::from_be_bytes([header[5], header[6]]))];
            if conn.read_exact(&mut body).await.is_err() {
                break;
            }
            upload.extend_from_slice(&body);
        }
    }
    let _ = conn.read_to_end(&mut upload).await;
    upload
}

/// Hold one attached connection as the resident answering a request: read the client's first Data frame,
/// then, unless the client's End follows within a moment, send `download` and End and answer the client's
/// End with Landed, telling `landed`. An End before the answer drops the connection unanswered. Returns the
/// upload's raw frames once the client hangs up.
async fn answer_request(
    mut conn: tokio::net::UnixStream,
    download: Vec<u8>,
    landed: std::sync::Arc<tokio::sync::Notify>,
) -> Vec<u8> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut upload = Vec::new();
    let mut header = [0; 7];
    if conn.read_exact(&mut header).await.is_err() {
        return upload;
    }
    upload.extend_from_slice(&header);
    let mut body = vec![0; usize::from(u16::from_be_bytes([header[5], header[6]]))];
    if conn.read_exact(&mut body).await.is_err() {
        return upload;
    }
    upload.extend_from_slice(&body);
    // A client that waits for the answer sends nothing more until it has one.
    if let Ok(Ok(_)) = tokio::time::timeout(
        core::time::Duration::from_millis(50),
        conn.read_exact(&mut header),
    )
    .await
    {
        upload.extend_from_slice(&header);
        return upload;
    }
    let mut sent = data(&download);
    sent.extend_from_slice(&END);
    if conn.write_all(&sent).await.is_err() {
        return upload;
    }
    while conn.read_exact(&mut header).await.is_ok() {
        upload.extend_from_slice(&header);
        if header == END {
            let _ = conn.write_all(&LANDED).await;
            landed.notify_one();
            break;
        }
        let mut body = vec![0; usize::from(u16::from_be_bytes([header[5], header[6]]))];
        if conn.read_exact(&mut body).await.is_err() {
            break;
        }
        upload.extend_from_slice(&body);
    }
    let _ = conn.read_to_end(&mut upload).await;
    upload
}

/// Hold one heard Open with no reply until the client hangs up: what it sent after.
async fn hold_silent(mut conn: tokio::net::UnixStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt as _;

    let mut sent = Vec::new();
    let _ = conn.read_to_end(&mut sent).await;
    sent
}

/// Hold one attached connection as the resident: read the client's upload to its End, then send
/// `download` and End. Returns the upload's raw frames, End included.
async fn answer_after_end(mut conn: tokio::net::UnixStream, download: Vec<u8>) -> Vec<u8> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut upload = Vec::new();
    let mut header = [0; 7];
    while conn.read_exact(&mut header).await.is_ok() {
        upload.extend_from_slice(&header);
        if header == END {
            let mut sent = data(&download);
            sent.extend_from_slice(&END);
            let _ = conn.write_all(&sent).await;
            break;
        }
        let mut body = vec![0; usize::from(u16::from_be_bytes([header[5], header[6]]))];
        if conn.read_exact(&mut body).await.is_err() {
            break;
        }
        upload.extend_from_slice(&body);
    }
    let _ = conn.read_to_end(&mut upload).await;
    upload
}

/// A bound for each wait a listener row makes: far past a local round trip, and the one-second asks
/// after a cut.
pub(crate) const ROW_BOUND: core::time::Duration = core::time::Duration::from_secs(10);

/// One local client that uploads `up`, closes its upload and reads to the end: what it read.
async fn client(local: core::net::SocketAddr, up: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut client = tokio::net::TcpStream::connect(local).await.unwrap();
    let _ = client.write_all(up).await;
    let _ = client.shutdown().await;
    let mut read = Vec::new();
    let _ = client.read_to_end(&mut read).await;
    read
}

/// `forward <port>`'s listener for `me/nas`'s `ssh` through a resident answering `answers`, `slip`
/// typed as the machine, while `clients` connect to it. Returns the line the run ended with and the
/// Opens the resident heard.
async fn forwarded(
    tag: &str,
    answers: Vec<Answer>,
    slip: Option<nauthy::Link>,
    clients: impl AsyncFnOnce(core::net::SocketAddr, &Rig),
) -> (eyre::Report, Vec<Heard>) {
    let (ended, heard, _) = warned(tag, answers, slip, clients).await;
    (ended, heard)
}

/// [`forwarded`], with what the run wrote to stderr as it ran. The run's admission is answered first,
/// attached, as `forward <port>` makes it, and is not among the Opens returned.
async fn warned(
    tag: &str,
    answers: Vec<Answer>,
    slip: Option<nauthy::Link>,
    clients: impl AsyncFnOnce(core::net::SocketAddr, &Rig),
) -> (eyre::Report, Vec<Heard>, String) {
    let mut served = Served::new(tag).await;
    let rig = Rig::default();
    let answers = core::iter::once(Answer::Attach).chain(answers).collect();
    let resident = scripted(&mut served, answers, &rig);
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ssh".parse().unwrap();
    let dial = Dial {
        machine: &peer,
        service: &service,
        contacts: &contacts,
    };
    let socket = Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
    let source = swoosh::streams::Tracked::new(
        swoosh::streams::Resident::new(Rc::clone(&socket)),
        std::collections::HashMap::new(),
    );
    let route = crate::commands::route::Route::Serve {
        dial: &dial,
        socket: &socket,
    };
    let ask = swoosh::streams::Ask {
        slip,
        ..crate::commands::connect::tests::listening(&peer)
    };
    let listener = crate::commands::connect::Listener {
        source: &source,
        ask: &ask,
        route: &route,
        machine: &peer,
    };
    listener.admit().await.unwrap();
    let local = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let at = local.local_addr().unwrap();
    let connecting = async {
        clients(at, &rig).await;
        core::future::pending::<()>().await;
    };
    let mut err = Vec::new();
    let ended = {
        let failures = crate::commands::connect::PipeFailures::new(&peer, &mut err);
        tokio::time::timeout(ROW_BOUND, async {
            tokio::select! {
                ended = listener.forward(local, &failures) => ended,
                () = connecting => unreachable!(),
            }
        })
        .await
        .expect("the run ended")
    };
    rig.stop.cancel();
    let mut heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .expect("the resident ended")
        .unwrap();
    heard.remove(0);
    (ended, heard, String::from_utf8(err).unwrap())
}

/// `n` clients, one at a time, each uploading nothing.
fn one_at_a_time(n: usize) -> impl AsyncFnOnce(core::net::SocketAddr, &Rig) {
    async move |local, _rig| {
        for _ in 0..n {
            client(local, b"").await;
        }
    }
}

/// A slip the machine `me/nas` issued for `ssh`, so an Open may present it.
pub(crate) fn nas_slip() -> nauthy::Link {
    swoosh::testkit::TestNode::seeded(0x61)
        .slip(
            &"ssh".parse().unwrap(),
            std::time::SystemTime::now() + core::time::Duration::from_secs(3600),
        )
        .unwrap()
        .link()
        .unwrap()
}

/// `forward <port>` through `serve` makes one Open per local connection, each on a control connection of
/// its own (one Open a connection is what the resident reads), each on Bulk, unobserved, and each
/// presenting the link typed as the machine; the pipe after the last finds no `serve` and ends the run
/// with the serve-stopped line.
#[tokio::test]
async fn a_port_through_serve_opens_each_pipe_on_bulk_unobserved_with_the_slip() {
    use swoosh::serve::control_codec::{Observation, OpenLane};

    let slip = nas_slip();
    let (ended, heard) = forwarded(
        "port-pipes",
        vec![Answer::Attach, Answer::Attach, Answer::Attach],
        Some(slip.clone()),
        one_at_a_time(4),
    )
    .await;
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 3);
    for open in heard {
        assert_eq!(open.lane, OpenLane::Bulk);
        assert_eq!(open.observation, Observation::Unobserved);
        assert_eq!(open.slip.as_deref(), Some(slip.as_str()));
    }
}

/// A pipe carries bytes both ways: the local client's upload reaches the resident as Data then End,
/// and the machine's bytes reach the client.
#[tokio::test]
async fn a_pipe_through_serve_carries_bytes_both_ways() {
    let mut read = Vec::new();
    let (ended, heard) = forwarded(
        "port-bytes",
        vec![Answer::Exchange(b"hello".to_vec())],
        None,
        async |local, rig: &Rig| {
            read = client(local, b"ping").await;
            rig.landed.notified().await;
            client(local, b"").await;
        },
    )
    .await;
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(read, b"hello");
    let mut upload = data(b"ping");
    upload.extend_from_slice(&END);
    assert_eq!(heard[0].upload, upload);
}

/// Pipes run together: while one is in flight, another is refused `Busy` and a third carries, and the
/// first then finishes its exchange whole.
#[tokio::test]
async fn pipes_through_serve_run_together_and_one_failing_leaves_the_others() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut read = Vec::new();
    let (ended, heard) = forwarded(
        "port-together",
        vec![
            Answer::Exchange(b"hello".to_vec()),
            Answer::Refuse(OpenRefusal::Busy),
            Answer::Attach,
        ],
        None,
        async |local, rig: &Rig| {
            let mut first = tokio::net::TcpStream::connect(local).await.unwrap();
            // The download ends on the machine's End while the upload stays open: the pipe is in flight.
            first.read_to_end(&mut read).await.unwrap();
            client(local, b"").await;
            client(local, b"").await;
            first.write_all(b"ping").await.unwrap();
            first.shutdown().await.unwrap();
            rig.landed.notified().await;
            client(local, b"").await;
        },
    )
    .await;
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 3);
    assert_eq!(read, b"hello");
    let mut upload = data(b"ping");
    upload.extend_from_slice(&END);
    assert_eq!(heard[0].upload, upload);
}

/// A pipe's own failure, `serve`'s `Busy`, the machine unavailable, or a cut while `serve` still answers,
/// ends that pipe alone: the next connection's Open is made and carries.
#[tokio::test]
async fn a_pipes_own_failure_keeps_the_port_listening() {
    let (ended, heard) = forwarded(
        "port-own",
        vec![
            Answer::Refuse(OpenRefusal::Busy),
            Answer::Refuse(OpenRefusal::Peer(PeerRefusal::Unavailable(
                RefusalDetail::bounded("down"),
            ))),
            Answer::Cut,
            Answer::Attach,
        ],
        None,
        one_at_a_time(5),
    )
    .await;
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 4);
}

/// The warning a run of failed pipes to `me/nas` prints for the first of them, with that pipe's clause.
pub(crate) fn warning(clause: &str) -> String {
    format!(
        "warning: a connection to me/nas failed: {clause}\n  Still listening for new connections.\n"
    )
}

/// The first pipe to fail after the start warns, the failures after it do not, and a pipe that opened is
/// carried whatever ends it: one cut after it attached, while `serve` still answers, warns nothing, and
/// the next Open refused warns again.
#[tokio::test]
async fn a_port_through_serve_warns_once_per_run_of_failed_pipes() {
    let (ended, heard, err) = warned(
        "port-warn",
        vec![
            Answer::Refuse(OpenRefusal::Busy),
            Answer::Refuse(OpenRefusal::Peer(PeerRefusal::Unavailable(
                RefusalDetail::bounded("down"),
            ))),
            Answer::Attach,
            Answer::Cut,
            Answer::Refuse(OpenRefusal::Busy),
        ],
        None,
        one_at_a_time(6),
    )
    .await;
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 5);
    let busy = warning("too many connections here");
    assert_eq!(err, format!("{busy}{busy}"));
}

/// A later pipe whose Open gets the resident's own error reply warns as a stream that failed to open:
/// `interrupted`, the resident's reason the log's alone.
#[tokio::test]
async fn a_resident_error_on_a_later_pipe_warns_interrupted() {
    let (ended, heard, err) = warned(
        "port-error",
        vec![Answer::Error("disk full\u{1b}[2K")],
        None,
        one_at_a_time(2),
    )
    .await;
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 1);
    assert_eq!(err, warning("interrupted"));
}

/// A pipe's refusal that every later Open would repeat ends the run with its line, as the first Open's
/// refusal would: the machine's `NotAdmitted`, an ended standing, the machine being this one.
#[tokio::test]
async fn a_refusal_every_later_pipe_would_meet_ends_the_port() {
    for (tag, refusal) in [
        ("port-admitted", OpenRefusal::Peer(PeerRefusal::NotAdmitted)),
        ("port-standing", OpenRefusal::StandingEnded),
        ("port-here", OpenRefusal::NotHere),
    ] {
        let expected = refusal.clone();
        let (ended, heard) =
            forwarded(tag, vec![Answer::Refuse(refusal)], None, one_at_a_time(1)).await;
        assert_eq!(heard.len(), 1);
        match expected {
            OpenRefusal::Peer(_) => {
                assert!(ended.is::<crate::commands::machine::Refused>(), "{ended:#}")
            }
            OpenRefusal::StandingEnded => assert!(ended.is::<StandingEnded>(), "{ended:#}"),
            _ => assert!(ended.is::<ThisMachine>(), "{ended:#}"),
        }
    }
}

/// `serve` stopping under a live pipe ends the run at once with the serve-stopped line: the cut asks the
/// socket, rather than waiting for a next connection that may never come.
#[tokio::test]
async fn serve_stopping_under_a_pipe_ends_the_port_at_once() {
    let (ended, heard) = forwarded("port-stop", vec![Answer::Stop], None, one_at_a_time(1)).await;
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 1);
}

/// A refused connect while `serve.lock` is held is a live `serve` that cannot take the connection now
/// (on macOS, a full accept queue), never a stopped one: a pipe cut then, and the next pipe refused,
/// each end alone. Once the lock is free, the next pipe ends the run.
#[tokio::test]
async fn a_refused_connect_under_a_held_lock_keeps_the_port_listening() {
    let released = core::cell::Cell::new(false);
    let (ended, heard) = forwarded(
        "port-deaf",
        vec![Answer::Deaf],
        None,
        async |local, rig: &Rig| {
            client(local, b"").await;
            client(local, b"").await;
            rig.stop.cancel();
            released.set(true);
            client(local, b"").await;
        },
    )
    .await;
    assert!(
        released.get(),
        "the run ended while the lock was held: {ended:#}"
    );
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 1);
}

/// A `serve` of another version answering a later pipe is a restarted one, so the run's `serve` is
/// gone: the run ends with the serve-stopped line rather than refusing every connection.
#[tokio::test]
async fn another_version_answering_a_pipe_ends_the_port_as_serve_stopped() {
    let (ended, heard) = forwarded(
        "port-version",
        vec![Answer::Version, Answer::Attach],
        None,
        one_at_a_time(1),
    )
    .await;
    assert!(ended.is::<super::ServeStopped>(), "{ended:#}");
    assert_eq!(heard.len(), 1);
}

/// A dialing verb's Open that gets no reply prints `Unresponsive` only when `serve` then fails a status
/// too: a resident that takes the Open and answers nothing more has stalled, exit 1 with stdout empty. One
/// that answers status but not the Open is a slow machine behind a working `serve`, so the line is the
/// cut's. Neither hangs past the bounded asks.
#[tokio::test]
async fn a_stalled_serve_is_unresponsive_for_a_dialing_verb() {
    tokio::time::pause();
    // A second answer keeps the stalling resident serving status until the row's stop.
    for (tag, answers, wedged) in [
        ("wedged", vec![Answer::Wedge], true),
        ("slow", vec![Answer::Stall, Answer::Hangup], false),
    ] {
        let mut served = Served::new(&format!("unresponsive-{tag}")).await;
        let rig = Rig::default();
        let resident = scripted(&mut served, answers, &rig);
        let contacts = book();
        let peer = machine(&contacts, "me/nas");
        let ran = tokio::time::timeout(
            core::time::Duration::from_secs(600),
            Dialing::of(&["ping", "me/nas"]).through(&served.home, &peer, &contacts),
        )
        .await
        .expect("the run never hung");
        rig.stop.cancel();
        let _ = resident.await;
        let report = ran.ended.expect_err("a stalled Open ends non-zero");
        assert_eq!(ran.out, "", "{tag}: stdout empty");
        assert_eq!(ran.err, "", "{tag}: the line is the run's error");
        if wedged {
            assert!(report.is::<super::Unresponsive>(), "{tag}: {report:#}");
            assert_eq!(
                printed(&report),
                "error: swoosh serve did not answer here\n  Restart it.\n"
            );
        } else {
            assert!(report.is::<ConnectionLost>(), "{tag}: {report:#}");
        }
    }
}

/// A live `serve` that refuses a connect while it holds its lock, as one whose accept queue is full does,
/// is no `serve` gone: a dialing verb's Open there prints the cut's line, never that `serve` is not
/// running.
#[tokio::test]
async fn a_refused_connect_under_a_held_lock_is_a_cut_for_a_dialing_verb() {
    let mut served = Served::new("refused-held").await;
    // The socket stays bound to no listener, and the lock stays held.
    drop(served.listener());
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let ran = tokio::time::timeout(
        ROW_BOUND,
        Dialing::of(&["ping", "me/nas"]).through(&served.home, &peer, &contacts),
    )
    .await
    .expect("the run ended");
    let report = ran.ended.expect_err("no stream, no exit 0");
    assert!(report.is::<ConnectionLost>(), "{report:#}");
    assert_eq!(ran.out, "");
}

/// `forward <port>` through a `serve` that takes its admission Open and answers nothing more, a status
/// included: the admission prints `Unresponsive`, once, as the run's error, and no listener starts.
#[tokio::test]
async fn a_stalled_serve_is_unresponsive_at_a_port_admission() {
    tokio::time::pause();
    let mut served = Served::new("admit-wedged").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![Answer::Wedge], &rig);
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let cmd = crate::commands::connect::tests::port_forward("me/nas");
    let dial = Dial {
        machine: &peer,
        service: &cmd.service,
        contacts: &contacts,
    };
    let socket = Rc::new(swoosh::node_client::UidSocket::resolve(&served.home).unwrap());
    let source = swoosh::streams::Tracked::new(
        swoosh::streams::Resident::new(Rc::clone(&socket)),
        std::collections::HashMap::new(),
    );
    let route = crate::commands::route::Route::Serve {
        dial: &dial,
        socket: &socket,
    };
    let report = tokio::time::timeout(
        core::time::Duration::from_secs(600),
        cmd.listen(&source, &route, &peer, &contacts, 0),
    )
    .await
    .expect("the admission never hung")
    .expect_err("a stalled admission is an error");
    rig.stop.cancel();
    let heard = resident.await.unwrap();
    assert!(report.is::<super::Unresponsive>(), "{report:#}");
    assert_eq!(
        printed(&report),
        "error: swoosh serve did not answer here\n  Restart it.\n"
    );
    assert_eq!(heard.len(), 1, "one admission Open");
}

/// The line for a `serve` that holds the lock but answers nowhere this command looked, at `at`: section 6's
/// second form, its last line left out on macOS, where no variable sets the root.
pub(crate) fn unreached_at(at: &std::path::Path) -> String {
    let last = match cfg!(target_os = "macos") {
        true => "",
        false => "\n  Otherwise set XDG_RUNTIME_DIR to the value swoosh serve has.",
    };
    format!(
        "error: swoosh serve is running for this home, but this command cannot reach it\n  Nothing \
         answers at {}.\n  If swoosh serve has just started, run this command again.{last}\n",
        at.display()
    )
}

/// The line for a key replacement under way: section 6's third form.
pub(crate) const REPLACING: &str = "error: this machine's key is being replaced\n  Run this command again when that has finished.\n";

/// Every pair of what the probe showed and what `serve.lock` said gives one arm: an answer rides whatever
/// the lock; only a free lock is no `serve`; a held one is the line for what the probe saw, and an empty
/// record the key replacement's, whatever it saw; an unanswered probe with no lock read is never free.
#[tokio::test]
async fn the_probe_rule_is_one_table() {
    use swoosh::home::{ResidentPresence as Lock, RuntimeRoot};

    use super::{Found, Probed, rule};

    let no_root = |why: &str| {
        format!(
            "error: swoosh serve is running for this home, but this command cannot reach it\n  Commands \
             find it through XDG_RUNTIME_DIR, which {why}.\n  Set XDG_RUNTIME_DIR to the value swoosh \
             serve has, usually /run/user/$(id -u).\n"
        )
    };
    let at = std::path::PathBuf::from("/run/user/1000/swoosh/0123/control.sock");
    let confstr = "could not resolve the per-user temp dir (confstr failed)";
    let unanswered = || {
        [
            (
                Probed::NoRoot(RuntimeRoot::Unset),
                no_root("is not set here"),
            ),
            (
                Probed::NoRoot(RuntimeRoot::Relative),
                no_root("is not a full path here"),
            ),
            (
                Probed::NoRoot(RuntimeRoot::Unresolved(confstr)),
                format!("error: {confstr}\n"),
            ),
            (Probed::Nothing { at: at.clone() }, unreached_at(&at)),
        ]
    };
    for (probed, _) in unanswered() {
        assert!(matches!(rule(probed, Some(Lock::Free)), Ok(Found::Absent)));
    }
    for (probed, line) in unanswered() {
        let refused = rule(probed, Some(Lock::Serving)).err().unwrap();
        assert_eq!(printed(&refused), line);
    }
    for (probed, line) in unanswered() {
        let refused = rule(probed, None).err().unwrap();
        assert_eq!(printed(&refused), line, "no lock read is never free");
    }
    for (probed, _) in unanswered() {
        let refused = rule(probed, Some(Lock::Replacing)).err().unwrap();
        assert_eq!(printed(&refused), REPLACING);
    }
    let locks = [
        None,
        Some(Lock::Free),
        Some(Lock::Serving),
        Some(Lock::Replacing),
    ];
    // Another version is its line whatever the lock says, and never no `serve`.
    for lock in locks {
        let refused = rule(Probed::Skew, lock).err().unwrap();
        assert_eq!(
            printed(&refused),
            "error: swoosh serve on this machine is a different version\n  Restart it with this \
             version.\n"
        );
    }
    // No reply in time: a held lock is a `serve` stalled, a free one only the timeout, never no `serve`.
    let silent = || Probed::Silent {
        phase: "response read",
    };
    for lock in [None, Some(Lock::Serving), Some(Lock::Replacing)] {
        let refused = rule(silent(), lock).err().unwrap();
        assert_eq!(
            printed(&refused),
            "error: swoosh serve did not answer here\n  Restart it.\n"
        );
    }
    // A connection ended before its reply: a free lock is no `serve`, an emptied one the key
    // replacement's line, and a held one, or no lock read, a `serve` that did not answer.
    assert!(matches!(
        rule(Probed::Dropped, Some(Lock::Free)),
        Ok(Found::Absent)
    ));
    assert_eq!(
        printed(&rule(Probed::Dropped, Some(Lock::Replacing)).err().unwrap()),
        REPLACING
    );
    for lock in [None, Some(Lock::Serving)] {
        let refused = rule(Probed::Dropped, lock).err().unwrap();
        assert_eq!(
            printed(&refused),
            "error: swoosh serve did not answer here\n  Restart it.\n"
        );
    }
    let refused = rule(silent(), Some(Lock::Free)).err().unwrap();
    assert!(matches!(
        refused.downcast_ref::<ControlError>(),
        Some(ControlError::Timeout {
            phase: "response read"
        })
    ));
    let served = Served::new("rule-answering").await;
    for lock in locks {
        let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
        let this = resident_key();
        assert!(matches!(
            rule(Probed::Answering { socket, this }, lock),
            Ok(Found::Answering { this: found, .. }) if found == this
        ));
    }
}

/// A `serve.lock` that cannot be read (here a directory at its name) behind no answer is the error, never
/// no `serve`.
#[tokio::test]
async fn a_lock_that_cannot_be_read_is_never_absent() {
    let home = empty_home("lock-unreadable");
    std::fs::create_dir_all(home.serve_lock()).unwrap();
    let probed = super::serve(&home).await;
    assert!(probed.is_err(), "a lock read error must not read as free");
    let _ = std::fs::remove_dir_all(home.dir());
}

/// `home.lock` held by another holder for good, beside a `serve.lock` a `serve` once left: the probe's
/// lock read ends within its bound, an error, never no `serve`, so one stuck holder cannot wedge every
/// command here.
#[tokio::test]
async fn a_home_lock_held_for_good_bounds_the_probe() {
    let home = empty_home("lock-wedged");
    let held = swoosh::home::HomeWrite::take(&home).await.unwrap();
    // Free and empty, as a stopped `serve` leaves it: an absent one is free without the lock read.
    std::fs::write(home.serve_lock(), b"").unwrap();
    let probed = tokio::time::timeout(swoosh::node_client::STOPPED_ASK * 5, super::serve(&home))
        .await
        .expect("the lock read is bounded");
    let error = probed.err().expect("a wedged lock read is an error");
    let lock = error
        .downcast_ref::<swoosh::home::LockError>()
        .expect("the lock read's own error");
    assert_eq!(lock.path, home.home_lock());
    assert_eq!(lock.source.kind(), io::ErrorKind::TimedOut);
    drop(held);
    let _ = std::fs::remove_dir_all(home.dir());
}

/// The `serve` at `served`'s socket for one connection: it reads the request, runs `then` with the
/// `serve.lock` it may let go, and ends the connection with no reply.
async fn one_dropped(
    served: &mut Served,
    then: impl FnOnce(swoosh::serve::InstanceLock) + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let listener = served.listener();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let lock = served.lock();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let _ = Request::read(&mut conn).await;
        then(lock);
        drop(conn);
    })
}

/// A `serve` that ends the probe's connection with no reply and has let its lock go, as one stopping
/// does: no `serve` runs, so the run binds its own.
#[tokio::test]
async fn probe_eof_lock_free_is_absent() {
    let mut served = Served::new("probe-eof-free").await;
    let resident = one_dropped(&mut served, drop).await;
    let found = super::serve(&served.home).await;
    resident.await.unwrap();
    assert!(
        matches!(found, Ok(super::Found::Absent)),
        "{:?}",
        found.err()
    );
}

/// A `serve` that ends the probe's connection with no reply and still holds its lock is a `serve` that
/// did not answer, never no `serve` and never the raw read error.
#[tokio::test]
async fn probe_eof_lock_held_is_unresponsive() {
    let mut served = Served::new("probe-eof-held").await;
    let (keep, kept) = std::sync::mpsc::channel();
    let resident = one_dropped(&mut served, move |lock| keep.send(lock).unwrap()).await;
    let refused = super::serve(&served.home).await.err().unwrap();
    resident.await.unwrap();
    drop(kept);
    assert_eq!(
        printed(&refused),
        "error: swoosh serve did not answer here\n  Restart it.\n"
    );
}

/// A `serve.lock` held with its record emptied behind the dropped connection, as a `serve` stopping
/// leaves it for a moment or a key replacement holds it: the replacement's line.
#[tokio::test]
async fn probe_eof_lock_replacing_is_unreached() {
    let mut served = Served::new("probe-eof-replacing").await;
    let record = served.home.serve_lock();
    let (keep, kept) = std::sync::mpsc::channel();
    let resident = one_dropped(&mut served, move |lock| {
        std::fs::OpenOptions::new()
            .write(true)
            .open(record)
            .unwrap()
            .set_len(0)
            .unwrap();
        keep.send(lock).unwrap();
    })
    .await;
    let refused = super::serve(&served.home).await.err().unwrap();
    resident.await.unwrap();
    drop(kept);
    assert_eq!(printed(&refused), REPLACING);
}

/// The `serve` at `served`'s socket for one connection: it reads the request and writes `reply`'s bytes.
async fn one_reply(served: &mut Served, reply: Vec<u8>) -> tokio::task::JoinHandle<()> {
    use tokio::io::AsyncWriteExt as _;

    let listener = served.listener();
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let _ = Request::read(&mut conn).await;
        let _ = conn.write_all(&reply).await;
    })
}

/// A `serve` of the build before the probe's `Whoami` answers in its own version: another version, never
/// a frame read as this one's.
#[tokio::test]
async fn probe_version_skew() {
    let mut served = Served::new("probe-skew").await;
    let resident = one_reply(&mut served, b"SWC1\x05\x00\x00".to_vec()).await;
    let refused = super::serve(&served.home).await.err().unwrap();
    resident.await.unwrap();
    assert!(refused.is::<Skew>(), "{refused:#}");
}

/// The text a `serve` answers the probe with, an error or a refusal, is printed escaped, as an Open's is:
/// a control byte in it never reaches the terminal raw.
#[tokio::test]
async fn the_probe_escapes_what_serve_says() {
    for (tag, reply) in [
        ("error", Response::Error("\x1b[31mx".to_owned())),
        ("refused", Response::Refused("\x1b[31mx".to_owned())),
    ] {
        let mut served = Served::new(&format!("probe-hostile-{tag}")).await;
        let mut bytes = Vec::new();
        reply.write(&mut bytes).await.unwrap();
        let resident = one_reply(&mut served, bytes).await;
        let refused = super::serve(&served.home).await.err().unwrap();
        resident.await.unwrap();
        let line = printed(&refused);
        assert!(!line.contains('\x1b'), "{tag}: {line:?}");
        assert!(line.contains("[31mx"), "{tag}: {line:?}");
    }
}

/// A run whose final path could not be read warns through the screen: one `warning:` head, held to the
/// screen law, styled only at a terminal, and the run's own result untouched.
#[test]
fn an_unread_final_path_warns_through_the_screen() {
    use swoosh::observation::{ObservationError, Observed};

    let failed = || Observed {
        last: Err(ObservationError::Unavailable),
        earlier: None,
    };
    let mut plain = Vec::new();
    assert!(super::final_path(failed(), &mut plain).unwrap().is_none());
    let plain = String::from_utf8(plain).unwrap();
    assert_eq!(plain, "warning: could not read the path of this run\n");
    if let Err(breach) = crate::screen::law::holds(&plain) {
        panic!("{breach}\n{plain}");
    }
    let warning = clap::builder::styling::Style::new()
        .bold()
        .fg_color(Some(clap::builder::styling::AnsiColor::Yellow.into()));
    let mut styled = anstream::AutoStream::always(Vec::new());
    assert!(super::final_path(failed(), &mut styled).unwrap().is_none());
    assert_eq!(
        String::from_utf8(styled.into_inner()).unwrap(),
        format!("{warning}warning:{warning:#} could not read the path of this run\n")
    );
}

/// The most columns any line of `text` can fill in any terminal, counted here apart from the code under
/// test: one per ASCII scalar, two per any other.
pub(crate) fn columns_at_most(text: &str) -> usize {
    text.lines()
        .map(|line| {
            line.chars()
                .map(|scalar| if scalar.is_ascii() { 1 } else { 2 })
                .sum()
        })
        .max()
        .unwrap_or(0)
}
