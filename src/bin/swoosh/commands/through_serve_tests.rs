//! The lines `forward <machine> <service> -` prints when it runs through `serve`, pinned to their ruled
//! words, and the stand-ins the observed verbs' tests run against.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use bifrost::{ConnInfo, NodeId, RefusalDetail};
use swoosh::contacts::Contacts;
use swoosh::node_client::NodeClient;
use swoosh::observation::{Observer, PathSource, Receipt};
use swoosh::peer::{Machine as PeerMachine, Peer};
use swoosh::serve::control_codec::{
    ControlError, DisabledList, OpenRefusal, PathRef, PathReply, PathRequest, PeerRefusal,
    ServiceMenu, StatusReply,
};
use swoosh::transport::ReachArgs;

use super::{Busy, Dial, Moot, OneStream, Skew, StandingEnded, Stream, ThisMachine};
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

    let mut frame = b"SWC1\x06\x00\x1c\x01".to_vec();
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
fn status_of(node_id: NodeId) -> StatusReply {
    StatusReply {
        node_id,
        pid: 1,
        addr: None,
        uptime_secs: 0,
        menu: ServiceMenu {
            catalog: tightbeam::tunnel::ServiceCatalog::decode(&0_u32.to_be_bytes()).unwrap(),
            disabled: DisabledList::Known(Vec::new()),
        },
        warm: Vec::new(),
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
    let reach = reach(&["forward"]);
    let pipe = Dial {
        machine: &peer,
        service: &service,
        slip: None,
        reach: &reach,
        contacts: &contacts,
    };
    let this = NodeId::from_ed25519_secret(&[0x62; 32]);
    let head = "error: this device's membership badge has ended, so a family-gated peer will refuse \
                this dial";
    let named = pipe
        .refused(OpenRefusal::StandingEnded, &Serve(Some(this)))
        .await;
    assert!(named.is::<StandingEnded>());
    assert_eq!(
        printed(&named),
        format!("{head}; {}\n", swoosh::badge::remedy(this))
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
    let reach = reach(&["forward"]);
    let pipe = Dial {
        machine: &peer,
        service: &service,
        slip: None,
        reach: &reach,
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
    let service = "ssh".parse().unwrap();
    let reach = reach(&["forward"]);
    let pipe = Dial {
        machine: &peer,
        service: &service,
        slip: None,
        reach: &reach,
        contacts: &contacts,
    };
    let (socket, connected) = super::serve(&served.home).await.unwrap().unwrap();
    let resident = async {
        let (mut conn, _) = listener.accept().await.unwrap();
        Request::read(&mut conn).await.unwrap();
        Response::Attached(Attached::from(info))
            .write(&mut conn)
            .await
            .unwrap();
        conn
    };
    let (stream, conn) = tokio::join!(
        pipe.open(&socket, connected, OpenLane::Main, Observation::Unobserved),
        resident
    );
    (stream.unwrap(), conn)
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
    let session = OneStream::new(nas(), stream.info, stream.read, stream.write);
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
    let session = OneStream::new(nas(), stream.info, stream.read, stream.write);
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
fn on_a_big_stack(runs: impl AsyncFnOnce() + Send + 'static) {
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
        None,
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
            use clap::Parser as _;

            #[derive(clap::Parser)]
            struct Wrap {
                #[command(flatten)]
                speed: crate::commands::speed::SpeedCmd,
            }

            // Byte-bounded runs end on the count, so only a time-bounded upload waits on the verb's End
            // for its reply: that leg runs a real 50 ms window, since measure reads the wall clock.
            for argv in [
                ["--down", "-n", "262144"],
                ["--up", "-n", "262144"],
                ["--bidir", "-n", "262144"],
                ["--up", "-t", "0.05"],
            ] {
                let cmd = Wrap::try_parse_from(["x", "me/nas"].into_iter().chain(argv))
                    .unwrap()
                    .speed;
                let machine = cmd.peer.machine(contacts).unwrap();
                let routed = tokio::time::timeout(
                    core::time::Duration::from_secs(10),
                    cmd.through_serve(home, &machine, None, contacts),
                )
                .await
                .expect("the run never ended")
                .unwrap();
                assert!(
                    matches!(routed, super::Routed::Ran(Ok(()))),
                    "not a run through serve that measured"
                );
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
            use clap::Parser as _;

            #[derive(clap::Parser)]
            enum Verb {
                Ping(crate::commands::ping::PingCmd),
                Status(crate::commands::status::StatusCmd),
            }

            for argv in [
                &["x", "ping", "bob/nas", "-c", "2", "-i", "0.05"][..],
                &["x", "ping", "bob/nas", "-v", "-c", "1"],
                &["x", "status", "bob/nas"],
            ] {
                // The open `ping` route admits one run a second per caller, and every run here is the
                // resident's, so each waits out the last one's.
                tokio::time::sleep(core::time::Duration::from_millis(1100)).await;
                let routed = match Verb::try_parse_from(argv).unwrap() {
                    Verb::Ping(cmd) => {
                        let machine = cmd.peer.machine(contacts).unwrap();
                        tokio::time::timeout(
                            core::time::Duration::from_secs(10),
                            cmd.through_serve(home, &machine, None, contacts),
                        )
                        .await
                    }
                    Verb::Status(cmd) => {
                        let machine = cmd.peer.as_ref().unwrap().machine(contacts).unwrap();
                        tokio::time::timeout(
                            core::time::Duration::from_secs(10),
                            cmd.through_serve(home, &machine, None, contacts),
                        )
                        .await
                    }
                };
                let routed = routed.expect("the run never ended").unwrap();
                assert!(
                    matches!(routed, super::Routed::Ran(Ok(()))),
                    "not a run through serve that answered: {argv:?}"
                );
            }
        })
        .await;
    });
}

/// `ping` and `status <machine>` through `serve` make one Open each, observed, on the held Main session,
/// for the service the probe names: `control.services` for one of your devices.
#[tokio::test]
async fn ping_and_status_open_once_observed_on_main() {
    use clap::Parser as _;
    use swoosh::serve::control_codec::{Observation, OpenLane, Request, Response};

    #[derive(clap::Parser)]
    enum Verb {
        Ping(crate::commands::ping::PingCmd),
        Status(crate::commands::status::StatusCmd),
    }

    for (argv, service) in [
        (["x", "ping", "me/nas"], "ping"),
        (["x", "status", "me/nas"], "control.services"),
    ] {
        let mut served = Served::new(&format!("open-{}", argv[1])).await;
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
        let run = async {
            match Verb::try_parse_from(argv).unwrap() {
                Verb::Ping(cmd) => {
                    cmd.through_serve(&served.home, &peer, None, &contacts)
                        .await
                }
                Verb::Status(cmd) => {
                    cmd.through_serve(&served.home, &peer, None, &contacts)
                        .await
                }
            }
        };
        let (routed, asked) = tokio::time::timeout(core::time::Duration::from_secs(10), async {
            tokio::join!(run, resident)
        })
        .await
        .expect("the Open was answered");
        let super::Routed::Ran(Err(busy)) = routed.unwrap() else {
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
    use clap::Parser as _;
    use swoosh::serve::control_codec::{Request, Response};

    #[derive(clap::Parser)]
    enum Verb {
        Ping(crate::commands::ping::PingCmd),
        Status(crate::commands::status::StatusCmd),
    }

    for argv in [["x", "ping", "me/nas"], ["x", "status", "me/nas"]] {
        let mut served = Served::new(&format!("unreached-{}", argv[1])).await;
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
        let run = async {
            match Verb::try_parse_from(argv).unwrap() {
                Verb::Ping(cmd) => {
                    cmd.through_serve(&served.home, &peer, None, &contacts)
                        .await
                }
                Verb::Status(cmd) => {
                    cmd.through_serve(&served.home, &peer, None, &contacts)
                        .await
                }
            }
        };
        let (routed, ()) = tokio::time::timeout(core::time::Duration::from_secs(10), async {
            tokio::join!(run, resident)
        })
        .await
        .expect("the Open was answered");
        let super::Routed::Ran(Err(unreached)) = routed.unwrap() else {
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
    let reach = reach(&["forward"]);
    let service = "ping".parse().unwrap();
    let dial = Dial {
        machine: &peer,
        service: &service,
        slip: None,
        reach: &reach,
        contacts: &contacts,
    };
    let (socket, _connected) = super::serve(&served.home).await.unwrap().unwrap();
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
pub(crate) const END: [u8; 7] = *b"SWC1\x0b\x00\x00";

/// A Landed frame: tag 12, empty, toward the client only.
const LANDED: [u8; 7] = *b"SWC1\x0c\x00\x00";

/// `bytes` as one Data frame, tag 10 (at most a frame's 8 KiB).
pub(crate) fn data(bytes: &[u8]) -> Vec<u8> {
    let mut frame = b"SWC1\x0a".to_vec();
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
    /// Attach, then drop the connection with no End: a cut, the resident still up.
    Cut,
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
    /// Hear the Open, then stop with no reply: the socket and the lock go before the connection does.
    Vanish,
    /// Refuse it so.
    Refuse(OpenRefusal),
}

/// One Open the scripted resident heard: what it asked for, and what an attached one uploaded.
pub(crate) struct Heard {
    pub(crate) service: String,
    pub(crate) lane: swoosh::serve::control_codec::OpenLane,
    pub(crate) observation: swoosh::serve::control_codec::Observation,
    pub(crate) slip: Option<String>,
    pub(crate) upload: Vec<u8>,
}

/// What a row holds of its scripted resident: `stop` ends it (it stops on its own once its answers run
/// out, unless it went deaf), and `landed` is told each time it answers an upload's End with Landed.
#[derive(Default)]
pub(crate) struct Rig {
    pub(crate) stop: tightbeam::tunnel::CancellationToken,
    pub(crate) landed: std::sync::Arc<tokio::sync::Notify>,
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
                Ok(Request::Status) => {
                    let _ = Response::Status(status_of(resident_key()))
                        .write(&mut conn)
                        .await;
                    continue;
                }
                _ => continue,
            };
            heard.push(Heard {
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
                    let _ = conn.write_all(b"SWC2").await;
                }
                Answer::Hangup => drop(conn),
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
                        Answer::Stop => {
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

/// [`forwarded`], with what the run wrote to stderr as it ran.
async fn warned(
    tag: &str,
    answers: Vec<Answer>,
    slip: Option<nauthy::Link>,
    clients: impl AsyncFnOnce(core::net::SocketAddr, &Rig),
) -> (eyre::Report, Vec<Heard>, String) {
    let mut served = Served::new(tag).await;
    let rig = Rig::default();
    let resident = scripted(&mut served, answers, &rig);
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ssh".parse().unwrap();
    let reach = reach(&["forward"]);
    let dial = Dial {
        machine: &peer,
        service: &service,
        slip,
        reach: &reach,
        contacts: &contacts,
    };
    let socket = swoosh::node_client::UidSocket::resolve(&served.home).unwrap();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let local = listener.local_addr().unwrap();
    let connecting = async {
        clients(local, &rig).await;
        core::future::pending::<()>().await;
    };
    let mut err = Vec::new();
    let failures = crate::commands::connect::PipeFailures::new(&peer, &mut err);
    let ended = tokio::time::timeout(ROW_BOUND, async {
        tokio::select! {
            ended = dial.carry_each(&socket, listener, &failures) => ended,
            () = connecting => unreachable!(),
        }
    })
    .await
    .expect("the run ended");
    rig.stop.cancel();
    let heard = tokio::time::timeout(ROW_BOUND, resident)
        .await
        .expect("the resident ended")
        .unwrap();
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

/// `forward <port>` through `serve` proves admission on one Open, ended with End, before it binds the
/// port or prints its start lines.
#[tokio::test]
async fn a_port_through_serve_admits_on_an_open_it_ends_with_end() {
    let mut served = Served::new("port-admit").await;
    let rig = Rig::default();
    let resident = scripted(&mut served, vec![Answer::Attach], &rig);
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ssh".parse().unwrap();
    let reach = reach(&["forward"]);
    let dial = Dial {
        machine: &peer,
        service: &service,
        slip: None,
        reach: &reach,
        contacts: &contacts,
    };
    let (socket, connected) = super::serve(&served.home).await.unwrap().unwrap();
    // A free port; the run listens on once admitted, and the resident resolves once the admission
    // stream has closed.
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let heard = tokio::time::timeout(ROW_BOUND, async {
        tokio::select! {
            ended = dial.forward_port(&socket, connected, port) => {
                panic!("the run ended before a connection: {ended:?}")
            }
            heard = resident => heard.unwrap(),
        }
    })
    .await
    .expect("the admission Open was made and closed");
    let [admission] = heard.as_slice() else {
        panic!("{} Opens, not the one admission", heard.len());
    };
    assert_eq!(
        admission.upload, END,
        "the admission stream ends with End alone"
    );
}
