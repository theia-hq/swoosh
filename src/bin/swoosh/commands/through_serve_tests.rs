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

use super::{Busy, Dial, Moot, OneStream, Skew, StandingEnded, Stream, ThisMachine, serve_gone};
use crate::commands::connect::{ConnectionLost, Machine};

/// The key of `me/nas`.
fn nas() -> NodeId {
    NodeId::from_ed25519_secret(&[0x61; 32])
}

fn book() -> Contacts {
    let mut contacts = Contacts::default();
    contacts.save(&"me/nas".parse().unwrap(), nas()).unwrap();
    contacts
}

fn machine(contacts: &Contacts, typed: &str) -> PeerMachine {
    typed.parse::<Peer>().unwrap().machine(contacts).unwrap()
}

/// What a run through `serve` did, in order: each line it wrote to stderr, as `stderr: <line>`, and each
/// query on its receipt, as `Sample` or `Finish`. A query reads the next of the replies it was given, or
/// `Unavailable` once they run out.
#[derive(Clone, Default)]
pub(crate) struct Events {
    log: Rc<RefCell<Vec<String>>>,
    replies: Rc<RefCell<VecDeque<PathReply>>>,
    /// Stderr written and not yet ended by a newline.
    pending: Rc<RefCell<String>>,
    /// Whether the resident takes every query and never answers it.
    stall: bool,
}

impl Events {
    /// A resident that answers the queries with `replies`, in order.
    pub(crate) fn answering(replies: impl IntoIterator<Item = PathReply>) -> Self {
        Self {
            replies: Rc::new(RefCell::new(replies.into_iter().collect())),
            ..Self::default()
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
            self.log
                .borrow_mut()
                .push(format!("stderr: {}", line.trim_end()));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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

#[test]
fn a_cut_with_nothing_answering_names_serve_and_otherwise_is_connection_lost() {
    let contacts = book();
    let named = Machine::of(&contacts, nas());
    // The line a cut prints: `serve`'s own when it is gone, else the own bind's.
    let after_a_cut =
        |asked, named, own: eyre::Report| serve_gone(asked, named).map_or(own, eyre::Report::new);
    let stopped = after_a_cut(Err(ControlError::NoResident), &named, ConnectionLost.into());
    assert_eq!(
        printed(&stopped),
        "error: swoosh serve stopped here and ended the connection to me/nas\n  Commands here \
         connect through it while it runs.\n  Run this command again to reconnect.\n"
    );
    for gone in [
        ControlError::Io(tokio::io::ErrorKind::ConnectionReset.into()),
        ControlError::Timeout {
            phase: "response read",
        },
    ] {
        assert!(
            printed(&after_a_cut(Err(gone), &named, ConnectionLost.into()))
                .starts_with("error: swoosh serve stopped")
        );
    }
    // `serve` still answers: the cut was the pipe's, and the line is the own bind's.
    let lost = after_a_cut(Ok(()), &named, ConnectionLost.into());
    assert!(lost.is::<ConnectionLost>());
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

/// A `serve` that answers status as the machine `this`, or not at all, and nothing else.
struct Serve(Option<NodeId>);

impl NodeClient for Serve {
    async fn services(&self) -> Result<ServiceMenu, ControlError> {
        Err(ControlError::NoResident)
    }

    async fn status(&self) -> Result<StatusReply, ControlError> {
        let node_id = self.0.ok_or(ControlError::NoResident)?;
        Ok(StatusReply {
            node_id,
            pid: 1,
            addr: None,
            uptime_secs: 0,
            menu: ServiceMenu {
                catalog: tightbeam::tunnel::ServiceCatalog::decode(&0_u32.to_be_bytes()).unwrap(),
                disabled: DisabledList::Known(Vec::new()),
            },
            warm: Vec::new(),
        })
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
struct Served {
    home: swoosh::home::Home,
    dir: std::path::PathBuf,
    listener: Option<std::os::unix::net::UnixListener>,
    _lock: swoosh::serve::InstanceLock,
}

impl Served {
    async fn new(tag: &str) -> Self {
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
            _lock: lock,
        }
    }

    /// The bound socket, as the resident takes it.
    fn listener(&mut self) -> std::os::unix::net::UnixListener {
        self.listener.take().unwrap()
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
    let mut pipe = Dial {
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
