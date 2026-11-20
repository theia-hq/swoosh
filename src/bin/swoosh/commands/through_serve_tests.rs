//! The lines `forward <machine> <service> -` prints when it runs through `serve`, pinned to their ruled
//! words.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bifrost::{NodeId, RefusalDetail};
use swoosh::contacts::Contacts;
use swoosh::node_client::NodeClient;
use swoosh::peer::{Machine as PeerMachine, Peer};
use swoosh::serve::control_codec::{
    ControlError, DisabledList, OpenRefusal, PeerRefusal, ServiceMenu, StatusReply,
};
use swoosh::transport::ReachArgs;

use super::{Busy, Dial, Moot, OneStream, Skew, StandingEnded, Stream, ThisMachine, after_a_cut};
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

/// `speed` through a running `serve`, end to end: the verb's Open reaches the real resident on this
/// home's socket, the resident dials the machine on a connection of its own, measure's responder there
/// answers each mode, and the run's Finish reads the path through the same socket. Driven on an 8 MiB
/// thread as the gated measure proof is: over mem both ends' transfer buffers share one thread's stack.
#[test]
fn speed_runs_through_the_resident_against_measures_responder() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(speed_through_serve()));
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn speed_through_serve() {
    use bifrost::{NoDiscovery, Node};
    use bifrost_mem::MemTransport;
    use clap::Parser as _;
    use tightbeam::tunnel::{self, CancellationToken, Router};

    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        speed: crate::commands::speed::SpeedCmd,
    }

    // The machine: `speed` opened to anyone, so a dial presenting nothing is admitted.
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let denylist = std::env::temp_dir().join(format!("swoosh-ts-deny-{}", std::process::id()));
    let _ = std::fs::remove_file(&denylist);
    let denylist = nauthy::Denylist::load(denylist).unwrap();
    tokio::task::spawn_local(async move {
        let public: Vec<nauthy::Service> = vec!["speed".parse().unwrap()];
        let gate = tunnel::resolve_gate(Some(host_id), denylist).unwrap();
        swoosh::serve::diagnostics(Router::new(gate), &public)
            .unwrap()
            .expose()
            .unwrap()
            .run(&host, CancellationToken::new())
            .await;
    });

    // This machine's `serve`, on this home's socket.
    let mut served = Served::new("speed").await;
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
    contacts.save(&"me/nas".parse().unwrap(), host_id).unwrap();
    // Byte-bounded runs end on the count, so only a time-bounded upload waits on the verb's End for its
    // reply: that leg runs a real 50 ms window, since measure reads the wall clock.
    let runs = async {
        for argv in [
            ["--down", "-n", "262144"],
            ["--up", "-n", "262144"],
            ["--bidir", "-n", "262144"],
            ["--up", "-t", "0.05"],
        ] {
            let cmd = Wrap::try_parse_from(["x", "me/nas"].into_iter().chain(argv))
                .unwrap()
                .speed;
            let machine = cmd.peer.machine(&contacts).unwrap();
            let routed = tokio::time::timeout(
                core::time::Duration::from_secs(10),
                cmd.through_serve(&served.home, &machine, None, &contacts),
            )
            .await
            .expect("the run never ended")
            .unwrap();
            assert!(
                matches!(routed, super::Routed::Ran(Ok(()))),
                "not a run through serve that measured"
            );
        }
    };
    tokio::select! {
        ended = resident.serve(listener, &opener) => panic!("the resident stopped: {ended:?}"),
        () = runs => {}
    }
}
