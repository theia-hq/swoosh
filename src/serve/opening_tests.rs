//! Server Open through the resident's real accept path over a unix socket, against a scripted peer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::os::fd::AsRawFd as _;
use std::sync::Arc;
use std::time::SystemTime;

use bifrost::{NoDiscovery, Node, NodeId, Refusal, RefusalDetail};
use futures::poll;
use nauthy::Link;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream};
use tokio::net::UnixStream;

use super::{
    BROKEN, ClientGone, HANGUP_DRAIN, MAX_BEYOND_MAIN, MAX_REACH, Opener, UNREACHABLE, failed,
    splice,
};
use crate::home::Home;
use crate::peers::{DialFailure, Hints, OpenError, Peers};
use crate::renewal::{Fetch, FetchError, OpenRenewal};
use crate::serve::control_codec::{
    OpenLane, OpenRefusal, OpenRequest, PeerRefusal, Request, Response,
};
use crate::serve::{MAX_CONTROL_CONNS, Resident};
use crate::testkit::{Script, ScriptedPeer, TestNode};

#[tokio::test]
async fn an_open_through_the_running_resident_attaches_and_splices() {
    let fixture = Fixture::new("splices", [Script::Lists(vec!["x"])]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            assert!(matches!(
                Response::read_open(&mut client).await.unwrap(),
                Response::Attached(_)
            ));
            let mut spliced = Vec::new();
            client.read_to_end(&mut spliced).await.unwrap();
            // The peer's own bytes after it admitted the stream: a list naming `x`.
            assert_eq!(spliced, [0, 0, 0, 1, 0, 1, b'x', 0]);
        })
        .await;
    assert_eq!(fixture.scripted.requests()[0].service, "ssh");
}

#[tokio::test]
async fn an_open_to_this_machine_is_not_here_and_dials_nothing() {
    let fixture = Fixture::new("self", [Script::Lists(vec![])]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.this, OpenLane::Main, None)).await;
            assert_eq!(refusal(&mut client).await, OpenRefusal::NotHere);
        })
        .await;
    assert_eq!(fixture.scripted.dials(), 0);
}

#[tokio::test]
async fn an_anyone_slip_is_not_here_and_dials_nothing() {
    let fixture = Fixture::new("anyone", [Script::Lists(vec![])]);
    let anyone = TestNode::seeded(PEER)
        .slip(&"ssh".parse().unwrap(), until())
        .unwrap()
        .link()
        .unwrap();
    fixture
        .run(async |socket| {
            let mut client =
                open(socket, request(fixture.peer, OpenLane::Main, Some(anyone))).await;
            assert_eq!(refusal(&mut client).await, OpenRefusal::NotHere);
        })
        .await;
    assert_eq!(fixture.scripted.dials(), 0);
}

#[tokio::test]
async fn an_observed_open_is_an_error_before_any_dial() {
    let fixture = Fixture::new("observed", [Script::Lists(vec![])]);
    let mut body = request(fixture.peer, OpenLane::Main, None)
        .encode()
        .unwrap();
    *body.last_mut().unwrap() = 1;
    fixture
        .run(async |socket| {
            let mut client = UnixStream::connect(socket).await.unwrap();
            client.write_all(b"SWC1\x04").await.unwrap();
            client
                .write_all(&u16::try_from(body.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            client.write_all(&body).await.unwrap();
            assert!(matches!(
                Response::read_open(&mut client).await.unwrap(),
                Response::Error(reason) if reason == "open request observation mode is unsupported"
            ));
        })
        .await;
    assert_eq!(fixture.scripted.dials(), 0);
}

#[tokio::test]
async fn a_peer_refusal_crosses_the_socket_typed() {
    let detail = RefusalDetail::try_from("down for maintenance").unwrap();
    let fixture = Fixture::new(
        "refusal",
        [Script::Refuse(Refusal::Unavailable {
            detail: detail.clone(),
        })],
    );
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            assert_eq!(
                refusal(&mut client).await,
                OpenRefusal::Peer(PeerRefusal::Unavailable(detail))
            );
        })
        .await;
}

#[tokio::test]
async fn an_open_gives_back_its_control_slot_before_the_dial_answers() {
    let fixture = Fixture::new("control", [Script::Silent]);
    fixture
        .run(async |socket| {
            let _client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            // The peer has the stream's request, so the open is waiting on the peer.
            until_true(|| !fixture.scripted.requests().is_empty()).await;
            // One slot is the accept loop's, taken before it waits for the next connection; the Open
            // holds none.
            assert_eq!(
                fixture.resident.semaphore().available_permits(),
                MAX_CONTROL_CONNS - 1
            );
        })
        .await;
}

#[tokio::test]
async fn an_unusable_hint_is_malformed_before_any_dial() {
    let fixture = Fixture::new("unusable", [Script::Lists(vec![])]);
    let mut body = request(fixture.peer, OpenLane::Main, None)
        .encode()
        .unwrap();
    // One hint, spelled `0.0.0.0:1`, after the 32-byte peer.
    body.splice(32..33, [1, 9].into_iter().chain(*b"0.0.0.0:1"));
    fixture
        .run(async |socket| {
            let mut client = UnixStream::connect(socket).await.unwrap();
            client.write_all(b"SWC1\x04").await.unwrap();
            client
                .write_all(&u16::try_from(body.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            client.write_all(&body).await.unwrap();
            assert!(matches!(
                Response::read_open(&mut client).await.unwrap(),
                Response::Error(reason) if reason == "open request hint cannot be a machine's address"
            ));
        })
        .await;
    assert_eq!(fixture.scripted.dials(), 0);
}

#[tokio::test]
async fn a_gone_client_releases_its_splice_from_a_silent_peer() {
    let fixture = Fixture::new("gone", [Script::Holds]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Bulk, None)).await;
            attached(&mut client).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            drop(client);
            released(&fixture.opener, HANG_GUARD).await;
            assert_eq!(
                fixture.opener.beyond_main.available_permits(),
                MAX_BEYOND_MAIN
            );
        })
        .await;
}

#[tokio::test]
async fn a_half_closed_client_keeps_its_splice() {
    let fixture = Fixture::new("halfclose", [Script::Holds]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Bulk, None)).await;
            attached(&mut client).await;
            client.shutdown().await.unwrap();
            tokio::time::sleep(HANG_GUARD).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
        })
        .await;
}

#[tokio::test]
async fn a_client_gone_before_attached_returns_its_slots() {
    let fixture = Fixture::new("early", [Script::Silent]);
    fixture
        .run(async |socket| {
            let client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            // The peer has the request and will never answer: the open waits on it.
            until_true(|| !fixture.scripted.requests().is_empty()).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            drop(client);
            released(&fixture.opener, HANG_GUARD).await;
        })
        .await;
}

#[tokio::test]
async fn an_isolated_splice_is_dropped_at_the_drain_deadline_when_the_peer_takes_nothing() {
    let fixture = Fixture::new("isolated", [Script::Holds]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            attached(&mut client).await;
            // More than the peer's stream holds, so bytes are left when the client goes.
            // Write until the path stalls, since nothing past the peer's stream drains it.
            let _ = tokio::time::timeout(HANG_GUARD, client.write_all(&[7; 1024 * 1024])).await;
            drop(client);
            tokio::time::sleep(HANGUP_DRAIN / 2).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            released(&fixture.opener, HANGUP_DRAIN).await;
        })
        .await;
}

#[tokio::test]
async fn the_hangup_watch_tells_close_from_half_close() {
    let (server, client) = UnixStream::pair().unwrap();
    let gone = ClientGone::watch(server.as_raw_fd()).unwrap();
    let (client_read, mut client_write) = client.into_split();
    client_write.shutdown().await.unwrap();
    assert!(
        tokio::time::timeout(HANG_GUARD, gone.wait()).await.is_err(),
        "a half-close is not a hang-up"
    );
    // The watch takes no wakeup from a writer on the same socket.
    let (_server_read, mut server_write) = server.into_split();
    server_write.write_all(b"ping").await.unwrap();
    let mut client_read = client_read;
    let mut ping = [0; 4];
    client_read.read_exact(&mut ping).await.unwrap();
    drop((client_read, client_write));
    assert!(
        tokio::time::timeout(HANG_GUARD, gone.wait()).await.is_ok(),
        "a socket closed both ways"
    );
}

#[tokio::test(start_paused = true)]
async fn a_gone_client_with_unsent_bytes_is_dropped_at_the_drain_deadline() {
    let mut pair = Pair::new();
    pair.client.write_all(&[7; 16 * 1024]).await.unwrap();
    drop(pair.client);
    let mut spliced = Box::pin(pair.splice);
    assert!(poll!(&mut spliced).is_pending());
    pair.hang_up.send(()).unwrap();
    assert!(poll!(&mut spliced).is_pending());
    tokio::time::advance(HANGUP_DRAIN - Duration::from_millis(1)).await;
    assert!(poll!(&mut spliced).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(poll!(&mut spliced).is_ready());
}

#[tokio::test(start_paused = true)]
async fn a_slow_peer_cannot_stretch_the_hangup_drain() {
    let mut pair = Pair::new();
    pair.client.write_all(&[7; 16 * 1024]).await.unwrap();
    drop(pair.client);
    let mut spliced = Box::pin(pair.splice);
    assert!(poll!(&mut spliced).is_pending());
    pair.hang_up.send(()).unwrap();
    let mut byte = [0];
    for _ in 0..7 {
        // The peer takes one byte each half second: progress, but never enough.
        assert!(poll!(&mut spliced).is_pending());
        pair.peer.read_exact(&mut byte).await.unwrap();
        tokio::time::advance(Duration::from_millis(500)).await;
    }
    assert!(poll!(&mut spliced).is_pending());
    tokio::time::advance(Duration::from_millis(500)).await;
    assert!(poll!(&mut spliced).is_ready());
}

#[tokio::test(start_paused = true)]
async fn a_gone_client_with_nothing_unsent_releases_at_once() {
    let pair = Pair::new();
    drop(pair.client);
    let mut spliced = Box::pin(pair.splice);
    pair.hang_up.send(()).unwrap();
    assert!(poll!(&mut spliced).is_ready());
}

#[tokio::test(start_paused = true)]
async fn a_peer_still_sending_does_not_hold_a_gone_client() {
    // One stream each way, so the client's writing can end while its reading does not.
    let (client_write, from_client) = tokio::io::duplex(64);
    let (to_client, client_read) = tokio::io::duplex(64);
    let (mut peer, peer_end) = tokio::io::duplex(64);
    let (from_peer, to_peer) = tokio::io::split(peer_end);
    let (hang_up, hung) = tokio::sync::oneshot::channel::<()>();
    // The client has stopped writing and reads nothing; the peer keeps its stream open to send more.
    drop(client_write);
    peer.write_all(&[1; 64]).await.unwrap();
    let mut spliced = Box::pin(splice(
        BufReader::new(from_client),
        to_client,
        from_peer,
        to_peer,
        async {
            let _ = hung.await;
        },
    ));
    assert!(poll!(&mut spliced).is_pending());
    hang_up.send(()).unwrap();
    assert!(poll!(&mut spliced).is_ready());
    drop((client_read, peer));
}

#[tokio::test]
async fn bytes_a_client_wrote_before_closing_reach_a_live_peer() {
    let mut pair = Pair::new();
    let sent: Vec<u8> = (0..64 * 1024).map(|at| (at % 251) as u8).collect();
    pair.client.write_all(&sent[..32]).await.unwrap();
    let (hang_up, mut peer, splice) = (pair.hang_up, pair.peer, pair.splice);
    let mut client = pair.client;
    let writer = async {
        client.write_all(&sent[32..]).await.unwrap();
        drop(client);
        hang_up.send(()).unwrap();
    };
    let reader = async {
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.unwrap();
        got
    };
    let joined = tokio::time::timeout(HANG_GUARD * 5, async {
        tokio::join!(writer, reader, splice)
    })
    .await;
    let ((), got, ()) = joined.expect("the splice ended");
    assert_eq!(got, sent);
}

#[test]
fn the_non_main_share_always_leaves_main_its_slots() {
    let fixture = Fixture::new("share", []);
    let opener = &fixture.opener;
    let mut held: Vec<_> = (0..MAX_BEYOND_MAIN)
        .map(|at| {
            let lane = [OpenLane::Bulk, OpenLane::Isolated][at % 2];
            opener.hold(lane, false).unwrap()
        })
        .collect();
    assert!(matches!(
        opener.hold(OpenLane::Bulk, false),
        Err(OpenRefusal::Busy)
    ));
    // A slip's Main rides a session of its own, so it is not ordinary Main.
    assert!(matches!(
        opener.hold(OpenLane::Main, true),
        Err(OpenRefusal::Busy)
    ));
    for _ in MAX_BEYOND_MAIN..MAX_REACH {
        held.push(opener.hold(OpenLane::Main, false).unwrap());
    }
    assert!(matches!(
        opener.hold(OpenLane::Main, false),
        Err(OpenRefusal::Busy)
    ));
    held.pop();
    assert!(opener.hold(OpenLane::Main, false).is_ok());
}

#[test]
fn a_failed_open_carries_only_fixed_words() {
    let named = bifrost::Error::Connect("dial 192.0.2.1:7 failed".into());
    let OpenRefusal::Unreachable(detail) = failed(&OpenError::Unreachable(DialFailure::Failed(
        Arc::new(named),
    ))) else {
        panic!("a dial failure is unreachable");
    };
    assert_eq!(detail.as_str(), UNREACHABLE);
    let OpenRefusal::Broken(detail) = failed(&OpenError::Open(bifrost::Error::Stream(
        "reset by 192.0.2.1:7".into(),
    ))) else {
        panic!("a stream failure is broken");
    };
    assert_eq!(detail.as_str(), BROKEN);
    assert_eq!(
        failed(&OpenError::Unreachable(DialFailure::TimedOut)),
        OpenRefusal::Timeout
    );
}

const THIS: u8 = 1;
const PEER: u8 = 0x63;

/// A resident and its opener over a scratch home, reaching one scripted peer.
struct Fixture {
    this: NodeId,
    peer: NodeId,
    scripted: ScriptedPeer,
    resident: Arc<Resident>,
    opener: Opener<'static, 'static, 'static, ScriptedPeer, NoDiscovery, Never>,
    dir: std::path::PathBuf,
}

impl Fixture {
    fn new(tag: &str, script: impl IntoIterator<Item = Script>) -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "swo-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        crate::config::create_store_dir(&dir).unwrap();
        let home: &'static Home = Box::leak(Box::new(Home::resolve(Some(dir.clone())).unwrap()));
        let this = TestNode::seeded(THIS).node_id();
        let peer = TestNode::seeded(PEER).node_id();
        let scripted = ScriptedPeer::new(peer, script);
        let node = Box::leak(Box::new(Node::new(scripted.clone(), NoDiscovery)));
        let peers = Box::leak(Box::new(Peers::new(node)));
        let renewal = Box::leak(Box::new(OpenRenewal::new(home, &Never)));
        let resident = Arc::new(Resident::new(
            this,
            None,
            ServiceCatalog::decode(&0u32.to_be_bytes()).unwrap(),
            crate::serve_toml::LiveServeToml::load(home).unwrap(),
            CancellationToken::new(),
            Arc::default(),
        ));
        Self {
            this,
            peer,
            scripted,
            resident,
            opener: Opener::new(peers, renewal, home, this),
            dir,
        }
    }

    /// Serve the control socket while `client` runs against it, on this one task: the opener's
    /// sessions are not `Send`.
    async fn run(&self, client: impl AsyncFnOnce(&std::path::Path)) {
        let socket = self.dir.join("c.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let serving = Arc::clone(&self.resident).serve(listener, &self.opener);
        tokio::select! {
            ended = serving => panic!("the resident stopped: {ended:?}"),
            () = client(&socket) => {}
        }
    }
}

/// A [`Fetch`] that never reaches a device: these homes are never due.
struct Never;

impl Fetch for Never {
    async fn fetch(&self, _peer: NodeId) -> Result<Option<Link>, FetchError> {
        Ok(None)
    }
}

fn until() -> SystemTime {
    SystemTime::now() + Duration::from_secs(3600)
}

/// An Open for `ssh` at `peer`.
fn request(peer: NodeId, lane: OpenLane, slip: Option<Link>) -> OpenRequest {
    OpenRequest::new(peer, Hints::NONE, "ssh".parse().unwrap(), lane, slip).unwrap()
}

/// Connect to the resident and send `open`.
async fn open(socket: &std::path::Path, open: OpenRequest) -> UnixStream {
    let mut client = UnixStream::connect(socket).await.unwrap();
    Request::Open(open).write(&mut client).await.unwrap();
    client
}

/// Read a refusal reply, and the end of the connection after it.
async fn refusal(client: &mut UnixStream) -> OpenRefusal {
    let Response::OpenRefusal(refusal) = Response::read_open(client).await.unwrap() else {
        panic!("expected a refusal");
    };
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    refusal
}

/// How long a test waits on something that should happen at once, before calling it lost.
const HANG_GUARD: Duration = Duration::from_secs(1);

/// The client's and the peer's ends of a splice over in-process streams, the peer's holding 64 bytes so
/// it fills, and the hang-up the test fires.
struct Pair<F> {
    client: DuplexStream,
    peer: DuplexStream,
    hang_up: tokio::sync::oneshot::Sender<()>,
    splice: F,
}

impl Pair<()> {
    #[allow(clippy::new_ret_no_self)]
    fn new() -> Pair<impl Future<Output = ()>> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (from_client, to_client) = tokio::io::split(server);
        let (peer, peer_end) = tokio::io::duplex(64);
        let (from_peer, to_peer) = tokio::io::split(peer_end);
        let (hang_up, hung) = tokio::sync::oneshot::channel::<()>();
        Pair {
            client,
            peer,
            hang_up,
            splice: splice(
                BufReader::new(from_client),
                to_client,
                from_peer,
                to_peer,
                async {
                    let _ = hung.await;
                },
            ),
        }
    }
}

/// Read the Attached reply.
async fn attached(client: &mut UnixStream) {
    assert!(matches!(
        Response::read_open(client).await.unwrap(),
        Response::Attached(_)
    ));
}

/// Wait at most `within` for every reach slot to be back.
async fn released(opener: &Opener<'_, '_, '_, ScriptedPeer, NoDiscovery, Never>, within: Duration) {
    let back = tokio::time::timeout(
        within,
        until_true(|| opener.reach.available_permits() == MAX_REACH),
    )
    .await;
    assert!(back.is_ok(), "the open kept its slots");
}

/// Wait, yielding to the resident, until `ready` holds.
async fn until_true(ready: impl Fn() -> bool) {
    while !ready() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
