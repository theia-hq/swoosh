//! Server Open through the resident's real accept path over a unix socket, against a scripted peer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::os::fd::AsRawFd as _;
use std::sync::Arc;
use std::time::SystemTime;

use bifrost::{
    NoDiscovery, Node, NodeId, Refusal, RefusalDetail, Session as _, Transport as _, WriteEnd,
};
use bifrost_mem::{MemRead, MemSession, MemTransport, MemWrite};
use futures::poll;
use nauthy::Link;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream};
use tokio::net::UnixStream;

use super::{
    BROKEN, ClientGone, HANGUP_DRAIN, MAX_BEYOND_MAIN, MAX_REACH, OPEN_FILES, Opener, UNREACHABLE,
    UNREADABLE_HOME, attach, failed, raise_open_files, splice,
};
use crate::home::Home;
use crate::peers::{DialFailure, Hints, OpenError, Peers};
use crate::renewal::renewal_tests::{DAY, LAPTOP, device, lapsed_laptop, node, now};
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
async fn an_isolated_close_releases_its_slot_once_the_peer_holds_what_was_sent() {
    let fixture = Fixture::new("iso-taken", [Script::EndsThenReads(HANGUP_DRAIN / 4)]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            attached(&mut client).await;
            client.write_all(b"the last of an upload").await.unwrap();
            client.shutdown().await.unwrap();
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
            // The peer ended first and takes the bytes only after its pause, well inside the drain.
            let taken = tokio::time::timeout(
                HANGUP_DRAIN,
                until_true(|| fixture.scripted.received() == b"the last of an upload"),
            )
            .await;
            assert!(
                taken.is_ok(),
                "the peer took {:?}",
                fixture.scripted.received()
            );
            // Delivery is confirmed now, three seconds before the drain would end.
            released(&fixture.opener, HANG_GUARD).await;
        })
        .await;
}

#[tokio::test]
async fn an_isolated_peer_that_never_takes_the_end_is_released_at_the_drain() {
    let fixture = Fixture::new("iso-never", [Script::Ends]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            attached(&mut client).await;
            client.write_all(b"never read").await.unwrap();
            client.shutdown().await.unwrap();
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
            // A clean end on both sides, and a peer that holds the stream without reading it.
            tokio::time::sleep(HANGUP_DRAIN - HANG_GUARD).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            released(&fixture.opener, HANG_GUARD * 2).await;
        })
        .await;
}

#[tokio::test]
async fn an_isolated_close_past_the_drain_loses_what_the_peer_did_not_take() {
    let late = HANGUP_DRAIN + HANG_GUARD;
    let fixture = Fixture::new("iso-late", [Script::EndsThenReads(late)]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            attached(&mut client).await;
            client.write_all(b"never taken").await.unwrap();
            client.shutdown().await.unwrap();
            let mut rest = Vec::new();
            client.read_to_end(&mut rest).await.unwrap();
            // A peer that keeps the connection and takes nothing holds it no longer than the drain.
            released(&fixture.opener, HANGUP_DRAIN + HANG_GUARD).await;
            tokio::time::sleep(late).await;
            assert!(fixture.scripted.received().is_empty());
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
    // The watch takes no wakeup from a writer on the same socket: more than the socket holds must wait
    // for the client to read, and that wait ends only if the writer's own wakeups reach it while the
    // watch is waiting too.
    let (_server_read, mut server_write) = server.into_split();
    let sent = vec![7; 1024 * 1024];
    let mut client_read = client_read;
    let mut got = vec![0; sent.len()];
    let moved = tokio::time::timeout(HANG_GUARD * 5, async {
        tokio::select! {
            () = gone.wait() => panic!("a write on the same socket is not a hang-up"),
            moved = async { tokio::join!(server_write.write_all(&sent), client_read.read_exact(&mut got)) } => moved,
        }
    })
    .await
    .expect("the writer lost its wakeup to the watch");
    moved.0.unwrap();
    moved.1.unwrap();
    assert_eq!(got, sent);
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
        core::future::pending(),
    ));
    assert!(poll!(&mut spliced).is_pending());
    hang_up.send(()).unwrap();
    assert!(poll!(&mut spliced).is_ready());
    drop((client_read, peer));
}

#[tokio::test(start_paused = true)]
async fn a_clean_end_leaves_the_close_the_whole_drain() {
    let pair = Pair::new();
    let (client, mut peer) = (pair.client, pair.peer);
    // Both directions end: the client stops writing, and the peer ends its own.
    drop(client);
    peer.shutdown().await.unwrap();
    let ended = tokio::time::Instant::now();
    let mut sent = Vec::new();
    let (close_by, read) = tokio::join!(pair.splice, peer.read_to_end(&mut sent));
    read.unwrap();
    assert_eq!(close_by, ended + HANGUP_DRAIN);
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
    let ((), got, _) = joined.expect("the splice ended");
    assert_eq!(got, sent);
}

#[tokio::test]
async fn an_open_dropped_mid_splice_resets_the_peers_stream() {
    let mut stream = MemStream::new().await;
    let mut client = stream.client.take().unwrap();
    client.write_all(b"half an upload").await.unwrap();
    // Dropped while it splices, as a gone client, `Stop` or a panic drops the Open.
    let spliced = tokio::time::timeout(HANG_GUARD / 4, stream.attach()).await;
    assert!(spliced.is_err(), "the splice ended on its own");
    assert_eq!(stream.peer_reads().await, Ended::Reset);
    drop(client);
}

#[tokio::test]
async fn a_splice_cut_at_the_drain_deadline_resets_the_peers_stream() {
    let mut stream = MemStream::new().await;
    let mut client = stream.client.take().unwrap();
    // More than the peer's stream holds, which the peer never reads, then gone.
    let goes = async {
        let _ = tokio::time::timeout(HANG_GUARD, client.write_all(&[7; 1024 * 1024])).await;
        drop(client);
    };
    let (close_by, ()) = tokio::join!(stream.attach(), goes);
    assert!(close_by <= tokio::time::Instant::now());
    assert_eq!(stream.peer_reads().await, Ended::Reset);
}

#[tokio::test]
async fn an_attached_reply_that_cannot_be_written_resets_the_peers_stream() {
    let mut stream = MemStream::new().await;
    let (_client, from_client) = tokio::io::duplex(64);
    attach(
        BufReader::new(from_client),
        Gone,
        stream.from_peer.take().unwrap(),
        &mut stream.to_peer,
        stream.sessions[0].conn_info(),
        &stream.gone,
    )
    .await;
    assert_eq!(stream.peer_reads().await, Ended::Reset);
}

#[tokio::test]
async fn a_clean_end_after_shutdown_stays_clean() {
    let mut stream = MemStream::new().await;
    let mut client = stream.client.take().unwrap();
    client.write_all(b"a whole upload").await.unwrap();
    client.shutdown().await.unwrap();
    stream.peer.0.shutdown().await.unwrap();
    let mut back = Vec::new();
    let (_, read) = tokio::join!(stream.attach(), client.read_to_end(&mut back));
    read.unwrap();
    let mut got = Vec::new();
    stream.peer.1.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"a whole upload");
    // mem ignores an abort after a clean end, so only the count tells one was never sent.
    assert_eq!(stream.to_peer.aborts, 0);
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

#[tokio::test]
async fn an_open_with_an_ended_badge_is_standing_ended() {
    let home = lapsed_laptop("open-ended").await;
    let fixture = Fixture::over(home, node(LAPTOP), Asks::default(), []);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            assert_eq!(refusal(&mut client).await, OpenRefusal::StandingEnded);
        })
        .await;
    assert_eq!(fixture.asks.asked(), 1, "the lapsed standing was due");
    assert_eq!(fixture.scripted.dials(), 0);
}

#[tokio::test]
async fn an_open_whose_home_cannot_be_read_is_an_error_not_standing_ended() {
    let home = device("open-unreadable", LAPTOP, now() + 90 * DAY).await;
    std::fs::create_dir(home.root_key()).unwrap();
    std::fs::set_permissions(
        home.root_key(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    let fixture = Fixture::over(home, node(LAPTOP), Asks::default(), []);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            assert_eq!(
                Response::read_open(&mut client).await.unwrap(),
                Response::Error(UNREADABLE_HOME.to_owned())
            );
        })
        .await;
    assert_eq!(fixture.scripted.dials(), 0);
}

#[tokio::test]
async fn a_badge_planted_as_a_fifo_does_not_hold_an_open() {
    let home = device("open-fifo", LAPTOP, now() + 90 * DAY).await;
    let _released = Fifo::plant(&home.key_cert());
    let fixture = Fixture::over(home, node(LAPTOP), Asks::default(), []);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            let reply = tokio::time::timeout(HANG_GUARD * 5, Response::read_open(&mut client))
                .await
                .expect("a FIFO held the Open");
            assert_eq!(reply.unwrap(), Response::Error(UNREADABLE_HOME.to_owned()));
        })
        .await;
}

#[tokio::test]
async fn both_badge_reads_refuse_a_fifo_at_once() {
    let home = device("reads-fifo", LAPTOP, now() + 90 * DAY).await;
    let _released = Fifo::plant(&home.key_cert());
    let standing = tokio::time::timeout(HANG_GUARD, crate::standing::Standing::read(&home)).await;
    assert!(
        standing
            .expect("the standing read waited on a FIFO")
            .is_err()
    );
    let badge = tokio::time::timeout(HANG_GUARD, crate::config::load_badge(&home)).await;
    assert!(badge.expect("the badge read waited on a FIFO").is_err());
}

#[tokio::test]
async fn a_busy_peer_lane_refuses_before_any_renewal() {
    let home = lapsed_laptop("busy-first").await;
    let fixture = Fixture::over(home, node(LAPTOP), Asks::default(), []);
    let places: Vec<_> = (0..4)
        .map(|_| fixture.peers.isolated_place(fixture.peer).unwrap())
        .collect();
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            assert_eq!(refusal(&mut client).await, OpenRefusal::Busy);
            assert_eq!(fixture.asks.asked(), 0, "a Busy Open started a renewal");
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH);
            // With room on the lane, the same Open renews first: the due standing is asked for.
            drop(places);
            let mut client = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            assert_eq!(refusal(&mut client).await, OpenRefusal::StandingEnded);
            assert_eq!(fixture.asks.asked(), 1);
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn an_isolated_open_times_out_at_bulks_ten_seconds() {
    let fixture = Fixture::new("isolated-timeout", [Script::Silent]);
    fixture
        .run(async |socket| {
            let start = tokio::time::Instant::now();
            let mut client = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            assert_eq!(refusal(&mut client).await, OpenRefusal::Timeout);
            let waited = start.elapsed();
            let ten = Duration::from_secs(10);
            assert!(
                waited >= ten && waited < ten + HANG_GUARD,
                "an isolated open waited {waited:?}"
            );
        })
        .await;
}

/// Attach a Bulk splice to a peer that ends its stream and never reads, read the peer's end, then
/// write until the path stalls, leaving the client's bytes unsent.
async fn stalled_after_the_peer_ended(socket: &std::path::Path, peer: NodeId) -> UnixStream {
    let mut client = open(socket, request(peer, OpenLane::Bulk, None)).await;
    attached(&mut client).await;
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    let _ = tokio::time::timeout(HANG_GUARD, client.write_all(&[7; 1024 * 1024])).await;
    client
}

#[tokio::test]
async fn a_gone_client_after_the_peer_ended_releases_at_the_drain() {
    let fixture = Fixture::new("ended-gone", [Script::Ends]);
    fixture
        .run(async |socket| {
            let client = stalled_after_the_peer_ended(socket, fixture.peer).await;
            drop(client);
            released(&fixture.opener, HANGUP_DRAIN + HANG_GUARD).await;
        })
        .await;
}

#[tokio::test]
async fn a_half_closed_client_after_the_peer_ended_releases_at_the_drain() {
    let fixture = Fixture::new("ended-half", [Script::Ends]);
    fixture
        .run(async |socket| {
            let mut client = stalled_after_the_peer_ended(socket, fixture.peer).await;
            client.shutdown().await.unwrap();
            released(&fixture.opener, HANGUP_DRAIN + HANG_GUARD).await;
            drop(client);
        })
        .await;
}

#[tokio::test]
async fn a_client_still_open_to_an_ended_peer_stays_live() {
    let fixture = Fixture::new("ended-live", [Script::Ends]);
    fixture
        .run(async |socket| {
            let client = stalled_after_the_peer_ended(socket, fixture.peer).await;
            tokio::time::sleep(HANGUP_DRAIN + HANG_GUARD).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            drop(client);
        })
        .await;
}

#[tokio::test]
async fn a_failed_write_to_the_client_still_sends_its_bytes_to_the_peer() {
    let (mut client, from_client) = tokio::io::duplex(1024);
    let (mut peer, peer_end) = tokio::io::duplex(1024);
    let (from_peer, to_peer) = tokio::io::split(peer_end);
    // The peer has a byte for the client, and the client's socket refuses it.
    peer.write_all(&[1]).await.unwrap();
    let mut spliced = Box::pin(splice(
        BufReader::new(from_client),
        Gone,
        from_peer,
        to_peer,
        core::future::pending(),
        core::future::pending(),
    ));
    assert!(
        poll!(&mut spliced).is_pending(),
        "a failed write ended the splice"
    );
    client.write_all(b"last words").await.unwrap();
    drop(client);
    let mut got = Vec::new();
    let (_, read) = tokio::join!(spliced, peer.read_to_end(&mut got));
    read.unwrap();
    assert_eq!(got, b"last words");
}

#[tokio::test]
async fn a_payload_in_the_requests_write_reaches_the_peer() {
    let fixture = Fixture::new("payload", [Script::Reads]);
    fixture
        .run(async |socket| {
            let mut bytes = Vec::new();
            Request::Open(request(fixture.peer, OpenLane::Main, None))
                .write(&mut bytes)
                .await
                .unwrap();
            bytes.extend_from_slice(b"sent with the request");
            let mut client = UnixStream::connect(socket).await.unwrap();
            client.write_all(&bytes).await.unwrap();
            client.shutdown().await.unwrap();
            attached(&mut client).await;
            let arrived = tokio::time::timeout(
                HANG_GUARD,
                until_true(|| fixture.scripted.received() == b"sent with the request"),
            )
            .await;
            assert!(
                arrived.is_ok(),
                "the peer read {:?}",
                fixture.scripted.received()
            );
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn a_renewal_an_open_left_runs_to_its_end_on_the_served_socket() {
    let home = lapsed_laptop("left-flight").await;
    let fixture = Fixture::over(home, node(LAPTOP), Asks::holding(), []);
    fixture
        .run(async |socket| {
            let client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            until_true(|| fixture.asks.asked() == 1).await;
            drop(client);
            // Nothing waits on the flight now; only the served socket's drive can end its ask.
            tokio::time::sleep(Duration::from_secs(10)).await;
            assert_eq!(fixture.asks.ended(), 1, "the flight was left parked");
        })
        .await;
}

/// The child half of [`a_watch_that_cannot_be_made_is_busy`]: an Open arriving with one descriptor
/// short of its watch.
#[tokio::test]
#[ignore = "run in its own process by a_watch_that_cannot_be_made_is_busy"]
async fn no_descriptor_child() {
    let fixture = Fixture::new("no-fd", [Script::Lists(vec![])]);
    set_open_files(128);
    fixture
        .run(async |socket| {
            let mut held = Vec::new();
            while let Ok(file) = std::fs::File::open("/dev/null") {
                held.push(file);
            }
            // Two left: the client's socket and the accepted one. The watch's duplicate finds none.
            held.truncate(held.len() - 2);
            let mut client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            assert_eq!(refusal(&mut client).await, OpenRefusal::Busy);
            drop(held);
        })
        .await;
    assert_eq!(fixture.scripted.dials(), 0);
}

#[test]
fn a_watch_that_cannot_be_made_is_busy() {
    in_own_process("serve::opening::tests::no_descriptor_child");
}

/// The child half of [`serve_raises_the_open_file_limit`].
#[test]
#[ignore = "run in its own process by serve_raises_the_open_file_limit"]
fn open_files_child() {
    set_open_files(64);
    raise_open_files().unwrap();
    let (soft, hard) = open_files();
    assert_eq!(soft, OPEN_FILES.min(hard));
    // Never lowered.
    set_open_files(OPEN_FILES.min(hard));
    raise_open_files().unwrap();
    assert_eq!(open_files().0, OPEN_FILES.min(hard));
}

#[test]
fn serve_raises_the_open_file_limit() {
    in_own_process("serve::opening::tests::open_files_child");
}

/// Run the ignored test `name` alone in a child of this test binary, and require it to pass.
fn in_own_process(name: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--include-ignored"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("1 passed"), "{stdout}");
}

/// This process's soft and hard open-file limits.
fn open_files() -> (libc::rlim_t, libc::rlim_t) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable `rlimit` for the call to fill.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    (limit.rlim_cur, limit.rlim_max)
}

/// Set this process's soft open-file limit to `soft`.
fn set_open_files(soft: libc::rlim_t) {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: open_files().1,
    };
    // SAFETY: `limit` is a valid `rlimit` that outlives the call, which only reads it.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
}

/// A FIFO planted in place of a file. Dropping it opens and closes the writing end, so a read the
/// guard failed to stop gets its end of file and the test's runtime can shut down.
struct Fifo(std::path::PathBuf);

impl Fifo {
    fn plant(path: &std::path::Path) -> Self {
        let _ = std::fs::remove_file(path);
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `name` is a valid NUL-terminated path for the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        Self(path.to_owned())
    }
}

impl Drop for Fifo {
    fn drop(&mut self) {
        use std::os::unix::fs::OpenOptionsExt as _;

        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&self.0);
    }
}

/// A client socket that refuses every write, as one whose client went refuses with `EPIPE`.
struct Gone;

impl tokio::io::AsyncWrite for Gone {
    // `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
        _buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        core::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }
}

const THIS: u8 = 1;
const PEER: u8 = 0x63;

/// A resident and its opener over a scratch home, reaching one scripted peer.
struct Fixture {
    this: NodeId,
    peer: NodeId,
    scripted: ScriptedPeer,
    resident: Arc<Resident>,
    peers: &'static Peers<'static, ScriptedPeer, NoDiscovery>,
    asks: &'static Asks,
    opener: Opener<'static, 'static, 'static, ScriptedPeer, NoDiscovery, Asks>,
    /// A short directory of its own for the socket, whose path has a length cap.
    dir: std::path::PathBuf,
}

impl Fixture {
    /// Over a fresh home with no standing, so nothing is due.
    fn new(tag: &str, script: impl IntoIterator<Item = Script>) -> Self {
        let home = Home::resolve(Some(scratch(tag))).unwrap();
        Self::over(
            home,
            TestNode::seeded(THIS).node_id(),
            Asks::default(),
            script,
        )
    }

    /// Over `home`, this machine being `this`, asking devices through `asks`.
    fn over(
        home: Home,
        this: NodeId,
        asks: Asks,
        script: impl IntoIterator<Item = Script>,
    ) -> Self {
        let dir = scratch("sock");
        let home: &'static Home = Box::leak(Box::new(home));
        let peer = TestNode::seeded(PEER).node_id();
        let scripted = ScriptedPeer::new(peer, script);
        let node = Box::leak(Box::new(Node::new(scripted.clone(), NoDiscovery)));
        let peers: &'static Peers<'static, ScriptedPeer, NoDiscovery> =
            Box::leak(Box::new(Peers::new(node)));
        let asks: &'static Asks = Box::leak(Box::new(asks));
        let renewal = Box::leak(Box::new(OpenRenewal::new(home, asks)));
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
            peers,
            asks,
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

/// A [`Fetch`] that counts its asks and answers no standing, at once or, when `holds`, never; it counts
/// the asks that ended, answered or cut off.
#[derive(Default)]
struct Asks {
    holds: bool,
    asked: AtomicU32,
    ended: Arc<AtomicU32>,
}

impl Asks {
    fn holding() -> Self {
        Self {
            holds: true,
            ..Self::default()
        }
    }

    fn asked(&self) -> u32 {
        self.asked.load(Ordering::Relaxed)
    }

    fn ended(&self) -> u32 {
        self.ended.load(Ordering::Relaxed)
    }
}

impl Fetch for Asks {
    async fn fetch(&self, _peer: NodeId) -> Result<Option<Link>, FetchError> {
        /// Counts the ask as ended however its future goes.
        struct Ending(Arc<AtomicU32>);
        impl Drop for Ending {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.asked.fetch_add(1, Ordering::Relaxed);
        let _ending = Ending(Arc::clone(&self.ended));
        if self.holds {
            core::future::pending::<()>().await;
        }
        Ok(None)
    }
}

/// A fresh owner-only directory under the temporary directory, short enough to hold a socket.
fn scratch(tag: &str) -> std::path::PathBuf {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "swo-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    crate::config::create_store_dir(&dir).unwrap();
    dir
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
    fn new() -> Pair<impl Future<Output = tokio::time::Instant>> {
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
                core::future::pending(),
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
async fn released(opener: &Opener<'_, '_, '_, ScriptedPeer, NoDiscovery, Asks>, within: Duration) {
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

/// An attached Open's two sides over a real socket and mem's transport, whose peer reads an abort as
/// `ConnectionReset`: the client's socket, the server's end of it and its watch, and the stream to the
/// peer, both ends.
struct MemStream {
    sessions: [MemSession; 2],
    client: Option<UnixStream>,
    server: Option<UnixStream>,
    gone: ClientGone,
    to_peer: Counted<MemWrite>,
    from_peer: Option<MemRead>,
    peer: (MemWrite, MemRead),
}

impl MemStream {
    async fn new() -> Self {
        let (near, far) = (MemTransport::bind(), MemTransport::bind());
        let session = near.connect(far.local_addr()).await.unwrap();
        let peer_session = far.accept().await.unwrap();
        let (to_peer, from_peer) = session.open_bi().await.unwrap();
        let peer = peer_session.accept_bi().await.unwrap();
        let (server, client) = UnixStream::pair().unwrap();
        let gone = ClientGone::watch(server.as_raw_fd()).unwrap();
        Self {
            sessions: [session, peer_session],
            client: Some(client),
            server: Some(server),
            gone,
            to_peer: Counted {
                half: to_peer,
                aborts: 0,
            },
            from_peer: Some(from_peer),
            peer,
        }
    }

    /// Attach the client to the peer, as an Open does once its stream opened.
    async fn attach(&mut self) -> tokio::time::Instant {
        let (from_client, to_client) = self.server.take().unwrap().into_split();
        attach(
            BufReader::new(from_client),
            to_client,
            self.from_peer.take().unwrap(),
            &mut self.to_peer,
            self.sessions[0].conn_info(),
            &self.gone,
        )
        .await
    }

    /// How the peer's read of the stream ends.
    // `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    async fn peer_reads(&mut self) -> Ended {
        let mut got = Vec::new();
        let read = tokio::time::timeout(HANG_GUARD, self.peer.1.read_to_end(&mut got)).await;
        match read.expect("the peer's read hung") {
            Ok(_) => Ended::Clean,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ended::Reset,
            Err(error) => Ended::Failed(error.to_string()),
        }
    }
}

/// How a peer's read of a stream ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// A clean end of stream: to the peer, everything was sent.
    Clean,
    /// `ConnectionReset`: the stream was cut off.
    Reset,
    /// Any other failure.
    Failed(String),
}

/// A write half that counts its aborts: mem ignores one after a clean end, so the peer cannot tell.
struct Counted<W> {
    half: W,
    aborts: u32,
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Counted<W> {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        core::pin::Pin::new(&mut self.get_mut().half).poll_write(cx, buf)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::pin::Pin::new(&mut self.get_mut().half).poll_flush(cx)
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::pin::Pin::new(&mut self.get_mut().half).poll_shutdown(cx)
    }
}

impl<W: WriteEnd> WriteEnd for Counted<W> {
    fn abort(&mut self) {
        self.aborts += 1;
        self.half.abort();
    }

    fn delivered(self) -> impl Future<Output = std::io::Result<()>> + Send + 'static {
        self.half.delivered()
    }
}
