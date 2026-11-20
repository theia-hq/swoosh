//! Server Open through the resident's real accept path over a unix socket, against a scripted peer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::cell::Cell;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::os::fd::AsRawFd as _;
use std::rc::Rc;
use std::sync::Arc;
use std::time::SystemTime;

use bifrost::{
    ConnInfo, NoDiscovery, Node, NodeId, Refusal, RefusalDetail, Session as _, Transport as _,
    WriteEnd,
};
use bifrost_mem::{MemRead, MemSession, MemTransport, MemWrite};
use futures::poll;
use nauthy::Link;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream};
use tokio::net::UnixStream;

use super::{
    BROKEN, Carrier, ClientGone, HANGUP_DRAIN, MAX_BEYOND_MAIN, MAX_REACH, OPEN_FILES, Observing,
    Opener, Opens as _, REPLY_TIMEOUT, TERMINAL_RETENTION, ToPeer, UNREACHABLE, UNREADABLE_HOME,
    attach, failed, raise_open_files, splice,
};
use crate::home::Home;
use crate::peers::{DialFailure, Hints, OpenError, Peers};
use crate::renewal::renewal_tests::{DAY, LAPTOP, device, lapsed_laptop, node, now};
use crate::renewal::{Fetch, FetchError, OpenRenewal};
use crate::serve::control_codec::{
    Attached, Epoch, MAX_FRAME, OpenLane, OpenRefusal, OpenRequest, PathAction, PathRef, PathReply,
    PathRequest, PeerRefusal, Request, Response,
};
use crate::serve::observing::Observations;
use crate::serve::socket::Ticket;
use crate::serve::socket::splice::{DataLen, Frame, HEADER, Toward, read_frame};
use crate::serve::{MAX_CONTROL_CONNS, Resident};
use crate::testkit::{Script, ScriptedPeer, TestNode, TestWrite};

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
            // The peer's own bytes after it admitted the stream, a list naming `x`, then its clean end.
            let spliced = download(&mut client).await;
            assert_eq!(spliced, [0, 0, 0, 1, 0, 1, b'x', 0]);
        })
        .await;
    assert_eq!(fixture.scripted.requests()[0].service, "ssh");
}

#[tokio::test]
async fn the_client_open_uploads_downloads_and_hears_landed_through_the_resident() {
    let fixture = Fixture::new("client", [Script::Reads]);
    fixture
        .run(async |socket| {
            let stream = UnixStream::connect(socket).await.unwrap();
            let opened = crate::node_client::UidSocket::open_on(
                stream,
                request(fixture.peer, OpenLane::Main, None),
            )
            .await
            .unwrap();
            let crate::node_client::Opened::Attached {
                mut read,
                mut write,
                ..
            } = opened
            else {
                panic!("not attached: {opened:?}");
            };
            write.write_all(b"an upload").await.unwrap();
            write.shutdown().await.unwrap();
            // The peer reads the upload to its end, then ends its own side with nothing sent.
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            assert!(got.is_empty());
            read.landed().await.unwrap();
            assert_eq!(fixture.scripted.received(), b"an upload");
        })
        .await;
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
async fn an_unknown_observation_mode_is_an_error_before_any_dial() {
    let fixture = Fixture::new("observed", [Script::Lists(vec![])]);
    let mut body = request(fixture.peer, OpenLane::Main, None)
        .encode()
        .unwrap();
    *body.last_mut().unwrap() = 2;
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
async fn a_client_that_ended_and_half_closed_keeps_its_download() {
    let fixture = Fixture::new("halfclose", [Script::ReadsThenHolds]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Bulk, None)).await;
            attached(&mut client).await;
            client.write_all(&END).await.unwrap();
            client.shutdown().await.unwrap();
            // The peer holds the upload's end, so Landed comes, and the download stays open.
            let mut header = [0; HEADER];
            client.read_exact(&mut header).await.unwrap();
            assert_eq!(header, LANDED);
            tokio::time::sleep(HANG_GUARD).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
        })
        .await;
}

#[tokio::test]
async fn a_stop_tag_after_attached_ends_the_open_and_never_stops_the_run() {
    let fixture = Fixture::new("stop-tag", [Script::Holds]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Main, None)).await;
            attached(&mut client).await;
            // A Stop request's frame inside the splice is malformed there, never a request.
            client.write_all(b"SWC1\x03\x00\x00").await.unwrap();
            released(&fixture.opener, HANG_GUARD).await;
            // The run still answers: a Stop would have ended `run`'s serving, failing the test.
            let mut asked = UnixStream::connect(socket).await.unwrap();
            Request::Status.write(&mut asked).await.unwrap();
            assert!(matches!(
                Response::read(&mut asked).await.unwrap(),
                Response::Status(_)
            ));
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
            let flood = framed(&[7; 1024 * 1024]);
            let _ = tokio::time::timeout(HANG_GUARD, client.write_all(&flood)).await;
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
            client
                .write_all(&ended(b"the last of an upload"))
                .await
                .unwrap();
            client.shutdown().await.unwrap();
            // The peer ended first and takes the bytes only after its pause, well inside the drain:
            // then the upload has landed, and the connection closes.
            let read = read_all(&mut client).await;
            assert!(read.end && read.landed, "{read:?}");
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
async fn an_isolated_peer_that_never_takes_the_end_is_released_at_the_drain_from_the_hang_up() {
    let fixture = Fixture::new("iso-never", [Script::Ends]);
    fixture
        .run(async |socket| {
            let mut client = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            attached(&mut client).await;
            client.write_all(&ended(b"never read")).await.unwrap();
            client.shutdown().await.unwrap();
            // A clean end on both sides, and a peer that holds the stream without reading it: an
            // attached client waits on, with no clock.
            assert!(download(&mut client).await.is_empty());
            tokio::time::sleep(HANGUP_DRAIN + HANG_GUARD).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            // Its hang-up starts the drain, and the drain alone ends the wait.
            drop(client);
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
            client.write_all(&ended(b"never taken")).await.unwrap();
            client.shutdown().await.unwrap();
            assert!(download(&mut client).await.is_empty());
            // A peer that keeps the connection and takes nothing holds it no longer than the drain
            // from the client's hang-up.
            drop(client);
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
    pair.client
        .write_all(&framed(&[7; 16 * 1024]))
        .await
        .unwrap();
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
    pair.client
        .write_all(&framed(&[7; 16 * 1024]))
        .await
        .unwrap();
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
        ToPeer::arm(TestWrite::from(to_peer)),
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
async fn the_landed_frame_follows_only_an_upload_the_peer_holds() {
    let pair = Pair::new();
    let (mut client, mut peer, holds) = (pair.client, pair.peer, pair.holds);
    client.write_all(&ended(b"an upload")).await.unwrap();
    let mut spliced = Box::pin(pair.splice);
    let mut got = Vec::new();
    // The peer reads the upload and its end, but its transport has not said it holds them.
    let reading = async {
        peer.read_to_end(&mut got).await.unwrap();
    };
    tokio::select! {
        () = &mut spliced => panic!("the splice ended before the peer held the upload"),
        () = reading => {}
    }
    assert_eq!(got, b"an upload");
    tokio::time::advance(HANGUP_DRAIN / 2).await;
    assert!(poll!(&mut spliced).is_pending());
    let mut header = [0; HEADER];
    assert!(
        poll!(Box::pin(client.read_exact(&mut header))).is_pending(),
        "no Landed before the peer holds the upload"
    );
    holds.send(()).unwrap();
    assert!(
        poll!(&mut spliced).is_pending(),
        "the download is still open"
    );
    client.read_exact(&mut header).await.unwrap();
    assert_eq!(header, LANDED);
    // The peer ends its own side: End, then the close.
    peer.shutdown().await.unwrap();
    let ((), read) = tokio::join!(spliced, read_all(&mut client));
    assert_eq!(
        read,
        Read {
            end: true,
            ..Read::default()
        }
    );
}

#[tokio::test(start_paused = true)]
async fn an_attached_client_gets_landed_for_a_delivery_slower_than_hangup_drain() {
    let pair = Pair::new();
    let (mut client, mut peer, holds) = (pair.client, pair.peer, pair.holds);
    client.write_all(&ended(b"an upload")).await.unwrap();
    let mut spliced = Box::pin(pair.splice);
    let mut got = Vec::new();
    tokio::select! {
        () = &mut spliced => panic!("the splice ended before the peer held the upload"),
        read = peer.read_to_end(&mut got) => { read.unwrap(); }
    }
    // A slow path: the peer holds the upload ten seconds after its End, past any drain.
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(
        poll!(&mut spliced).is_pending(),
        "an attached wait has no clock"
    );
    holds.send(()).unwrap();
    assert!(poll!(&mut spliced).is_pending());
    let mut header = [0; HEADER];
    client.read_exact(&mut header).await.unwrap();
    assert_eq!(header, LANDED);
    drop(peer);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_hangs_up_while_waiting_gets_hangup_drain_from_the_hang_up() {
    let pair = Pair::new();
    let (mut client, mut peer, _holds) = (pair.client, pair.peer, pair.holds);
    client.write_all(&ended(b"an upload")).await.unwrap();
    let mut spliced = Box::pin(pair.splice);
    let mut got = Vec::new();
    tokio::select! {
        () = &mut spliced => panic!("the splice ended before the peer read the upload"),
        read = peer.read_to_end(&mut got) => { read.unwrap(); }
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(poll!(&mut spliced).is_pending());
    drop(client);
    pair.hang_up.send(()).unwrap();
    assert!(poll!(&mut spliced).is_pending());
    tokio::time::advance(HANGUP_DRAIN - Duration::from_millis(1)).await;
    assert!(poll!(&mut spliced).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(poll!(&mut spliced).is_ready());
}

/// The download has ended, the client writes its End and half-closes: the wait for the peer to hold the
/// upload has no clock, over the real hang-up watch, and Landed comes however late the delivery.
#[tokio::test(start_paused = true)]
async fn a_clean_end_then_half_close_after_the_downloads_end_starts_no_clock() {
    let (server, mut client) = UnixStream::pair().unwrap();
    let gone = ClientGone::watch(server.as_raw_fd()).unwrap();
    let (mut peer, peer_end) = tokio::io::duplex(64);
    let (from_peer, to_peer) = tokio::io::split(peer_end);
    let (holds, held) = tokio::sync::oneshot::channel();
    let info = MemStream::new().await.sessions[0].conn_info();
    let sent: Vec<u8> = (0..4 * 1024).map(|at| (at % 251) as u8).collect();
    let (from_client, to_client) = server.into_split();
    let mut spliced = Box::pin(attach(
        BufReader::new(from_client),
        to_client,
        from_peer,
        TestWrite::read_by(to_peer, held),
        info,
        &gone,
        core::future::pending(),
        unobserved(),
    ));
    let waiting = async {
        attached(&mut client).await;
        peer.shutdown().await.unwrap();
        assert!(download(&mut client).await.is_empty());
        // More than the peer's stream holds, so the upload is still stalled on the peer when the
        // client half-closes, and stays stalled past any drain.
        client.write_all(&ended(&sent)).await.unwrap();
        client.shutdown().await.unwrap();
        tokio::time::sleep(HANGUP_DRAIN * 3).await;
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, sent);
    };
    tokio::select! {
        () = &mut spliced => panic!("a half-closed client's wait was cut"),
        () = waiting => {}
    }
    holds.send(()).unwrap();
    let ((), read) = tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(spliced, read_all(&mut client))
    })
    .await
    .expect("the splice ends once both directions are settled");
    assert_eq!(
        read,
        Read {
            landed: true,
            ..Read::default()
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_stopped_reader_ends_an_attached_wait_without_landed() {
    let pair = Pair::new();
    let (mut client, mut peer, holds) = (pair.client, pair.peer, pair.holds);
    client.write_all(&ended(b"an upload")).await.unwrap();
    let mut spliced = Box::pin(pair.splice);
    let mut got = Vec::new();
    tokio::select! {
        () = &mut spliced => panic!("the splice ended before the peer read the upload"),
        read = peer.read_to_end(&mut got) => { read.unwrap(); }
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(poll!(&mut spliced).is_pending());
    // The transport says the far side stopped reading: the wait ends there, with no Landed.
    drop(holds);
    peer.write_all(b"a reply").await.unwrap();
    peer.shutdown().await.unwrap();
    let ((), read) = tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(spliced, read_all(&mut client))
    })
    .await
    .expect("the splice did not end at the stopped reader's answer");
    assert_eq!(
        read,
        Read {
            data: b"a reply".to_vec(),
            end: true,
            landed: false,
        }
    );
}

/// A peer that stops taking the upload, so a write toward it fails: the upload is cut, and the download
/// still reaches the client whole, End included, with no Landed.
#[tokio::test]
async fn a_peer_that_stops_reading_the_upload_still_hands_over_its_download() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let (from_client, to_client) = tokio::io::split(server);
    // One stream each way, so the peer can stop reading while it still writes.
    let (peer_in, to_peer) = tokio::io::duplex(64);
    let (mut peer_out, from_peer) = tokio::io::duplex(64);
    let (_holds, held) = tokio::sync::oneshot::channel::<()>();
    let (aborted, cut) = tokio::sync::oneshot::channel();
    let spliced = splice(
        BufReader::new(from_client),
        to_client,
        from_peer,
        ToPeer::arm(Signalled {
            half: TestWrite::read_by(to_peer, held),
            aborted: Some(aborted),
        }),
        core::future::pending(),
        core::future::pending(),
    );
    drop(peer_in);
    client.write_all(&framed(b"an upload")).await.unwrap();
    let far = async {
        // Only once the upload has failed toward the peer, and the splice aborted it, does the peer
        // answer.
        cut.await.unwrap();
        peer_out.write_all(b"a reply").await.unwrap();
        peer_out.shutdown().await.unwrap();
    };
    let ((), (), read) = tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(spliced, far, read_all(&mut client))
    })
    .await
    .expect("the splice did not end with its download");
    assert_eq!(
        read,
        Read {
            data: b"a reply".to_vec(),
            end: true,
            landed: false,
        }
    );
}

/// A peer that takes none of the upload, its stream still open: the download flows past the stalled
/// upload to its End.
#[tokio::test]
async fn a_stalled_upload_never_stalls_the_download() {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let (from_client, to_client) = tokio::io::split(server);
    let (_peer_in, to_peer) = tokio::io::duplex(64);
    let (mut peer_out, from_peer) = tokio::io::duplex(64);
    let (_holds, held) = tokio::sync::oneshot::channel::<()>();
    let mut spliced = Box::pin(splice(
        BufReader::new(from_client),
        to_client,
        from_peer,
        ToPeer::arm(TestWrite::read_by(to_peer, held)),
        core::future::pending(),
        core::future::pending(),
    ));
    // More than the peer's stream holds, so the upload stalls on it.
    client.write_all(&framed(&[7; 4 * 1024])).await.unwrap();
    let sent: Vec<u8> = (0..32 * 1024).map(|at| (at % 251) as u8).collect();
    let far = async {
        peer_out.write_all(&sent).await.unwrap();
        peer_out.shutdown().await.unwrap();
    };
    let got = tokio::time::timeout(HANG_GUARD, async {
        tokio::select! {
            () = &mut spliced => panic!("the splice ended under a stalled upload"),
            (got, ()) = async { tokio::join!(download(&mut client), far) } => got,
        }
    })
    .await
    .expect("the stalled upload held the download back");
    assert_eq!(got, sent);
}

#[tokio::test(start_paused = true)]
async fn an_upload_the_peer_will_never_hold_keeps_its_download_without_landed() {
    let pair = Pair::new();
    let (mut client, mut peer, holds) = (pair.client, pair.peer, pair.holds);
    client.write_all(&ended(b"an upload")).await.unwrap();
    // The transport says the peer will never hold the upload, as one whose service stopped reading does.
    drop(holds);
    let far = async {
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.unwrap();
        peer.write_all(b"a reply").await.unwrap();
        peer.shutdown().await.unwrap();
    };
    let ((), (), read) = tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(pair.splice, far, read_all(&mut client))
    })
    .await
    .expect("the splice did not end with its download");
    assert_eq!(
        read,
        Read {
            data: b"a reply".to_vec(),
            end: true,
            landed: false,
        }
    );
}

/// A far TCP service that answers and closes both ways partway through an upload: tightbeam's forward
/// stops reading for it, so the upload never lands and the client hears no Landed. The close with the
/// upload unread is a reset, so the download is cut too: no End, and the answer arrives whole or, where
/// the reset discards it first, not at all.
#[tokio::test]
async fn a_service_closing_both_ways_mid_upload_never_earns_landed() {
    let (read, ()) = through_a_forward(async |mut service| {
        let mut first = vec![0; 64 * 1024];
        service.read_exact(&mut first).await.unwrap();
        service.write_all(b"no").await.unwrap();
        drop(service);
    })
    .await;
    assert!(!read.landed, "an upload its service dropped landed");
    assert!(!read.end, "a download its service reset read as finished");
    assert!(
        read.data.is_empty() || read.data == b"no",
        "the answer arrived in part: {:?}",
        read.data
    );
}

/// A far TCP service that half-closes its output and reads on: tightbeam's forward hands it the whole
/// upload, so the client hears Landed after the service's own End.
#[tokio::test]
async fn a_service_half_closing_its_output_still_lands_the_upload() {
    let (read, taken) = through_a_forward(async |mut service| {
        service.write_all(b"ready").await.unwrap();
        service.shutdown().await.unwrap();
        let mut got = Vec::new();
        service.read_to_end(&mut got).await.unwrap();
        got.len()
    })
    .await;
    assert_eq!(taken, FORWARDED);
    assert_eq!(
        read,
        Read {
            data: b"ready".to_vec(),
            end: true,
            landed: true,
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_client_that_stops_reading_releases_the_splice_by_the_final_write_deadline() {
    // Room for one frame mark and part of a second.
    let pair = Pair::sized(HEADER + 4);
    let (mut client, mut peer, holds) = (pair.client, pair.peer, pair.holds);
    client.write_all(&END).await.unwrap();
    holds.send(()).unwrap();
    // An empty download: End and Landed are all the resident writes, and the second one is the last.
    peer.shutdown().await.unwrap();
    let mut spliced = Box::pin(pair.splice);
    assert!(poll!(&mut spliced).is_pending());
    tokio::time::advance(REPLY_TIMEOUT - Duration::from_millis(1)).await;
    assert!(poll!(&mut spliced).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(poll!(&mut spliced).is_ready());
    drop(client);
}

#[tokio::test]
async fn bytes_and_end_a_client_wrote_before_closing_reach_a_live_peer() {
    let mut pair = Pair::new();
    let sent: Vec<u8> = (0..64 * 1024).map(|at| (at % 251) as u8).collect();
    let wire = ended(&sent);
    pair.client.write_all(&wire[..32]).await.unwrap();
    let (hang_up, mut peer, holds, splice) = (pair.hang_up, pair.peer, pair.holds, pair.splice);
    let mut client = pair.client;
    let writer = async {
        client.write_all(&wire[32..]).await.unwrap();
        drop(client);
        hang_up.send(()).unwrap();
    };
    let reader = async {
        let mut got = Vec::new();
        // A clean end: the client's End reached the peer within the drain.
        peer.read_to_end(&mut got).await.unwrap();
        holds.send(()).unwrap();
        got
    };
    let joined = tokio::time::timeout(HANG_GUARD * 5, async {
        tokio::join!(writer, reader, splice)
    })
    .await;
    let ((), got, ()) = joined.expect("the splice ended");
    assert_eq!(got, sent);
}

#[tokio::test]
async fn an_open_dropped_mid_splice_resets_the_peers_stream() {
    let mut stream = MemStream::new().await;
    let mut client = stream.client.take().unwrap();
    client.write_all(&framed(b"half an upload")).await.unwrap();
    // Dropped while it splices, as `Stop` or a panic drops the Open; a gone client drains instead.
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
    let flood = framed(&[7; 1024 * 1024]);
    let goes = async {
        let _ = tokio::time::timeout(HANG_GUARD, client.write_all(&flood)).await;
        drop(client);
    };
    let ((), ()) = tokio::join!(stream.attach(), goes);
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
        stream.to_peer.take().unwrap(),
        stream.sessions[0].conn_info(),
        &stream.gone,
        core::future::pending(),
        unobserved(),
    )
    .await;
    assert_eq!(stream.peer_reads().await, Ended::Reset);
}

#[tokio::test]
async fn a_clean_end_after_shutdown_stays_clean() {
    let MemStream {
        sessions,
        client,
        server,
        gone,
        to_peer,
        from_peer,
        peer: (mut peer_write, mut peer_read),
    } = MemStream::new().await;
    let mut client = client.unwrap();
    let to_peer = to_peer.unwrap();
    let aborts = Rc::clone(&to_peer.aborts);
    client.write_all(&ended(b"a whole upload")).await.unwrap();
    client.shutdown().await.unwrap();
    peer_write.shutdown().await.unwrap();
    let mut got = Vec::new();
    let ((), read, taken) = tokio::join!(
        splice_mem(
            server.unwrap(),
            from_peer.unwrap(),
            to_peer,
            &sessions[0],
            &gone
        ),
        async {
            attached(&mut client).await;
            read_all(&mut client).await
        },
        peer_read.read_to_end(&mut got)
    );
    taken.unwrap();
    assert_eq!(got, b"a whole upload");
    // The peer read it all and its end, so the upload landed, beside the download's own End.
    assert!(read.end && read.landed, "{read:?}");
    // mem ignores an abort after a clean end, so only the count tells one was never sent.
    assert_eq!(aborts.get(), 0);
}

/// An attached mem splice whose client, once it has read Attached, writes `wire` and then does `then` to
/// its socket, run while the peer reads its stream: how the peer's read ended.
async fn upload_ends(wire: &[u8], then: impl FnOnce(UnixStream) -> Option<UnixStream>) -> Ended {
    let MemStream {
        sessions,
        client,
        server,
        gone,
        to_peer,
        from_peer,
        peer: (_peer_write, mut peer_read),
    } = MemStream::new().await;
    let mut client = client.unwrap();
    let splicing = splice_mem(
        server.unwrap(),
        from_peer.unwrap(),
        to_peer.unwrap(),
        &sessions[0],
        &gone,
    );
    let near_and_far = async {
        attached(&mut client).await;
        client.write_all(wire).await.unwrap();
        let _kept = then(client);
        reads(&mut peer_read).await
    };
    tokio::pin!(splicing, near_and_far);
    tokio::select! {
        ended = &mut near_and_far => ended,
        () = &mut splicing => near_and_far.await,
    }
}

#[tokio::test]
async fn a_client_closing_without_end_resets_the_peers_stream() {
    // A crash: data frames, then the socket closed both ways, with no End.
    let ended = upload_ends(&framed(b"half an upload"), |client| {
        drop(client);
        None
    })
    .await;
    assert_eq!(ended, Ended::Reset);
}

#[tokio::test]
async fn a_frame_cut_off_mid_body_resets_the_peers_stream() {
    let mut wire = framed(b"a whole frame");
    wire.truncate(wire.len() - 4);
    let ended = upload_ends(&wire, |client| {
        drop(client);
        None
    })
    .await;
    assert_eq!(ended, Ended::Reset);
}

#[tokio::test]
async fn a_malformed_frame_after_attached_resets_the_peer_and_ends_the_open() {
    // An empty Data, an unknown tag, a Stop request, Landed from the client, a declared 8193 bytes
    // and a foreign magic. The client stays connected, so only the frame ends the Open.
    for bad in [
        *b"SWC1\x0a\x00\x00",
        *b"SWC1\x0d\x00\x00",
        *b"SWC1\x03\x00\x00",
        *b"SWC1\x0c\x00\x00",
        *b"SWC1\x0a\x20\x01",
        *b"SWC2\x0a\x00\x01",
    ] {
        let mut wire = framed(b"before");
        wire.extend(bad);
        wire.extend([7; 16]);
        let MemStream {
            sessions,
            client,
            server,
            gone,
            to_peer,
            from_peer,
            peer: (_peer_write, mut peer_read),
        } = MemStream::new().await;
        let mut client = client.unwrap();
        client.write_all(&wire).await.unwrap();
        tokio::time::timeout(
            HANG_GUARD,
            splice_mem(
                server.unwrap(),
                from_peer.unwrap(),
                to_peer.unwrap(),
                &sessions[0],
                &gone,
            ),
        )
        .await
        .expect("a malformed frame ends the open");
        // mem's abort drops what the peer had not read, so only the reset is left to read.
        assert_eq!(reads(&mut peer_read).await, Ended::Reset, "{bad:?}");
        // The resident closed the connection with no End and no Landed.
        attached(&mut client).await;
        assert_eq!(read_all(&mut client).await, Read::default());
    }
}

#[tokio::test]
async fn a_client_half_closing_without_end_resets_the_upload_and_keeps_the_download() {
    let MemStream {
        sessions,
        client,
        server,
        gone,
        to_peer,
        from_peer,
        peer: (mut peer_write, mut peer_read),
    } = MemStream::new().await;
    let mut client = client.unwrap();
    client.write_all(&framed(b"half")).await.unwrap();
    client.shutdown().await.unwrap();
    let far = async {
        assert_eq!(reads(&mut peer_read).await, Ended::Reset);
        // The download still flows after the upload was cut.
        peer_write.write_all(b"reply").await.unwrap();
        peer_write.shutdown().await.unwrap();
    };
    let ((), (), read) = tokio::join!(
        splice_mem(
            server.unwrap(),
            from_peer.unwrap(),
            to_peer.unwrap(),
            &sessions[0],
            &gone
        ),
        far,
        async {
            attached(&mut client).await;
            read_all(&mut client).await
        }
    );
    assert_eq!(
        read,
        Read {
            data: b"reply".to_vec(),
            end: true,
            landed: false,
        }
    );
}

#[tokio::test]
async fn a_client_crash_after_the_peer_ended_resets_the_peers_stream() {
    let MemStream {
        sessions,
        client,
        server,
        gone,
        to_peer,
        from_peer,
        peer: (mut peer_write, mut peer_read),
    } = MemStream::new().await;
    let mut client = client.unwrap();
    // The far service answers and ends first; then the client dies mid-upload.
    peer_write.shutdown().await.unwrap();
    let near = async {
        attached(&mut client).await;
        assert!(download(&mut client).await.is_empty());
        client.write_all(&framed(b"half an upload")).await.unwrap();
        drop(client);
    };
    let far = reads(&mut peer_read);
    let ((), (), ended) = tokio::join!(
        splice_mem(
            server.unwrap(),
            from_peer.unwrap(),
            to_peer.unwrap(),
            &sessions[0],
            &gone
        ),
        near,
        far
    );
    assert_eq!(ended, Ended::Reset);
}

#[tokio::test]
async fn a_peer_reset_reaches_the_client_without_an_end() {
    let MemStream {
        sessions,
        client,
        server,
        gone,
        to_peer,
        from_peer,
        peer: (mut peer_write, mut peer_read),
    } = MemStream::new().await;
    let mut client = client.unwrap();
    client.write_all(&END).await.unwrap();
    peer_write.write_all(b"part").await.unwrap();
    let far = async {
        // The far side holds the upload's end, then cuts its own stream.
        let mut got = Vec::new();
        peer_read.read_to_end(&mut got).await.unwrap();
        peer_write.abort();
    };
    let ((), (), read) = tokio::join!(
        splice_mem(
            server.unwrap(),
            from_peer.unwrap(),
            to_peer.unwrap(),
            &sessions[0],
            &gone
        ),
        far,
        async {
            attached(&mut client).await;
            read_all(&mut client).await
        }
    );
    assert_eq!(read.data, b"part");
    assert!(!read.end, "a cut-off download never reads as finished");
}

/// A peer whose stream fails while its client is connected and idle, with no End sent: the Open ends at
/// once, the client reads a close with no End, and the upload toward the peer is aborted, all with the
/// client still holding its socket and writing nothing.
#[tokio::test]
async fn a_peer_cut_under_an_idle_client_ends_the_open_at_once() {
    let MemStream {
        sessions,
        client,
        server,
        gone,
        to_peer,
        from_peer,
        peer: (mut peer_write, mut peer_read),
    } = MemStream::new().await;
    let mut client = client.unwrap();
    peer_write.abort();
    let (spliced, read, ended) = tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(
            splice_mem(
                server.unwrap(),
                from_peer.unwrap(),
                to_peer.unwrap(),
                &sessions[0],
                &gone,
            ),
            async {
                attached(&mut client).await;
                read_all(&mut client).await
            },
            reads(&mut peer_read),
        )
    })
    .await
    .expect("an idle client was not told of the cut");
    let () = spliced;
    assert_eq!(
        read,
        Read::default(),
        "a cut-off download never reads as finished"
    );
    assert_eq!(
        ended,
        Ended::Reset,
        "the upload toward the peer was not aborted"
    );
    drop(client);
}

#[tokio::test]
async fn a_peer_clean_end_reaches_the_client_as_end() {
    let mut stream = MemStream::new().await;
    let mut client = stream.client.take().unwrap();
    stream.peer.0.write_all(b"whole").await.unwrap();
    stream.peer.0.shutdown().await.unwrap();
    let splicing = stream.attach();
    tokio::pin!(splicing);
    let got = tokio::time::timeout(HANG_GUARD, async {
        tokio::select! {
            () = &mut splicing => panic!("the open ended with its upload open"),
            got = async {
                attached(&mut client).await;
                download(&mut client).await
            } => got,
        }
    })
    .await
    .expect("the download's end never reached the client");
    assert_eq!(got, b"whole");
}

#[tokio::test]
async fn a_stop_mid_download_reaches_the_client_without_an_end() {
    let mut stream = MemStream::new().await;
    let mut client = stream.client.take().unwrap();
    stream.peer.0.write_all(b"part").await.unwrap();
    {
        let splicing = stream.attach();
        tokio::pin!(splicing);
        let mut header = [0; HEADER];
        tokio::select! {
            () = &mut splicing => panic!("the open ended on its own"),
            () = async {
                attached(&mut client).await;
                client.read_exact(&mut header).await.unwrap();
            } => {}
        }
        let mut body = [0; 4];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"part");
        // Dropped here, as `Stop` drops the Open.
    }
    assert_eq!(read_all(&mut client).await, Read::default());
}

#[tokio::test]
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn a_whole_open_dropped_mid_splice_resets_the_peers_stream() {
    let far = MemTransport::bind();
    let node = Node::new(MemTransport::bind(), NoDiscovery);
    let peers = Peers::new(&node);
    let home = Home::resolve(Some(scratch("dropped-open"))).unwrap();
    let asks = Asks::default();
    let renewal = OpenRenewal::new(&home, &asks);
    let opener = Opener::new(&peers, &renewal, &home, node.node_id()).unwrap();
    let (server, mut client) = UnixStream::pair().unwrap();
    let gone = ClientGone::watch(server.as_raw_fd()).unwrap();
    let (from_client, to_client) = server.into_split();
    let control = tokio::sync::Semaphore::new(1);
    // Main, so the held session outlives the Open and only the Open's own abort can cut the stream.
    let mut opening = Box::pin(opener.open(
        request(far.node_id(), OpenLane::Main, None),
        BufReader::new(from_client),
        to_client,
        gone,
        control.try_acquire().unwrap(),
    ));
    // The far side admits the stream and reads the upload's first bytes, so the Open is mid-splice.
    let spliced = async {
        let session = far.accept().await.unwrap();
        let (mut to, mut from) = session.accept_bi().await.unwrap();
        tightbeam::protocol::Request::read(&mut from).await.unwrap();
        tightbeam::protocol::Response::Ok
            .write(&mut to)
            .await
            .unwrap();
        attached(&mut client).await;
        client.write_all(&framed(b"half an upload")).await.unwrap();
        let mut got = [0; 14];
        from.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"half an upload");
        (session, to, from)
    };
    let (_session, _to, mut from) = tokio::select! {
        () = &mut opening => panic!("the open ended on its own"),
        far = spliced => far,
    };
    // Dropped whole, as `Stop` or a panic drops it.
    drop(opening);
    let mut rest = Vec::new();
    let read = tokio::time::timeout(HANG_GUARD, from.read_to_end(&mut rest)).await;
    let ended = read.expect("the peer's read hung").unwrap_err();
    assert_eq!(ended.kind(), std::io::ErrorKind::ConnectionReset);
    drop(client);
}

#[tokio::test]
async fn a_guard_dropped_with_its_shutdown_pending_aborts() {
    let half = Unshut::default();
    let (shutdowns, aborts) = (Rc::clone(&half.shutdowns), Rc::clone(&half.aborts));
    let finishing = ToPeer::arm(half).finish();
    assert!(poll!(Box::pin(finishing)).is_pending());
    assert_eq!(shutdowns.get(), 1, "the shutdown was never asked");
    assert_eq!(aborts.get(), 1);
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
    assert!(download(&mut client).await.is_empty());
    let flood = framed(&[7; 1024 * 1024]);
    let _ = tokio::time::timeout(HANG_GUARD, client.write_all(&flood)).await;
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
async fn a_half_closed_client_after_the_peer_ended_stays_live() {
    let fixture = Fixture::new("ended-half", [Script::Ends]);
    fixture
        .run(async |socket| {
            let mut client = stalled_after_the_peer_ended(socket, fixture.peer).await;
            client.shutdown().await.unwrap();
            tokio::time::sleep(HANGUP_DRAIN + HANG_GUARD).await;
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            drop(client);
            released(&fixture.opener, HANGUP_DRAIN + HANG_GUARD).await;
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

/// A peer that ended its side, then cuts the session (a revoke or an expiry) while the client idles
/// with its upload open, on a held lane and on an isolated connection: the Open ends at once, and the
/// client reads a close with no Landed.
#[tokio::test]
async fn a_session_cut_after_the_downloads_end_reaches_an_idle_client_at_once() {
    for lane in [OpenLane::Main, OpenLane::Isolated] {
        let fixture = Fixture::new("cut", [Script::Ends]);
        fixture
            .run(async |socket| {
                let mut client = open(socket, request(fixture.peer, lane, None)).await;
                attached(&mut client).await;
                assert!(download(&mut client).await.is_empty());
                fixture.scripted.cut();
                let read = tokio::time::timeout(HANG_GUARD, read_all(&mut client))
                    .await
                    .unwrap_or_else(|_| {
                        panic!("the cut never reached the idle client on {lane:?}")
                    });
                assert_eq!(
                    read,
                    Read::default(),
                    "nothing follows the End, Landed least"
                );
                released(&fixture.opener, HANG_GUARD).await;
            })
            .await;
    }
}

#[tokio::test]
async fn a_failed_write_to_the_client_still_sends_its_bytes_to_the_peer() {
    let (mut client, from_client) = tokio::io::duplex(1024);
    let (mut peer, peer_end) = tokio::io::duplex(1024);
    let (from_peer, to_peer) = tokio::io::split(peer_end);
    let (holds, held) = tokio::sync::oneshot::channel();
    // The peer has a byte for the client, and the client's socket refuses it.
    peer.write_all(&[1]).await.unwrap();
    let mut spliced = Box::pin(splice(
        BufReader::new(from_client),
        Gone,
        from_peer,
        ToPeer::arm(TestWrite::read_by(to_peer, held)),
        core::future::pending(),
        core::future::pending(),
    ));
    assert!(
        poll!(&mut spliced).is_pending(),
        "a failed write ended the splice"
    );
    client.write_all(&ended(b"last words")).await.unwrap();
    drop(client);
    let mut got = Vec::new();
    let reader = async {
        // A clean end, never the reset of a cut-off: only the way to the client failed.
        let read = peer.read_to_end(&mut got).await;
        holds.send(()).unwrap();
        read
    };
    let ((), read) = tokio::join!(spliced, reader);
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
            bytes.extend_from_slice(&ended(b"sent with the request"));
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
            opener: Opener::new(peers, renewal, home, this).unwrap(),
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

/// The upload [`through_a_forward`] sends: past a stream's window and both sockets' buffers, so a far
/// side that stops reading is seen before the upload could have landed.
const FORWARDED: usize = 8 * 1024 * 1024;

/// Splice a client over a held iroh lane to a real tightbeam forward whose TCP service runs `service` on
/// the one connection it accepts, while the client uploads [`FORWARDED`] bytes and its End: what the
/// client read, and what `service` returned.
async fn through_a_forward<T>(service: impl AsyncFnOnce(tokio::net::TcpStream) -> T) -> (Read, T) {
    let dir = scratch("fwd");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let store = Arc::new(nauthy::Denylist::load(dir.join("denylist")).unwrap());
    let host = Node::new(
        bifrost_iroh::Endpoint::bind_local().await.unwrap(),
        NoDiscovery,
    );
    let mut hints = bifrost::StaticDiscovery::new();
    hints.insert(host.node_id(), host.local_addr().hints);
    let node = Node::new(bifrost_iroh::Endpoint::bind_local().await.unwrap(), hints);
    let name: nauthy::Service = crate::serve::SYNC_SERVICE.parse().unwrap();
    let exposer = tightbeam::tunnel::Router::new(nauthy::Gate::rooted(
        crate::testkit::TestRoot::seeded(1).verify_key(),
        store,
    ))
    .forward(
        name.clone(),
        &format!("tcp:{}", listener.local_addr().unwrap()),
    )
    .unwrap()
    .expose()
    .unwrap();
    let badge = crate::testkit::TestRoot::seeded(1)
        .device_badge(node.node_id(), until())
        .unwrap();
    let cancel = CancellationToken::new();
    let exercise = async {
        let peers = Peers::new(&node);
        let place = peers
            .place(host.node_id(), crate::peers::Lane::Main)
            .unwrap();
        let (_, session, to_peer, from_peer) = peers
            .open_placed(
                place,
                Hints::NONE,
                name,
                crate::peers::Presents::Standing(Some(badge)),
            )
            .await
            .unwrap();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (from_client, to_client) = tokio::io::split(server);
        let spliced = splice(
            BufReader::new(from_client),
            to_client,
            from_peer,
            ToPeer::arm(to_peer),
            core::future::pending(),
            session.closed(),
        );
        let (mut reading, mut writing) = tokio::io::split(&mut client);
        let upload = async {
            let _ = writing.write_all(&ended(&vec![7; FORWARDED])).await;
        };
        let served = async { service(listener.accept().await.unwrap().0).await };
        let ((), (), read, served) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(spliced, upload, read_all(&mut reading), served)
        })
        .await
        .expect("the splice through the forward did not end");
        cancel.cancel();
        (read, served)
    };
    let ((), done) = tokio::join!(exposer.run(&host, cancel.clone()), exercise);
    node.close().await;
    host.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
    done
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
/// it fills, the hang-up the test fires, and the word that the peer holds the upload, which the test
/// sends as a transport's delivery would.
struct Pair<F> {
    client: DuplexStream,
    peer: DuplexStream,
    hang_up: tokio::sync::oneshot::Sender<()>,
    holds: tokio::sync::oneshot::Sender<()>,
    splice: F,
}

impl Pair<()> {
    #[allow(clippy::new_ret_no_self)]
    fn new() -> Pair<impl Future<Output = ()>> {
        Self::sized(64 * 1024)
    }

    /// With room for `room` bytes toward the client.
    fn sized(room: usize) -> Pair<impl Future<Output = ()>> {
        let (client, server) = tokio::io::duplex(room);
        let (from_client, to_client) = tokio::io::split(server);
        let (peer, peer_end) = tokio::io::duplex(64);
        let (from_peer, to_peer) = tokio::io::split(peer_end);
        let (hang_up, hung) = tokio::sync::oneshot::channel::<()>();
        let (holds, held) = tokio::sync::oneshot::channel::<()>();
        Pair {
            client,
            peer,
            hang_up,
            holds,
            splice: splice(
                BufReader::new(from_client),
                to_client,
                from_peer,
                ToPeer::arm(TestWrite::read_by(to_peer, held)),
                async {
                    let _ = hung.await;
                },
                core::future::pending(),
            ),
        }
    }
}

/// A Data frame's header and body for each piece of `data`, at most the frame ceiling each.
fn framed(data: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    for piece in data.chunks(MAX_FRAME) {
        wire.extend(Frame::Data(DataLen::new(piece.len()).unwrap()).header());
        wire.extend(piece);
    }
    wire
}

/// `data` framed, then End: a whole upload.
fn ended(data: &[u8]) -> Vec<u8> {
    let mut wire = framed(data);
    wire.extend(END);
    wire
}

/// The End frame's bytes.
const END: [u8; HEADER] = *b"SWC1\x0b\x00\x00";
/// The Landed frame's bytes.
const LANDED: [u8; HEADER] = *b"SWC1\x0c\x00\x00";

/// What a client read until the resident closed the connection: the download, whether its End came,
/// and whether Landed came.
#[derive(Debug, Default, PartialEq, Eq)]
struct Read {
    data: Vec<u8>,
    end: bool,
    landed: bool,
}

/// Read frames until the connection closes. Data after the download's End, a second End or Landed,
/// or a malformed frame fails the test.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn read_all<R: tokio::io::AsyncRead + Unpin>(client: &mut R) -> Read {
    let mut read = Read::default();
    loop {
        let frame = match read_frame(client, Toward::Client).await {
            Ok(frame) => frame,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return read,
            Err(error) => panic!("a malformed frame from the resident: {error}"),
        };
        match frame {
            Frame::Data(len) => {
                assert!(!read.end, "data after the download's end");
                let mut body = vec![0; len.get()];
                client.read_exact(&mut body).await.unwrap();
                read.data.extend(body);
            }
            Frame::End => {
                assert!(!read.end, "a second end");
                read.end = true;
            }
            Frame::Landed => {
                assert!(!read.landed, "a second landed");
                read.landed = true;
            }
        }
    }
}

/// Read the download up to its End, never past it.
async fn download<R: tokio::io::AsyncRead + Unpin>(client: &mut R) -> Vec<u8> {
    let mut got = Vec::new();
    loop {
        match read_frame(client, Toward::Client).await.unwrap() {
            Frame::Data(len) => {
                let mut body = vec![0; len.get()];
                client.read_exact(&mut body).await.unwrap();
                got.extend(body);
            }
            Frame::End => return got,
            Frame::Landed => {}
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

/// Read the Attached reply and the reference it carries.
async fn observed(client: &mut UnixStream) -> PathRef {
    let Response::Attached(Attached {
        reference: Some(reference),
        ..
    }) = Response::read_open(client).await.unwrap()
    else {
        panic!("expected attached with a reference");
    };
    reference
}

/// Ask the resident at `socket` to act on `reference`, on a connection of its own, and read the reply
/// and the close after it.
async fn path(socket: &std::path::Path, reference: PathRef, action: PathAction) -> Response {
    let mut client = UnixStream::connect(socket).await.unwrap();
    Request::Path(PathRequest { reference, action })
        .write(&mut client)
        .await
        .unwrap();
    let reply = Response::read_path(&mut client).await.unwrap();
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    reply
}

/// A sample of `info`, as a Path reply.
fn sampled(info: &ConnInfo) -> Response {
    Response::Path(PathReply::Sample(info.clone()))
}

/// The unavailable Path reply.
const UNAVAILABLE: Response = Response::Path(PathReply::Unavailable);

/// A direct path report.
fn direct() -> ConnInfo {
    ConnInfo {
        path: bifrost::Path::Direct,
        rtt: Some(Duration::from_micros(12_031)),
        remote: Some("192.0.2.9:7".parse().unwrap()),
    }
}

/// A relayed path report.
fn relayed() -> ConnInfo {
    ConnInfo {
        path: bifrost::Path::Relayed(bifrost::Relay::from(
            url::Url::parse("https://relay.example/").unwrap(),
        )),
        rtt: None,
        remote: None,
    }
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
    to_peer: Option<Counted<MemWrite>>,
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
            to_peer: Some(Counted {
                half: to_peer,
                aborts: Rc::default(),
            }),
            from_peer: Some(from_peer),
            peer,
        }
    }

    /// Attach the client to the peer, as an Open does once its stream opened.
    async fn attach(&mut self) {
        let (from_client, to_client) = self.server.take().unwrap().into_split();
        let (from_peer, to_peer) = (self.from_peer.take().unwrap(), self.to_peer.take().unwrap());
        attach(
            BufReader::new(from_client),
            to_client,
            from_peer,
            to_peer,
            self.sessions[0].conn_info(),
            &self.gone,
            self.sessions[0].wait_closed(),
            unobserved(),
        )
        .await;
    }

    /// How the peer's read of the stream ends.
    async fn peer_reads(&mut self) -> Ended {
        reads(&mut self.peer.1).await
    }
}

/// No observation, for an attach a test drives directly.
fn unobserved() -> Option<(
    &'static Observing<'static, Carrier<MemSession>>,
    Carrier<MemSession>,
)> {
    None
}

/// Attach an Open's parts: what [`MemStream::attach`] does, borrowing only the watch, so a test can
/// read the peer's end while it runs.
async fn splice_mem(
    server: UnixStream,
    from_peer: MemRead,
    to_peer: Counted<MemWrite>,
    session: &MemSession,
    gone: &ClientGone,
) {
    let (from_client, to_client) = server.into_split();
    attach(
        BufReader::new(from_client),
        to_client,
        from_peer,
        to_peer,
        session.conn_info(),
        gone,
        session.wait_closed(),
        unobserved(),
    )
    .await;
}

/// How a peer's read of a stream ends, within the hang guard.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn reads(peer: &mut MemRead) -> Ended {
    let mut got = Vec::new();
    let read = tokio::time::timeout(HANG_GUARD, peer.read_to_end(&mut got)).await;
    match read.expect("the peer's read hung") {
        Ok(_) => Ended::Clean,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ended::Reset,
        Err(error) => Ended::Failed(error.to_string()),
    }
}

/// How a peer's read of a stream ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// A clean end of stream: the sender shut it down.
    Clean,
    /// `ConnectionReset`: the stream was cut off.
    Reset,
    /// Any other failure.
    Failed(String),
}

/// A write half that counts its aborts: mem ignores one after a clean end, so the peer cannot tell.
struct Counted<W> {
    half: W,
    aborts: Rc<Cell<u32>>,
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
        self.aborts.set(self.aborts.get() + 1);
        self.half.abort();
    }

    fn delivered(self) -> impl Future<Output = std::io::Result<()>> + Send + 'static {
        self.half.delivered()
    }
}

/// A write half that says when it is aborted.
struct Signalled<W> {
    half: W,
    aborted: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Signalled<W> {
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

impl<W: WriteEnd> WriteEnd for Signalled<W> {
    fn abort(&mut self) {
        if let Some(aborted) = self.aborted.take() {
            let _ = aborted.send(());
        }
        self.half.abort();
    }

    fn delivered(self) -> impl Future<Output = std::io::Result<()>> + Send + 'static {
        self.half.delivered()
    }
}

/// A write half whose shutdown never completes; it counts the shutdowns asked and the aborts.
#[derive(Default)]
struct Unshut {
    shutdowns: Rc<Cell<u32>>,
    aborts: Rc<Cell<u32>>,
}

impl tokio::io::AsyncWrite for Unshut {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        core::task::Poll::Ready(Ok(buf.len()))
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
        let shutdowns = &self.get_mut().shutdowns;
        shutdowns.set(shutdowns.get() + 1);
        core::task::Poll::Pending
    }
}

impl WriteEnd for Unshut {
    fn abort(&mut self) {
        self.aborts.set(self.aborts.get() + 1);
    }

    fn delivered(self) -> impl Future<Output = std::io::Result<()>> + Send + 'static {
        core::future::pending()
    }
}

#[tokio::test]
async fn an_observed_open_samples_its_own_connection_and_finish_retires_only_the_reference() {
    let fixture = Fixture::new("obs-own", [Script::Lists(vec![]), Script::Reads]);
    fixture
        .run(async |socket| {
            // An unobserved Open first: it takes no ticket, so the observed one is ticket 1.
            let mut plain = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            assert!(matches!(
                Response::read_open(&mut plain).await.unwrap(),
                Response::Attached(Attached {
                    reference: None,
                    ..
                })
            ));
            let mut client = open(
                socket,
                request(fixture.peer, OpenLane::Isolated, None).observed(),
            )
            .await;
            let reference = observed(&mut client).await;
            assert_eq!(reference.ticket(), Ticket::FIRST);
            // The sample reads the connection as it is now, not as it attached.
            fixture.scripted.set_path(1, direct());
            assert_eq!(
                path(socket, reference, PathAction::Sample).await,
                sampled(&direct())
            );
            fixture.scripted.set_path(1, relayed());
            assert_eq!(
                path(socket, reference, PathAction::Finish).await,
                sampled(&relayed())
            );
            assert_eq!(
                path(socket, reference, PathAction::Finish).await,
                UNAVAILABLE
            );
            assert_eq!(
                path(socket, reference, PathAction::Sample).await,
                UNAVAILABLE
            );
            // Another run's epoch names nothing here.
            let elsewhere = PathRef::new(Epoch::draw(&mut Fill(9)).unwrap(), reference.ticket());
            assert_eq!(
                path(socket, elsewhere, PathAction::Sample).await,
                UNAVAILABLE
            );
            // The stream still carries: a Finish retired only the observation.
            client.write_all(&ended(b"after finish")).await.unwrap();
            let read = read_all(&mut client).await;
            assert!(read.end && read.landed, "{read:?}");
            assert_eq!(fixture.scripted.received(), b"after finish");
            // Finished, so the ended Open lets its slots go at once.
            drop(plain);
            released(&fixture.opener, HANG_GUARD).await;
        })
        .await;
}

#[tokio::test]
async fn two_isolated_runs_each_sample_their_own_connection() {
    let fixture = Fixture::new("obs-two", [Script::Holds, Script::Holds]);
    fixture
        .run(async |socket| {
            let isolated = || request(fixture.peer, OpenLane::Isolated, None).observed();
            let mut a = open(socket, isolated()).await;
            let a_ref = observed(&mut a).await;
            let mut b = open(socket, isolated()).await;
            let b_ref = observed(&mut b).await;
            assert_ne!(a_ref, b_ref);
            fixture.scripted.set_path(0, relayed());
            fixture.scripted.set_path(1, direct());
            assert_eq!(
                path(socket, a_ref, PathAction::Sample).await,
                sampled(&relayed())
            );
            assert_eq!(
                path(socket, b_ref, PathAction::Sample).await,
                sampled(&direct())
            );
            // Only A's own connection moving changes A's sample.
            fixture.scripted.set_path(0, direct());
            fixture.scripted.set_path(1, ConnInfo::default());
            assert_eq!(
                path(socket, a_ref, PathAction::Sample).await,
                sampled(&direct())
            );
            assert_eq!(
                path(socket, b_ref, PathAction::Sample).await,
                sampled(&ConnInfo::default())
            );
            // B ending changes nothing for A.
            assert_eq!(
                path(socket, b_ref, PathAction::Finish).await,
                sampled(&ConnInfo::default())
            );
            drop(b);
            assert_eq!(
                path(socket, a_ref, PathAction::Finish).await,
                sampled(&direct())
            );
        })
        .await;
}

#[tokio::test]
async fn opens_sharing_a_held_session_take_their_own_tickets_and_survive_its_replacement() {
    let fixture = Fixture::new("obs-reuse", [Script::Holds, Script::Holds, Script::Holds]);
    fixture
        .run(async |socket| {
            let main = || request(fixture.peer, OpenLane::Main, None).observed();
            let mut first = open(socket, main()).await;
            let first_ref = observed(&mut first).await;
            let mut second = open(socket, main()).await;
            let second_ref = observed(&mut second).await;
            assert_eq!(fixture.scripted.dials(), 1);
            assert_ne!(first_ref.ticket(), second_ref.ticket());
            fixture.scripted.set_path(0, relayed());
            assert_eq!(
                path(socket, first_ref, PathAction::Finish).await,
                sampled(&relayed())
            );
            assert_eq!(
                path(socket, second_ref, PathAction::Sample).await,
                sampled(&relayed())
            );
            // The host cuts the session; the next Open dials a new one into the same cache slot. The
            // old reference still reads the old session, through its retention.
            fixture.scripted.cut();
            let mut third = open(socket, main()).await;
            let third_ref = observed(&mut third).await;
            assert_eq!(fixture.scripted.dials(), 2);
            fixture.scripted.set_path(1, direct());
            assert_eq!(
                path(socket, second_ref, PathAction::Sample).await,
                sampled(&relayed())
            );
            assert_eq!(
                path(socket, third_ref, PathAction::Sample).await,
                sampled(&direct())
            );
        })
        .await;
}

#[tokio::test]
async fn an_ended_observed_open_gives_back_its_lane_but_keeps_its_reach_slot_until_finished() {
    // Four isolated connections are a peer's cap; a fifth Open fits only once their counts are back.
    let fixture = Fixture::new(
        "obs-ended",
        [
            Script::Reads,
            Script::Reads,
            Script::Reads,
            Script::Reads,
            Script::Lists(vec![]),
        ],
    );
    fixture
        .run(async |socket| {
            let mut references = Vec::new();
            for _ in 0..4 {
                let mut client = open(
                    socket,
                    request(fixture.peer, OpenLane::Isolated, None).observed(),
                )
                .await;
                references.push(observed(&mut client).await);
                client.write_all(&ended(b"")).await.unwrap();
                let read = read_all(&mut client).await;
                assert!(read.end && read.landed, "{read:?}");
            }
            // Every stream has ended both ways: their lanes are back, their reach slots are not.
            let mut fifth = open(socket, request(fixture.peer, OpenLane::Isolated, None)).await;
            attached(&mut fifth).await;
            assert_eq!(download(&mut fifth).await, [0, 0, 0, 0]);
            drop(fifth);
            tokio::time::timeout(
                HANG_GUARD,
                until_true(|| fixture.opener.reach.available_permits() == MAX_REACH - 4),
            )
            .await
            .expect("the fifth open kept its reach slot");
            // Each ended connection still answers, and a Finish lets its slot go at once.
            for (at, reference) in references.into_iter().enumerate() {
                assert!(matches!(
                    path(socket, reference, PathAction::Finish).await,
                    Response::Path(PathReply::Sample(_))
                ));
                let left = MAX_REACH - 3 + at;
                tokio::time::timeout(
                    HANG_GUARD,
                    until_true(|| fixture.opener.reach.available_permits() == left),
                )
                .await
                .unwrap();
            }
        })
        .await;
}

/// The held-lane case: an observed Main stream that has ended both ways gives back its place on the lane
/// at once, and keeps its reach slot until its Finish.
#[tokio::test]
async fn an_ended_observed_main_open_gives_back_its_lane_but_keeps_its_reach_slot_until_finished() {
    let fixture = Fixture::new("obs-main-end", [Script::Reads]);
    fixture
        .run(async |socket| {
            let mut client = open(
                socket,
                request(fixture.peer, OpenLane::Main, None).observed(),
            )
            .await;
            let reference = observed(&mut client).await;
            client.write_all(&ended(b"")).await.unwrap();
            let read = read_all(&mut client).await;
            assert!(read.end && read.landed, "{read:?}");
            drop(client);
            // Every one of the peer's Main places is free again: the ended stream holds none.
            let places = tokio::time::timeout(HANG_GUARD, async {
                loop {
                    let places: Result<Vec<_>, _> = (0..64)
                        .map(|_| fixture.peers.place(fixture.peer, crate::peers::Lane::Main))
                        .collect();
                    if let Ok(places) = places {
                        return places;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the ended stream kept its Main place");
            assert!(matches!(
                fixture.peers.place(fixture.peer, crate::peers::Lane::Main),
                Err(OpenError::Busy)
            ));
            drop(places);
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            assert_eq!(
                path(socket, reference, PathAction::Finish).await,
                sampled(&ConnInfo::default())
            );
            released(&fixture.opener, HANG_GUARD).await;
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn an_ended_observed_open_unfinished_lets_go_at_the_retention_deadline() {
    let fixture = Fixture::new("obs-expire", [Script::Reads]);
    fixture
        .run(async |socket| {
            let mut client = open(
                socket,
                request(fixture.peer, OpenLane::Isolated, None).observed(),
            )
            .await;
            observed(&mut client).await;
            client.write_all(&ended(b"")).await.unwrap();
            read_all(&mut client).await;
            let ended = tokio::time::Instant::now();
            released(&fixture.opener, TERMINAL_RETENTION * 2).await;
            let held = tokio::time::Instant::now() - ended;
            assert!(
                held >= TERMINAL_RETENTION - Duration::from_millis(1),
                "{held:?}"
            );
        })
        .await;
}

/// An observed Isolated connection whose stream has ended stays open, for its path, through the
/// retention, and is closed when the retention lets it go.
#[tokio::test(start_paused = true)]
async fn an_ended_observed_isolated_connection_stays_open_until_the_retention_deadline() {
    let fixture = Fixture::new("obs-iso-open", [Script::Reads]);
    fixture
        .run(async |socket| {
            let mut client = open(
                socket,
                request(fixture.peer, OpenLane::Isolated, None).observed(),
            )
            .await;
            observed(&mut client).await;
            client.write_all(&ended(b"")).await.unwrap();
            let read = read_all(&mut client).await;
            assert!(read.end && read.landed, "{read:?}");
            let ended = tokio::time::Instant::now();
            tokio::time::sleep_until(ended + TERMINAL_RETENTION - Duration::from_millis(10)).await;
            assert_eq!(fixture.scripted.closes(), 0, "closed inside the retention");
            released(&fixture.opener, TERMINAL_RETENTION).await;
            assert_eq!(fixture.scripted.closes(), 1, "left open past the retention");
        })
        .await;
}

/// An ordinary Main Open and a slip's Main Open to one peer ride two sessions, and each reference reads
/// its own.
#[tokio::test]
async fn an_ordinary_and_a_slip_open_to_one_peer_each_sample_their_own_session() {
    let fixture = Fixture::new("obs-slip", [Script::Holds, Script::Holds]);
    let slip = TestNode::seeded(PEER)
        .bound_slip(
            &"ssh".parse().unwrap(),
            TestNode::seeded(THIS).verify_key(),
            until(),
        )
        .unwrap();
    fixture
        .run(async |socket| {
            let mut ordinary = open(
                socket,
                request(fixture.peer, OpenLane::Main, None).observed(),
            )
            .await;
            let ordinary_ref = observed(&mut ordinary).await;
            let mut slipped = open(
                socket,
                request(fixture.peer, OpenLane::Main, Some(slip)).observed(),
            )
            .await;
            let slipped_ref = observed(&mut slipped).await;
            assert_eq!(fixture.scripted.dials(), 2);
            fixture.scripted.set_path(0, relayed());
            fixture.scripted.set_path(1, direct());
            assert_eq!(
                path(socket, ordinary_ref, PathAction::Sample).await,
                sampled(&relayed())
            );
            assert_eq!(
                path(socket, slipped_ref, PathAction::Sample).await,
                sampled(&direct())
            );
            // Only the slip's session moving changes the slip's sample.
            fixture.scripted.set_path(1, ConnInfo::default());
            assert_eq!(
                path(socket, slipped_ref, PathAction::Finish).await,
                sampled(&ConnInfo::default())
            );
            assert_eq!(
                path(socket, ordinary_ref, PathAction::Finish).await,
                sampled(&relayed())
            );
        })
        .await;
}

/// The client's End ends only the upload: while the download is still open the Open is live, so no
/// retention starts, however long the half-close lasts, and its reference still answers.
#[tokio::test(start_paused = true)]
async fn an_observed_open_half_closed_by_the_client_stays_observable() {
    let fixture = Fixture::new("obs-half", [Script::ReadsThenHolds]);
    fixture
        .run(async |socket| {
            let mut client = open(
                socket,
                request(fixture.peer, OpenLane::Isolated, None).observed(),
            )
            .await;
            let reference = observed(&mut client).await;
            client.write_all(&ended(b"up")).await.unwrap();
            tokio::time::timeout(
                HANG_GUARD,
                until_true(|| fixture.scripted.received() == b"up"),
            )
            .await
            .expect("the peer never read the upload");
            tokio::time::sleep(TERMINAL_RETENTION * 2).await;
            fixture.scripted.set_path(0, direct());
            assert_eq!(
                path(socket, reference, PathAction::Sample).await,
                sampled(&direct())
            );
            assert_eq!(fixture.opener.reach.available_permits(), MAX_REACH - 1);
            assert_eq!(
                path(socket, reference, PathAction::Finish).await,
                sampled(&direct())
            );
            // The download is still open: the Finish took the reference, not the stream.
            drop(client);
            released(&fixture.opener, HANG_GUARD).await;
        })
        .await;
}

#[tokio::test]
async fn path_takes_no_reach_slot() {
    let fixture = Fixture::new("obs-full", [Script::Holds]);
    fixture
        .run(async |socket| {
            let mut client = open(
                socket,
                request(fixture.peer, OpenLane::Main, None).observed(),
            )
            .await;
            let reference = observed(&mut client).await;
            let rest = u32::try_from(MAX_REACH - 1).unwrap();
            let _full = fixture.opener.reach.try_acquire_many(rest).unwrap();
            assert_eq!(fixture.opener.reach.available_permits(), 0);
            assert_eq!(
                path(socket, reference, PathAction::Finish).await,
                sampled(&ConnInfo::default())
            );
        })
        .await;
}

#[tokio::test]
async fn a_malformed_path_is_the_fixed_error_and_finishes_nothing() {
    let fixture = Fixture::new("obs-bad", [Script::Holds]);
    fixture
        .run(async |socket| {
            let mut client = open(
                socket,
                request(fixture.peer, OpenLane::Main, None).observed(),
            )
            .await;
            let reference = observed(&mut client).await;
            let mut sample = Vec::new();
            Request::Path(PathRequest {
                reference,
                action: PathAction::Sample,
            })
            .write(&mut sample)
            .await
            .unwrap();
            for patch in [(31, 2), (31, 0xff)] {
                let mut bad = sample.clone();
                bad[patch.0] = patch.1;
                let mut raw = UnixStream::connect(socket).await.unwrap();
                raw.write_all(&bad).await.unwrap();
                assert_eq!(
                    Response::read_path(&mut raw).await.unwrap(),
                    Response::Error("invalid path request".to_owned())
                );
            }
            // A body of 24 is refused without being read, with the same words.
            let mut raw = UnixStream::connect(socket).await.unwrap();
            raw.write_all(b"SWC1\x05\x00\x18").await.unwrap();
            assert_eq!(
                Response::read_path(&mut raw).await.unwrap(),
                Response::Error("invalid path request".to_owned())
            );
            assert_eq!(
                path(socket, reference, PathAction::Finish).await,
                sampled(&ConnInfo::default())
            );
        })
        .await;
}

#[tokio::test]
async fn an_observed_open_past_the_last_ticket_is_an_error_before_any_dial() {
    let fixture = Fixture::new("obs-spent", [Script::Lists(vec![])]);
    fixture.opener.observations.spend_tickets();
    fixture
        .run(async |socket| {
            let mut client = open(
                socket,
                request(fixture.peer, OpenLane::Main, None).observed(),
            )
            .await;
            assert_eq!(
                Response::read_open(&mut client).await.unwrap(),
                Response::Error("swoosh serve can read no more paths until it restarts".to_owned())
            );
        })
        .await;
    assert_eq!(fixture.scripted.dials(), 0);
    released(&fixture.opener, HANG_GUARD).await;
}

/// An Attached written part way is not yet a reference anyone can use; written whole, it is, before
/// the splice can yield; cut part way, it never becomes one.
#[tokio::test]
async fn a_reference_answers_only_once_attached_is_written_whole() {
    let scripted = ScriptedPeer::new(
        TestNode::seeded(PEER).node_id(),
        [Script::Holds, Script::Holds],
    );
    let node = Node::new(scripted.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let set = Observations::new(Epoch::draw(&mut Fill(1)).unwrap(), 4).unwrap();
    let sample = |reference| {
        set.answer(
            PathRequest {
                reference,
                action: PathAction::Sample,
            },
            tokio::time::Instant::now(),
        )
    };
    for whole in [true, false] {
        let connection = Rc::new(
            peers
                .isolated(scripted.node_id(), Hints::NONE)
                .await
                .unwrap(),
        );
        let (to_peer, from_peer) = bifrost::Session::open_bi(&*connection).await.unwrap();
        let observing = set.reserve().unwrap();
        let reference = observing.reference();
        let (watched, _client) = UnixStream::pair().unwrap();
        let gone = ClientGone::watch(watched.as_raw_fd()).unwrap();
        // Room for 8 bytes, so the 35-byte Attached frame waits on the reader.
        let (mut reader, to_client) = tokio::io::duplex(8);
        let (_upload, from_client) = tokio::io::duplex(64);
        let mut attaching = Box::pin(attach(
            BufReader::new(from_client),
            to_client,
            from_peer,
            to_peer,
            connection.conn_info(),
            &gone,
            core::future::pending(),
            Some((&observing, Carrier::Isolated(Rc::clone(&connection)))),
        ));
        assert!(poll!(attaching.as_mut()).is_pending());
        assert_eq!(sample(reference), PathReply::Unavailable);
        if !whole {
            drop(attaching);
            assert_eq!(sample(reference), PathReply::Unavailable);
            drop(observing);
            assert_eq!(sample(reference), PathReply::Unavailable);
            continue;
        }
        let mut frame = [0; 35];
        let mut read = 0;
        while read < frame.len() {
            read += reader.read(&mut frame[read..]).await.unwrap();
            // Polled only while bytes are still to come: the poll that writes the last of them must
            // publish before it returns, so an await slipped in before the publish leaves it unpublished.
            if read < frame.len() {
                let _ = poll!(attaching.as_mut());
            }
        }
        assert_eq!(&frame[..7], b"SWC1\x06\x00\x1c");
        assert_eq!(sample(reference), PathReply::Sample(ConnInfo::default()));
        drop(attaching);
    }
}

/// A random source that fills with one byte.
struct Fill(u8);

impl rand::RngCore for Fill {
    fn next_u32(&mut self) -> u32 {
        u32::from(self.0)
    }

    fn next_u64(&mut self) -> u64 {
        u64::from(self.0)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        dest.fill(self.0);
        Ok(())
    }
}

/// The resident at a socket path, asked directly: the Path exchange a receipt makes, without the
/// listener-attribution checks a home's socket adds.
struct AtSocket(std::path::PathBuf);

impl crate::observation::PathSource for AtSocket {
    async fn path(
        &self,
        request: PathRequest,
    ) -> Result<PathReply, crate::serve::control_codec::ControlError> {
        let mut client = UnixStream::connect(&self.0).await.unwrap();
        Request::Path(request).write(&mut client).await.unwrap();
        match Response::read_path(&mut client).await? {
            Response::Path(reply) => Ok(reply),
            other => panic!("not a path reply: {other:?}"),
        }
    }
}

/// The client's own observed Open, its observer sampling beside the run, and a Finish after it that
/// reads the path the connection took after the last sample, not the one it attached on.
#[tokio::test(start_paused = true)]
async fn a_client_observer_finishes_on_its_own_connections_last_path() {
    use crate::observation::{Observer, Receipt};

    let fixture = Fixture::new("obs-client", [Script::Reads]);
    fixture
        .run(async |socket| {
            let stream = UnixStream::connect(socket).await.unwrap();
            let opened = crate::node_client::UidSocket::open_on(
                stream,
                request(fixture.peer, OpenLane::Isolated, None).observed(),
            )
            .await
            .unwrap();
            let crate::node_client::Opened::Attached {
                info,
                reference: Some(reference),
                mut read,
                mut write,
            } = opened
            else {
                panic!("not attached with a reference: {opened:?}");
            };
            assert_eq!(info, ConnInfo::default());
            let source = Rc::new(AtSocket(socket.to_owned()));
            let mut observer = Observer::new(Receipt::new(reference, source), info);
            // The connection moves after it attached: only a sample can have seen this.
            fixture.scripted.set_path(0, relayed());
            let run = async {
                // Long enough, on the paused clock, for one sample beside the run.
                tokio::time::sleep(Duration::from_millis(1200)).await;
                write.write_all(b"measured").await.unwrap();
                write.shutdown().await.unwrap();
                let mut got = Vec::new();
                read.read_to_end(&mut got).await.unwrap();
                read.landed().await.unwrap();
            };
            tokio::select! {
                never = observer.watch() => match never {},
                () = run => {}
            }
            assert_eq!(observer.latest(), &relayed());
            fixture.scripted.set_path(0, direct());
            let observed = observer.finish().await;
            assert_eq!(observed.last.unwrap(), direct());
            assert!(observed.earlier.is_none());
            assert_eq!(fixture.scripted.received(), b"measured");
            released(&fixture.opener, HANG_GUARD).await;
        })
        .await;
}
