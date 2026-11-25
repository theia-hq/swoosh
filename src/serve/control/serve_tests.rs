use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use nauthy::Denylist;
use tightbeam::tunnel::{self, CancellationToken, Router};
use tokio::io::{self, AsyncWrite};

use super::{ACK_GRACE, Answer, FirstRound, Hold, REQUEST_DEADLINE, Request, Serve};
use crate::serve::{StopKind, StopSource};
use crate::testkit::{TestNode, TestRoot};

/// Each request and answer survives its byte, and every other byte is refused rather than read as one:
/// the closed decode is what makes an unknown tag `BadRequest` and never a silent default.
#[test]
fn serve_answers_round_trip() {
    for request in [Request::List, Request::Stop] {
        assert_eq!(Request::decode(request.encode()), Some(request));
    }
    for answer in [Answer::Done, Answer::NotYet, Answer::BadRequest] {
        assert_eq!(Answer::decode(answer.encode()), Some(answer));
    }
    // The founder's codes (W1a), so SC1 adds its own without renumbering.
    assert_eq!(
        [Request::List.encode(), Request::Stop.encode()],
        [1, 2],
        "the request codes"
    );
    assert_eq!(
        [
            Answer::Done.encode(),
            Answer::NotYet.encode(),
            Answer::BadRequest.encode()
        ],
        [0, 4, 5],
        "the answer codes"
    );
    for byte in (0..=u8::MAX).filter(|byte| ![1, 2].contains(byte)) {
        assert_eq!(Request::decode(byte), None, "{byte} is not a request");
    }
    for byte in (0..=u8::MAX).filter(|byte| ![0, 4, 5].contains(byte)) {
        assert_eq!(Answer::decode(byte), None, "{byte} is not an answer");
    }
}

/// A member that grants no credit for the answer cannot park the handler on it: each answer, `Done` after
/// a stop, `NotYet` during the hold, `BadRequest`, and a list, gives up at the bound, and a `Done` that never
/// left stops nothing.
#[tokio::test(start_paused = true)]
async fn an_unread_answer_is_dropped_at_the_bound() {
    for (request, held) in [
        (Request::Stop.encode(), false),
        (Request::Stop.encode(), true),
        (3, false),
        (Request::List.encode(), false),
    ] {
        let (first_round, hold) = FirstRound::new();
        if !held {
            first_round.finished();
        }
        let handler = Handler::new(hold);
        let peer = TestNode::seeded(2).verify_key();
        let exchanged = tokio::time::timeout(
            REQUEST_DEADLINE * 2,
            handler.serve.exchange(peer, Stalled, &[request][..]),
        )
        .await
        .unwrap_or_else(|_| panic!("request {request} (held {held}) parked past the bound"));
        let error = exchanged.expect_err("an answer past the bound is dropped, never finished");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            !handler.cancel.is_cancelled(),
            "a stalled answer stops nothing"
        );
        assert_eq!(handler.source.first(), None, "and notes nothing");
    }
}

/// A `Done` that left and then a `shutdown` that stalls still stops the node, and within the bound. The guard
/// is armed once the byte is written, so a handler dropped mid-stall stops the node the caller was told
/// stopped; run on, the stalled `shutdown` gives up at [`REQUEST_DEADLINE`] and the node stops after the
/// caller's close, never later than that bound and [`ACK_GRACE`].
#[tokio::test(start_paused = true)]
async fn a_done_then_a_stalled_shutdown_still_stops_within_the_bound() {
    let peer = TestNode::seeded(2).verify_key();
    let request = [Request::Stop.encode()];

    // Dropped while the `shutdown` waits: `Done` is out, so the drop stops the node.
    let (first_round, hold) = FirstRound::new();
    first_round.finished();
    let handler = Handler::new(hold);
    let dropped = tokio::time::timeout(
        REQUEST_DEADLINE / 2,
        handler.serve.exchange(peer, ShutdownStalls, &request[..]),
    )
    .await;
    assert!(dropped.is_err(), "the shutdown was still waiting");
    assert!(
        handler.cancel.is_cancelled(),
        "a written Done stops the node"
    );
    assert_eq!(handler.source.first(), Some(StopKind::Wire(peer)));

    // Run on: the `shutdown` gives up at its bound, and the node stops then.
    let (first_round, hold) = FirstRound::new();
    first_round.finished();
    let handler = Handler::new(hold);
    let exchanged = tokio::time::timeout(
        REQUEST_DEADLINE + ACK_GRACE,
        handler.serve.exchange(peer, ShutdownStalls, &request[..]),
    )
    .await
    .expect("a stalled shutdown gives up at the bound");
    let error = exchanged.expect_err("an unfinished answer is dropped, never shut down");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(handler.cancel.is_cancelled(), "and the node still stops");
    assert_eq!(handler.source.first(), Some(StopKind::Wire(peer)));
}

/// A `Done` write that fails outright still stops the node: the byte may have left before the stream broke,
/// so the caller may hold `Done`, and the stop it reads is kept true. Only a write past the bound arms nothing.
#[tokio::test(start_paused = true)]
async fn a_done_write_that_breaks_still_stops() {
    let peer = TestNode::seeded(2).verify_key();
    let (first_round, hold) = FirstRound::new();
    first_round.finished();
    let handler = Handler::new(hold);
    let exchanged = handler
        .serve
        .exchange(peer, Broken, &[Request::Stop.encode()][..])
        .await;
    let error = exchanged.expect_err("a broken stream is not an answer");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(handler.cancel.is_cancelled(), "the node still stops");
    assert_eq!(handler.source.first(), Some(StopKind::Wire(peer)));
}

/// A `Serve` over an empty catalog and no revocations, with the token and source it stops through.
struct Handler {
    serve: Serve,
    cancel: CancellationToken,
    source: Arc<StopSource>,
}

impl Handler {
    fn new(hold: Hold) -> Self {
        let path = std::env::temp_dir().join(format!(
            "swoosh-control-serve-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let revoked = Arc::new(Denylist::load(path).expect("an absent denylist loads empty"));
        let gate = tunnel::resolve_gate(Some(TestRoot::seeded(1).node_id()), Arc::clone(&revoked))
            .expect("a gate");
        let catalog = Router::new(gate).catalog(None);
        let cancel = CancellationToken::new();
        let source = Arc::new(StopSource::new());
        Self {
            serve: Serve::new(catalog, cancel.clone(), Arc::clone(&source), hold, revoked),
            cancel,
            source,
        }
    }
}

/// A writer whose peer never grants credit: every write and shutdown waits forever.
struct Stalled;

impl AsyncWrite for Stalled {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

/// A writer that takes every byte at once, and whose peer never acknowledges the end: `shutdown` waits
/// forever, after the answer has left.
struct ShutdownStalls;

impl AsyncWrite for ShutdownStalls {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

/// A writer whose stream has broken: every write fails at once.
struct Broken;

impl AsyncWrite for Broken {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }
}
