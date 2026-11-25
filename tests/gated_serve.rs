// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `control.serve`, end to end over the in-process transport, bound through the SAME `control::bind_serve`
//! the `swoosh serve` product path calls: one request per stream, a list or a stop, member-only.
//!
//! What is proven:
//!
//! 1. A stop during the first sync round answers `NotYet` and arms nothing; after it, the same request
//!    stops the node and notes the member's key.
//! 2. A list answers during the hold.
//! 3. A stream with no request, silent or ended, is reset within the route's 5 s bound, never cleanly
//!    ended and never a stop.
//! 4. Any tag but a list or a stop, the pause tags included, answers `BadRequest` and changes nothing.
//! 5. A stranger's badge and a delegate's slip are refused before `Response::Ok`.
//! 6. A device revoked while its stream sat open through the first round cannot stop the node on it.
//! 7. A second request on a stream is never read.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a membership badge is signed here
//! bound to the member's mem node id, as `gated_stop` documents.

use core::time::Duration;
use std::sync::Arc;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::{Denylist, Revocation};
use swoosh::serve::control::{self, Answer, REQUEST_DEADLINE};
use swoosh::serve::{CONTROL_SERVE_SERVICE, StopKind, StopSource};
use swoosh::testkit::TestRoot;
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Router, ServiceCatalog};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The byte the signet's fixed key is seeded with; its public half is the root the gate trusts.
const SIGNET: u8 = 7;

/// A member's `Stop` while the first round runs answers `NotYet`, the stream ends cleanly, the node keeps
/// running and nothing is noted; once the round has ended, the same request stops the node and notes the
/// member's key. The hold is read before anything is armed, so a held stop can never cancel.
#[tokio::test]
async fn a_held_stop_answers_not_yet_and_never_cancels() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut serving = Serving::start().await;
            let member = Node::new(MemTransport::bind(), NoDiscovery);

            let (mut writer, mut reader) = serving.open(&member, SIGNET).await;
            writer
                .write_all(&[control::Request::Stop.encode()])
                .await
                .unwrap();
            let mut answer = Vec::new();
            reader
                .read_to_end(&mut answer)
                .await
                .expect("a held stop is answered and the stream ended cleanly");
            assert_eq!(answer, [Answer::NotYet.encode()]);
            serving.still_running().await;

            serving.finish_first_round();
            let (mut writer, mut reader) = serving.open(&member, SIGNET).await;
            writer
                .write_all(&[control::Request::Stop.encode()])
                .await
                .unwrap();
            let mut answer = [0u8; 1];
            reader.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer[0], Answer::Done.encode());
            writer.shutdown().await.unwrap();
            serving.stopped().await;
            assert_eq!(
                serving.source.first(),
                Some(StopKind::Wire(member.node_id().verify_key().unwrap()))
            );
        })
        .await;
}

/// A list is answered during the hold: `Done`, then the catalog `serve` cut, which lists `control.serve`.
#[tokio::test]
async fn a_list_answers_during_the_hold() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let serving = Serving::start().await;
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let (mut writer, mut reader) = serving.open(&member, SIGNET).await;
            writer
                .write_all(&[control::Request::List.encode()])
                .await
                .unwrap();
            let listed = read_list(&mut reader).await;
            assert_eq!(listed, serving.catalog);
            assert!(
                listed
                    .entries()
                    .any(|entry| entry.name == CONTROL_SERVE_SERVICE),
                "the route lists itself"
            );
            serving.still_running().await;
        })
        .await;
}

/// A member that opens `control.serve` and says nothing is cut off within the route's bound, well before
/// tightbeam's own 10 s first-traffic bound, and the node runs on with nothing noted. The end is a reset,
/// never a clean end a caller could read as an answer.
#[tokio::test]
async fn a_silent_serve_request_is_dropped() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut serving = Serving::start().await;
            serving.finish_first_round();
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let (_writer, mut reader) = serving.open(&member, SIGNET).await;
            let started = tokio::time::Instant::now();
            let mut byte = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(8), reader.read(&mut byte))
                .await
                .expect("a silent stream is dropped within the route's bound");
            assert!(
                read.is_err(),
                "a dropped stream reads as cut off, never a clean end: {read:?}"
            );
            assert!(
                started.elapsed() >= REQUEST_DEADLINE - Duration::from_millis(500),
                "dropped at the bound, not before: {:?}",
                started.elapsed()
            );
            serving.still_running().await;
        })
        .await;
}

/// A member that ends its side with no request gets no answer: the stream is reset, never ended cleanly.
#[tokio::test]
async fn a_stream_ended_with_no_request_is_reset() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut serving = Serving::start().await;
            serving.finish_first_round();
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let (mut writer, mut reader) = serving.open(&member, SIGNET).await;
            writer.shutdown().await.unwrap();
            let mut byte = [0u8; 1];
            let read = reader.read(&mut byte).await;
            assert!(read.is_err(), "no request, no clean end: {read:?}");
            serving.still_running().await;
        })
        .await;
}

/// Every tag but a list or a stop, SC1's pause tags `3` and `4` included, answers `BadRequest`: the node
/// runs, nothing is noted, and every bound service still admits. No pause rides in silently.
#[tokio::test]
async fn a_pause_request_is_a_bad_request() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut serving = Serving::start().await;
            serving.finish_first_round();
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            for tag in [0, 3, 4, 255] {
                let (mut writer, mut reader) = serving.open(&member, SIGNET).await;
                writer.write_all(&[tag]).await.unwrap();
                let mut answer = Vec::new();
                reader
                    .read_to_end(&mut answer)
                    .await
                    .expect("an unknown tag is answered and the stream ended cleanly");
                assert_eq!(answer, [Answer::BadRequest.encode()], "tag {tag}");
            }
            serving.still_running().await;
            // Every bound service still admits: the diagnostics, and `control.serve` itself.
            for service in ["ping", "speed", CONTROL_SERVE_SERVICE] {
                let session = Connector::to_node(
                    serving.host,
                    service.parse().unwrap(),
                    Some(signet_badge(SIGNET, member.node_id()).parse().unwrap()),
                )
                .open_service(&member)
                .await
                .unwrap();
                session
                    .open_bi()
                    .await
                    .unwrap_or_else(|error| panic!("{service} still admits: {error}"));
            }
        })
        .await;
}

/// A stranger's badge is refused at the gate and a delegate's slip for `control.serve` at the member floor,
/// both with the uniform refusal before `Response::Ok`, so neither reaches the handler.
#[tokio::test]
async fn a_stranger_and_a_slip_are_refused_at_control_serve() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut serving = Serving::start().await;
            serving.finish_first_round();
            let stranger = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(SIGNET + 1, stranger.node_id());
            let delegate = Node::new(MemTransport::bind(), NoDiscovery);
            let slip = TestRoot::seeded(SIGNET)
                .bound_slip(
                    &CONTROL_SERVE_SERVICE.parse().unwrap(),
                    delegate.node_id().verify_key().unwrap(),
                    nauthy::Request::expires_in(Duration::from_secs(300)),
                )
                .unwrap();
            for (who, node, credential) in [
                ("a stranger", &stranger, badge.parse().unwrap()),
                ("a slip", &delegate, slip),
            ] {
                let session = Connector::to_node(
                    serving.host,
                    CONTROL_SERVE_SERVICE.parse().unwrap(),
                    Some(credential),
                )
                .open_service(node)
                .await
                .expect("the base connect lands; the gate refuses per-stream");
                let refused = session.open_bi().await;
                assert!(
                    matches!(
                        refused,
                        Err(bifrost::Error::Refused(bifrost::Refusal::NotAdmitted))
                    ),
                    "{who} is refused before Ok: {refused:?}"
                );
            }
            serving.still_running().await;
        })
        .await;
}

/// A device revoked while this machine was down opens `control.serve` during the first round, while the
/// gate still admits it. The round folds its revocation and ends; a `Stop` on the stream it already holds
/// is refused, unanswered and reset, since the handler asks the gate's own revocations at the stop. The
/// node runs on and nothing is noted.
#[tokio::test]
async fn a_device_revoked_by_the_first_round_cannot_stop_on_a_stream_opened_during_it() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut serving = Serving::start().await;
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let (mut writer, mut reader) = serving.open(&member, SIGNET).await;

            // The first round's fold, as `serve` makes it: the key is written to the file through another
            // instance, the round waits out the stat debounce, then ends. The store the gate and the handler
            // share learns it only from the file.
            let writer_side = Denylist::for_repair(serving.revoked.path().to_owned());
            let lock = writer_side.lock().unwrap();
            writer_side
                .revoke(
                    &lock,
                    [Revocation::Key(member.node_id().verify_key().unwrap())],
                )
                .unwrap();
            drop(lock);
            tokio::time::sleep(nauthy::STAT_DEBOUNCE).await;
            serving.finish_first_round();

            writer
                .write_all(&[control::Request::Stop.encode()])
                .await
                .unwrap();
            let mut answer = Vec::new();
            let read = reader.read_to_end(&mut answer).await;
            assert!(
                read.is_err() && answer.is_empty(),
                "a revoked device's stop is never answered: {read:?} {answer:?}"
            );
            serving.still_running().await;
        })
        .await;
}

/// Two requests in one write: the first is answered and the second is never read, so `[List, Stop]` lists
/// and the node runs on.
#[tokio::test]
async fn a_second_request_on_a_stream_is_never_read() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut serving = Serving::start().await;
            serving.finish_first_round();
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let (mut writer, mut reader) = serving.open(&member, SIGNET).await;
            writer
                .write_all(&[
                    control::Request::List.encode(),
                    control::Request::Stop.encode(),
                ])
                .await
                .unwrap();
            assert_eq!(read_list(&mut reader).await, serving.catalog);
            serving.still_running().await;
        })
        .await;
}

/// A node serving the diagnostics and `control.serve`, bound as `serve` binds it, running.
struct Serving {
    host: NodeId,
    run: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
    source: Arc<StopSource>,
    /// The one store the gate and the handler read.
    revoked: Arc<Denylist>,
    catalog: ServiceCatalog,
    /// The first round, until a test ends it.
    first_round: Option<control::FirstRound>,
}

impl Serving {
    /// Bind and run the node. The diagnostics are there because a node exposing exactly one service answers
    /// every name with it.
    async fn start() -> Self {
        let path = std::env::temp_dir().join(format!(
            "swoosh-gated-serve-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_file(&path);
        let revoked = Arc::new(Denylist::load(path).unwrap());
        let gate = tunnel::resolve_gate(
            Some(TestRoot::seeded(SIGNET).node_id()),
            Arc::clone(&revoked),
        )
        .unwrap();
        let router = swoosh::serve::diagnostics(Router::new(gate), &[]).unwrap();
        let cancel = CancellationToken::new();
        let source = Arc::new(StopSource::new());
        let (router, catalog, first_round) = control::bind_serve(
            router,
            cancel.clone(),
            Arc::clone(&source),
            Arc::clone(&revoked),
        )
        .unwrap();
        let exposer = router.expose().unwrap();
        let node = Node::new(MemTransport::bind(), NoDiscovery);
        let host = node.node_id();
        let run = tokio::task::spawn_local({
            let cancel = cancel.clone();
            async move { exposer.run(&node, cancel).await }
        });
        Self {
            host,
            run,
            cancel,
            source,
            revoked,
            catalog,
            first_round: Some(first_round),
        }
    }

    /// End the first round.
    fn finish_first_round(&mut self) {
        if let Some(first_round) = self.first_round.take() {
            first_round.finished();
        }
    }

    /// Open one `control.serve` stream from `member` with a badge the key `signer` seeds signed.
    async fn open(
        &self,
        member: &Node<MemTransport, NoDiscovery>,
        signer: u8,
    ) -> (
        impl tokio::io::AsyncWrite + Unpin + use<>,
        impl tokio::io::AsyncRead + Unpin + use<>,
    ) {
        let badge = signet_badge(signer, member.node_id());
        let session = Connector::to_node(
            self.host,
            CONTROL_SERVE_SERVICE.parse().unwrap(),
            Some(badge.parse().unwrap()),
        )
        .open_service(member)
        .await
        .unwrap();
        session.open_bi().await.expect("a member is admitted")
    }

    /// The node is still running 50 ms on, and nothing noted a stop.
    async fn still_running(&self) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!self.run.is_finished(), "the node still runs");
        assert!(!self.cancel.is_cancelled(), "nothing asked it to stop");
        assert_eq!(self.source.first(), None, "and nothing was noted");
    }

    /// The node stopped, gracefully, within a few seconds.
    async fn stopped(&mut self) {
        tokio::time::timeout(Duration::from_secs(5), &mut self.run)
            .await
            .expect("the stop ends the run")
            .expect("the run task joins");
    }
}

/// Read a list's answer to its end: `Done`, then the catalog.
async fn read_list(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> ServiceCatalog {
    let mut answer = Vec::new();
    reader.read_to_end(&mut answer).await.unwrap();
    let (code, blob) = answer.split_first().expect("an answer byte");
    assert_eq!(*code, Answer::Done.encode());
    ServiceCatalog::decode(blob).unwrap()
}

/// A membership badge the key `signer` seeds signed, bound to `bound`, the dialer's proven node id.
fn signet_badge(signer: u8, bound: NodeId) -> String {
    TestRoot::seeded(signer)
        .device_badge(bound, nauthy::Request::expires_in(Duration::from_secs(300)))
        .unwrap()
        .to_string()
}

/// A suffix that keeps each test's denylist file its own.
fn rand_suffix() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
