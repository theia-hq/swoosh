// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The node-lifecycle stop, end to end over the in-process transport: a `Stop` on `control.serve` stops
//! the node, bound through the SAME `control::bind_serve` the `swoosh serve` product path calls, and a local
//! `serve --for` deadline stops the node by itself. Who reaches the route, the first round's hold and a
//! revoked device are `gated_serve`'s; this file holds the stop's own bounds.
//!
//! 1. `serve --for` shape: a local timer cancelling the token stops the exposer's `run`, gracefully.
//! 2. A MEMBER's `Stop` cancels the SAME token the exposer owns, so the run returns, and the member reads
//!    `Done` confirming the stop was actioned.
//! 3. The stopped node records the key the connection proved as the stop's source, never a name from the
//!    request, and names it from its own book, one of your devices first.
//! 4. The node stops only once the member has closed its side after `Done`, so its teardown cannot drop
//!    the answer in flight; a member that never closes delays the stop by the bound and no more; and a
//!    handler dropped in that wait still stops the node.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a membership badge binds to whatever
//! id the mem transport proves for the dialer (the same accommodation `gated_measure` documents at length):
//! the badge is signed here bound to the member's mem node id.

use core::time::Duration;
use std::sync::Arc;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use swoosh::contacts::Contacts;
use swoosh::serve::control::{ACK_GRACE, Answer, Request, stopped_by};
use swoosh::serve::{CONTROL_SERVE_SERVICE, StopKind, StopSource, Stopped, control};
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{CancellationToken, Connector, Exposer, Router};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The byte the signet's fixed key is seeded with; its ed25519 public half is the signet the family gate
/// trusts.
const SIGNET: u8 = 7;

/// A local `serve --for` deadline stops the exposer by itself: a timer cancels the node's teardown token,
/// and `run` returns gracefully. This is the mechanism `serve --for <duration>` drives (a `sleep` then a
/// `cancel`), proven here with a fast deadline instead of a real duration.
#[tokio::test]
async fn a_for_deadline_stops_the_exposer_by_itself() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let node = Node::new(MemTransport::bind(), NoDiscovery);
            let cancel = CancellationToken::new();
            let exposer = build_exposer(cancel.clone()).await;

            // The `--for` timer: after a fast deadline, cancel the token (exactly what `ServeCmd::run`
            // spawns for `--for <duration>`).
            let timer = cancel.clone();
            tokio::task::spawn_local(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                timer.cancel();
            });

            let run = tokio::task::spawn_local(async move { exposer.run(&node, cancel).await });
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("a --for deadline must stop the exposer promptly, not run forever")
                .expect("the run task joins");
        })
        .await;
}

/// An ADMITTED member's `Stop` on `control.serve` stops the node: it cancels the SAME token the exposer
/// owns, so `run` returns, and the member reads `Done` confirming the stop was actioned (not merely
/// admitted).
#[tokio::test]
async fn a_member_stops_a_gated_node_over_control_serve() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let cancel = CancellationToken::new();
            let exposer = build_exposer(cancel.clone()).await;
            let run = tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });

            // A member: a badge the signet signed, rooted at the trusted signet and bound to the member's
            // proven mem id, so the gate admits it (the shape `mint` mints for a device; see `gated_measure`
            // for why it is signed here rather than run through invite/join over mem).
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(SIGNET, member.node_id());
            let session = Connector::to_node(
                host_id,
                CONTROL_SERVE_SERVICE.parse().unwrap(),
                Some(badge.parse().unwrap()),
            )
            .open_service(&member)
            .await
            .expect("member reaches control.serve");
            let (mut writer, mut reader) = session
                .open_bi()
                .await
                .expect("a member is admitted at the gated control.serve route");
            writer
                .write_all(&[Request::Stop.encode()])
                .await
                .expect("the request is sent");

            // `Done` confirms the stop was actioned (the client verb reads exactly this).
            let mut answer = [0u8; 1];
            reader
                .read_exact(&mut answer)
                .await
                .expect("the node answers the stop before closing");
            assert_eq!(answer[0], Answer::Done.encode(), "the node answers Done");
            // The member closes its side, as the client does: the node stops once it sees that end.
            writer.shutdown().await.expect("the member closes its side");

            // The stop cancelled the exposer's token, so its run returns. That return is EXACTLY what
            // `serve` classifies as a graceful, exit-0 stop: its run maps an exposer that returned (the
            // token fired) to `Stopped::Requested` and exits 0, so a deliberate `swoosh stop` (a CI
            // teardown) reads as SUCCESS, not a crash.
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("an admitted stop must stop the node, not leave it running")
                .expect("the run task joins");
            let stopped = Stopped::Requested;
            assert!(
                stopped.message().contains("gracefully"),
                "the graceful-stop line names it a graceful stop: {:?}",
                stopped.message()
            );
        })
        .await;
}

/// The node stops only once the member has closed its side after reading `Done`: until then the run goes
/// on and nothing is noted, and the close ends it at once. Cancel before `Done` has left and the teardown
/// can drop it in flight, so a stop that worked reports itself unconfirmed.
#[tokio::test(start_paused = true)]
async fn the_node_stops_once_the_member_closes_after_the_ack() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let mut stopping = acked_stop().await;
            tokio::time::sleep(ACK_GRACE / 2).await;
            assert!(
                !stopping.run.is_finished(),
                "the node waits for the member's close before it stops"
            );
            assert_eq!(
                stopping.source.first(),
                None,
                "nothing is noted before the close"
            );

            let closed = tokio::time::Instant::now();
            stopping.close().await;
            stopping.ended().await;
            assert!(
                closed.elapsed() < ACK_GRACE / 2,
                "the close ends the run at once, not at the bound: {:?}",
                closed.elapsed()
            );
        })
        .await;
}

/// A member that reads `Done` and never closes its side still stops the node, at the bound: the stop it
/// asked for always happens, and holding the stream open delays it by the bound and no more.
#[tokio::test(start_paused = true)]
async fn a_member_holding_its_side_open_stops_the_node_at_the_bound() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let started = tokio::time::Instant::now();
            let stopping = acked_stop().await;
            let member = stopping.member;
            let source = Arc::clone(&stopping.source);
            stopping.ended().await;
            assert!(
                started.elapsed() >= ACK_GRACE,
                "a held side delays the stop to the bound: {:?}",
                started.elapsed()
            );
            assert!(
                started.elapsed() < ACK_GRACE * 2,
                "and no further: {:?}",
                started.elapsed()
            );
            assert_eq!(
                source.first(),
                Some(StopKind::Wire(member.verify_key().unwrap()))
            );
        })
        .await;
}

/// A handler dropped after `Done`, while it waits for the member's close, still stops the node: it notes
/// the member and cancels the token. A live cut ending the session in that window drops it this way, and
/// the member has already printed `Stopped`, so the node must not run on with nothing noted.
#[tokio::test(start_paused = true)]
async fn a_handler_dropped_after_the_ack_still_stops_the_node() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let stopping = acked_stop().await;
            tokio::time::sleep(ACK_GRACE / 2).await;
            assert!(
                !stopping.cancel.is_cancelled(),
                "the handler is still waiting"
            );
            assert_eq!(stopping.source.first(), None, "nothing is noted yet");

            // Drop the run mid-wait, and the handler future with it; the member's side stays open.
            stopping.run.abort();
            let aborted = stopping.run.await;
            assert!(
                aborted.is_err_and(|error| error.is_cancelled()),
                "the run was dropped, not ended"
            );
            assert!(
                stopping.cancel.is_cancelled(),
                "a dropped handler cancels the token"
            );
            assert_eq!(
                stopping.source.first(),
                Some(StopKind::Wire(stopping.member.verify_key().unwrap())),
                "and notes the member that asked"
            );
        })
        .await;
}

/// The stopped node says who stopped it, by the key the connection proved: the handler records that key
/// as the stop's source, and with no name for it in the book the line is the whole key. Any of your devices
/// can stop any other, so this line is the one trail a stop leaves; record nothing and it is gone.
#[tokio::test]
async fn stopped_node_prints_who_stopped_it() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (member, recorded) = stopped_over_the_wire(b"").await;
            assert_eq!(recorded, Some(StopKind::Wire(member.verify_key().unwrap())));
            let Some(StopKind::Wire(key)) = recorded else {
                unreachable!("asserted above");
            };
            assert_eq!(
                stopped_by(&Contacts::default(), key),
                format!("Stopped by {member}.")
            );
        })
        .await;
}

/// The line's key is the connection's and its name is the stopped node's own: a caller that writes another
/// device's name on the stream after its request is still named as itself. Print a name from the request and a device could
/// claim to be me/nas.
#[tokio::test]
async fn stopped_by_line_names_the_authenticated_key() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (member, recorded) = stopped_over_the_wire(b"me/nas").await;
            let Some(StopKind::Wire(key)) = recorded else {
                panic!("a wire stop records the key that asked: {recorded:?}");
            };
            let mut contacts = Contacts::default();
            let nas = TestNode::seeded(0x0a).node_id();
            for (name, node) in [("laptop", member), ("nas", nas)] {
                contacts.add("me".parse().unwrap(), Some(name.parse().unwrap()), node);
            }
            assert_eq!(
                stopped_by(&contacts, key),
                format!("Stopped by me/laptop ({}).", short(member))
            );
        })
        .await;
}

/// One of your devices that the book also holds under another name (saved as a contact's machine before it
/// joined) is named as yours: look the key up in name order and `alice` comes before `me`.
#[test]
fn stopped_by_names_your_device_first() {
    let laptop = TestNode::seeded(0x0c).node_id();
    let mut contacts = Contacts::default();
    contacts.add("alice".parse().unwrap(), Some("x".parse().unwrap()), laptop);
    contacts.add(
        "me".parse().unwrap(),
        Some("laptop".parse().unwrap()),
        laptop,
    );
    assert_eq!(
        stopped_by(&contacts, laptop.verify_key().unwrap()),
        format!("Stopped by me/laptop ({}).", short(laptop))
    );
}

/// The short form of `node` a line that names the machine carries.
fn short(node: NodeId) -> String {
    let head: String = node.to_string().chars().take(12).collect();
    format!("{head}\u{2026}")
}

/// Assemble a gated exposer serving `control.serve` and the default reach diagnostics, rooted at the signet,
/// through the SAME `control::bind_serve` the product `serve` path calls, its first round already ended so
/// a stop is taken. A second route is there because a node exposing exactly one service answers every name
/// with it. The exposer owns `cancel`; the handler holds a clone as the node-control capability.
async fn build_exposer(cancel: CancellationToken) -> Exposer {
    build_exposer_noting(cancel, Arc::default()).await
}

/// [`build_exposer`], with the handler noting how the node was asked to stop in `source`.
async fn build_exposer_noting(cancel: CancellationToken, source: Arc<StopSource>) -> Exposer {
    let signet = TestRoot::seeded(SIGNET).node_id();
    let (gate, cut, _home) =
        swoosh::testkit::admitting(signet, TestNode::seeded(SIGNET + 1).node_id()).await;
    let (router, _catalog, first_round) = control::bind_serve(
        swoosh::serve::diagnostics(Router::new(gate), &[]).unwrap(),
        cancel,
        source,
        &cut,
    )
    .unwrap();
    first_round.finished();
    router.expose().unwrap()
}

/// A member's `Stop` on a fresh `control.serve` stream to `host_id`, then `then`, with `Done` read: the
/// member's writer, still open, and its reader and session, held so only the writer's close ends the stream.
async fn sent_stop(
    host_id: NodeId,
    member: &Node<MemTransport, NoDiscovery>,
    then: &[u8],
) -> (
    Box<dyn tokio::io::AsyncWrite + Unpin>,
    Box<dyn core::any::Any>,
) {
    let badge = signet_badge(SIGNET, member.node_id());
    let session = Connector::to_node(
        host_id,
        CONTROL_SERVE_SERVICE.parse().unwrap(),
        Some(badge.parse().unwrap()),
    )
    .open_service(member)
    .await
    .expect("member reaches control.serve");
    let (mut writer, mut reader) = session
        .open_bi()
        .await
        .expect("a member is admitted at control.serve");
    writer
        .write_all(&[Request::Stop.encode()])
        .await
        .expect("the request is sent");
    // The node reads past the request only to see the stream end and keeps nothing, so bytes written after
    // it are read and dropped.
    let _ = writer.write_all(then).await;
    let mut answer = [0u8; 1];
    reader
        .read_exact(&mut answer)
        .await
        .expect("the node answers the stop");
    assert_eq!(answer[0], Answer::Done.encode());
    (Box::new(writer), Box::new((reader, session)))
}

/// A member stops a node, writing `then` on the stream after its request: the member's key, and how the
/// stopped node recorded the stop once its run has ended.
async fn stopped_over_the_wire(then: &[u8]) -> (NodeId, Option<StopKind>) {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_id = member.node_id();
    let cancel = CancellationToken::new();
    let source = Arc::new(StopSource::new());
    let exposer = build_exposer_noting(cancel.clone(), Arc::clone(&source)).await;
    let run = tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });

    let (mut writer, _held) = sent_stop(host_id, &member, then).await;
    writer.shutdown().await.expect("the member closes its side");
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("the stop ends the run")
        .expect("the run task joins");
    (member_id, source.first())
}

/// A node a member has asked to stop, past `Done`: its run, how it notes the stop, the member's key, and
/// the member's side of the stream, still open.
struct Stopping {
    run: tokio::task::JoinHandle<()>,
    source: Arc<StopSource>,
    /// The node's teardown token, the one the handler cancels.
    cancel: CancellationToken,
    member: NodeId,
    /// The member's writer, until [`close`](Self::close).
    writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin>>,
    /// The member's reader, session and node, held so only the writer's close ends the stream.
    _held: Box<dyn core::any::Any>,
}

impl Stopping {
    /// The member closes its side, as the client does once it holds `Done`.
    async fn close(&mut self) {
        if let Some(mut writer) = self.writer.take() {
            writer.shutdown().await.expect("the member closes its side");
        }
    }

    /// Wait for the run to end, gracefully, within the bound and a margin.
    async fn ended(self) {
        tokio::time::timeout(ACK_GRACE * 2, self.run)
            .await
            .expect("the stop ends the run within the bound")
            .expect("the run task joins");
    }
}

/// A member asks a node to stop and reads `Done`, holding its side open.
async fn acked_stop() -> Stopping {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_id = member.node_id();
    let cancel = CancellationToken::new();
    let source = Arc::new(StopSource::new());
    let exposer = build_exposer_noting(cancel.clone(), Arc::clone(&source)).await;
    let run = tokio::task::spawn_local({
        let cancel = cancel.clone();
        async move { exposer.run(&host, cancel).await }
    });

    let (writer, held) = sent_stop(host_id, &member, &[]).await;
    Stopping {
        run,
        source,
        cancel,
        member: member_id,
        writer: Some(writer),
        _held: Box::new((held, member)),
    }
}

/// Mint a membership badge signed by the key `signer` seeds, bound to `bound` (the dialer's proven node id):
/// the shape a signet holder self-signs and `mint` mints for a device. Rooted at the signet it admits; rooted
/// at a stranger key it is refused. Signed here (not via invite/join) so it binds to the mem proven id.
fn signet_badge(signer: u8, bound: NodeId) -> String {
    TestRoot::seeded(signer)
        .device_badge(bound, nauthy::Request::expires_in(Duration::from_secs(300)))
        .unwrap()
        .to_string()
}
