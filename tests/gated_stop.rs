// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The node-lifecycle stop, end to end over the in-process transport: the proof that `control.stop` rides
//! the family gate, so a MEMBER can stop a gated node but a STRANGER cannot, and that a local `serve --for`
//! deadline stops the node by itself.
//!
//! `control.stop` is one more member-only service, assembled through the SAME `Stop` handler the `swoosh
//! serve` product path injects (not a hand-rolled near-copy) and declared member-only exactly as `serve`
//! declares it. Seven things are proven:
//!
//! 1. `serve --for` shape: a local timer cancelling the token stops the exposer's `run`, gracefully.
//! 2. `control.stop`: a MEMBER reaching the member-only service cancels the SAME token the exposer owns, so
//!    the run returns -- the node stops -- and the member reads the ack byte confirming the stop was actioned.
//! 3. A STRANGER's `control.stop` is refused LOUDLY at the gate (a typed error, never a silent no-op), and
//!    the node keeps running.
//! 4. A DELEGATE's `control.stop` slip is refused LOUDLY at the route's member floor BEFORE `Response::Ok`
//!    (the gate grants the slip, the floor refuses it), and the node keeps running.
//! 5. The stopped node records the key the connection proved as the stop's source, never a name from the
//!    request, and names it from its own book, one of your devices first.
//! 6. The node stops only once the member has closed its side after the ack, so its teardown cannot drop
//!    the ack in flight; a member that never closes delays the stop by the bound and no more; and a handler
//!    dropped in that wait still stops the node.
//! 7. A member's `control.stop` is refused at the gate until the node's first sync round has ended, and
//!    the same member stops it once that round has.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a membership badge binds to whatever
//! id the mem transport proves for the dialer (the same accommodation `gated_measure` documents at length):
//! the badge is signed here bound to the member's mem node id, proving the GATE admits a signet-rooted bound
//! badge and refuses a non-signet one, which is the load-bearing stranger case for a stop.

use core::time::Duration;
use std::sync::Arc;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::Denylist;
use swoosh::contacts::Contacts;
use swoosh::serve::{
    ACK_GRACE, CONTROL_STOP_SERVICE, FirstRound, STOP_ACK, Stop, StopKind, StopSource, Stopped,
    stopped_by,
};
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::enabled::AllEnabled;
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Exposer, Router};
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
            let ended = tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("a --for deadline must stop the exposer promptly, not run forever")
                .expect("the run task joins");
            assert!(ended.is_ok(), "a --for stop returns Ok(()): {ended:?}");
        })
        .await;
}

/// An ADMITTED member reaching `control.stop` stops the node: it cancels the SAME token the exposer owns, so
/// `run` returns, and the member reads the ack byte confirming the stop was actioned (not merely admitted).
#[tokio::test]
async fn a_member_stops_a_gated_node_over_control_stop() {
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
                CONTROL_STOP_SERVICE.parse().unwrap(),
                Some(badge.parse().unwrap()),
            )
            .open_service(&member)
            .await
            .expect("member reaches control.stop");
            let (mut writer, mut reader) = session
                .open_bi()
                .await
                .expect("a member is admitted at the gated control.stop service");

            // The ack byte confirms the stop was actioned (the client verb reads exactly this).
            let mut ack = [0u8; 1];
            reader
                .read_exact(&mut ack)
                .await
                .expect("the node acks the stop before closing");
            assert_eq!(ack[0], STOP_ACK, "the node acks with the stop byte");
            // The member closes its side, as the client does: the node stops once it sees that end.
            writer.shutdown().await.expect("the member closes its side");

            // The stop cancelled the exposer's token, so its run returns gracefully. This `Ok` is EXACTLY
            // what `serve` classifies as a graceful, exit-0 stop: its run maps an exposer `Ok` (the token
            // fired) to `Stopped::Requested` and exits 0, so a deliberate `swoosh stop` (a CI teardown)
            // reads as SUCCESS, not a crash. An `Err` here would instead propagate and exit non-zero; a
            // `control.stop` never produces one.
            let ended = tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("an admitted control.stop must stop the node, not leave it running")
                .expect("the run task joins");
            ended.expect("a stopped node returns Ok(()), the exit-0 graceful stop");
            let stopped = Stopped::Requested;
            assert!(
                stopped.message().contains("gracefully"),
                "the graceful-stop line names it a graceful stop: {:?}",
                stopped.message()
            );
        })
        .await;
}

/// The node stops only once the member has closed its side after reading the ack: until then the run goes
/// on and nothing is noted, and the close ends it at once. Cancel before the ack has left and the teardown
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

/// A member that reads the ack and never closes its side still stops the node, at the bound: the stop it
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

/// A handler dropped after the ack, while it waits for the member's close, still stops the node: it notes
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

/// A STRANGER (a badge rooted at a key the gate has never seen) is refused at `control.stop`, LOUDLY: a
/// typed stream error, never a silent success. And the node keeps running -- a stranger cannot stop it.
#[tokio::test]
async fn a_stranger_is_refused_at_control_stop_and_the_node_keeps_running() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let cancel = CancellationToken::new();
            let exposer = build_exposer(cancel.clone()).await;
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });

            // A stranger: a self-signed badge rooted at a RANDOM key the gate never trusts.
            let stranger = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(3, stranger.node_id());
            let session = Connector::to_node(
                host_id,
                CONTROL_STOP_SERVICE.parse().unwrap(),
                Some(badge.parse().unwrap()),
            )
            .open_service(&stranger)
            .await
            .expect("the base connect lands; the gate refuses per-stream");
            let refused = session.open_bi().await;
            assert!(
                matches!(
                    refused,
                    Err(bifrost::Error::Refused(bifrost::Refusal::NotAdmitted))
                ),
                "a stranger's control.stop must be refused at the gate, not admitted: {refused:?}"
            );

            // The refusal did NOT stop the node: its run is still going. Give it a beat, then confirm the run
            // has not returned, and stop it ourselves so the test ends.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !run.is_finished(),
                "a refused stranger must not have stopped the node"
            );
            cancel.cancel();
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("the node stops on our own cancel")
                .expect("the run task joins")
                .expect("graceful stop");
        })
        .await;
}

/// A member's `control.stop` is refused at the gate while the node's first sync round runs, with the same
/// refusal a stranger gets, and the handler never runs; once the round has ended, the same member stops
/// the node. Admit it at once and a revoked device could stop a restarted machine before it learns of the
/// revocation, every time it comes back.
#[tokio::test]
async fn a_remote_stop_waits_for_the_first_round() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let cancel = CancellationToken::new();
            let source = Arc::new(StopSource::new());
            let (exposer, first_round) = FirstRound::hold(
                build_exposer_noting(cancel.clone(), Arc::clone(&source)).await,
                AllEnabled,
            );
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });

            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(SIGNET, member.node_id());
            let connector = || {
                Connector::to_node(
                    host_id,
                    CONTROL_STOP_SERVICE.parse().unwrap(),
                    Some(badge.parse().unwrap()),
                )
            };

            let session = connector()
                .open_service(&member)
                .await
                .expect("the base connect lands; the gate refuses per-stream");
            let refused = session.open_bi().await;
            assert!(
                matches!(
                    refused,
                    Err(bifrost::Error::Refused(bifrost::Refusal::NotAdmitted))
                ),
                "a member's control.stop is refused before the first round ends: {refused:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!run.is_finished(), "a held stop did not stop the node");
            assert_eq!(source.first(), None, "and the stop handler never ran");

            first_round.finished();
            let session = connector()
                .open_service(&member)
                .await
                .expect("member reaches control.stop");
            let (mut writer, mut reader) = session
                .open_bi()
                .await
                .expect("a member is admitted at control.stop once the first round has ended");
            let mut ack = [0u8; 1];
            reader
                .read_exact(&mut ack)
                .await
                .expect("the node acks the stop");
            assert_eq!(ack[0], STOP_ACK);
            writer.shutdown().await.expect("the member closes its side");
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("the stop ends the run")
                .expect("the run task joins")
                .expect("a graceful stop");
            assert_eq!(
                source.first(),
                Some(StopKind::Wire(member.node_id().verify_key().unwrap()))
            );
        })
        .await;
}

/// A DELEGATED slip for `control.stop` is refused at the member floor BEFORE `Response::Ok`: the gate
/// admits the slip (it grants the service to this device), and the route's member-only floor turns that
/// admission into the SAME uniform typed refusal a gate miss gives. The node keeps running: a delegate
/// cannot stop it.
#[tokio::test]
async fn a_control_stop_slip_is_refused_before_ok_and_the_node_keeps_running() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let cancel = CancellationToken::new();
            let exposer = build_exposer(cancel.clone()).await;
            let run = tokio::task::spawn_local({
                let cancel = cancel.clone();
                async move { exposer.run(&host, cancel).await }
            });

            // A delegate: a slip the signet signed for `control.stop`, bound to the delegate's proven mem
            // id, so the GATE grants it. (A wrong-service or unbound slip would need no floor to refuse.)
            let delegate = Node::new(MemTransport::bind(), NoDiscovery);
            let slip = TestRoot::seeded(SIGNET)
                .bound_slip(
                    &CONTROL_STOP_SERVICE.parse().unwrap(),
                    delegate.node_id().verify_key().expect("a usable key"),
                    nauthy::Request::expires_in(Duration::from_secs(300)),
                )
                .unwrap();
            let session =
                Connector::to_node(host_id, CONTROL_STOP_SERVICE.parse().unwrap(), Some(slip))
                    .open_service(&delegate)
                    .await
                    .expect("the base connect lands; the gate decides per-stream");

            // The refusal is the uniform gate-class one, delivered BEFORE any Ok: `open_bi` errors, so the
            // stop client's post-Ok "EOF is success" arm never sees a false stop.
            let refused = session.open_bi().await;
            assert!(
                matches!(
                    refused,
                    Err(bifrost::Error::Refused(bifrost::Refusal::NotAdmitted))
                ),
                "a control.stop slip must be refused pre-Ok as not admitted: {refused:?}"
            );

            // The refusal did NOT stop the node: its run is still going. Give it a beat, then confirm the run
            // has not returned, and stop it ourselves so the test ends.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !run.is_finished(),
                "a refused delegate must not have stopped the node"
            );
            cancel.cancel();
            tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("the node stops on our own cancel")
                .expect("the run task joins")
                .expect("graceful stop");
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
/// device's name on the stream is still named as itself. Print a name from the request and a device could
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

/// Assemble a gated exposer serving `control.stop` and the default reach diagnostics, rooted at the signet,
/// through the SAME `Stop` handler the product `serve` path injects and with the SAME member-only
/// declaration `serve` makes. A second route is there because a node exposing exactly one service answers
/// every name with it, which would let a dial to any service land on `control.stop`. The exposer owns
/// `cancel`; the injected handler holds a clone as the node-control capability.
async fn build_exposer(cancel: CancellationToken) -> Exposer {
    build_exposer_noting(cancel, Arc::default()).await
}

/// [`build_exposer`], with the handler noting how the node was asked to stop in `source`.
async fn build_exposer_noting(cancel: CancellationToken, source: Arc<StopSource>) -> Exposer {
    let signet = TestRoot::seeded(SIGNET).node_id();
    let gate = tunnel::resolve_gate(Some(signet), empty_denylist().await).unwrap();
    swoosh::serve::diagnostics(Router::new(gate), &[])
        .unwrap()
        .member_service(
            CONTROL_STOP_SERVICE.parse().unwrap(),
            Stop::new(cancel, source),
        )
        .unwrap()
        .expose()
        .unwrap()
}

/// A member stops a node, writing `request` on the control stream first: the member's key, and how the
/// stopped node recorded the stop once its run has ended.
async fn stopped_over_the_wire(request: &[u8]) -> (NodeId, Option<StopKind>) {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_id = member.node_id();
    let cancel = CancellationToken::new();
    let source = Arc::new(StopSource::new());
    let exposer = build_exposer_noting(cancel.clone(), Arc::clone(&source)).await;
    let run = tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });

    let badge = signet_badge(SIGNET, member_id);
    let session = Connector::to_node(
        host_id,
        CONTROL_STOP_SERVICE.parse().unwrap(),
        Some(badge.parse().unwrap()),
    )
    .open_service(&member)
    .await
    .expect("member reaches control.stop");
    let (mut writer, mut reader) = session
        .open_bi()
        .await
        .expect("a member is admitted at control.stop");
    // The node reads the stream only to see it end and keeps nothing, so a request written there is read
    // and dropped.
    let _ = writer.write_all(request).await;
    let mut ack = [0u8; 1];
    reader
        .read_exact(&mut ack)
        .await
        .expect("the node acks the stop");
    writer.shutdown().await.expect("the member closes its side");
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("the stop ends the run")
        .expect("the run task joins")
        .expect("a graceful stop");
    (member_id, source.first())
}

/// A node a member has asked to stop, past the ack: its run, how it notes the stop, the member's key, and
/// the member's side of the stream, still open.
struct Stopping {
    run: tokio::task::JoinHandle<eyre::Result<()>>,
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
    /// The member closes its side, as the client does once it holds the ack.
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
            .expect("the run task joins")
            .expect("a graceful stop");
    }
}

/// A member asks a node to stop and reads the ack, holding its side open.
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

    let badge = signet_badge(SIGNET, member_id);
    let session = Connector::to_node(
        host_id,
        CONTROL_STOP_SERVICE.parse().unwrap(),
        Some(badge.parse().unwrap()),
    )
    .open_service(&member)
    .await
    .expect("member reaches control.stop");
    let (writer, mut reader) = session
        .open_bi()
        .await
        .expect("a member is admitted at control.stop");
    let mut ack = [0u8; 1];
    reader
        .read_exact(&mut ack)
        .await
        .expect("the node acks the stop");
    assert_eq!(ack[0], STOP_ACK);
    Stopping {
        run,
        source,
        cancel,
        member: member_id,
        writer: Some(Box::new(writer)),
        _held: Box::new((reader, session, member)),
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

/// An empty revocation denylist: this proof exercises membership admission, not revocation, so the gate
/// loads from a path that does not exist (an absent file is an empty set).
async fn empty_denylist() -> Denylist {
    let path = std::env::temp_dir().join(format!("swoosh-gated-stop-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Denylist::load(path).unwrap()
}
