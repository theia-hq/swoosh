// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The node-lifecycle stop, end to end over the in-process transport: the proof that `control.stop` rides
//! the family gate, so a MEMBER can stop a gated node but a STRANGER cannot, and that a local `serve --for`
//! deadline stops the node by itself.
//!
//! `control.stop` is one more family-gated service, assembled through the SAME `stop_handler` the `swoosh
//! serve` product path injects (not a hand-rolled near-copy). Three things are proven:
//!
//! 1. `serve --for` shape: a local timer cancelling the token stops the exposer's `run`, gracefully.
//! 2. `control.stop`: a MEMBER reaching the gated service cancels the SAME token the exposer owns, so the
//!    run returns -- the node stops -- and the member reads the ack byte confirming the stop was actioned.
//! 3. A STRANGER's `control.stop` is refused LOUDLY at the gate (a typed error, never a silent no-op), and
//!    the node keeps running.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a membership badge binds to whatever
//! id the mem transport proves for the dialer (the same accommodation `gated_measure` documents at length):
//! the badge is signed here bound to the member's mem node id, proving the GATE admits a signet-rooted bound
//! badge and refuses a non-signet one, which is the load-bearing stranger case for a stop.

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::{Denylist, Identity};
use swoosh::commands::serve::{CONTROL_STOP_SERVICE, STOP_ACK, Stop};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Exposer, Registry, Services};
use tokio::io::AsyncReadExt as _;

/// The signet's fixed secret; its ed25519 public half is the signet the family gate trusts.
const SIGNET_SECRET: [u8; 32] = [7u8; 32];

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
            // for why it is signed here rather than run through mint/adopt over mem).
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(&SIGNET_SECRET, member.node_id());
            let session = Connector::to_node(host_id, CONTROL_STOP_SERVICE.to_owned(), Some(badge))
                .open_service(&member)
                .await
                .expect("member reaches control.stop");
            let (writer, mut reader) = session
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
            drop(writer);

            // The stop cancelled the exposer's token, so its run returns gracefully.
            let ended = tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .expect("an admitted control.stop must stop the node, not leave it running")
                .expect("the run task joins");
            assert!(ended.is_ok(), "a stopped node returns Ok(()): {ended:?}");
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
            let badge = signet_badge(&[3u8; 32], stranger.node_id());
            let session = Connector::to_node(host_id, CONTROL_STOP_SERVICE.to_owned(), Some(badge))
                .open_service(&stranger)
                .await
                .expect("the base connect lands; the gate refuses per-stream");
            let refused = session.open_bi().await;
            assert!(
                refused.is_err(),
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

/// Assemble a gated exposer serving `control.stop` (and the default reach diagnostics), rooted at the
/// signet, through the SAME `stop_handler` the product `serve` path injects. The exposer owns `cancel`; the
/// injected handler holds a clone as the node-control capability.
async fn build_exposer(cancel: CancellationToken) -> Exposer {
    let signet = NodeId::from_ed25519_secret(&SIGNET_SECRET);
    let services =
        Services::parse(&[format!("{CONTROL_STOP_SERVICE}={CONTROL_STOP_SERVICE}:")]).unwrap();
    let gate = tunnel::resolve_gate(false, Some(signet), empty_denylist().await).unwrap();
    let registry = Registry::new().with(CONTROL_STOP_SERVICE, Stop::new(cancel));
    Exposer::new(services, registry, gate).unwrap()
}

/// Mint a membership badge signed by `secret`, bound to `bound` (the dialer's proven node id): the shape a
/// signet holder self-signs and `mint` mints for a device. Rooted at the signet it admits; rooted at a
/// stranger key it is refused. Signed here (not via mint/adopt) so it binds to the mem proven id.
fn signet_badge(secret: &[u8; 32], bound: NodeId) -> String {
    Identity::from_secret(secret)
        .unwrap()
        .mint_member(
            bound.verify_key(),
            nauthy::expires_in(Duration::from_secs(300)),
        )
        .unwrap()
        .seal()
        .unwrap()
        .link()
        .unwrap()
}

/// An empty revocation denylist: this proof exercises membership admission, not revocation, so the gate
/// loads from a path that does not exist (an absent file is an empty set).
async fn empty_denylist() -> Denylist {
    let path = std::env::temp_dir().join(format!("swoosh-gated-stop-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Denylist::load(path).await.unwrap()
}
