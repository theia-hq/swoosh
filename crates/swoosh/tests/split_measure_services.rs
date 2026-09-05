// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `ping` and `speed` as two independent services, end to end over the in-process transport: the proof
//! that a node may advertise `ping` WITHOUT `speed` (and the reverse), so the founder's "a node MAY want to
//! be a public ping responder, or a speedtest server, but not both" holds at the service boundary.
//!
//! A node exposes exactly ONE of the two services, gated on its own self-signet, through the SAME
//! `registry()` the product `serve` path builds (the registry always holds both; the `Services` map
//! is what selects which one this node OFFERS). A member reaches the offered method and MEASURES it; the
//! member's OTHER method does not succeed against that node, because the served method must match the
//! service the gate admitted and the handler refuses the wrong frame at the wire. The member-admitted /
//! stranger-refused invariant still holds per service: a stranger reaches neither.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a badge binds to that id rather than
//! a device's derived ed25519 key, exactly as `gated_measure.rs` documents; what this proves is that the gate
//! admits a signet-rooted bound badge and that the OFFERED-service boundary is real, not that mint/adopt
//! store the badge (that is `device_badge_wiring.rs`).

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId};
use bifrost_mem::MemTransport;
use measure::{Limit, Mode, Ping, ProtocolError, Speedtest};
use nauthy::{FileDenylist, Identity};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{
    self, CancellationToken, Connector, Exposer, PublicUnsafeRequest, Services,
};

/// The node's OWN secret: its ed25519 public half is both its identity key and the self-signet its gate
/// roots at (a person-zero node is its own signet root), so a member badge rooted here is admitted.
const SELF_SECRET: [u8; 32] = [21u8; 32];

/// The ssh host-key seed the shared `registry()` carries. Unused here (this exercises the measure halves), but
/// a fixed value keeps the build stable with and without the `ssh` feature.
const HOST_SEED: [u8; 32] = [9u8; 32];

#[test]
fn a_node_offering_only_ping_answers_ping_and_not_speed() {
    run(proof_ping_only);
}

#[test]
fn a_node_offering_only_speed_answers_speed_and_not_ping() {
    run(proof_speed_only);
}

/// Run one proof on a worker thread with a generous stack, for the same reason as `gated_measure.rs`: measure's
/// transfer engine holds a 64 KiB chunk buffer per direction on the stack, and over mem both sides run on
/// one LocalSet thread, so a bidir speedtest nests several at once. An 8 MiB thread keeps that safe.
fn run<F, Fut>(proof: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: core::future::Future<Output = ()>,
{
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(proof()));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// A node offering ONLY `ping`: a member pings it (answered), the member's speed does NOT succeed
/// against it, and a stranger reaches neither.
async fn proof_ping_only() {
    let host = expose(&["ping=ping:".to_owned()]).await;

    // A member reaches the OFFERED ping service and measures it.
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_badge = self_badge(&SELF_SECRET, member.node_id());
    let ping = Connector::to_node(host, "ping".to_owned(), Some(member_badge.clone()))
        .open_service(&member)
        .await
        .expect("a member reaches the offered ping");
    let report = Ping {
        count: 3,
        interval: Duration::ZERO,
    }
    .run(&ping)
    .await
    .expect("a member's ping runs against a ping-only node");
    assert_eq!(
        report.received(),
        3,
        "the ping-only node answers every probe"
    );

    // The member's SPEED does not flow against a ping-only node. A node offering exactly one service
    // resolves any request to it, so `speed` resolves to the sole `ping`, whose handler refuses the speed
    // frame at the wire with a typed `Response::Unsupported` BEFORE sourcing a byte. The client decodes
    // that to `ProtocolError::Refused` and short-circuits: a refusal is a LOUD error, NEVER a `0.00 MiB/s`
    // report over the elapsed window. (This test used to enshrine the bug by asserting `Some(0)` bytes.)
    let speed = Connector::to_node(host, "speed".to_owned(), Some(member_badge))
        .open_service(&member)
        .await
        .expect("the base connect lands; the offered service is resolved per-stream");
    let refused = Speedtest::new(Mode::Down, Limit::ByBytes(1 << 16))
        .run(&speed)
        .await;
    assert!(
        matches!(refused, Err(ProtocolError::Refused(_))),
        "a node offering only ping must REFUSE speed loudly, not source zero bytes: {refused:?}"
    );

    // The stranger reaches neither: a badge rooted at a key the self-gate never trusted is refused.
    assert_stranger_refused(host).await;
}

/// A node offering ONLY `speed`: a member speed-tests it (answered), the member's ping does NOT
/// succeed against it, and a stranger reaches neither.
async fn proof_speed_only() {
    let host = expose(&["speed=speed:".to_owned()]).await;

    // A member reaches the OFFERED speed service and moves bytes.
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_badge = self_badge(&SELF_SECRET, member.node_id());
    let speed = Connector::to_node(host, "speed".to_owned(), Some(member_badge.clone()))
        .open_service(&member)
        .await
        .expect("a member reaches the offered speed");
    let report = Speedtest::new(Mode::Bidir, Limit::ByBytes(1 << 16))
        .run(&speed)
        .await
        .expect("a member's speedtest runs against a speed-only node");
    assert!(
        report.up().is_some_and(|leg| leg.bytes() > 0),
        "the speed-only node moves bytes"
    );

    // The member's PING does not succeed against a speed-only node: `ping` resolves to the sole offered
    // `speed`, whose handler refuses the ping frame at the wire with a typed `Response::Unsupported`
    // before echoing. The client decodes that to `ProtocolError::Refused` and short-circuits: a refusal
    // is a LOUD error, NEVER a `100% loss` report. (This test used to enshrine the bug by asserting
    // `received() == 0`.)
    let ping = Connector::to_node(host, "ping".to_owned(), Some(member_badge))
        .open_service(&member)
        .await
        .expect("the base connect lands; the offered service is resolved per-stream");
    let refused = Ping {
        count: 3,
        interval: Duration::ZERO,
    }
    .run(&ping)
    .await;
    assert!(
        matches!(refused, Err(ProtocolError::Refused(_))),
        "a node offering only speed must REFUSE ping loudly, not report 100% loss: {refused:?}"
    );

    // The stranger reaches neither.
    assert_stranger_refused(host).await;
}

/// Spawn a person-zero node exposing exactly `services`, gated on its own self-signet through the shared
/// `registry()` and `resolve_gate` policy, and return its node id. The registry always holds both the ping
/// and speed handlers; `services` is what this node OFFERS.
async fn expose(services: &[String]) -> NodeId {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let self_signet = NodeId::from_ed25519_secret(&SELF_SECRET);
    let services = Services::parse(services).unwrap();
    tokio::task::spawn_local(async move {
        let gate = tunnel::resolve_gate(Some(self_signet), empty_denylist("offer").await).unwrap();
        let registry = swoosh::commands::serve::registry(HOST_SEED, std::env::temp_dir()).unwrap();
        Exposer::new(services, registry, gate, PublicUnsafeRequest::none())
            .unwrap()
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });
    host_id
}

/// A stranger (a badge rooted at a key the self-gate never trusted) is refused at BOTH services: the
/// per-service member-admitted / stranger-refused invariant. Its probes error at the gate, never answered.
async fn assert_stranger_refused(host: NodeId) {
    let stranger = Node::new(MemTransport::bind(), NoDiscovery);
    let stranger_badge = self_badge(&[3u8; 32], stranger.node_id());

    let ping = Connector::to_node(host, "ping".to_owned(), Some(stranger_badge.clone()))
        .open_service(&stranger)
        .await
        .expect("the base connect lands; the gate refuses per-stream");
    let refused = Ping {
        count: 1,
        interval: Duration::ZERO,
    }
    .run(&ping)
    .await;
    assert!(refused.is_err(), "a stranger cannot ping the node");

    let speed = Connector::to_node(host, "speed".to_owned(), Some(stranger_badge))
        .open_service(&stranger)
        .await
        .expect("the base connect lands; the gate refuses per-stream");
    let refused = Speedtest::new(Mode::Down, Limit::ByBytes(1 << 16))
        .run(&speed)
        .await;
    assert!(refused.is_err(), "a stranger cannot speedtest the node");
}

/// Mint a membership badge signed by `secret`, bound to `bound` (the dialer's proven mem node id): a
/// `member(true)` badge rooted at the signing key. A badge rooted at the node's OWN key admits at its
/// self-gate; one rooted at a stranger key is refused. Signed here (not via mint/adopt) so it binds to the
/// mem transport's synthetic proven id; see the module note and `gated_measure.rs`.
fn self_badge(secret: &[u8; 32], bound: NodeId) -> String {
    Identity::from_secret(secret)
        .unwrap()
        .mint_member(
            bound.verify_key(),
            nauthy::Request::expires_in(Duration::from_secs(300)),
        )
        .unwrap()
        .seal()
        .unwrap()
        .link()
        .unwrap()
}

/// An empty revocation denylist: these tests exercise membership admission, not revocation, so the gate
/// loads from a path that does not exist (an absent file is an empty set). `tag` keeps parallel paths apart.
async fn empty_denylist(tag: &str) -> FileDenylist {
    let path =
        std::env::temp_dir().join(format!("swoosh-split-measure-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    FileDenylist::load(path).await.unwrap()
}
