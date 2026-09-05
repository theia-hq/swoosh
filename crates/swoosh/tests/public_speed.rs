// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The flagship delib-39 proof, end to end over the in-process transport: a per-service `--public speed`
//! node admits a STRANGER (no badge) to `speed` while every other service stays family-gated. This is the
//! `swoosh serve --public speed` scenario that shipped BROKEN (a node-wide open gate died on the always-on
//! `control.stop`); per-service exposure is the fix, and a live run certifies it, not a code read.
//!
//! One node serves `ping` (gated), `speed` (opened via `--public speed`), and the always-on `control.stop`
//! (never openable), assembled through the SAME `registry()` the product `serve` path builds and opened
//! through the SAME `Exposer::with_public` wall. A STRANGER presenting no capability at all is ADMITTED to
//! `speed` (a real speedtest moves bytes) but REFUSED at `ping` and at `control.stop`, byte-uniformly. The
//! refusals are the load-bearing half: opening `speed` leaks nothing about the gated services, and the
//! control surface can never be opened.

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use measure::{Limit, Mode, Ping, Speedtest};
use nauthy::Denylist;
use swoosh::commands::serve::{CONTROL_STOP_SERVICE, Stop};
use tightbeam::tunnel::{
    self, CancellationToken, Connector, Exposer, PublicRequest, PublicUnsafeRequest, Services,
};

/// The signet's fixed secret: its public half is the family the gate trusts. No badge here is rooted at it,
/// because the whole point is that a STRANGER (rooted nowhere the gate trusts) still reaches the OPEN service.
const SIGNET_SECRET: [u8; 32] = [7u8; 32];

/// The ssh host-key seed the shared `registry()` derives `sshd` from. Unused by this test (it exercises the
/// measure services + control.stop), but a fixed value keeps the build stable with and without the feature.
const HOST_SEED: [u8; 32] = [9u8; 32];

/// Run the proof on a worker thread with a generous stack: over mem a bidir speedtest nests several 64 KiB
/// chunk buffers on one LocalSet thread, which can exceed the default stack (see `gated_measure.rs`).
#[test]
fn a_public_speed_node_admits_a_stranger_to_speed_but_refuses_ping_and_control_stop() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
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

async fn proof() {
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let signet = NodeId::from_ed25519_secret(&SIGNET_SECRET);

    tokio::task::spawn_local(async move {
        // The services a `swoosh serve speed --public speed` node carries: the gated `ping`, the opened
        // `speed`, and the always-on gated `control.stop` every node answers.
        let requested = vec![
            "ping=ping:".to_owned(),
            "speed=speed:".to_owned(),
            format!("{CONTROL_STOP_SERVICE}={CONTROL_STOP_SERVICE}:"),
        ];
        let services = Services::parse(&requested).unwrap();
        let gate = tunnel::resolve_gate(Some(signet), empty_denylist("host").await).unwrap();
        let registry = swoosh::commands::serve::registry(HOST_SEED, std::env::temp_dir())
            .unwrap()
            .with(CONTROL_STOP_SERVICE, Stop::new(CancellationToken::new()));
        // `--public speed` SUCCEEDS: `speed` is OptIn (openable), and `control.stop` (Never) is left gated by
        // set non-membership, so `with_public` does not refuse the node. This is the build that used to die.
        let exposer = Exposer::new(services, registry, gate, PublicUnsafeRequest::none())
            .unwrap()
            .with_public(PublicRequest::new(["speed".to_owned()]))
            .expect("`--public speed` builds: speed is openable, control.stop stays gated");
        exposer.run(&host, CancellationToken::new()).await.unwrap();
    });

    // A STRANGER: a fresh node presenting NO capability. Over the opened `speed` service the gate admits it,
    // and a real speedtest moves bytes both ways: the flagship scenario now works.
    let stranger = Node::new(MemTransport::bind(), NoDiscovery);
    let speed = Connector::to_node(host_id, "speed".to_owned(), None)
        .open_service(&stranger)
        .await
        .expect("a stranger reaches the opened speed service");
    let report = Speedtest::new(Mode::Bidir, Limit::ByBytes(1 << 16))
        .run(&speed)
        .await
        .expect("a stranger's speedtest runs over the OPENED speed service");
    assert!(
        report.up().is_some_and(|leg| leg.bytes() > 0)
            && report.down().is_some_and(|leg| leg.bytes() > 0),
        "the opened speed service moves bytes for an anonymous stranger"
    );

    // The same stranger is REFUSED at the still-gated `ping`: opening `speed` opened nothing else.
    let ping = Connector::to_node(host_id, "ping".to_owned(), None)
        .open_service(&stranger)
        .await
        .expect("the base connect lands; the gate refuses per-stream");
    let refused = Ping {
        count: 1,
        interval: Duration::ZERO,
    }
    .run(&ping)
    .await;
    assert!(
        refused.is_err(),
        "a stranger must still be refused at the gated ping service: {refused:?}"
    );

    // And REFUSED at the always-on `control.stop`: the control surface can never be opened, so a stranger
    // cannot stop this node. The refusal surfaces as the ServiceSession's own stream error.
    let control = Connector::to_node(host_id, CONTROL_STOP_SERVICE.to_owned(), None)
        .open_service(&stranger)
        .await
        .expect("the base connect lands; the gate refuses per-stream");
    assert!(
        control.open_bi().await.is_err(),
        "a stranger must be refused at the always-on control.stop, even on a --public node"
    );
}

/// An empty revocation denylist: this test exercises admission, not revocation, so the gate loads from a
/// path that does not exist (an absent file is an empty set). `tag` keeps parallel tests' paths apart.
async fn empty_denylist(tag: &str) -> Denylist {
    let path =
        std::env::temp_dir().join(format!("swoosh-public-speed-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Denylist::load(path).await.unwrap()
}
