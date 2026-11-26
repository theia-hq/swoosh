// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! A node's served list, end to end over the in-process transport: a MEMBER asking `control.serve` for its
//! list reads exactly the services the node serves, each with its gate posture.
//!
//! The node is assembled through the SAME `control::bind_serve` the `swoosh serve` product path calls, over
//! the SAME `Router::catalog` snapshot it cuts. Who may ask, and every other answer of the route, are
//! `gated_serve`'s.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a membership badge binds to whatever
//! id the mem transport proves for the dialer (the same accommodation `gated_stop` documents): the badge is
//! signed here bound to the member's mem node id.

use core::time::Duration;
use std::sync::Arc;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use swoosh::home::Home;
use swoosh::serve::control::{self, Answer};
use swoosh::serve::{CONTROL_SERVE_SERVICE, StopSource};
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::tunnel::{CancellationToken, Connector, Exposer, Posture, Router, ServiceCatalog};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The byte the signet's fixed key is seeded with; its ed25519 public half is the signet the family gate
/// trusts.
const SIGNET: u8 = 7;

/// The services this proof's node serves, beyond its own `control.serve`. Raw socket forwards (a real
/// served kind that needs no injected handler), so the exposer builds from just `control.serve` while the
/// catalog still lists these by name: the list reflects what the node serves, not what the test happened
/// to register.
const SERVED: [&str; 3] = [
    "web=tcp:127.0.0.1:8080",
    "db=tcp:127.0.0.1:5432",
    "api=tcp:127.0.0.1:9000",
];

/// An ADMITTED member asking `control.serve` for its list reads the node's served list: `Done`, then a
/// catalog naming exactly the served names and `control.serve`, each `gated` on this gated node.
#[tokio::test]
async fn a_member_reads_a_gated_nodes_services_over_control_serve() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let cancel = CancellationToken::new();
            let (exposer, home) = build_exposer().await;
            let run = tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });

            // A member: a badge the signet signed, rooted at the trusted signet and bound to the member's
            // proven mem id, so the gate admits it (the shape `mint` mints for a device).
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
            let (mut send, mut recv) = session
                .open_bi()
                .await
                .expect("a member is admitted at control.serve");
            send.write_all(&[control::Request::List.encode()])
                .await
                .unwrap();
            send.shutdown().await.unwrap();

            let mut answer = Vec::new();
            recv.read_to_end(&mut answer)
                .await
                .expect("read the list's answer");
            let (code, blob) = answer.split_first().expect("an answer byte");
            assert_eq!(*code, Answer::Done.encode());
            let catalog = ServiceCatalog::decode(blob).expect("the served catalog decodes");

            let names: Vec<&str> = catalog.entries().map(|entry| entry.name.as_str()).collect();
            assert_eq!(
                names,
                ["api", "control.serve", "db", "web"],
                "the list is exactly the served names, name-sorted"
            );
            assert!(
                catalog
                    .entries()
                    .all(|entry| entry.posture == Posture::Gated),
                "every service on a gated node reports the gated posture: {catalog:?}"
            );

            // Stop the node so the test ends, and remove the gate's scratch home.
            drop(recv);
            run.abort();
            let _ = std::fs::remove_dir_all(home.dir());
        })
        .await;
}

/// Assemble a gated exposer rooted at the signet serving the raw forwards and `control.serve`, bound through
/// the SAME `control::bind_serve` the product `serve` path calls, which cuts the catalog from the route
/// table exactly as `run_serve` does. The scratch home the gate reads is the caller's to remove.
async fn build_exposer() -> (Exposer, Home) {
    let (gate, cut, home) = swoosh::testkit::admitting(
        TestRoot::seeded(SIGNET).node_id(),
        TestNode::seeded(SIGNET + 2).node_id(),
    )
    .await;
    let mut router = Router::new(gate);
    for entry in SERVED {
        router = router.parse(&[entry.to_owned()]).unwrap();
    }
    let (router, _catalog, _first_round) = control::bind_serve(
        router,
        CancellationToken::new(),
        Arc::new(StopSource::new()),
        &cut,
    )
    .unwrap();
    (router.expose().unwrap(), home)
}

/// Mint a membership badge signed by the key `signer` seeds, bound to `bound` (the dialer's proven node id):
/// the shape a signet holder self-signs and `mint` mints for a device. Signed here (not via invite/join) so
/// it binds to the mem proven id.
fn signet_badge(signer: u8, bound: NodeId) -> String {
    TestRoot::seeded(signer)
        .device_badge(bound, nauthy::Request::expires_in(Duration::from_secs(300)))
        .unwrap()
        .to_string()
}
