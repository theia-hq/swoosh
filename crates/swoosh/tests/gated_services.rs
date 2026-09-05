// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The node-lifecycle READ, end to end over the in-process transport: the proof that `control.services`
//! rides the family gate, so a MEMBER can read a gated node's served list but a STRANGER cannot.
//!
//! `control.services` is one more family-gated service, assembled through the SAME `ServiceList` handler the
//! `swoosh serve` product path injects (not a hand-rolled near-copy), over the SAME `Services::catalog`
//! snapshot `serve` cuts. Two things are proven:
//!
//! 1. `control.services`: a MEMBER reaching the gated service reads the self-delimiting catalog blob, decodes
//!    it, and sees exactly the served names with their gate posture (every service gated on this gated node).
//! 2. A STRANGER's `control.services` is refused LOUDLY at the gate (a typed error, never a silent empty
//!    read), so the service menu never leaks to a non-member.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a membership badge binds to whatever
//! id the mem transport proves for the dialer (the same accommodation `gated_stop` documents): the badge is
//! signed here bound to the member's mem node id, proving the GATE admits a signet-rooted bound badge and
//! refuses a non-signet one, the load-bearing stranger case for a read.

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::{Denylist, Identity};
use swoosh::commands::serve::{CONTROL_SERVICES_SERVICE, ServiceList};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{
    self, CancellationToken, Connector, Exposer, Posture, PublicRequest, PublicUnsafeRequest,
    Registry, ServiceCatalog, Services,
};
use tokio::io::AsyncReadExt as _;

/// The signet's fixed secret; its ed25519 public half is the signet the family gate trusts.
const SIGNET_SECRET: [u8; 32] = [7u8; 32];

/// The services this proof's node serves, beyond the always-on `control.services` read itself. Raw socket
/// forwards (a real served kind that needs no injected handler), so the exposer builds from just the
/// `control.services` handler while the catalog still lists these by name: the read reflects what the node
/// serves, not what the test happened to register.
const SERVED: [&str; 3] = [
    "web=127.0.0.1:8080",
    "db=127.0.0.1:5432",
    "api=127.0.0.1:9000",
];

/// An ADMITTED member reaching `control.services` reads the node's served list: it decodes the catalog blob
/// and sees exactly the served names, each `gated` on this gated node.
#[tokio::test]
async fn a_member_reads_a_gated_nodes_services_over_control_services() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let cancel = CancellationToken::new();
            let exposer = build_exposer().await;
            let run = tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });

            // A member: a badge the signet signed, rooted at the trusted signet and bound to the member's
            // proven mem id, so the gate admits it (the shape `mint` mints for a device).
            let member = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(&SIGNET_SECRET, member.node_id());
            let session =
                Connector::to_node(host_id, CONTROL_SERVICES_SERVICE.to_owned(), Some(badge))
                    .open_service(&member)
                    .await
                    .expect("member reaches control.services");
            let (send, mut recv) = session
                .open_bi()
                .await
                .expect("a member is admitted at the gated control.services read");
            // The read sends nothing; drop the write half so the handler's write completes (the client verb
            // does exactly this).
            drop(send);

            let mut bytes = Vec::new();
            recv.read_to_end(&mut bytes)
                .await
                .expect("read the catalog blob");
            let catalog = ServiceCatalog::decode(&bytes).expect("the served catalog decodes");

            let names: Vec<&str> = catalog.entries().map(|entry| entry.name.as_str()).collect();
            assert_eq!(
                names,
                ["api", "control.services", "db", "web"],
                "the read returns exactly the served names, name-sorted"
            );
            assert!(
                catalog
                    .entries()
                    .all(|entry| entry.posture == Posture::Gated),
                "every service on a gated node reports the gated posture: {catalog:?}"
            );

            // Stop the node so the test ends.
            drop(recv);
            run.abort();
        })
        .await;
}

/// A STRANGER (a badge rooted at a key the gate has never seen) is refused at `control.services`, LOUDLY: a
/// typed stream error, never a silent empty read. The service menu never leaks to a non-member.
#[tokio::test]
async fn a_stranger_is_refused_at_control_services() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let host = Node::new(MemTransport::bind(), NoDiscovery);
            let host_id = host.node_id();
            let cancel = CancellationToken::new();
            let exposer = build_exposer().await;
            let run = tokio::task::spawn_local(async move { exposer.run(&host, cancel).await });

            // A stranger: a self-signed badge rooted at a RANDOM key the gate never trusts.
            let stranger = Node::new(MemTransport::bind(), NoDiscovery);
            let badge = signet_badge(&[3u8; 32], stranger.node_id());
            let session =
                Connector::to_node(host_id, CONTROL_SERVICES_SERVICE.to_owned(), Some(badge))
                    .open_service(&stranger)
                    .await
                    .expect("the base connect lands; the gate refuses per-stream");
            let refused = session.open_bi().await;
            assert!(
                refused.is_err(),
                "a stranger's control.services must be refused at the gate, not admitted: {refused:?}"
            );

            run.abort();
        })
        .await;
}

/// Assemble a gated exposer serving `control.services` (over the served menu) rooted at the signet, through
/// the SAME `ServiceList` handler + `Services::catalog` snapshot the product `serve` path builds. The
/// catalog is cut from the parsed services and the resolved gate, exactly as `run_serve` does.
async fn build_exposer() -> Exposer {
    let signet = NodeId::from_ed25519_secret(&SIGNET_SECRET);
    let mut requested: Vec<String> = SERVED.iter().map(|s| (*s).to_owned()).collect();
    requested.push(format!(
        "{CONTROL_SERVICES_SERVICE}={CONTROL_SERVICES_SERVICE}:"
    ));
    let services = Services::parse(&requested).unwrap();
    let gate = tunnel::resolve_gate(Some(signet), empty_denylist().await).unwrap();
    let catalog = services.catalog(&gate, &PublicRequest::none(), &PublicUnsafeRequest::none());
    // The served menu is raw socket forwards (no injected handler), so the registry holds just the
    // `control.services` read handler over the catalog snapshot. `Exposer::new` only requires a registered
    // handler for HANDLER-scheme services; a forward needs none, and the only stream this proof dials is the
    // read itself.
    let registry = Registry::new().with(CONTROL_SERVICES_SERVICE, ServiceList::new(catalog));
    Exposer::new(services, registry, gate, PublicUnsafeRequest::none()).unwrap()
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
    let path = std::env::temp_dir().join(format!("swoosh-gated-services-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Denylist::load(path).await.unwrap()
}
