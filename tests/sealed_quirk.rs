// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The sealed wrapper at swoosh's composition root: a gated dial over `Noise<Quirk>` on loopback.
//!
//! quirk declares `Announced` and moves plaintext bytes on one stream; wrapped in `Noise`, the same
//! endpoint declares `Sealed` and its peer is proven by a Noise handshake. This test composes that
//! exactly as `swoosh --transport quirk+noise` does: quirk bound under a 32-byte seed, wrapped by a
//! `Noise::new` carrying the same seed, paired with the composed `PeerHint` discovery, and served by
//! the SAME `diagnostics` assembly and rooted gate `swoosh serve` binds.
//!
//! The member's badge is minted the way `swoosh mint` mints one (signet-rooted, bound to the device's
//! derived `NodeId`), and the wrapper proves exactly that `NodeId`, so the gate's bound-device check
//! admits over real keys rather than over a synthetic test id. The load-bearing half sits beside it:
//! the rooted gate arms over the wrapper and REFUSES the bare, announced inner, so `quirk` alone still
//! cannot carry a credential.

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId};
use bifrost_noise::Noise;
use bifrost_quirk::Endpoint;
use measure::Ping;
use nauthy::{FileDenylist, Identity};
use swoosh::transport::PeerHint;
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Router};

/// The signet's fixed secret; its ed25519 public half is the signet the family gate trusts, and it roots
/// every membership badge minted here.
const SIGNET_SECRET: [u8; 32] = [7u8; 32];

/// The ssh host-key seed the exposer's route table carries. Unused by this test (it exercises `ping`, not
/// `sshd`), but the shared `diagnostics` helper derives `sshd` from it, so a fixed value keeps the build stable.
const HOST_SEED: [u8; 32] = [9u8; 32];

/// A fixed 32-byte identity seed, so each end binds and wraps under one deterministic `NodeId`.
fn seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Bind a quirk endpoint under `byte`'s seed and wrap it with the SAME seed, the composition
/// `--transport quirk+noise` performs: one address, one identity, two layers.
async fn sealed(byte: u8) -> Noise<Endpoint> {
    let inner = Endpoint::bind_with_secret(seed(byte))
        .await
        .expect("bind quirk on loopback");
    Noise::new(inner, seed(byte)).expect("wrap quirk under its own identity")
}

/// A membership badge the signet signed and bound to `bound`, the shape `swoosh mint` mints for a device
/// and the signet holder self-signs. The gate trusts the signet root and checks the binding against the
/// session's proven peer, so over the wrapper this is the real device-badge path.
fn signet_badge(bound: NodeId) -> String {
    Identity::from_secret(&SIGNET_SECRET)
        .expect("the signet identity")
        .mint_member(
            bound.verify_key(),
            nauthy::Request::expires_in(Duration::from_secs(300)),
        )
        .expect("mint a member badge")
        .seal()
        .expect("seal the badge")
        .link()
        .expect("render the badge link")
        .to_string()
}

/// An empty revocation denylist: this test exercises membership admission, not revocation, so the gate
/// loads from a path that does not exist (an absent file is an empty set). `tag` keeps parallel tests'
/// paths apart.
async fn empty_denylist(tag: &str) -> FileDenylist {
    let path =
        std::env::temp_dir().join(format!("swoosh-sealed-quirk-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    FileDenylist::load(path)
        .await
        .expect("load the empty denylist")
}

/// The rooted gate both cases share: the same assembly `swoosh serve` binds for its diagnostics.
async fn gated_exposer(tag: &str) -> tightbeam::tunnel::Exposer {
    let signet = NodeId::from_ed25519_secret(&SIGNET_SECRET);
    let gate = tunnel::resolve_gate(Some(signet), empty_denylist(tag).await)
        .expect("the signet-rooted gate resolves");
    swoosh::commands::serve::diagnostics(Router::new(gate), HOST_SEED, &[])
        .expect("the diagnostics routes bind")
        .expose()
        .expect("the exposer assembles")
}

/// A member's gated ping rides the sealed wrapper on loopback: the dial reaches the node, the gate
/// admits the signet-bound badge against the wrapper-proven `NodeId`, and every probe answers.
#[tokio::test]
async fn a_gated_dial_rides_the_sealed_wrapper_over_loopback_quirk() {
    let receiver = sealed(31).await;
    let host = Node::new(receiver, NoDiscovery);
    let host_id = host.node_id();
    let addr = host.local_addr();
    let exposer = gated_exposer("dial").await;

    // The member: quirk under the wrapper, paired with the composed discovery the composition root
    // builds, carrying the receiver's direct address as a `--peer` hint.
    let member_transport = sealed(32).await;
    let hint: PeerHint = format!("{host_id}={}", addr.hints[0])
        .parse()
        .expect("the direct hint parses");
    let discovery = PeerHint::discovery(&member_transport, [hint]).discovery;
    let member = Node::new(member_transport, discovery);
    let badge = signet_badge(member.node_id());

    let cancel = CancellationToken::new();
    // The exposer arms (its own `run` repeats the profile refusal) and serves while the member dials.
    // `join!`, not `spawn`: this stays on the test task, so no `Send` bound is imposed on the exposer.
    // The timeout fails a broken composition fast: quirk's connect carries no deadline of its own.
    let serving = exposer.run(&host, cancel.clone());
    let dialing = async {
        let session = Connector::to_node(
            host_id,
            "ping".parse().expect("the ping service name"),
            Some(badge.parse().expect("the badge link")),
        )
        .open_service(&member)
        .await
        .expect("the gated dial rides the sealed wrapper");
        let report = Ping {
            count: 3,
            interval: Duration::ZERO,
        }
        .run(&session)
        .await
        .expect("the gated ping runs over the wrapper");
        assert_eq!(report.received(), 3, "every probe answers over the wrapper");
        assert_eq!(
            report.loss(),
            0.0,
            "the gated ping over the wrapper loses nothing"
        );
        cancel.cancel();
    };
    let (served, ()) = tokio::join!(serving, async {
        tokio::time::timeout(Duration::from_secs(10), dialing)
            .await
            .expect("the member completes its gated dial within the deadline");
    });
    served.expect("the exposer ends Ok once the member finishes");
}

/// The enforcement holds at the composition seam: a signet-rooted gate arms over `Noise<Quirk>` (the
/// wrapper's own handshake earns the profile) and REFUSES bare quirk, whose key is only announced.
#[tokio::test]
async fn a_rooted_gate_refuses_to_arm_over_bare_quirk() {
    let exposer = gated_exposer("refusal").await;

    exposer
        .prove_security::<Noise<Endpoint>>()
        .expect("the wrapper proves the peer, so the rooted gate arms over it");
    let refused = exposer
        .prove_security::<Endpoint>()
        .expect_err("bare quirk announces its key, so the rooted gate must refuse to arm");
    let message = format!("{refused:#}");
    assert!(
        message.contains("announced"),
        "the refusal names the announced profile: {message}"
    );
}
