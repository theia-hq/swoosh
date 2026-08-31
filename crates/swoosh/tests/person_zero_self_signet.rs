// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Person-zero self-signet, end to end over the in-process transport: the security proof that a node with
//! its OWN key but NO provisioned signet gates on ITSELF. A plain `swoosh serve` (no `adopt`, no `--public`)
//! self-trusts: it admits its own self-signed member badge (rooted at this node's key) and refuses a
//! STRANGER (a badge rooted at any other key). This is what lets a plain node answer its own gated
//! `ping`/`speed` without opening to the world. These are TWO independent services, so the proof
//! runs ping over `ping` and speed over `speed`; self-gating walls each independently.
//!
//! The composition root supplies the gate root: when `config::load_signet` finds no `signet` file, `serve`
//! passes the node's OWN id to `resolve_gate` (proved at the seam by
//! `serve_with_no_signet_gates_on_the_nodes_own_key` in `main.rs`). So here the gate is built through the
//! SAME `resolve_gate` policy with the signet root set to the node's OWN identity key K -- exactly the value
//! the product path derives from `secret.node_id()` when nothing was adopted. A client whose member badge is
//! rooted at K (the node itself, or a device K later signs) is admitted; a client whose badge roots at a
//! random key is REFUSED. The stranger-refused case is the load-bearing proof: self-gating is not open.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a badge binds to whatever id the mem
//! transport proves for the dialer -- NOT to a device's derived ed25519 key. That is why the member badge is
//! signed here, bound to the member's mem node id, rather than run through the real self-sign path (which
//! binds to swoosh's ed25519 id, unequal to a mem proven id). This mirrors the accommodation documented in
//! `gated_diag.rs`; what it proves is that a self-rooted gate admits a badge rooted at K and refuses one that
//! is not. `device_badge_wiring.rs` proves `mint`/`adopt` actually produce and store the device credential.

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId};
use bifrost_mem::MemTransport;
use diag::{Limit, Mode, Ping, Speedtest};
use nauthy::{Denylist, Identity};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, Connector, Exposer, Services};

/// The person-zero node's OWN secret. Its ed25519 public half is BOTH the node's identity key AND the signet
/// root its self-gate trusts, because a person-zero node IS its own signet root. This is the value the
/// composition root derives from `secret.node_id()` when no signet file was ever written.
const SELF_SECRET: [u8; 32] = [11u8; 32];

/// The ssh host-key seed the exposer's registry carries. Unused by this test (it exercises `diag`, not
/// `sshd`), but the shared `registry()` derives `sshd` from it, so a fixed value keeps the build stable.
const HOST_SEED: [u8; 32] = [9u8; 32];

/// Run the proof on a worker thread with a generous stack, for the same reason as `gated_diag.rs`: diag's
/// transfer engine holds a 64 KiB chunk buffer per direction on the stack, and over mem both sides run on
/// one LocalSet thread, so a bidir speedtest nests several at once. An 8 MiB thread keeps that safe.
#[test]
fn a_person_zero_node_admits_itself_and_refuses_a_stranger() {
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

/// The proof body: a person-zero node self-gates on its OWN key, admits a member rooted at that key
/// (ping + speed), and refuses a stranger.
async fn proof() {
    {
        // The person-zero exposer node: it serves `ping`/`speed` behind a family gate rooted at its OWN key (no
        // provisioned signet, no `--public`), assembled through the SAME `resolve_gate` policy and
        // `registry()` the product `serve` path uses. `self_signet` is the id the composition root supplies
        // from `secret.node_id()` when `load_signet` returns `None`.
        let host = Node::new(MemTransport::bind(), NoDiscovery);
        let host_id = host.node_id();
        let self_signet = NodeId::from_ed25519_secret(&SELF_SECRET);
        tokio::task::spawn_local(async move {
            let services =
                Services::parse(&["ping=ping:".to_owned(), "speed=speed:".to_owned()]).unwrap();
            // Person-zero self-signet: the gate roots at the node's OWN key, exactly as
            // `resolve_gate(false, Some(secret.node_id()), ...)` builds it when nothing was adopted.
            let gate = tunnel::resolve_gate(false, Some(self_signet), empty_denylist("self").await)
                .unwrap();
            let registry = swoosh::commands::serve::registry(HOST_SEED).unwrap();
            Exposer::new(services, registry, gate)
                .unwrap()
                .run(&host)
                .await
                .unwrap();
        });

        // ITSELF (a member rooted at K): a badge signed by the node's OWN key, bound to the dialer's proven
        // mem id. This is the shape `member_badge` self-signs for the signet holder -- rooted at K,
        // member(true), bound to the dialer -- and the shape a device K adopts carries. Because the gate
        // trusts K and the binding matches the proven dialer, it admits.
        let member = Node::new(MemTransport::bind(), NoDiscovery);
        let member_badge = self_badge(&SELF_SECRET, member.node_id());

        // Ping over the gated `ping` service: the round trip proves the self-gate admits a member.
        let diag = Connector::to_node(host_id, "ping".to_owned(), Some(member_badge.clone()))
            .open_service(&member)
            .await
            .expect("a member reaches the person-zero node's gated ping");
        let report = Ping {
            count: 3,
            interval: Duration::ZERO,
        }
        .run(&diag)
        .await
        .expect("member ping runs over the self-gated ping service");
        assert_eq!(report.received(), 3, "a member's every probe is answered");
        assert_eq!(
            report.loss(),
            0.0,
            "a member's self-gated ping loses nothing"
        );

        // Speedtest over the gated `speed` service: bytes move both ways, so the self-gate admits the
        // transfer stream too, not just a ping.
        let diag = Connector::to_node(host_id, "speed".to_owned(), Some(member_badge))
            .open_service(&member)
            .await
            .expect("a member reaches the self-gated speed service");
        let speed = Speedtest::new(Mode::Bidir, Limit::ByBytes(1 << 16))
            .run(&diag)
            .await
            .expect("member speedtest runs over the self-gated speed service");
        assert!(
            speed.up().is_some_and(|leg| leg.bytes() > 0),
            "a member's self-gated speedtest moves upload bytes"
        );
        assert!(
            speed.down().is_some_and(|leg| leg.bytes() > 0),
            "a member's self-gated speedtest moves download bytes"
        );

        // A STRANGER: a badge rooted at a RANDOM key the self-gate has never trusted (not K), bound to its
        // own proven id. It roots at a non-K key, so the family gate rejects it no matter the binding: a
        // stranger cannot reach a self-gating node. THIS is the load-bearing proof that self-gating is not
        // an open door.
        let stranger = Node::new(MemTransport::bind(), NoDiscovery);
        let stranger_badge = self_badge(&[3u8; 32], stranger.node_id());

        // Refused at ping: the ping ERRORS (the gate refuses the stream), it does not hang or succeed.
        let diag = Connector::to_node(host_id, "ping".to_owned(), Some(stranger_badge.clone()))
            .open_service(&stranger)
            .await
            .expect("the base connect lands; the gate refuses per-stream");
        let refused = Ping {
            count: 1,
            interval: Duration::ZERO,
        }
        .run(&diag)
        .await;
        assert!(
            refused.is_err(),
            "a stranger's ping must be refused at a person-zero node's gated ping, not answered"
        );

        // Refused at speed too: a stranger cannot speedtest a self-gating node.
        let diag = Connector::to_node(host_id, "speed".to_owned(), Some(stranger_badge))
            .open_service(&stranger)
            .await
            .expect("the base connect lands; the gate refuses per-stream");
        let refused = Speedtest::new(Mode::Down, Limit::ByBytes(1 << 16))
            .run(&diag)
            .await;
        assert!(
            refused.is_err(),
            "a stranger's speedtest must be refused at a person-zero node's gated speed"
        );
    }
}

/// Mint a membership badge signed by `secret`, bound to `bound` (the dialer's proven node id): a
/// `member(true)` badge rooted at the signing key. When `secret` is the node's OWN key K, this is the
/// self-sign the signet holder produces (`identity::Secret::member_badge`); a badge rooted at K admits at a
/// K-rooted gate, and one rooted at a stranger key is refused. Signed here (not via the real self-sign path)
/// so it binds to the mem transport's synthetic proven id; see the module note.
fn self_badge(secret: &[u8; 32], bound: NodeId) -> String {
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

/// An empty revocation denylist: this test exercises membership admission, not revocation, so the gate loads
/// from a path that does not exist (an absent file is an empty set). `tag` keeps parallel tests' paths apart.
async fn empty_denylist(tag: &str) -> Denylist {
    let path =
        std::env::temp_dir().join(format!("swoosh-person-zero-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Denylist::load(path).await.unwrap()
}
