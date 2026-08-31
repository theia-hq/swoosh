// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The gated `diag:` client, end to end over the in-process transport: the security proof that a diagnostic
//! (`ping`/`speed`) rides the family gate, so a MEMBER can measure a gated node but a STRANGER cannot.
//!
//! One node exposes `ssh`/`fetch`/`diag` under a family gate rooted at a signet, assembled through the SAME
//! `registry()` the `swoosh serve` / `swoosh tunnel expose` product path builds, so this test exercises the
//! identical registry swoosh serves rather than a hand-rolled near-copy. A client that dials under the
//! signet's own key self-signs a membership badge the gate admits: it pings the node (a round trip), speed-
//! tests it (bytes move both ways), and is admitted at `fetch`. A client under a RANDOM key self-signs a
//! badge that roots at that stranger key, which the gate has never seen, so it is REFUSED at `diag` (its
//! ping errors, not hangs, not succeeds) and equally at `fetch`. The stranger-refused case is the load-
//! bearing proof: a stranger cannot ping, speedtest, or fetch a gated node.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a badge must bind to whatever id the
//! mem transport proves for the dialer -- NOT to a device's derived ed25519 key. That is why this test
//! signs the member's badge here, bound to the member's mem node id: the real `mint`/`adopt` path binds a
//! badge to the DEVICE's derived key, which cannot equal the mem transport's synthetic proven id, so an
//! honest device-adopt-then-DIAL run is not expressible over `mem`. This is a deliberate, documented
//! accommodation, not a paper-over: what this test proves is that the family GATE admits a signet-rooted,
//! bound badge for the proven dialer and REFUSES a non-signet-rooted one (the load-bearing stranger case).
//! What it does NOT prove is that `mint`/`adopt` produce and store that badge for a device -- that is the
//! job of `device_badge_wiring.rs` (the real mint -> adopt -> stored-badge -> verify-at-signet-root proof),
//! and the true second-device-reaches-a-gated-service demo is the Operator's live quirk run (bifrost-quirk
//! carries real ed25519 ids, so the device's derived key IS its proven id there).

use core::time::Duration;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use diag::{Limit, Mode, Ping, Speedtest};
use nauthy::{Denylist, Identity};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, Connector, Exposer, Services};

/// The signet's fixed secret. Its ed25519 public half is the signet the family gate trusts, and it roots
/// every membership badge minted here.
const SIGNET_SECRET: [u8; 32] = [7u8; 32];

/// The ssh host-key seed the exposer's registry carries. Unused by this test (it exercises `diag`/`fetch`,
/// not `sshd`), but the shared `registry()` derives `sshd` from it, so a fixed value keeps the build stable.
const HOST_SEED: [u8; 32] = [9u8; 32];

/// Run the proof on a worker thread with a generous stack. diag's transfer engine holds a 64 KiB chunk
/// buffer on the stack per direction (`payload::CHUNK`); over mem, client and responder run on ONE
/// LocalSet thread, so a bidir speedtest nests several of those at once. That is fine over the real
/// transports (each side spawns), but on a test thread it can exceed the default stack, so this drives the
/// runtime on an 8 MiB thread. A plain `#[tokio::test]` cannot size its worker stack.
#[test]
fn a_member_pings_speeds_and_fetches_a_gated_node_a_stranger_is_refused() {
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

/// The proof body: expose a gated node, admit a member (ping + speed + fetch), refuse a stranger.
async fn proof() {
    {
        // The exposer node, serving ssh/fetch/diag behind a family gate rooted at the signet, through
        // the SAME registry the product `serve`/`tunnel expose` path assembles.
        let host = Node::new(MemTransport::bind(), NoDiscovery);
        let host_id = host.node_id();
        let signet = NodeId::from_ed25519_secret(&SIGNET_SECRET);
        tokio::task::spawn_local(async move {
            let services = Services::parse(&[
                "ssh=sshd:".to_owned(),
                "fetch=fetch:".to_owned(),
                "diag=diag:".to_owned(),
            ])
            .unwrap();
            let gate =
                tunnel::resolve_gate(false, Some(signet), empty_denylist("host").await).unwrap();
            let registry = swoosh::commands::tunnel::expose::registry(HOST_SEED).unwrap();
            Exposer::new(services, registry, gate)
                .unwrap()
                .run(&host)
                .await
                .unwrap();
        });

        // A MEMBER: a client presenting a badge the SIGNET signed, rooted at the signet (the key the gate
        // trusts) and bound to the member's proven mem node id, so the gate's `bound_device` check matches.
        // This is the SHAPE `mint` mints for a device -- signet root, member(true), device-bound -- signed
        // here rather than run through `mint`/`adopt` because the badge must bind to the mem transport's
        // SYNTHETIC proven id (a real device badge binds to the device's derived ed25519 key, which cannot
        // equal a mem proven id; see the module note). `device_badge_wiring.rs` proves `mint`/`adopt`
        // actually produce and store this credential; here we prove the GATE admits it.
        let member = Node::new(MemTransport::bind(), NoDiscovery);
        let member_badge = signet_badge(&SIGNET_SECRET, member.node_id());

        // Ping over the gated `diag:` service: the round trip proves the whole diagnostic rides the gate
        // unchanged, one admitted stream at a time.
        let diag = Connector::to_node(host_id, "diag".to_owned(), Some(member_badge.clone()))
            .open_service(&member)
            .await
            .expect("member reaches diag");
        let report = Ping {
            count: 3,
            interval: Duration::ZERO,
        }
        .run(&diag)
        .await
        .expect("member ping runs over the gated diag service");
        assert_eq!(report.received(), 3, "a member's every probe is answered");
        assert_eq!(report.loss(), 0.0, "a member's gated ping loses nothing");

        // Speedtest over the same gated service: bytes move both ways, so the gate admits the transfer
        // stream too, not just a ping.
        let diag = Connector::to_node(host_id, "diag".to_owned(), Some(member_badge.clone()))
            .open_service(&member)
            .await
            .expect("member reaches diag for speed");
        let speed = Speedtest::new(Mode::Bidir, Limit::ByBytes(1 << 16))
            .run(&diag)
            .await
            .expect("member speedtest runs over the gated diag service");
        assert!(
            speed.up().is_some_and(|leg| leg.bytes() > 0),
            "a member's gated speedtest moves upload bytes"
        );
        assert!(
            speed.down().is_some_and(|leg| leg.bytes() > 0),
            "a member's gated speedtest moves download bytes"
        );

        // Fetch is a raw handler, so admission (not the HTTP egress) is what the gate rules on: a member
        // is admitted, so opening the gated fetch stream succeeds (the handler then awaits a request).
        let fetch = Connector::to_node(host_id, "fetch".to_owned(), Some(member_badge))
            .open_service(&member)
            .await
            .expect("member reaches the fetch connector");
        assert!(
            fetch.open_bi().await.is_ok(),
            "a member is admitted at the gated fetch service"
        );

        // A STRANGER: a client whose self-signed badge roots at a RANDOM key the gate has never seen,
        // bound to its own proven id. It roots at a non-signet key, so the family gate rejects it no
        // matter the binding: a stranger's self-signed badge is correctly useless.
        let stranger = Node::new(MemTransport::bind(), NoDiscovery);
        let stranger_badge = signet_badge(&[3u8; 32], stranger.node_id());

        // Refused at diag: the ping ERRORS (the gate refuses the stream), it does not hang or succeed.
        // This is the security proof: a stranger cannot ping a gated node.
        let diag = Connector::to_node(host_id, "diag".to_owned(), Some(stranger_badge.clone()))
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
            "a stranger's ping must be refused at the gated diag service, not answered"
        );

        // Refused at speed too: a stranger cannot speedtest a gated node.
        let diag = Connector::to_node(host_id, "diag".to_owned(), Some(stranger_badge.clone()))
            .open_service(&stranger)
            .await
            .expect("the base connect lands; the gate refuses per-stream");
        let refused = Speedtest::new(Mode::Down, Limit::ByBytes(1 << 16))
            .run(&diag)
            .await;
        assert!(
            refused.is_err(),
            "a stranger's speedtest must be refused at the gated diag service"
        );

        // Refused at fetch too: a stranger cannot fetch through a gated node. Opening the gated stream
        // fails at the gate, the same refusal the diagnostics hit.
        let fetch = Connector::to_node(host_id, "fetch".to_owned(), Some(stranger_badge))
            .open_service(&stranger)
            .await
            .expect("the base connect lands; the gate refuses per-stream");
        assert!(
            fetch.open_bi().await.is_err(),
            "a stranger must be refused at the gated fetch service"
        );
    }
}

/// Mint a membership badge signed by `secret`, bound to `bound` (the dialer's proven node id). This is the
/// shape the signet mints for a device (`identity::Secret::sign_device_badge`, delivered by `mint` and
/// stored by `adopt`) and the shape a signet holder self-signs (`member_badge`): a `member(true)` badge
/// rooted at the signing key and bound to the dialer. A badge rooted at the signet admits (the gate trusts
/// that key AND its binding matches the proven dialer); one rooted at a stranger key is refused, because
/// the gate trusts only the signet's key. Signed here (not via `mint`/`adopt`) so it binds to the mem
/// transport's synthetic proven id; `device_badge_wiring.rs` covers the real mint/adopt production.
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

/// An empty revocation denylist: this test exercises membership admission, not revocation, so the gate loads
/// from a path that does not exist (an absent file is an empty set). `tag` keeps parallel tests' paths apart.
async fn empty_denylist(tag: &str) -> Denylist {
    let path = std::env::temp_dir().join(format!("swoosh-gated-diag-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Denylist::load(path).await.unwrap()
}
