// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Invites, end to end: the REAL CLI provisions the device, then a live gated reach proves the standing
//! the `invite:` line carried is the one the joining device's gate admits.
//!
//! The flow under test is the offline round trip:
//!
//! 1. the DEVICE makes its key and prints it (`swoosh status --key`);
//! 2. the ROOT signs for that key, as `swoosh invite laptop <key>` does where it is kept, so no seed ever
//!    travels (built in process from a test root: signing takes the root's passphrase at a terminal,
//!    which a child process has none of; the command's own half is proven in `commands/invite_tests.rs`);
//! 3. the DEVICE joins with the `invite:` line (`swoosh join`), keeping its identity;
//! 4. the device's node serves behind the gate `serve` builds from its home; a standing the root signed
//!    for the owner's node is ADMITTED, proving `join` wrote the pin the gate reads, while a stranger
//!    with no standing is REFUSED;
//! 5. the owner's node serves; it pins no root, so it admits no member, and the device's stored standing
//!    is REFUSED there.
//!
//! The transport is `Noise<Quirk>` on loopback, so the gate's `bound_device` check runs against the
//! REAL key the device binds under (the wrapper proves the NodeId), not a synthetic test id.

use core::time::Duration;
use std::path::Path;
use std::process::Command;

use bifrost::{NoDiscovery, Node, NodeId};
use bifrost_noise::Noise;
use bifrost_quirk::Endpoint;
use measure::Ping;
use swoosh::config;
use swoosh::credential::Credential;
use swoosh::home::Home;
use swoosh::invite::Invite;
use swoosh::reaching::BindRole;
use swoosh::testkit::TestRoot;
use swoosh::transport::PeerHint;
use tightbeam::tunnel::{CancellationToken, Connector, Router};

/// The role every node that dials here binds under: it browses the LAN and advertises nothing.
const DIALING: BindRole = BindRole::Dialing(Credential::Family { present: None });

/// Bind a quirk endpoint under `seed` and wrap it with the SAME seed, the composition
/// `--transport quirk+noise` performs: one address, one identity, two layers.
async fn sealed(seed: [u8; 32]) -> Noise<Endpoint> {
    let inner = Endpoint::bind_with_secret(&seed)
        .await
        .expect("bind quirk on loopback");
    Noise::new(inner, &seed).expect("wrap quirk under its own identity")
}

/// The gate `serve` builds for a node from its home, over the diagnostics, with the live cut wired.
async fn anchored_exposer(home: &Home, own: NodeId) -> tightbeam::tunnel::Exposer {
    let (gate, cut) = swoosh::gate::anchored(home, own)
        .await
        .expect("the gate builds");
    swoosh::serve::diagnostics(Router::new(gate), &[])
        .expect("the diagnostics routes bind")
        .expose()
        .expect("the exposer assembles")
        .with_live_cuts(cut)
}

/// The member's gated ping rides the sealed wrapper: the dial reaches the node, the gate admits the
/// invite's device-bound badge, and every probe answers.
#[tokio::test]
async fn the_invite_round_trip_admits_the_device_and_refuses_a_stranger() {
    let base = std::env::temp_dir().join(format!("swoosh-tier1-invites-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let signet_dir = base.join("signet-holder");
    let device_dir = base.join("device");
    std::fs::create_dir_all(&signet_dir).unwrap();
    std::fs::create_dir_all(&device_dir).unwrap();

    // 1. The device makes its key and prints it.
    let identity = swoosh(&["status", "--key", "--home", path_str(&device_dir)]);
    assert!(
        identity.status.success(),
        "status --key failed: {}",
        stderr(&identity)
    );
    let device_id: NodeId = String::from_utf8(identity.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("status --key prints the key alone");

    // 2. The root signs for that key: no seed travels. The owner's machine is where the invite says it
    //    came from.
    let owner = swoosh(&["status", "--key", "--home", path_str(&signet_dir)]);
    assert!(
        owner.status.success(),
        "status --key failed: {}",
        stderr(&owner)
    );
    let owner_id: NodeId = String::from_utf8(owner.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("status --key prints the key alone");
    let root = TestRoot::seeded(0x21);
    let standing = root
        .device_badge(
            device_id,
            std::time::SystemTime::now() + Duration::from_secs(90 * 24 * 60 * 60),
        )
        .unwrap();
    let token = Invite::bound(owner_id, "laptop".parse().unwrap(), standing).to_string();

    // 3. The device joins, keeping its identity; the pin and the standing land beside it. Its first exchange
    //    is with the owner's machine, which is not serving, so it ends at once over loopback.
    let joined = swoosh(&[
        "join",
        &token,
        "--transport",
        "quirk+noise",
        "--home",
        path_str(&device_dir),
    ]);
    assert!(joined.status.success(), "join failed: {}", stderr(&joined));
    let device_seed: [u8; 32] = std::fs::read(device_dir.join("key"))
        .unwrap()
        .try_into()
        .expect("the device key is 32 bytes");
    let badge: nauthy::Link = std::fs::read_to_string(device_dir.join("badge"))
        .unwrap()
        .trim()
        .parse()
        .expect("the stored badge parses");
    let device_home = Home::resolve(Some(device_dir.clone())).unwrap();
    let signet = config::load_signet(&device_home)
        .await
        .unwrap()
        .expect("join wrote the pin the device's gate will arm from");
    assert_eq!(signet, root.node_id(), "the device pins the invite's root");
    let owner_seed: [u8; 32] = std::fs::read(signet_dir.join("key"))
        .unwrap()
        .try_into()
        .expect("the owner key is 32 bytes");

    // 4. The DEVICE's node serves, gated at the pin `join` wrote; the owner dials presenting a standing the
    //    root signed for its node, and is admitted as one of the root's devices.
    let device_transport = sealed(device_seed).await;
    let device_host = Node::new(device_transport, NoDiscovery);
    let device_id_bound = device_host.node_id();
    let device_addr = device_host.local_addr();
    let exposer = anchored_exposer(&device_home, device_id).await;

    let owner_transport = sealed(owner_seed).await;
    let owner_hint: PeerHint = format!("{device_id_bound}={}", device_addr.hints[0])
        .parse()
        .expect("the direct hint parses");
    let owner_discovery =
        PeerHint::discovery(&owner_transport, [owner_hint.clone()], &DIALING).discovery;
    let owner = Node::new(owner_transport, owner_discovery);
    let owner_badge = root
        .device_badge(
            owner_id,
            nauthy::Request::expires_in(Duration::from_secs(300)),
        )
        .unwrap();

    let cancel = CancellationToken::new();
    let serving = exposer.run(&device_host, cancel.clone());
    let dialing = async {
        let session =
            Connector::to_node(device_id_bound, "ping".parse().unwrap(), Some(owner_badge))
                .open_service(&owner)
                .await
                .expect("the owner opens the device's gated ping");
        let report = Ping {
            count: 3,
            interval: Duration::ZERO,
        }
        .run(&session)
        .await
        .expect("the gated ping runs for the owner");
        assert_eq!(report.received(), 3, "every probe answers for the owner");

        // A STRANGER: a different key, no badge at all. The gate refuses the stream.
        let stranger_transport = sealed([0x5a; 32]).await;
        let stranger_discovery =
            PeerHint::discovery(&stranger_transport, [owner_hint.clone()], &DIALING).discovery;
        let stranger = Node::new(stranger_transport, stranger_discovery);
        let refused = Connector::to_node(device_id_bound, "ping".parse().unwrap(), None)
            .open_service(&stranger)
            .await
            .expect("the base connect lands; the gate refuses per-stream");
        let report = Ping {
            count: 1,
            interval: Duration::ZERO,
        }
        .run(&refused)
        .await;
        assert!(
            report.is_err(),
            "a stranger without a badge must be refused, not answered: {report:?}"
        );
        cancel.cancel();
    };
    let (served, ()) = tokio::join!(serving, async {
        tokio::time::timeout(Duration::from_secs(15), dialing)
            .await
            .expect("the owner completes its gated dial within the deadline");
    });
    served.expect("the device's exposer ends Ok once the dials finish");

    // 5. The OWNER's node serves. It pins no root, so the device's standing admits nothing here.
    let owner_home = Home::resolve(Some(signet_dir.clone())).unwrap();
    let host_transport = sealed(owner_seed).await;
    let host = Node::new(host_transport, NoDiscovery);
    let host_id = host.node_id();
    let addr = host.local_addr();
    let exposer = anchored_exposer(&owner_home, owner_id).await;

    let member_transport = sealed(device_seed).await;
    let hint: PeerHint = format!("{host_id}={}", addr.hints[0])
        .parse()
        .expect("the direct hint parses");
    let discovery = PeerHint::discovery(&member_transport, [hint], &DIALING).discovery;
    let member = Node::new(member_transport, discovery);

    let cancel = CancellationToken::new();
    let serving = exposer.run(&host, cancel.clone());
    let dialing = async {
        let session = Connector::to_node(host_id, "ping".parse().unwrap(), Some(badge))
            .open_service(&member)
            .await
            .expect("the base connect lands; the gate refuses per-stream");
        let report = Ping {
            count: 1,
            interval: Duration::ZERO,
        }
        .run(&session)
        .await;
        assert!(
            report.is_err(),
            "a machine with no pin admits no member, even one its own key signed: {report:?}"
        );
        cancel.cancel();
    };
    let (served, ()) = tokio::join!(serving, async {
        tokio::time::timeout(Duration::from_secs(15), dialing)
            .await
            .expect("the refused dial completes within the deadline");
    });
    served.expect("the owner's exposer ends Ok once the dial finishes");

    let _ = std::fs::remove_dir_all(&base);
}

/// Run the compiled `swoosh` binary with `args`, capturing its output.
fn swoosh(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_swoosh"))
        .args(args)
        .env("HOME", std::env::temp_dir())
        .output()
        .expect("the swoosh binary runs")
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("the temp path is valid utf-8")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
