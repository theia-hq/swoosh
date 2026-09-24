// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Tier-1 invites, end to end: the REAL CLI provisions two homes, then a live gated reach proves the
//! credential the `invite:` artifact carried is the one a signet-rooted gate admits.
//!
//! The flow under test is the spec's offline round trip:
//!
//! 1. the DEVICE makes its key and prints it (`swoosh identity`);
//! 2. the OWNER signs for that key (`swoosh invite add laptop --for <key>`), so no seed ever travels;
//! 3. the DEVICE adopts the `invite:` artifact (`swoosh adopt`), keeping its identity;
//! 4. the owner's node serves; the adopted device dials with its stored badge and is ADMITTED, while a
//!    stranger with no badge is REFUSED;
//! 5. the device's node serves; the owner (self-signing, the signet holder) dials and is admitted,
//!    proving `adopt` wrote the signet the serve gate arms from.
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
use nauthy::FileDenylist;
use swoosh::config;
use swoosh::credential::Credential;
use swoosh::home::Home;
use swoosh::reaching::BindRole;
use swoosh::testkit::TestRoot;
use swoosh::transport::PeerHint;
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Router};

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

/// The rooted gate `serve` arms for a node: the signet it trusts plus an empty denylist.
async fn gated_exposer(tag: &str, signet: NodeId) -> tightbeam::tunnel::Exposer {
    let path = std::env::temp_dir().join(format!("swoosh-tier1-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let gate = tunnel::resolve_gate(Some(signet), FileDenylist::load(path).await.unwrap())
        .expect("the signet-rooted gate resolves");
    swoosh::serve::diagnostics(Router::new(gate), &[])
        .expect("the diagnostics routes bind")
        .expose()
        .expect("the exposer assembles")
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
    let identity = swoosh(&["identity", "--home", path_str(&device_dir)]);
    assert!(
        identity.status.success(),
        "identity failed: {}",
        stderr(&identity)
    );
    let device_id: NodeId = String::from_utf8(identity.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .expect("identity prints the node id first");

    // 2. The owner signs for that key: no seed travels.
    let create = swoosh(&[
        "invite",
        "add",
        "laptop",
        "--for",
        &device_id.to_string(),
        "--home",
        path_str(&signet_dir),
    ]);
    assert!(
        create.status.success(),
        "invite add --for failed: {}",
        stderr(&create)
    );
    let token = String::from_utf8(create.stdout)
        .unwrap()
        .split_whitespace()
        .find(|word| word.starts_with("invite:"))
        .expect("invite add --for prints an invite: token")
        .to_owned();

    // 3. The device adopts, keeping its identity; the trust + badge land beside it.
    let adopt = swoosh(&["adopt", &token, "--home", path_str(&device_dir)]);
    assert!(adopt.status.success(), "adopt failed: {}", stderr(&adopt));
    let device_seed: [u8; 32] = std::fs::read(device_dir.join("identity.key"))
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
        .expect("adopt wrote the signet the device's gate will arm from");
    let owner_seed: [u8; 32] = std::fs::read(signet_dir.join("identity.key"))
        .unwrap()
        .try_into()
        .expect("the owner key is 32 bytes");
    let owner_id = NodeId::from_ed25519_secret(&owner_seed);
    assert_eq!(signet, owner_id, "the invite roots at the owner's signet");

    // The membership edit CUT a signed roster on the owner's machine, there and then: no node is serving
    // here and no second verb was typed. This is the write half the loop was missing, and the reason
    // `fleet cut` is not a verb.
    let owner_home = Home::resolve(Some(signet_dir.clone())).unwrap();
    assert!(
        owner_home.roster().exists(),
        "`invite add` cuts a roster on the signet's machine"
    );
    let cut = swoosh::roster::Artifact::open(owner_home.roster())
        .await
        .unwrap();
    let doc = swoosh::roster::verify(&cut.bytes(), owner_id.verify_key())
        .expect("the cut roster verifies against the owner's signet");
    assert_eq!(
        doc.epoch(),
        swoosh::roster::Epoch(1),
        "the first membership edit publishes version 1, which is newer than every floor in the field"
    );
    assert_eq!(doc.members().len(), 1);
    let first_cut = cut.bytes();

    // A RENEWAL: `invite add` for a key already on file mints a fresh badge and leaves the member SET
    // byte-identical, so it must publish nothing. Bumping here would weld the quarterly credential
    // cadence to the membership version and drive a fleet-wide re-pull four times a year for no delta.
    let renew = swoosh(&[
        "invite",
        "add",
        "laptop",
        "--for",
        &device_id.to_string(),
        "--home",
        path_str(&signet_dir),
    ]);
    assert!(renew.status.success(), "renewal failed: {}", stderr(&renew));
    let after_renewal = swoosh::roster::Artifact::open(owner_home.roster())
        .await
        .unwrap();
    assert_eq!(
        after_renewal.bytes(),
        first_cut,
        "a renewal changes no member, so it must not re-publish the roster"
    );

    // 4a. The OWNER's node serves; the adopted device is ADMITTED with its stored badge.
    let host_transport = sealed(owner_seed).await;
    let host = Node::new(host_transport, NoDiscovery);
    let host_id = host.node_id();
    let addr = host.local_addr();
    let exposer = gated_exposer("owner-serves", owner_id).await;

    let member_transport = sealed(device_seed).await;
    let hint: PeerHint = format!("{host_id}={}", addr.hints[0])
        .parse()
        .expect("the direct hint parses");
    let discovery = PeerHint::discovery(&member_transport, [hint.clone()], &DIALING).discovery;
    let member = Node::new(member_transport, discovery);

    let cancel = CancellationToken::new();
    let serving = exposer.run(&host, cancel.clone());
    let dialing = async {
        let session = Connector::to_node(host_id, "ping".parse().unwrap(), Some(badge))
            .open_service(&member)
            .await
            .expect("the admitted device opens the gated ping");
        let report = Ping {
            count: 3,
            interval: Duration::ZERO,
        }
        .run(&session)
        .await
        .expect("the gated ping runs for the admitted device");
        assert_eq!(
            report.received(),
            3,
            "every probe answers for the adopted device"
        );

        // A STRANGER: a different key, no badge at all. The gate refuses the stream.
        let stranger_transport = sealed([0x5a; 32]).await;
        let stranger_discovery =
            PeerHint::discovery(&stranger_transport, [hint.clone()], &DIALING).discovery;
        let stranger = Node::new(stranger_transport, stranger_discovery);
        let refused = Connector::to_node(host_id, "ping".parse().unwrap(), None)
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
            .expect("the member completes its gated dial within the deadline");
    });
    served.expect("the owner's exposer ends Ok once the dials finish");

    // 4b. The DEVICE's node serves, gated at the signet `adopt` wrote; the owner (the signet holder,
    //     self-signing) dials and is admitted. This is the reverse half of the same membership.
    let device_transport = sealed(device_seed).await;
    let device_host = Node::new(device_transport, NoDiscovery);
    let device_id_bound = device_host.node_id();
    let device_addr = device_host.local_addr();
    let exposer = gated_exposer("device-serves", signet).await;

    let owner_transport = sealed(owner_seed).await;
    let owner_hint: PeerHint = format!("{device_id_bound}={}", device_addr.hints[0])
        .parse()
        .expect("the direct hint parses");
    let owner_discovery = PeerHint::discovery(&owner_transport, [owner_hint], &DIALING).discovery;
    let owner = Node::new(owner_transport, owner_discovery);
    let owner_badge = TestRoot::from_seed(owner_seed)
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
                .expect("the signet holder opens the device's gated ping");
        let report = Ping {
            count: 3,
            interval: Duration::ZERO,
        }
        .run(&session)
        .await
        .expect("the gated ping runs for the owner");
        assert_eq!(report.received(), 3, "every probe answers for the owner");
        cancel.cancel();
    };
    let (served, ()) = tokio::join!(serving, async {
        tokio::time::timeout(Duration::from_secs(15), dialing)
            .await
            .expect("the owner completes its gated dial within the deadline");
    });
    served.expect("the device's exposer ends Ok once the dial finishes");

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
