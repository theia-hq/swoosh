// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The pick-up route end to end over the in-process transport, bound beside the update route and `ping`
//! the way `serve` binds them, behind the same anchored gate.
//!
//! Over `mem` the proven peer is the transport's synthetic node id, so the update the serving device holds
//! lists a row for that id, as it lists a device of yours by its key; see `gated_send.rs` for the full note.

use core::time::Duration;
use std::time::SystemTime;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use keystore::{KeyFile, Protection};
use nauthy::Link;
use swoosh::contacts::DeviceLabel;
use swoosh::home::Home;
use swoosh::renewal::{Fetch as _, NodeFetch};
use swoosh::roster::{Epoch, Member, RosterDoc, fold};
use swoosh::serve::{RENEWAL_SERVICE, SYNC_SERVICE};
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{CancellationToken, Connector, Router};
use tokio::io::AsyncReadExt as _;

/// The root every device here belongs to.
const ROOT: u8 = 0x51;
/// The device that serves the route.
const NAS: u8 = 0x52;

/// How long any one ask may take here before the test calls it hung.
const BOUND: Duration = Duration::from_secs(5);

/// Run `test` on a thread with room for the node's stack, on one local task set.
fn on_a_node<F: core::future::Future<Output = ()>>(test: impl FnOnce() -> F + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(test()));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// A fresh home for the device `seed`: its key, the pin, and a live standing the root signed for it.
async fn device_home(tag: &str, seed: u8) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-pick-up-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut secret = TestNode::seeded(seed).seed();
    swoosh::identity::make_machine_dir(&home).unwrap();
    KeyFile::new(home.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    swoosh::config::write_signet(
        &swoosh::testkit::lock(),
        &home,
        TestRoot::seeded(ROOT).node_id(),
    )
    .unwrap();
    let badge = TestRoot::seeded(ROOT)
        .device_badge(
            TestNode::seeded(seed).node_id(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
        )
        .unwrap();
    swoosh::config::write_badge(&swoosh::testkit::lock(), &home, &badge).unwrap();
    home
}

/// A live row for `node`, named `label`.
fn row(node: NodeId, label: &str) -> Member {
    TestRoot::seeded(ROOT)
        .member(
            node.verify_key().unwrap(),
            label.parse::<DeviceLabel>().unwrap(),
        )
        .unwrap()
}

/// Make the nas's held update list itself and `laptop`, and return the laptop's renewed standing.
async fn renewing(nas: &Home, laptop: NodeId) -> Link {
    let own = row(laptop, "laptop");
    let standing = own.standing.clone();
    let members = vec![row(TestNode::seeded(NAS).node_id(), "nas"), own];
    let doc = RosterDoc::with_revocations(Epoch(1), members, vec![], Vec::new()).unwrap();
    fold(
        &swoosh::home::HomeWrite::take(nas).await.unwrap(),
        nas,
        &TestRoot::seeded(ROOT).sign_update(&doc),
    )
    .await
    .unwrap();
    standing
}

/// Serve `home` on `host` as `serve` does: `ping`, the update route, and the pick-up route, behind the
/// anchored gate, with the live cut.
fn serve(home: Home, host: Node<MemTransport, NoDiscovery>) {
    tokio::task::spawn_local(async move {
        let (gate, cut) = swoosh::gate::anchored(
            &home,
            TestNode::seeded(NAS).node_id(),
            swoosh::serve::BoundTargets::default(),
        )
        .await
        .unwrap();
        let router = swoosh::serve::diagnostics(Router::new(gate), &[]).unwrap();
        let router = router
            .member_service(
                SYNC_SERVICE.parse().unwrap(),
                swoosh::serve::Exchange::new(home.clone()),
            )
            .unwrap();
        let (router, _known) = swoosh::serve::bind_renewal(router, &home).await.unwrap();
        router
            .expose()
            .unwrap()
            .with_live_cuts(cut)
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });
}

/// Open `service` on `host` from `from`, presenting nothing: whether the node let the stream through.
async fn opens(from: &Node<MemTransport, NoDiscovery>, host: NodeId, service: &str) -> bool {
    let session = Connector::to_node(host, service.parse().unwrap(), None)
        .open_service(from)
        .await
        .expect("the base connect lands; the node rules per stream");
    session.open_bi().await.is_ok()
}

/// A device of yours, whose standing the nas holds renewed, reaches the pick-up route with no token and
/// takes its standing there; with the same proven key and no token it reaches neither `ping` nor the
/// update route.
#[test]
fn a_door_peer_reaches_no_other_route() {
    on_a_node(|| async {
        let nas = device_home("isolation", NAS).await;
        let laptop = Node::new(MemTransport::bind(), NoDiscovery);
        let renewed = renewing(&nas, laptop.node_id()).await;
        let host = Node::new(MemTransport::bind(), NoDiscovery);
        let host_id = host.node_id();
        serve(nas, host);

        let fetched = tokio::time::timeout(BOUND, NodeFetch::new(&laptop).fetch(host_id))
            .await
            .expect("the pick-up answers in time")
            .expect("the pick-up runs");
        assert_eq!(
            fetched.map(|link| link.as_str().to_owned()),
            Some(renewed.as_str().to_owned()),
            "the door hands the laptop its renewed standing"
        );
        assert!(
            !opens(&laptop, host_id, "ping").await,
            "a door peer does not reach ping"
        );
        assert!(
            !opens(&laptop, host_id, SYNC_SERVICE).await,
            "a door peer does not reach the update route"
        );
    });
}

/// The route answers without reading: a dialer that opens it and sends nothing, with its side left open,
/// still reads the whole answer and the close.
#[test]
fn a_door_peer_is_never_asked_for_bytes() {
    on_a_node(|| async {
        let nas = device_home("no-bytes", NAS).await;
        let laptop = Node::new(MemTransport::bind(), NoDiscovery);
        let renewed = renewing(&nas, laptop.node_id()).await;
        let host = Node::new(MemTransport::bind(), NoDiscovery);
        let host_id = host.node_id();
        serve(nas, host);

        let session = Connector::to_node(host_id, RENEWAL_SERVICE.parse().unwrap(), None)
            .open_service(&laptop)
            .await
            .unwrap();
        // The writer is held, unwritten and unclosed, for the whole read.
        let (_writer, mut reader) = session.open_bi().await.expect("the door admits the laptop");
        let mut answer = Vec::new();
        tokio::time::timeout(BOUND, reader.read_to_end(&mut answer))
            .await
            .expect("the door answers without waiting on the dialer")
            .unwrap();
        let text = renewed.as_str().as_bytes();
        assert_eq!(answer.first(), Some(&0x01), "a hit");
        assert_eq!(
            &answer[3..],
            text,
            "the laptop's own standing, then the close"
        );
    });
}

/// Keys the nas holds nothing for are refused before the route's shared slots: a crowd of them, each
/// holding its session open, never reaches the handler, and the laptop still takes its standing.
#[test]
fn a_stranger_flood_does_not_hold_a_proven_permit() {
    on_a_node(|| async {
        let nas = device_home("flood", NAS).await;
        let laptop = Node::new(MemTransport::bind(), NoDiscovery);
        let renewed = renewing(&nas, laptop.node_id()).await;
        let host = Node::new(MemTransport::bind(), NoDiscovery);
        let host_id = host.node_id();
        serve(nas, host);

        let mut held = Vec::new();
        for _ in 0..16 {
            let stranger = Node::new(MemTransport::bind(), NoDiscovery);
            let session = Connector::to_node(host_id, RENEWAL_SERVICE.parse().unwrap(), None)
                .open_service(&stranger)
                .await
                .unwrap();
            assert!(
                session.open_bi().await.is_err(),
                "a key the nas holds nothing for is refused before a slot"
            );
            held.push((stranger, session));
        }

        let fetched = tokio::time::timeout(BOUND, NodeFetch::new(&laptop).fetch(host_id))
            .await
            .expect("the pick-up answers in time")
            .expect("the pick-up runs");
        assert_eq!(
            fetched.map(|link| link.as_str().to_owned()),
            Some(renewed.as_str().to_owned()),
            "the laptop still takes its standing"
        );
        drop(held);
    });
}

/// A home whose files disagree answers nobody on the route, even where its update still verifies under
/// the pin and lists the dialer live: the key is refused before the route's shared slots.
#[test]
fn a_damaged_home_lets_no_key_reach_the_door() {
    on_a_node(|| async {
        let nas = device_home("damaged", NAS).await;
        let laptop = Node::new(MemTransport::bind(), NoDiscovery);
        renewing(&nas, laptop.node_id()).await;
        // A pin with no standing beside it: the home reads as damaged.
        std::fs::remove_file(nas.key_cert()).unwrap();
        let host = Node::new(MemTransport::bind(), NoDiscovery);
        let host_id = host.node_id();
        serve(nas, host);

        assert!(
            !opens(&laptop, host_id, RENEWAL_SERVICE).await,
            "a damaged home lets no key through to the route"
        );
    });
}

/// A file the pick-up route reads from that cannot be read keeps the devices it knew, rather than
/// dropping every one until some file changes; once it can be read again it is read again.
#[test]
fn a_read_error_keeps_the_devices_the_door_knows() {
    use std::os::unix::fs::PermissionsExt as _;

    on_a_node(|| async {
        let nas = device_home("read-error", NAS).await;
        let laptop = TestNode::seeded(0x53).node_id();
        renewing(&nas, laptop).await;
        let key = laptop.verify_key().unwrap();
        let known = swoosh::serve::Known::load(&nas).await;
        assert!(known.knows(&key), "the door knows the laptop");

        for path in [nas.root_pub(), nas.devices()] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            known.refresh().await;
            let kept = known.knows(&key);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(kept, "{} unreadable keeps the laptop known", path.display());
            known.refresh().await;
            assert!(known.knows(&key), "{} readable again", path.display());
        }
    });
}

/// A device revoked here while the node serves, though the update held here still lists it live, reaches
/// no route from then on: the gate refuses its key before the pick-up route's own check and its shared
/// slots, as it does at every other route.
#[test]
fn a_revoked_key_reaches_no_route() {
    on_a_node(|| async {
        let nas = device_home("revoked-key", NAS).await;
        let laptop = Node::new(MemTransport::bind(), NoDiscovery);
        renewing(&nas, laptop.node_id()).await;
        let host = Node::new(MemTransport::bind(), NoDiscovery);
        let host_id = host.node_id();
        serve(nas.clone(), host);
        assert!(
            opens(&laptop, host_id, RENEWAL_SERVICE).await,
            "before the revoke the laptop reaches the door"
        );

        swoosh::revoked::add(
            &swoosh::testkit::lock(),
            &nas,
            [nauthy::Revocation::Key(
                laptop.node_id().verify_key().unwrap(),
            )],
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        for service in [RENEWAL_SERVICE, SYNC_SERVICE, "ping"] {
            assert!(
                !opens(&laptop, host_id, service).await,
                "a revoked key does not reach {service}"
            );
        }
    });
}

/// A router over `home`'s anchored gate carrying only the pick-up route, bound as `serve` binds it.
async fn router(home: &Home) -> Router {
    let (gate, _cut) = swoosh::gate::anchored(
        home,
        TestNode::seeded(NAS).node_id(),
        swoosh::serve::BoundTargets::default(),
    )
    .await
    .unwrap();
    swoosh::serve::bind_renewal(Router::new(gate), home)
        .await
        .unwrap()
        .0
}

/// The route requires a key the transport proved: a node serving it refuses to arm over bare quirk, whose
/// key is only announced, and the route cannot be opened to everyone.
#[tokio::test]
async fn the_door_refuses_an_announced_peer() {
    let nas = device_home("announced", NAS).await;

    let exposer = router(&nas).await.expose().unwrap();
    exposer
        .prove_security::<bifrost_noise::Noise<bifrost_quirk::Endpoint>>()
        .expect("a transport that proves the peer carries the route");
    assert!(
        exposer.prove_security::<bifrost_quirk::Endpoint>().is_err(),
        "an announced key never reaches the route"
    );
    assert!(
        router(&nas)
            .await
            .public([RENEWAL_SERVICE.parse().unwrap()])
            .expose()
            .is_err(),
        "the route cannot be opened to peers the transport did not prove"
    );
}
