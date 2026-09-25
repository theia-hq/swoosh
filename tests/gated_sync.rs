// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The update route end to end over the in-process transport. A device serves `control.sync` behind the
//! same anchored gate `serve` builds from its home; another device of the same root dials it through the
//! connector every exchange uses and gives it a newer update, which its gate honors at once. A stranger is
//! refused at the gate, and so is a link the serving node signed itself, since the route admits devices
//! only.
//!
//! Over `mem` the proven peer is the transport's synthetic node id, so the dialer presents a standing bound
//! to that id, while its home (whose standing is bound to its own key) runs the exchange; see
//! `gated_send.rs` for the full note.

use core::time::Duration;
use std::time::SystemTime;

use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use keystore::{KeyFile, Protection};
use nauthy::{Revocations as _, VerifyKey};
use swoosh::contacts::DeviceLabel;
use swoosh::gate::KeyedDenylist;
use swoosh::grants::{Delegation, GrantKind, GrantRecord, Grants};
use swoosh::home::Home;
use swoosh::roster::{Epoch, RosterDoc, fold};
use swoosh::serve::SYNC_SERVICE;
use swoosh::sync::Answer;
use swoosh::testkit::{STANDING_UNTIL, TestNode, TestRoot};
use tightbeam::tunnel::{CancellationToken, Connector, Router};

/// The root both devices belong to.
const ROOT: u8 = 7;
/// The serving device.
const NAS: u8 = 8;
/// The dialing device.
const DESK: u8 = 9;
/// A device the newer update revokes.
const STOLEN: u8 = 10;

#[test]
fn a_device_gives_an_update_over_the_gated_route_a_stranger_is_refused() {
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
    let nas_home = device_home("nas", NAS).await;
    let desk_home = device_home("desk", DESK).await;
    fold(&nas_home, &update(1, vec![])).await.unwrap();
    fold(&desk_home, &update(1, vec![])).await.unwrap();
    fold(&desk_home, &update(2, vec![key(STOLEN)]))
        .await
        .unwrap();
    let own_slip = issue_own_slip(&nas_home).await;

    // The serving device: `control.sync` behind the anchored gate its home pins to the root, through the
    // same handler and access class the product `serve` binds.
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let serving = nas_home.clone();
    tokio::task::spawn_local(async move {
        let (gate, cut) = swoosh::gate::anchored(&serving, TestNode::seeded(NAS).node_id())
            .await
            .unwrap();
        Router::new(gate)
            .member_service(
                SYNC_SERVICE.parse().unwrap(),
                swoosh::serve::Exchange::new(serving),
            )
            .unwrap()
            .expose()
            .unwrap()
            .with_live_cuts(cut)
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });

    // A device of the root dials through the connector every exchange uses, and gives its newer update.
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let standing = device_standing(ROOT, member.node_id());
    let session = swoosh::sync::connector(host_id, Some(standing))
        .unwrap()
        .open_service(&member)
        .await
        .expect("a device reaches the update route");
    let (writer, reader) = session.open_bi().await.expect("a device is admitted");
    let answer = swoosh::sync::exchange(&desk_home, reader, writer)
        .await
        .unwrap();
    assert_eq!(answer, Answer::Gave);
    assert!(
        KeyedDenylist::load(&nas_home)
            .await
            .unwrap()
            .is_revoked_peer(&key(STOLEN)),
        "the serving device refuses the key the update revoked"
    );

    // A stranger (a standing from a root this gate never trusts) is refused at the route.
    let stranger = Node::new(MemTransport::bind(), NoDiscovery);
    let refused = swoosh::sync::connector(host_id, Some(device_standing(3, stranger.node_id())))
        .unwrap()
        .open_service(&stranger)
        .await
        .expect("the base connect lands; the gate refuses per-stream");
    assert!(
        refused.open_bi().await.is_err(),
        "a stranger is refused at the update route"
    );

    // A link the serving node signed itself, for this very route: the gate admits the slip, and the
    // route's member floor refuses it.
    let holder = Node::new(MemTransport::bind(), NoDiscovery);
    let refused = Connector::to_node(host_id, SYNC_SERVICE.parse().unwrap(), Some(own_slip))
        .open_service(&holder)
        .await
        .expect("the base connect lands; the route refuses per-stream");
    assert!(
        refused.open_bi().await.is_err(),
        "the update route admits devices only, never a link"
    );
}

fn key(seed: u8) -> VerifyKey {
    TestNode::seeded(seed).verify_key()
}

/// The update at `number`, listing both devices and revoking `keys`.
fn update(number: u64, keys: Vec<VerifyKey>) -> Vec<u8> {
    let root = TestRoot::seeded(ROOT);
    let members = [(NAS, "nas"), (DESK, "desk")]
        .into_iter()
        .map(|(seed, label)| {
            root.member(key(seed), label.parse::<DeviceLabel>().unwrap())
                .unwrap()
        })
        .collect();
    let doc = RosterDoc::with_revocations(Epoch(number), members, vec![], keys).unwrap();
    root.sign_update(&doc)
}

/// A scratch home for the device `seed`: its key, the pin, and a standing the root signed for it.
async fn device_home(tag: &str, seed: u8) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-gated-sync-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut secret = TestNode::seeded(seed).seed();
    KeyFile::device(home.key())
        .write(&keystore::Secret::take(&mut secret), Protection::Plain)
        .unwrap();
    swoosh::config::write_signet(&home, TestRoot::seeded(ROOT).node_id())
        .await
        .unwrap();
    let badge = TestRoot::seeded(ROOT)
        .device_badge(
            TestNode::seeded(seed).node_id(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(STANDING_UNTIL),
        )
        .unwrap();
    swoosh::config::write_badge(&home, &badge).await.unwrap();
    home
}

/// A link for the update route the serving node's own key signs, recorded in its ledger, so the gate
/// admits it and only the route's member floor stands between it and the exchange.
async fn issue_own_slip(home: &Home) -> nauthy::Link {
    let service: nauthy::Service = SYNC_SERVICE.parse().unwrap();
    let slip = TestNode::seeded(NAS)
        .slip(
            &service,
            nauthy::Request::expires_in(Duration::from_secs(300)),
        )
        .unwrap();
    Grants::at(home.links())
        .append(&GrantRecord {
            target: service,
            kind: GrantKind::Bearer,
            delegation: Delegation::Delegable,
            holder: swoosh::grants::ANYONE.to_owned(),
            root_id: slip.root_revocation_id().unwrap(),
            expiry: nauthy::Request::expires_in(Duration::from_secs(300)),
        })
        .await
        .unwrap();
    slip.link().unwrap()
}

fn device_standing(root: u8, bound: NodeId) -> nauthy::Link {
    TestRoot::seeded(root)
        .device_badge(bound, nauthy::Request::expires_in(Duration::from_secs(300)))
        .unwrap()
}
