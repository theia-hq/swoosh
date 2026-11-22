//! The own bind's Isolated stream: a connection of its own, which the stream's two halves hold. And an
//! ask the resident's Open cannot carry.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::rc::Rc;

use bifrost::{NoDiscovery, Node};

use super::{Ask, OwnBind, Resident, StreamSource as _, Unopened};
use crate::credential::Credential;
use crate::home::Home;
use crate::node_client::UidSocket;
use crate::peers::{Hints, Peers};
use crate::serve::control_codec::{MalformedOpen, OpenLane};
use crate::testkit::{Script, ScriptedPeer, TestNode};

/// A run that presents this home's standing.
const FAMILY: Credential = Credential::Family { present: None };

/// An Isolated stream dials a connection for itself alone and closes it only once both its halves have
/// dropped, so a half the caller still reads keeps the connection it measures.
#[tokio::test]
async fn an_isolated_stream_holds_its_connection_until_both_halves_drop() {
    let peer = TestNode::seeded(0x63).node_id();
    let scripted = ScriptedPeer::new(peer, [Script::Holds]);
    let node = Node::new(scripted.clone(), NoDiscovery);
    let peers = Peers::new(&node);
    let dir = std::env::temp_dir().join(format!("swoosh-streams-isolated-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = Home::resolve(Some(dir.clone())).unwrap();
    let ask = Ask {
        peer,
        hints: Hints::NONE,
        service: "speed".parse().unwrap(),
        lane: OpenLane::Isolated,
        slip: None,
    };

    let opened = OwnBind::new(&peers, &home, node.node_id(), &FAMILY)
        .open(&ask)
        .await
        .expect("the isolated stream opened");
    let _ = std::fs::remove_dir_all(dir);
    assert_eq!(scripted.dials(), 1);
    drop(opened.write);
    assert_eq!(
        scripted.closes(),
        0,
        "the read half still holds the connection"
    );
    drop(opened.read);
    assert_eq!(
        scripted.closes(),
        1,
        "both halves gone, the connection closed"
    );
}

/// A slip that addresses another machine cannot be put as an Open, so no request is sent: the outcome is
/// `Malformed`, never a control failure, and it ends the run, since every later open carries the same
/// slip for the same peer.
#[tokio::test]
async fn a_slip_for_another_peer_is_malformed_and_ends_the_run() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!("swoosh-streams-malformed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = Home::resolve(Some(dir.clone())).unwrap();
    let root = crate::home::runtime_root().unwrap();
    // Another test may have made the shared root at the umask's mode, which the lock refuses.
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_lock, _listener) = crate::serve::acquire_single(&home, &root).await.unwrap();
    let socket = UidSocket::resolve(&home).unwrap();
    let other = TestNode::seeded(0x64)
        .slip(
            &"recv".parse().unwrap(),
            std::time::SystemTime::now() + core::time::Duration::from_secs(3600),
        )
        .unwrap()
        .link()
        .unwrap();
    let ask = Ask {
        peer: TestNode::seeded(0x63).node_id(),
        hints: Hints::NONE,
        service: "recv".parse().unwrap(),
        lane: OpenLane::Bulk,
        slip: Some(other),
    };

    let opened = Resident::new(Rc::new(socket)).open(&ask).await;
    let _ = std::fs::remove_dir_all(dir);
    let Err(unopened) = opened else {
        panic!("an Open whose slip addresses another machine was sent");
    };
    assert!(
        matches!(unopened, Unopened::Malformed(MalformedOpen::SlipPeer)),
        "{unopened:?}"
    );
    assert!(unopened.ends_run());
}
