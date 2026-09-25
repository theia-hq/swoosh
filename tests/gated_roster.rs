// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The update route end to end over the in-process transport: the whole roster-sync loop minus the live
//! infra. A node serves its signet-signed roster on the member-gated route every `serve` binds, behind the
//! same anchored gate `serve` builds from its home; a MEMBER pulls it, VERIFIES it against the signet, and
//! HYDRATES its contacts, seeing the whole fleet with no id-copying; a STRANGER is refused at the gate and
//! never reads the member set, and so is a link the node signed itself, since the route admits members
//! only.
//!
//! This exercises steps 4 (the served handler) and 5 (the pull: read, verify, hydrate) of the build spec.
//! The only thing it does not cover is the real GitHub-runner dial (step 6), which needs a live box.
//!
//! Over `mem` the proven peer is the transport's synthetic node id, so a member badge binds to whatever id
//! the mem transport proves for the dialer; see `gated_send.rs` for the full note.

use core::time::Duration;
use std::sync::Arc;

use bifrost::{CryptoKind, NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::VerifyKey;
use swoosh::contacts::{Contacts, DeviceLabel};
use swoosh::grants::{Delegation, GrantKind, GrantRecord, GrantTarget, Grants};
use swoosh::home::Home;
use swoosh::roster::{self, Epoch, RosterDoc};
use swoosh::serve::ROSTER_SERVICE;
use swoosh::testkit::{TestNode, TestRoot};
use tightbeam::tunnel::{CancellationToken, Connector, Router};
use tokio::io::AsyncReadExt as _;

/// The byte the signet's fixed key is seeded with: its ed25519 public half is the signet the gate trusts and
/// the key that signs the roster, so a puller that trusts this signet accepts the served roster and refuses
/// any other.
const SIGNET: u8 = 7;

/// The serving machine's own key, which signs the links it issues.
const OWN: u8 = 8;

#[test]
fn a_member_pulls_and_verifies_the_roster_a_stranger_is_refused() {
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
    // The fleet the operator's signet vouches for: two devices under `me`, keyed by fixed ed25519 keys so
    // the puller's hydrated node ids are assertable.
    let signet = TestRoot::seeded(SIGNET);
    let doc = RosterDoc::new(
        Epoch(1),
        vec![
            signet
                .member(
                    VerifyKey::new([1u8; 32]),
                    "desk".parse::<DeviceLabel>().unwrap(),
                )
                .unwrap(),
            signet
                .member(
                    VerifyKey::new([2u8; 32]),
                    "ci-runner".parse::<DeviceLabel>().unwrap(),
                )
                .unwrap(),
        ],
    )
    .unwrap();
    // The blob a puller reads is the ARTIFACT on disk, cut by the signet when membership last changed,
    // so this proof assembles the handler exactly as the product `serve` path does: write, load, serve.
    let artifact_path = std::env::temp_dir().join(format!(
        "swoosh-gated-roster-artifact-{}/roster",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(artifact_path.parent().unwrap());
    roster::Artifact::write(&artifact_path, &signet.sign_update(&doc))
        .await
        .unwrap();
    let artifact = Arc::new(roster::Artifact::open(artifact_path.clone()).await.unwrap());

    // The coordination node: serves the update route behind the anchored gate its home pins to the
    // signet, through the SAME handler and access class the product `serve` path binds.
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let host_home = pinned_home("host").await;
    let own_slip = issue_own_slip(&host_home).await;
    tokio::task::spawn_local(async move {
        let (gate, cut) = swoosh::gate::anchored(&host_home, TestNode::seeded(OWN).node_id())
            .await
            .unwrap();
        let router = Router::new(gate)
            .member_service(
                ROSTER_SERVICE.parse().unwrap(),
                swoosh::serve::Roster::new(artifact),
            )
            .unwrap();
        router
            .expose()
            .unwrap()
            .with_live_cuts(cut)
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });

    // A MEMBER pulls the roster: open the gated service, read the blob to EOF, decode, and VERIFY against the
    // signet it trusts. The blob is self-delimiting + signature-checked, so a valid pull yields the doc.
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_badge = signet_badge(SIGNET, member.node_id());
    let session = Connector::to_node(
        host_id,
        ROSTER_SERVICE.parse().unwrap(),
        Some(member_badge.parse().unwrap()),
    )
    .open_service(&member)
    .await
    .expect("member reaches the roster service");
    let (send, mut recv) = session
        .open_bi()
        .await
        .expect("member is admitted at roster");
    drop(send); // the roster is a read; signal we send nothing so the handler's write completes
    let mut bytes = Vec::new();
    recv.read_to_end(&mut bytes)
        .await
        .expect("read the roster blob");

    let verified = roster::verify(&bytes, signet.verify_key())
        .expect("the roster is signed by the signet we trust");

    // Hydrate contacts from the VERIFIED doc and see the whole fleet under `me`, with no id copied by hand.
    let mut contacts = Contacts::default();
    let _ = contacts.hydrate(&verified);
    assert_eq!(
        resolve(&contacts, "me/desk"),
        vec![NodeId::new(CryptoKind::Ed25519, [1u8; 32])]
    );
    assert_eq!(
        resolve(&contacts, "me/ci-runner"),
        vec![NodeId::new(CryptoKind::Ed25519, [2u8; 32])]
    );

    // A node whose signet has cut NOTHING yet: the puller must be able to tell that apart from a node
    // serving a blob it cannot verify, because the two have completely different fixes.
    let empty_path = std::env::temp_dir().join(format!(
        "swoosh-gated-roster-empty-{}/roster",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(empty_path.parent().unwrap());
    let empty = Arc::new(roster::Artifact::open(empty_path).await.unwrap());
    let bare = Node::new(MemTransport::bind(), NoDiscovery);
    let bare_id = bare.node_id();
    let bare_home = pinned_home("bare").await;
    tokio::task::spawn_local(async move {
        let (gate, _cut) = swoosh::gate::anchored(&bare_home, TestNode::seeded(OWN).node_id())
            .await
            .unwrap();
        Router::new(gate)
            .member_service(
                ROSTER_SERVICE.parse().unwrap(),
                swoosh::serve::Roster::new(empty),
            )
            .unwrap()
            .expose()
            .unwrap()
            .run(&bare, CancellationToken::new())
            .await
            .unwrap();
    });
    let member_badge = signet_badge(SIGNET, member.node_id());
    let session = Connector::to_node(
        bare_id,
        ROSTER_SERVICE.parse().unwrap(),
        Some(member_badge.parse().unwrap()),
    )
    .open_service(&member)
    .await
    .expect("a member reaches the service");
    let (send, mut recv) = session.open_bi().await.expect("the member is admitted");
    drop(send);
    let mut bytes = Vec::new();
    recv.read_to_end(&mut bytes).await.expect("the read lands");
    assert_eq!(
        roster::verify(&bytes, signet.verify_key()),
        Err(roster::RosterVerifyError::Empty),
        "a node that has cut nothing is its OWN condition; reporting it as a signature failure sends \
         the operator hunting a forgery that is not there"
    );

    // A STRANGER (a badge rooted at a key the gate never trusts) is refused at the gated roster service, so
    // it never reads the member set (delib-28 containment).
    let stranger = Node::new(MemTransport::bind(), NoDiscovery);
    let stranger_badge = signet_badge(3, stranger.node_id());
    let refused = Connector::to_node(
        host_id,
        ROSTER_SERVICE.parse().unwrap(),
        Some(stranger_badge.parse().unwrap()),
    )
    .open_service(&stranger)
    .await
    .expect("the base connect lands; the gate refuses per-stream");
    assert!(
        refused.open_bi().await.is_err(),
        "a stranger must be refused at the gated roster service"
    );

    // A link the node signed itself, for this very route, recorded in its ledger: the gate admits the
    // slip, and the route's member floor refuses it, so a link never reads the member set.
    let holder = Node::new(MemTransport::bind(), NoDiscovery);
    let refused = Connector::to_node(host_id, ROSTER_SERVICE.parse().unwrap(), Some(own_slip))
        .open_service(&holder)
        .await
        .expect("the base connect lands; the route refuses per-stream");
    assert!(
        refused.open_bi().await.is_err(),
        "the update route admits members only, never a link"
    );
}

/// A scratch home pinned to the signet, as a device of it holds one.
async fn pinned_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-gated-roster-home-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let home = Home::resolve(Some(dir)).unwrap();
    swoosh::config::write_signet(&home, TestRoot::seeded(SIGNET).node_id())
        .await
        .unwrap();
    home
}

/// A link for the update route the node's own key signs, recorded in its ledger as `grant issue` records
/// one, so the gate admits it and only the route's member floor stands between it and the member set.
async fn issue_own_slip(home: &Home) -> nauthy::Link {
    let service: nauthy::Service = ROSTER_SERVICE.parse().unwrap();
    let slip = TestNode::seeded(OWN)
        .slip(
            &service,
            nauthy::Request::expires_in(Duration::from_secs(300)),
        )
        .unwrap();
    Grants::at(home.grants())
        .append(&GrantRecord {
            target: GrantTarget::Service(service),
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

/// Resolve a `me/<device>` address to its node ids through a hydrated contacts book.
fn resolve(contacts: &Contacts, addr: &str) -> Vec<NodeId> {
    contacts
        .resolve_candidates(&addr.parse().unwrap())
        .unwrap()
        .into_iter()
        .map(|candidate| candidate.node)
        .collect()
}

fn signet_badge(signer: u8, bound: NodeId) -> String {
    TestRoot::seeded(signer)
        .device_badge(bound, nauthy::Request::expires_in(Duration::from_secs(300)))
        .unwrap()
        .to_string()
}
