// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The gated `roster:` service end to end over the in-process transport: the whole B1 roster-sync loop
//! minus the live infra. A node serves its signet-signed roster (the SAME `roster_handler` the `swoosh
//! serve` path uses); a MEMBER pulls it, VERIFIES it against the signet, and HYDRATES its contacts, seeing
//! the whole fleet with no id-copying; a STRANGER is refused at the gate and never reads the member set.
//!
//! This exercises steps 4 (the served handler) and 5 (the pull: read, verify, hydrate) of the build spec.
//! The only thing it does not cover is the real GitHub-runner dial (step 6), which needs a live box.
//!
//! Over `mem` the proven peer is the transport's synthetic node id, so a member badge binds to whatever id
//! the mem transport proves for the dialer; see `gated_beam.rs` for the full note.

use core::time::Duration;

use bifrost::{CryptoKind, NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::{Denylist, Identity, VerifyKey};
use std::sync::Arc;
use swoosh::contacts::{Contacts, DeviceLabel};
use swoosh::roster::{self, Epoch, Member, RosterDoc};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Exposer, Services};
use tokio::io::AsyncReadExt as _;

/// The signet's fixed secret: its ed25519 public half is the signet the gate trusts and the key that signs
/// the roster, so a puller that trusts this signet accepts the served roster and refuses any other.
const SIGNET_SECRET: [u8; 32] = [7u8; 32];

/// The ssh host-key seed the shared `registry()` derives `sshd` from. Unused here (this exercises
/// `roster`), but a fixed value keeps the assembled registry stable.
const HOST_SEED: [u8; 32] = [9u8; 32];

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
    let signet = Identity::from_secret(&SIGNET_SECRET).unwrap();
    let doc = RosterDoc::new(
        Epoch(1),
        vec![
            Member {
                node: VerifyKey::new([1u8; 32]),
                label: "desk".parse::<DeviceLabel>().unwrap(),
            },
            Member {
                node: VerifyKey::new([2u8; 32]),
                label: "ci-runner".parse::<DeviceLabel>().unwrap(),
            },
        ],
    )
    .unwrap();
    let blob = Arc::new(roster::cut(&signet, &doc));

    // The coordination node: serves `roster:` behind a family gate rooted at the signet, through the SAME
    // handler the product `serve` path adds.
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let signet_id = NodeId::from_ed25519_secret(&SIGNET_SECRET);
    tokio::task::spawn_local(async move {
        let services = Services::parse(&["roster=roster:".to_owned()]).unwrap();
        let gate = tunnel::resolve_gate(false, Some(signet_id), empty_denylist("host").await).unwrap();
        let registry = swoosh::commands::serve::registry(HOST_SEED, std::env::temp_dir())
            .unwrap()
            .with("roster", swoosh::commands::serve::Roster::new(blob));
        Exposer::new(services, registry, gate)
            .unwrap()
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });

    // A MEMBER pulls the roster: open the gated service, read the blob to EOF, decode, and VERIFY against the
    // signet it trusts. The blob is self-delimiting + signature-checked, so a valid pull yields the doc.
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_badge = signet_badge(&SIGNET_SECRET, member.node_id());
    let session = Connector::to_node(host_id, "roster".to_owned(), Some(member_badge))
        .open_service(&member)
        .await
        .expect("member reaches the roster service");
    let (send, mut recv) = session.open_bi().await.expect("member is admitted at roster");
    drop(send); // the roster is a read; signal we send nothing so the handler's write completes
    let mut bytes = Vec::new();
    recv.read_to_end(&mut bytes).await.expect("read the roster blob");

    let verified = roster::verify(&bytes, signet.node_id())
        .expect("the roster is signed by the signet we trust");

    // Hydrate contacts from the VERIFIED doc and see the whole fleet under `me`, with no id copied by hand.
    let mut contacts = Contacts::default();
    contacts.hydrate(&verified);
    assert_eq!(
        resolve(&contacts, "me/desk"),
        vec![NodeId::new(CryptoKind::Ed25519, [1u8; 32])]
    );
    assert_eq!(
        resolve(&contacts, "me/ci-runner"),
        vec![NodeId::new(CryptoKind::Ed25519, [2u8; 32])]
    );

    // A STRANGER (a badge rooted at a key the gate never trusts) is refused at the gated roster service, so
    // it never reads the member set (delib-28 containment).
    let stranger = Node::new(MemTransport::bind(), NoDiscovery);
    let stranger_badge = signet_badge(&[3u8; 32], stranger.node_id());
    let refused = Connector::to_node(host_id, "roster".to_owned(), Some(stranger_badge))
        .open_service(&stranger)
        .await
        .expect("the base connect lands; the gate refuses per-stream");
    assert!(
        refused.open_bi().await.is_err(),
        "a stranger must be refused at the gated roster service"
    );
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

async fn empty_denylist(tag: &str) -> Denylist {
    let path = std::env::temp_dir().join(format!("swoosh-gated-roster-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Denylist::load(path).await.unwrap()
}
