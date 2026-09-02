// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The gated beam (PUSH file transfer), end to end over the in-process transport: the proof that a pushed
//! file rides the family gate (a MEMBER can beam a file to a gated node, a STRANGER cannot), that the bytes
//! are verified end to end, and that a tampered blob is REJECTED, never written.
//!
//! One node exposes `beam=beam:` behind a family gate rooted at a signet, assembled through the SAME
//! `registry()` the `swoosh serve` product path builds (so this exercises the identical handler swoosh
//! serves, into a real temp output directory). A member drives `bifrost-wire`'s verified `Transfer` over
//! the gated `beam` service exactly as `swoosh beam` does: it opens one stream per file, sends the blob, and
//! the receiver saves it under the safe relative name. A stranger's push is refused at the gate. And a blob
//! whose bytes do not match its advertised root is rejected by the receiver's BLAKE3 check, so a tampered
//! transfer leaves no file behind.
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a badge must bind to whatever id the
//! mem transport proves for the dialer; see `gated_measure.rs` for the full note on why the badge is signed
//! here rather than run through `mint`/`adopt`.

use core::time::Duration;

use bifrost::wire::{Blob, Transfer};
use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::{Denylist, Identity};
use tightbeam::identity::AsVerifyKey as _;
use tightbeam::tunnel::{self, CancellationToken, Connector, Exposer, Services};

/// The signet's fixed secret. Its ed25519 public half is the signet the family gate trusts, and it roots
/// every membership badge minted here.
const SIGNET_SECRET: [u8; 32] = [7u8; 32];

/// The ssh host-key seed the exposer's registry carries. Unused by this test (it exercises `beam`, not
/// `sshd`), but the shared `registry()` derives `sshd` from it, so a fixed value keeps the build stable.
const HOST_SEED: [u8; 32] = [9u8; 32];

#[test]
fn a_member_beams_a_file_a_stranger_is_refused_and_a_tampered_blob_is_rejected() {
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

/// The proof body: expose a gated beam-receive node, beam a file as a member, refuse a stranger, reject a
/// tampered blob.
async fn proof() {
    let out = out_dir();
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let signet = NodeId::from_ed25519_secret(&SIGNET_SECRET);
    let out_for_host = out.clone();
    tokio::task::spawn_local(async move {
        let services = Services::parse(&["beam=beam:".to_owned()]).unwrap();
        let gate = tunnel::resolve_gate(false, Some(signet), empty_denylist("host").await).unwrap();
        let registry = swoosh::commands::serve::registry(
            HOST_SEED,
            out_for_host,
            fetch::OriginAllowlist::default(),
        )
        .unwrap();
        Exposer::new(services, registry, gate)
            .unwrap()
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });

    // A MEMBER: a badge the signet signed, rooted at the signet and bound to the member's proven mem id, so
    // the gate's `bound_device` check matches. See `gated_measure.rs` for why it is signed here.
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_badge = signet_badge(&SIGNET_SECRET, member.node_id());

    // Beam a file exactly as `swoosh beam` does: open the gated `beam` service, then drive `bifrost-wire`'s
    // verified `Transfer` over one admitted stream, naming the file so the receiver saves it under that name.
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(1000);
    let session = Connector::to_node(host_id, "beam".to_owned(), Some(member_badge.clone()))
        .open_service(&member)
        .await
        .expect("member reaches the beam service");
    let (send, recv) = session.open_bi().await.expect("member is admitted at beam");
    let blob = Blob::hash(&mut payload.as_slice()).await.unwrap();
    Transfer::new(send, recv)
        .send(b"report.txt", &blob, &mut payload.as_slice())
        .await
        .expect("the member's push is accepted and acknowledged");

    // The file landed under the receiver's output directory, byte-for-byte.
    let landed = wait_for_file(&out.join("report.txt")).await;
    assert_eq!(landed, payload, "the beamed file arrives byte-for-byte");

    // A STRANGER: a self-signed badge rooted at a random key the gate never trusts. Its push is refused at
    // the gate, so opening the beam stream fails; no file is written.
    let stranger = Node::new(MemTransport::bind(), NoDiscovery);
    let stranger_badge = signet_badge(&[3u8; 32], stranger.node_id());
    let refused = Connector::to_node(host_id, "beam".to_owned(), Some(stranger_badge))
        .open_service(&stranger)
        .await
        .expect("the base connect lands; the gate refuses per-stream");
    assert!(
        refused.open_bi().await.is_err(),
        "a stranger must be refused at the gated beam service"
    );

    // A TAMPERED blob: a member advertises one root but sends different bytes. The receiver's BLAKE3 check
    // fails, so the send is NAKed (an error to the sender) and no file with that name is written.
    let session = Connector::to_node(host_id, "beam".to_owned(), Some(member_badge))
        .open_service(&member)
        .await
        .expect("member reaches the beam service");
    let (send, recv) = session.open_bi().await.expect("member is admitted at beam");
    let honest = b"the bytes I hashed".to_vec();
    let blob = Blob::hash(&mut honest.as_slice()).await.unwrap();
    // Send DIFFERENT bytes than the hash names (same length, so only the content check can catch it).
    let mut tampered = b"THE BYTES I SWAPD".to_vec();
    tampered.resize(honest.len(), b'!');
    let result = Transfer::new(send, recv)
        .send(b"tampered.txt", &blob, &mut tampered.as_slice())
        .await;
    assert!(
        result.is_err(),
        "a blob whose bytes do not match its root must be rejected by the receiver"
    );
    assert!(
        !out.join("tampered.txt").exists(),
        "a rejected transfer must leave no file behind"
    );

    let _ = std::fs::remove_dir_all(&out);
}

/// A fresh, empty output directory for this test run's received files.
fn out_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("swoosh-gated-beam-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Wait briefly for the receiver's task to write and rename the file into place (the push acked, but the
/// atomic rename runs just after on the host's task), then read it. Bounded so a real failure does not hang.
async fn wait_for_file(path: &std::path::Path) -> Vec<u8> {
    for _ in 0..200 {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return bytes;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("beamed file never landed at {}", path.display());
}

/// Mint a membership badge signed by `secret`, bound to `bound` (the dialer's proven node id). See
/// `gated_measure.rs` for the full rationale.
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

/// An empty revocation denylist (an absent file is an empty set). `tag` keeps parallel tests' paths apart.
async fn empty_denylist(tag: &str) -> Denylist {
    let path = std::env::temp_dir().join(format!("swoosh-gated-beam-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Denylist::load(path).await.unwrap()
}
