//! Tests for the bounded roster read: an honest coordination node's snapshot reads back whole, a blob
//! sitting at the wire's ceiling is read whole rather than truncated, and a node that streams past the
//! bound is refused for OVERRUNNING the read rather than for a signature that never failed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};
use std::sync::Arc;

use bifrost::NodeId;
use nauthy::VerifyKey;
use swoosh::contacts::DeviceLabel;
use swoosh::peer::Peer;
use swoosh::roster::{Epoch, MAX_ROSTER_BLOB, Member, RosterDoc};
use swoosh::testkit::TestRoot;
use tokio::io;

use super::read_roster;

/// How many times the wire's own cap the flooding fixture offers. Comfortably past the cap so a bounded
/// read is visibly bounded, and finite so that REMOVING the cap fails the assertions below instead of
/// hanging the suite on an endless peer, which reports nothing.
const FLOOD_MULTIPLE: u64 = 4;

/// The byte the flood is made of: any value, since nothing downstream of the read parses it. The read is
/// what is under test, and it counts bytes rather than reading them.
const FLOOD_BYTE: u8 = 0xAA;

/// A peer to name in a refusal. A raw key, so the fixture needs no contact store.
fn peer(seed: u8) -> Peer {
    Peer::Raw(NodeId::from_ed25519_secret(&[seed; 32]))
}

/// A deterministic signet for the cut/verify path.
fn signet(seed: u8) -> TestRoot {
    TestRoot::seeded(seed)
}

/// A roster of `count` members signed by `signet`: the blob a real coordination node serves.
fn cut_roster(signet: &TestRoot, count: usize) -> Vec<u8> {
    let standing = signet.standing(VerifyKey::new([0; 32])).unwrap();
    let members = (0..count)
        .map(|nth| Member {
            // Distinct and non-colliding: the first two bytes carry the index.
            node: VerifyKey::new({
                let mut bytes = [0u8; VerifyKey::LEN];
                bytes[..2].copy_from_slice(&(nth as u16).to_be_bytes());
                bytes
            }),
            label: format!("device-{nth}").parse::<DeviceLabel>().unwrap(),
            until: 0,
            duration: 0,
            ids: Vec::new(),
            standing: standing.clone(),
        })
        .collect();
    signet.sign_update(&RosterDoc::new(Epoch(9), members).unwrap())
}

/// A coordination node on the serving end of `roster:` that streams forever: it answers the read with
/// `remaining` bytes of noise and counts what it actually handed over.
///
/// What the counter proves and does not prove. It CANNOT see allocations: this workspace denies `unsafe`,
/// so a test cannot install an allocator probe and assert a `Vec`'s capacity from outside. What it can see
/// is how many bytes the node got to deliver, and `read_to_end` cannot buffer bytes it was never given, so
/// a delivery bounded at the cap is a buffer bounded at the cap. That is the property the guard exists for,
/// measured at the only seam a safe test can observe it from.
struct FloodingNode {
    /// Bytes still on offer; the fixture reports EOF once it reaches zero.
    remaining: u64,
    /// Bytes actually handed to the reader, shared so the test can read it after the refusal.
    delivered: Arc<AtomicU64>,
}

impl io::AsyncRead for FloodingNode {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let want = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.remaining());
        // Filling nothing is how this fixture spells EOF: the node has streamed all it offered.
        if want > 0 {
            buf.initialize_unfilled_to(want).fill(FLOOD_BYTE);
            buf.advance(want);
            self.remaining -= want as u64;
            self.delivered.fetch_add(want as u64, Ordering::Relaxed);
        }
        Poll::Ready(Ok(()))
    }
}

/// An honest node's roster still reads: the bound admits every snapshot a signet cuts, so the guard costs
/// the normal path nothing (zero, one, many).
#[tokio::test]
async fn a_roster_under_the_cap_reads_back_whole() {
    let signet = signet(7);
    for count in [0, 1, 32] {
        let blob = cut_roster(&signet, count);
        let read = read_roster(&blob[..], &peer(1))
            .await
            .expect("an honest node's roster reads");
        assert_eq!(read, blob, "the roster survives the bounded read");
    }
}

/// The read-seam half of the misdiagnosis guard: a blob sitting exactly AT the cap is a legitimate roster,
/// so it must come back whole and must not be mistaken for a node that would not stop. Short bytes here
/// fail the signature check downstream, which is how a size problem gets reported as a forgery.
///
/// What it cannot see: whether the cap is the RIGHT number. It builds its blob from `MAX_ROSTER_BLOB`, so
/// it holds only the off-by-one between reading the ceiling and refusing past it. That the ceiling is the
/// largest roster the parser accepts is the roster module's own exactness test, and only that test fails
/// when the bound drifts below the wire.
#[tokio::test]
async fn a_blob_at_the_ceiling_is_read_whole_rather_than_truncated() {
    let at_ceiling = vec![FLOOD_BYTE; MAX_ROSTER_BLOB as usize];
    let read = read_roster(&at_ceiling[..], &peer(1))
        .await
        .expect("a blob at the wire's ceiling is a legitimate roster, not an overrun");
    // The negative assertion FIRST: a truncating read also returns Ok, just short, and short bytes are
    // what get reported as a bad signature. Asserting the LENGTH is what fails when the cap drops below
    // the wire's own maximum; asserting only that the read succeeded would stay green.
    assert_eq!(
        read.len() as u64,
        MAX_ROSTER_BLOB,
        "the read must hand back every byte of the largest roster the parser accepts"
    );
    assert_eq!(read, at_ceiling, "and hand back the bytes the node served");
}

/// `swoosh fleet <peer>` reads bytes a REMOTE node chooses, so the coordination node is the attacker here:
/// without a bound on the READ it can grow this client's buffer for as long as it cares to stream, and the
/// parse-side caps cannot help because the buffer is already full by the time verify is called.
///
/// The fixture offers FLOOD_MULTIPLE times the wire's cap and the client must refuse, having accepted no
/// more than the cap plus the one byte that tells at-the-ceiling from over-it. See [`FloodingNode`] for
/// what the byte counter does and does not prove.
#[tokio::test]
async fn a_flooding_coordination_node_is_refused_before_it_fills_the_buffer() {
    let delivered = Arc::new(AtomicU64::new(0));
    let node = FloodingNode {
        remaining: MAX_ROSTER_BLOB * FLOOD_MULTIPLE,
        delivered: Arc::clone(&delivered),
    };
    let dial = peer(9);

    let Err(error) = read_roster(node, &dial).await else {
        panic!("a node streaming past the cap must be refused, never buffered");
    };
    // The negative assertion FIRST, and on the TEXT rather than merely on the error. Removing the cap is
    // caught above, by the `else` arm: an uncapped read swallows the whole flood and returns it. What the
    // text holds is the OTHER half, that the refusal names the right cause: the pull fails either way, and
    // failing at the signature seam on four times a roster's worth of noise is the forgery report this
    // change exists to stop. Asserting only that some error came back would report that as covered.
    let message = format!("{error:#}");
    assert!(
        message.contains("sent more than a roster can be"),
        "the refusal says the node overran the read, not that its roster is unsigned: {message}"
    );
    assert!(
        message.contains(&dial.to_string()),
        "the refusal names which node did it: {message}"
    );
    assert!(
        delivered.load(Ordering::Relaxed) <= MAX_ROSTER_BLOB + 1,
        "the client took {} bytes of the {} the node offered; the read is not bounded",
        delivered.load(Ordering::Relaxed),
        MAX_ROSTER_BLOB * FLOOD_MULTIPLE
    );
}

/// A fresh home that trusts `signet`, with `disabled` written to its latch.
async fn home_trusting(tag: &str, signet: NodeId, disabled: &[NodeId]) -> swoosh::home::Home {
    use tightbeam::identity::AsVerifyKey as _;

    let dir = std::env::temp_dir().join(format!("swoosh-fleet-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = swoosh::home::Home::resolve(Some(dir)).expect("resolve the home");
    swoosh::config::write_signet(&home, signet)
        .await
        .expect("trust the signet");
    for key in disabled {
        nauthy::DisabledRoots::open_for_repair(home.disabled_roots())
            .disable(key.verify_key())
            .await
            .expect("disable");
    }
    home
}

/// Pull from a coordination node that does not exist, so any dial fails: the error says whether the
/// pull got as far as dialing.
async fn pull(home: &swoosh::home::Home) -> eyre::Report {
    let node = bifrost::Node::new(bifrost_mem::MemTransport::bind(), bifrost::NoDiscovery);
    let cmd = super::FleetCmd {
        peer: peer(9),
        present: None,
        reach: swoosh::transport::ReachArgs {
            transport: swoosh::transport::Transport::default(),
            local: false,
            peer: Vec::new(),
            relay: None,
            resolver: None,
        },
    };
    cmd.run_fleet(
        &node,
        &swoosh::contacts::Contacts::default(),
        None,
        None,
        home,
    )
    .await
    .expect_err("there is no coordination node to pull from")
}

#[tokio::test]
async fn a_disabled_signet_refuses_the_pull_before_dialing() {
    let signet = NodeId::from_ed25519_secret(&[21u8; 32]);
    let home = home_trusting("disabled", signet, &[signet]).await;
    let refusal = format!("{:#}", pull(&home).await);
    assert!(
        refusal.contains("disabled at this node"),
        "the pull is refused for the disabled signet, before any dial: {refusal}"
    );
    assert!(
        !home.contacts().exists(),
        "a refused pull writes no contact"
    );
}

#[tokio::test]
async fn a_live_signet_goes_on_to_dial() {
    // Another key disabled, this one not: the pull proceeds to the dial, which fails for its own reason.
    let signet = NodeId::from_ed25519_secret(&[22u8; 32]);
    let other = NodeId::from_ed25519_secret(&[23u8; 32]);
    let home = home_trusting("live", signet, &[other]).await;
    let failure = format!("{:#}", pull(&home).await);
    assert!(
        !failure.contains("disabled"),
        "a signet that is not disabled is not refused as one: {failure}"
    );
}
