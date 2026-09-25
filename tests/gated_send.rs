// Setup helpers here are free functions, so they fall outside `allow-unwrap-in-tests` (which exempts only
// test-attributed functions); panicking on failed test setup is exactly the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The gated send/recv (PUSH file transfer), end to end over the in-process transport: the proof that a
//! pushed file rides the family gate (a MEMBER can send a file to a gated node, a STRANGER cannot), that the bytes
//! are verified end to end, and that a tampered blob is REJECTED, never written.
//!
//! One node exposes `recv=recv:` behind a family gate rooted at a signet, built with the SAME `Recv` handler
//! the `swoosh serve` product path instances per receive service (recv is bound per service by value,
//! like `fetch:`, so this proof constructs the one receiver directly, into a real temp output
//! directory). A member drives `bifrost-wire`'s verified `Transfer` over the gated `recv` service exactly as
//! `swoosh send` does: it opens one stream per file, sends the blob, and the receiver saves it under the safe
//! relative name. A stranger's push is refused at the gate. And a blob whose bytes do not match its advertised
//! root is rejected by the receiver's BLAKE3 check, so a tampered transfer leaves no file behind.
//!
//! A second proof (`two_receive_services_each_save_into_their_own_dir`) exercises the per-service de-merge
//! end to end: two receive services, each its OWN `Recv` instance bound to ONLY its own output directory, so a
//! push to one lands in its dir and NEVER in the other's (the single-sink bug this fix removes).
//!
//! Over `mem` the proven peer is the transport's SYNTHETIC node id, so a badge must bind to whatever id the
//! mem transport proves for the dialer; see `gated_measure.rs` for the full note on why the badge is signed
//! here rather than run through `invite`/`join`.

use core::time::Duration;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bifrost::wire::{Blob, Transfer};
use bifrost::{NoDiscovery, Node, NodeId, Session as _};
use bifrost_mem::MemTransport;
use nauthy::FileDenylist;
use swoosh::serve::{Activity, Recv, bind_recv};
use swoosh::testkit::TestRoot;
use tightbeam::tunnel::{self, CancellationToken, Connector, Router};
use transfer::{Received, ReceivedSink};

/// The byte the signet's fixed key is seeded with. Its ed25519 public half is the signet the family gate
/// trusts, and it roots every membership badge minted here.
const SIGNET: u8 = 7;

#[test]
fn a_member_sends_a_file_a_stranger_is_refused_and_a_tampered_blob_is_rejected() {
    let _serial = one_receiver_at_a_time();
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

/// The proof body: expose a gated recv node, send a file as a member, refuse a stranger, reject a
/// tampered blob.
async fn proof() {
    let out = out_dir();
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let signet = TestRoot::seeded(SIGNET).node_id();
    let out_for_host = out.clone();
    tokio::task::spawn_local(async move {
        let gate = tunnel::resolve_gate(Some(signet), empty_denylist("host").await).unwrap();
        // recv is bound per service by value, so this proof builds the ONE receive handler directly, the
        // identical `Recv` the product path instances per receive service.
        Router::new(gate)
            .service("recv".parse().unwrap(), Recv::new(out_for_host))
            .unwrap()
            .expose()
            .unwrap()
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });

    // A MEMBER: a badge the signet signed, rooted at the signet and bound to the member's proven mem id, so
    // the gate's `bound_device` check matches. See `gated_measure.rs` for why it is signed here.
    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_badge = signet_badge(SIGNET, member.node_id());

    // Send a file exactly as `swoosh send` does: open the gated `recv` service, then drive `bifrost-wire`'s
    // verified `Transfer` over one admitted stream, naming the file so the receiver saves it under that name.
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(1000);
    let session = Connector::to_node(
        host_id,
        "recv".parse().unwrap(),
        Some(member_badge.clone().parse().unwrap()),
    )
    .open_service(&member)
    .await
    .expect("member reaches the recv service");
    let (send, recv) = session.open_bi().await.expect("member is admitted at recv");
    let blob = Blob::hash(&mut payload.as_slice()).await.unwrap();
    Transfer::new(send, recv)
        .send(b"report.txt", &blob, &mut payload.as_slice())
        .await
        .expect("the member's push is accepted and acknowledged");

    // The file landed under the receiver's output directory, byte-for-byte.
    let landed = wait_for_file(&out.join("report.txt")).await;
    assert_eq!(landed, payload, "the sent file arrives byte-for-byte");

    // A STRANGER: a self-signed badge rooted at a random key the gate never trusts. Its push is refused at
    // the gate, so opening the recv stream fails; no file is written.
    let stranger = Node::new(MemTransport::bind(), NoDiscovery);
    let stranger_badge = signet_badge(3, stranger.node_id());
    let refused = Connector::to_node(
        host_id,
        "recv".parse().unwrap(),
        Some(stranger_badge.parse().unwrap()),
    )
    .open_service(&stranger)
    .await
    .expect("the base connect lands; the gate refuses per-stream");
    assert!(
        refused.open_bi().await.is_err(),
        "a stranger must be refused at the gated recv service"
    );

    // A TAMPERED blob: a member advertises one root but sends different bytes. The receiver's BLAKE3 check
    // fails, so the send is NAKed (an error to the sender) and no file with that name is written.
    let session = Connector::to_node(
        host_id,
        "recv".parse().unwrap(),
        Some(member_badge.parse().unwrap()),
    )
    .open_service(&member)
    .await
    .expect("member reaches the recv service");
    let (send, recv) = session.open_bi().await.expect("member is admitted at recv");
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

/// The per-service de-merge, end to end: two receive services `a=recv:/x` and `b=recv:/y`, each its OWN `Recv`
/// instance bound to ONLY its own dir, so a push to `a` lands in /x and a push to `b` in /y, never crossing.
/// This is the proof the single-sink bug (both services writing to the first-named dir) is gone.
#[test]
fn two_receive_services_each_save_into_their_own_dir() {
    let _serial = one_receiver_at_a_time();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(two_dirs_proof()));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// The proof body: expose two receive services under distinct dirs, push a distinct file to each, and assert
/// each file lands ONLY in its own service's dir.
async fn two_dirs_proof() {
    let dir_a = out_dir_tagged("dir-a");
    let dir_b = out_dir_tagged("dir-b");
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let signet = TestRoot::seeded(SIGNET).node_id();
    let (a, b) = (dir_a.clone(), dir_b.clone());
    tokio::task::spawn_local(async move {
        // Two receive services, each its OWN `Recv` instance bound to ONLY its own dir, wired the way the
        // product `serve` path de-merges `a=recv:/x b=recv:/y`: each served name binds its own `Recv`
        // scoped to a single sink. This is the shape that makes the per-service dir load-bearing rather
        // than a shared node-wide value.
        let gate = tunnel::resolve_gate(Some(signet), empty_denylist("two-dirs").await).unwrap();
        Router::new(gate)
            .service("a".parse().unwrap(), Recv::new(a))
            .unwrap()
            .service("b".parse().unwrap(), Recv::new(b))
            .unwrap()
            .expose()
            .unwrap()
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });

    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let member_badge = signet_badge(SIGNET, member.node_id());

    // Push a distinct file to each service. The payloads differ so a crossed sink would be caught by content,
    // not just presence.
    let alpha = b"alpha payload".repeat(500);
    let beta = b"beta payload".repeat(500);
    push_file(&member, host_id, "a", &member_badge, b"alpha.txt", &alpha).await;
    push_file(&member, host_id, "b", &member_badge, b"beta.txt", &beta).await;

    // Each file lands in its OWN service's dir, byte-for-byte, and NOT in the other's: the per-service sink
    // holds, so the first-named dir no longer swallows every service's pushes.
    assert_eq!(
        wait_for_file(&dir_a.join("alpha.txt")).await,
        alpha,
        "service a's file lands in a's dir"
    );
    assert_eq!(
        wait_for_file(&dir_b.join("beta.txt")).await,
        beta,
        "service b's file lands in b's dir"
    );
    assert!(
        !dir_b.join("alpha.txt").exists(),
        "a's file must NOT appear in b's dir"
    );
    assert!(
        !dir_a.join("beta.txt").exists(),
        "b's file must NOT appear in a's dir"
    );

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// The engine's invariant, end to end over a real gated push: a `Recv` with a sink hands the landed file
/// to that sink as a value, exactly once, with the peer's raw name and the verified length, and prints
/// nothing itself. Its whole log target is captured for the run and must stay empty; a control event
/// proves the capture is live first, so an empty capture is a real observation and not a dead writer.
#[test]
fn an_engine_with_a_sink_reports_the_fact_and_prints_nothing() {
    let _serial = one_receiver_at_a_time();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(sink_proof()));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// The proof body: capture the engine's log target on this thread (the host runs on it too), expose a
/// sink-carrying `Recv`, push one hostile-named file, and read what the sink and the log each received.
async fn sink_proof() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&log);
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("transfer=trace")
        .with_writer(move || LogCapture(Arc::clone(&writer)))
        .finish();
    let _capturing = tracing::subscriber::set_default(subscriber);
    tracing::info!(target: "transfer", "control");
    assert!(
        !log.lock().unwrap().is_empty(),
        "the capture sees the engine's target"
    );
    log.lock().unwrap().clear();

    let out = out_dir_tagged("sink");
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let signet = TestRoot::seeded(SIGNET).node_id();
    let reported = Recorder::default();
    let engine = Recv::new(out.clone()).with_sink(reported.clone());
    tokio::task::spawn_local(async move {
        let gate =
            tunnel::resolve_gate(Some(signet), empty_denylist("sink-denylist").await).unwrap();
        Router::new(gate)
            .service("recv".parse().unwrap(), engine)
            .unwrap()
            .expose()
            .unwrap()
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });

    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let badge = signet_badge(SIGNET, member.node_id());
    let hostile = "evil\nname\u{1b}[31m\r.txt";
    let payload = b"hostile payload".repeat(100);
    push_file(
        &member,
        host_id,
        "recv",
        &badge,
        hostile.as_bytes(),
        &payload,
    )
    .await;
    assert_eq!(wait_for_file(&out.join(hostile)).await, payload);

    let facts = reported.settled().await;
    assert!(
        log.lock().unwrap().is_empty(),
        "the engine printed on its own: {:?}",
        String::from_utf8_lossy(&log.lock().unwrap())
    );
    assert_eq!(facts.len(), 1, "one landed file is one fact: {facts:?}");
    assert_eq!(
        facts[0].path,
        std::path::Path::new(hostile),
        "the fact carries the raw name"
    );
    assert_eq!(facts[0].bytes, payload.len() as u64);

    let _ = std::fs::remove_dir_all(&out);
}

/// The product's receive binding, both ways, over real gated pushes: `bind_recv` with the node's
/// renderer hands the engine its route's sink, so a landed file becomes one escaped line on the
/// renderer's writer; with no renderer (a `--quiet` node) the route gets no sink. Both routes serve on
/// one node, so the one line on the writer is also proof the quiet route added none.
#[test]
fn the_product_binding_renders_a_line_only_when_given_a_renderer() {
    let _serial = one_receiver_at_a_time();
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(binding_proof()));
        })
        .unwrap()
        .join()
        .unwrap();
}

/// The proof body: bind `loud` with a renderer and `hush` without one, push a hostile-named file to
/// each, and read the renderer's writer.
async fn binding_proof() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let activity = Activity::spawn(LogCapture(Arc::clone(&written))).unwrap();
    let loud_dir = out_dir_tagged("bind-loud");
    let hush_dir = out_dir_tagged("bind-hush");
    let host = Node::new(MemTransport::bind(), NoDiscovery);
    let host_id = host.node_id();
    let signet = TestRoot::seeded(SIGNET).node_id();
    let gate = tunnel::resolve_gate(Some(signet), empty_denylist("bind-denylist").await).unwrap();
    let router = Router::new(gate);
    let router = bind_recv(
        router,
        "loud".parse().unwrap(),
        loud_dir.clone(),
        Some(&activity),
    )
    .unwrap();
    let router = bind_recv(router, "hush".parse().unwrap(), hush_dir.clone(), None).unwrap();
    tokio::task::spawn_local(async move {
        router
            .expose()
            .unwrap()
            .run(&host, CancellationToken::new())
            .await
            .unwrap();
    });

    let member = Node::new(MemTransport::bind(), NoDiscovery);
    let badge = signet_badge(SIGNET, member.node_id());
    let hostile = "evil\nname\u{1b}[31m\r.txt";
    let payload = b"hostile payload".repeat(100);
    for (route, dir) in [("hush", &hush_dir), ("loud", &loud_dir)] {
        push_file(
            &member,
            host_id,
            route,
            &badge,
            hostile.as_bytes(),
            &payload,
        )
        .await;
        assert_eq!(wait_for_file(&dir.join(hostile)).await, payload);
    }

    let expected = "loud: received evil\\nname\\u{1b}[31m\\r.txt (1500 bytes)\n";
    for _ in 0..200 {
        if !written.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Held long enough for a second line, had the quiet route produced one, to reach the writer too.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        String::from_utf8_lossy(&written.lock().unwrap()),
        expected,
        "the route bound with the renderer prints one escaped line, and the quiet route none"
    );

    let _ = std::fs::remove_dir_all(&loud_dir);
    let _ = std::fs::remove_dir_all(&hush_dir);
}

/// Every test here that serves a `Recv` holds this for its whole run. tracing caches, per call site,
/// whether any subscriber wants an event, and a receiver running on another test's thread with no
/// subscriber can settle that cache while the no-print proof's capture is live, so an engine event
/// would slip past it and the proof would pass on a mutant. One receiver at a time closes that race.
fn one_receiver_at_a_time() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A sink that keeps every fact it is handed.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Received>>>);

impl ReceivedSink for Recorder {
    fn received(&self, file: Received) {
        self.0.lock().unwrap().push(file);
    }
}

impl Recorder {
    /// The facts so far, once the first has arrived: the engine reports just after its rename, so a test
    /// that saw the file land may still be a poll ahead of the report.
    async fn settled(&self) -> Vec<Received> {
        for _ in 0..200 {
            if !self.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.0.lock().unwrap().clone()
    }
}

/// A log writer into a shared buffer.
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Push one named file to a receiver `service` exactly as `swoosh send` does: open the gated service with the
/// member badge, then drive `bifrost-wire`'s verified `Transfer` over one admitted stream.
async fn push_file(
    member: &Node<MemTransport, NoDiscovery>,
    host_id: NodeId,
    service: &str,
    badge: &str,
    name: &[u8],
    payload: &[u8],
) {
    let session = Connector::to_node(
        host_id,
        service.parse().unwrap(),
        Some(badge.parse().unwrap()),
    )
    .open_service(member)
    .await
    .expect("member reaches the receive service");
    let (send, recv) = session.open_bi().await.expect("member is admitted at recv");
    // Two independent slice cursors over the same bytes: hashing advances one to EOF, so the send reads from
    // a fresh cursor at the start.
    let mut to_hash = payload;
    let blob = Blob::hash(&mut to_hash).await.unwrap();
    let mut to_send = payload;
    Transfer::new(send, recv)
        .send(name, &blob, &mut to_send)
        .await
        .expect("the member's push is accepted and acknowledged");
}

/// A fresh, empty output directory for this test run's received files.
fn out_dir() -> std::path::PathBuf {
    out_dir_tagged("out")
}

/// A fresh, empty output directory tagged so parallel receive services (or parallel tests) keep their sinks
/// apart. Removed first so a prior run's files never leak into an assertion.
fn out_dir_tagged(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("swoosh-gated-send-{tag}-{}", std::process::id()));
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
    panic!("sent file never landed at {}", path.display());
}

/// Mint a membership badge signed by the key `signer` seeds, bound to `bound` (the dialer's proven node id).
/// See `gated_measure.rs` for the full rationale.
fn signet_badge(signer: u8, bound: NodeId) -> String {
    TestRoot::seeded(signer)
        .device_badge(bound, nauthy::Request::expires_in(Duration::from_secs(300)))
        .unwrap()
        .to_string()
}

/// An empty revocation denylist (an absent file is an empty set). `tag` keeps parallel tests' paths apart.
async fn empty_denylist(tag: &str) -> FileDenylist {
    let path = std::env::temp_dir().join(format!("swoosh-gated-send-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    FileDenylist::load(path).await.unwrap()
}
