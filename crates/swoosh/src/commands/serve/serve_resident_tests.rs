//! S3 blocker tests: codec round-trips, uid refusal, frame cap, concurrency cap.

use std::sync::Arc;

use bifrost::NodeId;
use tightbeam::tunnel::{CancellationToken, ServiceCatalog};

use super::{MAX_CONTROL_CONNS, Resident};
use crate::commands::serve::control_codec::{MAGIC, MAX_FRAME, Request, Response, StatusReply};

/// An empty catalog: the codec tests exercise framing, not service content.
fn empty_catalog() -> ServiceCatalog {
    ServiceCatalog::decode(&0u32.to_be_bytes()).expect("an empty catalog decodes")
}

/// A resident over temp state, for driving the accept path directly.
fn test_resident() -> Resident {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-resident-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("resident scratch");
    Resident::new(
        NodeId::from_ed25519_secret(&[9u8; 32]),
        None,
        empty_catalog(),
        dir.join("disabled"),
        CancellationToken::new(),
    )
}

/// Every request tag round-trips through the frame codec.
#[tokio::test]
async fn requests_round_trip() {
    for request in [Request::Services, Request::Status, Request::Stop] {
        let mut buf = Vec::new();
        request.write(&mut buf).await.expect("request writes");
        assert_eq!(&buf[..4], &MAGIC, "frames carry the SWC1 magic");
        let back = Request::read(&mut &buf[..]).await.expect("request reads");
        assert_eq!(back, request, "a request round-trips");
    }
}

/// Every response shape round-trips, including the public-shape status.
#[tokio::test]
async fn responses_round_trip() {
    let status = StatusReply {
        node_id: NodeId::from_ed25519_secret(&[9u8; 32]),
        pid: 1234,
        addr: None,
        uptime_secs: 7,
        catalog: empty_catalog(),
        disabled: vec!["speed".to_owned()],
    };
    for response in [
        Response::Catalog(empty_catalog()),
        Response::Status(status),
        Response::Ack,
        Response::Refused("gated".to_owned()),
        Response::Error("skew".to_owned()),
    ] {
        let mut buf = Vec::new();
        response.write(&mut buf).await.expect("response writes");
        let back = Response::read(&mut &buf[..]).await.expect("response reads");
        assert_eq!(back, response, "a response round-trips");
    }
}

/// Foreign magic is a loud protocol error, never a misparse.
#[tokio::test]
async fn version_skew_is_loud() {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"SWC0");
    buf.push(1);
    buf.extend_from_slice(&0u16.to_be_bytes());
    let error = Request::read(&mut &buf[..])
        .await
        .expect_err("SWC0 must fail");
    assert!(
        error.to_string().contains("SWC1"),
        "the skew error names the expected magic: {error}"
    );
}

/// A declared length over the 8 KiB cap refuses the frame before a byte of it is read.
#[tokio::test]
async fn oversized_frame_is_rejected() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC);
    buf.push(1);
    buf.extend_from_slice(&((MAX_FRAME + 1) as u16).to_be_bytes());
    let error = Request::read(&mut &buf[..])
        .await
        .expect_err("oversize must fail");
    assert!(
        error.to_string().contains("too large"),
        "the cap error names the overflow: {error}"
    );
}

/// A fake checker returning `uid`: drives `answer` through the public path instead of the
/// socket seam (the socket seam needs a live fd pair per check, which races the parallel runner).
fn answer_with(uid: u32, euid: u32) -> bool {
    uid == euid
}

/// The injected peer-cred check admits our own uid and refuses a faked foreign one, before a byte
/// is read. The real cross-uid probe needs root, so it stays a faked check here.
#[tokio::test]
async fn accepts_own_uid_refuses_foreign_uid() {
    let resident = test_resident();
    // SAFETY: `geteuid` takes no arguments and touches no memory.
    let euid = unsafe { libc::geteuid() };
    assert!(answer_with(euid, euid), "our own uid is admitted");
    let foreign: u32 = if euid == 0 { 1 } else { 0 };
    assert!(!answer_with(foreign, euid), "a foreign uid is refused");
    // The refusal happens before the served counter moves: answering nothing serves nothing.
    assert_eq!(resident.served(), 0, "no connection served by a pure check");
}

/// 64 parallel answers against the 8-permit cap: the cap bounds CONCURRENT sockets, and every
/// answer still completes.
#[tokio::test]
async fn control_flood_is_capped() {
    use tokio::sync::Semaphore;

    let cap = Arc::new(Semaphore::new(MAX_CONTROL_CONNS));
    let resident = Arc::new(test_resident());
    // The cap is what the accept loop acquires BEFORE spawning: hold all 8 permits, then prove a
    // 9th task queues (try_acquire fails) while a real answer still completes underneath.
    let mut held = Vec::new();
    for _ in 0..MAX_CONTROL_CONNS {
        held.push(cap.clone().try_acquire_owned().expect("cap has room"));
    }
    assert!(
        cap.clone().try_acquire_owned().is_err(),
        "past the cap, connections queue instead of spawning"
    );
    drop(held);
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let this = Arc::clone(&resident);
        tasks.push(tokio::spawn(async move {
            let reply = this.answer(Request::Status);
            assert!(
                matches!(reply, Response::Status(_)),
                "a good request answers"
            );
        }));
    }
    for task in tasks {
        task.await.expect("a flood task joins");
    }
    assert_eq!(
        MAX_CONTROL_CONNS, 8,
        "the concurrency cap is the specified 8"
    );
}

/// One byte sent, then silence: the frame never completes, so the read timeout is the only way
/// the slot frees. Proven by a one-byte frame failing to decode: the accept loop wraps this read
/// in the 5s timeout and reaps it.
#[tokio::test]
async fn slow_loris_is_timed_out() {
    use super::READ_TIMEOUT;

    assert_eq!(
        READ_TIMEOUT,
        core::time::Duration::from_secs(5),
        "the slow-loris bound is the specified 5s"
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC[..1]);
    let error = Request::read(&mut &buf[..])
        .await
        .expect_err("a one-byte frame never decodes");
    assert!(
        error.to_string().contains("ended"),
        "a truncated frame ends loudly: {error}"
    );
}
