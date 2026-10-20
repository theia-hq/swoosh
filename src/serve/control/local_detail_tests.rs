use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::alloc::System;

use tokio::io;

use super::{
    ControlError, LocalDetailCaptureError, LocalDetailError, LocalDetailLimit, LocalServicePairs,
    LocalServiceSnapshot, checked_end, decode, protocol, storage,
};
use crate::serve::control::{Request, Response};

// Thread-local accounting excludes unrelated parallel tests and measures requested storage, not RSS.
std::thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static FAIL: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static POINTER: Cell<usize> = const { Cell::new(0) };
}
struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

// SAFETY: every successful operation delegates unchanged to System; failure returns a null pointer.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL.get() {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller supplied a valid allocation layout.
        let pointer = unsafe { System.alloc(layout) };
        if TRACK.get() {
            ALLOCS.set(ALLOCS.get() + 1);
            POINTER.set(pointer as usize);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer and layout are passed through from the allocation's owner.
        unsafe { System.dealloc(pointer, layout) };
    }
}

fn body(pairs: &[(&[u8], &[u8], u8)]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&u16::try_from(pairs.len()).unwrap().to_be_bytes());
    for (name, target, refused) in pairs {
        out.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
        out.extend_from_slice(target);
        out.push(*refused);
    }
    out
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = b"SWC1\x09".to_vec();
    out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn read(payload: &[u8]) -> Result<Response, ControlError> {
    Response::read(&mut frame(payload).as_slice()).await
}

async fn rejects(payload: &[u8], expected: &str) {
    let error = read(payload).await.unwrap_err();
    assert!(
        matches!(error, ControlError::Protocol(ref reason) if reason == expected),
        "{error:?}"
    );
}

#[tokio::test]
async fn exact_vectors_round_trip_without_normalizing_targets() {
    let vectors: &[&[u8]] = &[
        &[0, 0, 0],
        &[0, 0, 1, 0, 1, b'a', 0, 1, b'x', 0],
        &[0, 0, 1, 0, 1, b'a', 0, 1, b'x', 1],
        &[1],
        &[2, 1],
        &[2, 2],
        &[2, 3],
        &[2, 4],
        &[3],
    ];
    for payload in vectors {
        let response = read(payload).await.unwrap();
        let mut encoded = Vec::new();
        response.write(&mut encoded).await.unwrap();
        assert_eq!(encoded, frame(payload));
    }
    let Response::LocalServiceDetail(Ok(empty)) = read(vectors[0]).await.unwrap() else {
        panic!()
    };
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    for refused in [0, 1] {
        let payload = body(&[(b"a", "unix:秘密=a=b".as_bytes(), refused)]);
        let Response::LocalServiceDetail(Ok(snapshot)) = read(&payload).await.unwrap() else {
            panic!()
        };
        let pair = snapshot.get("a").unwrap();
        assert_eq!(pair.name().as_str(), "a");
        assert_eq!(pair.target().as_str(), "unix:秘密=a=b");
        assert_eq!(pair.refused(), refused == 1);
        assert!(!snapshot.contains("A"));
        assert!(!format!("{snapshot:?}").contains("秘密"));
    }
    for (payload, expected) in vectors[3..].iter().zip([
        LocalDetailCaptureError::MissingStartup,
        LocalDetailCaptureError::LimitExceeded(LocalDetailLimit::BoundCount),
        LocalDetailCaptureError::LimitExceeded(LocalDetailLimit::NameBytes),
        LocalDetailCaptureError::LimitExceeded(LocalDetailLimit::TargetBytes),
        LocalDetailCaptureError::LimitExceeded(LocalDetailLimit::PayloadBytes),
        LocalDetailCaptureError::InconsistentState,
    ]) {
        assert_eq!(
            read(payload).await.unwrap(),
            Response::LocalServiceDetail(Err(expected))
        );
        let mapped: LocalDetailError = expected.into();
        assert_eq!(mapped.to_string(), expected.to_string());
    }
}

#[tokio::test]
async fn malformed_bodies_reach_the_named_canonical_check() {
    let valid = body(&[(b"a", b"x", 0)]);
    for end in 0..valid.len() {
        rejects(&valid[..end], "local service detail is truncated").await;
    }
    for name in [
        b"".as_slice(),
        b"A",
        b"a.b",
        b"-a",
        b"a_",
        b"control",
        b"lookup",
        &[255],
    ] {
        rejects(&body(&[(name, b"x", 0)]), "invalid local service name").await;
    }
    for target in [b"".as_slice(), &[255]] {
        rejects(&body(&[(b"a", target, 0)]), "invalid local service target").await;
    }
    for refused in [2, 255] {
        rejects(
            &body(&[(b"a", b"x", refused)]),
            "invalid local service refusal byte",
        )
        .await;
    }
    for second in [b"a".as_slice(), b"0"] {
        rejects(
            &body(&[(b"a", b"x", 0), (second, b"y", 1)]),
            "local service names are not strictly ordered",
        )
        .await;
    }
    rejects(&[4], "unknown local service detail outcome").await;
    for dimension in [0, 5, 255] {
        rejects(&[2, dimension], "unknown local service detail limit").await;
    }
    for mut payload in [valid, vec![1], vec![2, 1], vec![3]] {
        payload.push(0);
        rejects(&payload, "unexpected trailing local service detail bytes").await;
    }
    rejects(&[2], "local service detail is truncated").await;
}

#[tokio::test]
async fn simultaneous_field_count_and_frame_limits_hold() {
    let name = [b'a'; 63];
    assert!(read(&body(&[(&name, b"x", 0)])).await.is_ok());
    rejects(
        &body(&[(&[b'a'; 64], b"x", 0)]),
        "local service name exceeds 63 bytes",
    )
    .await;
    assert!(read(&body(&[(b"a", &[b'x'; 4096], 0)])).await.is_ok());
    rejects(
        &body(&[(b"a", &[b'x'; 4097], 0)]),
        "local service target exceeds 4096 bytes",
    )
    .await;
    let names: Vec<_> = (0..256).map(|i| format!("a{i:03}")).collect();
    let pairs: Vec<_> = names
        .iter()
        .map(|name| (name.as_bytes(), b"x".as_slice(), 0))
        .collect();
    assert!(read(&body(&pairs)).await.is_ok());
    rejects(
        &[0, 1, 1],
        "local service detail has too many bound services",
    )
    .await;
    let exact = body(&[(b"a", &[b'x'; 4096], 0), (b"b", &[b'y'; 4081], 0)]);
    assert_eq!(exact.len(), 8192);
    let response = read(&exact).await.unwrap();
    let mut output = Vec::new();
    response.write(&mut output).await.unwrap();
    assert_eq!(output, frame(&exact));
    let over = body(&[(b"a", &[b'x'; 4096], 0), (b"b", &[b'y'; 4082], 0)]);
    assert_eq!(over.len(), 8193);
    assert!(matches!(
        read(&over).await,
        Err(ControlError::TooLarge(8193))
    ));
    assert!(matches!(
        checked_end(usize::MAX, 1),
        Err(ControlError::Protocol(_))
    ));
    assert_eq!(checked_end(8191, 1).unwrap(), 8192);
}

#[test]
fn storage_is_fallible_bounded_and_transferred_without_copying() {
    assert!(matches!(storage(8193), Err(ControlError::TooLarge(8193))));
    for len in [0, 3, 8192] {
        let bytes = storage(len).unwrap();
        assert_eq!(bytes.len(), len);
        assert!(bytes.capacity() <= 8192);
    }
    FAIL.set(true);
    let failed = storage(10);
    let diagnostic_failed = protocol("invalid local service name");
    FAIL.set(false);
    assert!(matches!(
        failed,
        Err(ControlError::LocalDetail(
            LocalDetailError::ResourceUnavailable
        ))
    ));
    assert!(matches!(
        diagnostic_failed,
        ControlError::LocalDetail(LocalDetailError::ResourceUnavailable)
    ));
    let payload = body(&[(b"a", b"secret", 1), (b"b", b"x", 0)]);
    let pointer = payload.as_ptr();
    ALLOCS.set(0);
    TRACK.set(true);
    let snapshot = decode(payload).unwrap().unwrap();
    let count = snapshot.pairs().count();
    let contains = snapshot.contains("b");
    let target = snapshot.get("a").unwrap().target().as_str();
    TRACK.set(false);
    assert_eq!(ALLOCS.get(), 0);
    assert_eq!(snapshot.payload.as_ptr(), pointer);
    assert_eq!((count, contains, target), (2, true, "secret"));
    assert!(core::mem::size_of::<LocalServiceSnapshot>() <= core::mem::size_of::<Vec<u8>>() + 8);
    assert_eq!(
        core::mem::size_of::<LocalServicePairs<'_>>(),
        2 * core::mem::size_of::<usize>()
    );
}

struct BorrowWriter {
    header: [u8; 7],
    used: usize,
    pointer: usize,
    len: usize,
}
impl io::AsyncWrite for BorrowWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.used < 7 {
            let at = self.used;
            self.header[at..at + bytes.len()].copy_from_slice(bytes);
            self.used += bytes.len();
        } else {
            self.pointer = bytes.as_ptr() as usize;
            self.len = bytes.len();
        }
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn response_io_owns_one_payload_and_writes_it_by_borrow() {
    let encoded = frame(&body(&[(b"a", b"private-target", 0)]));
    ALLOCS.set(0);
    TRACK.set(true);
    let response = Response::read(&mut encoded.as_slice()).await.unwrap();
    TRACK.set(false);
    assert_eq!(ALLOCS.get(), 1);
    let Response::LocalServiceDetail(Ok(snapshot)) = &response else {
        panic!()
    };
    assert_eq!(snapshot.payload.as_ptr() as usize, POINTER.get());
    assert!(snapshot.payload.capacity() <= 8192);
    let mut writer = BorrowWriter {
        header: [0; 7],
        used: 0,
        pointer: 0,
        len: 0,
    };
    ALLOCS.set(0);
    TRACK.set(true);
    response.write(&mut writer).await.unwrap();
    TRACK.set(false);
    assert_eq!(ALLOCS.get(), 0);
    assert_eq!(writer.header, encoded[..7]);
    assert_eq!(writer.pointer, snapshot.payload.as_ptr() as usize);
    assert_eq!(writer.len, snapshot.payload.len());
    assert!(!format!("{response:?}").contains("private-target"));
    // A header-only input proves refusal precedes any payload read or allocation.
    ALLOCS.set(0);
    TRACK.set(true);
    let too_large = Response::read(&mut b"SWC1\x09\x20\x01".as_slice()).await;
    TRACK.set(false);
    assert!(matches!(too_large, Err(ControlError::TooLarge(8193))));
    assert_eq!(ALLOCS.get(), 0);
    let mut joined = encoded;
    joined.extend_from_slice(&frame(&[1]));
    let mut input = joined.as_slice();
    assert!(matches!(
        Response::read(&mut input).await,
        Ok(Response::LocalServiceDetail(Ok(_)))
    ));
    assert_eq!(input, frame(&[1]));
}

#[tokio::test]
async fn the_foundation_does_not_activate_request_six() {
    for (request, tag) in [
        (Request::Services, 1),
        (Request::Status, 2),
        (Request::Stop, 3),
    ] {
        let mut encoded = Vec::new();
        request.write(&mut encoded).await.unwrap();
        assert_eq!(encoded, [b'S', b'W', b'C', b'1', tag, 0, 0]);
        assert_eq!(
            Request::read(&mut encoded.as_slice()).await.unwrap(),
            request
        );
    }
    assert!(matches!(
        Request::read(&mut b"SWC1\x06\0\0".as_slice()).await,
        Err(ControlError::Protocol(_))
    ));
}
