use bifrost::{RefusalDetail, RefusalDetailError};

use super::{MethodRefusal, ProtocolError, Request, Response};

#[tokio::test]
async fn request_variants_roundtrip() {
    let requests = [
        Request::Ping {
            seq: 7,
            sent_unix_nanos: 1_234_567_890,
        },
        Request::SpeedSink {
            limit_bytes: 8 * 1024 * 1024,
        },
        Request::SpeedSource {
            limit_bytes: Some(4 * 1024 * 1024),
        },
        // The unbounded (time-bounded download) source, encoded via the sentinel.
        Request::SpeedSource { limit_bytes: None },
        Request::SpeedBidir {
            limit_bytes: Some(2 * 1024 * 1024),
        },
        // The unbounded (time-bounded) bidir, encoded via the same sentinel.
        Request::SpeedBidir { limit_bytes: None },
    ];
    for request in requests {
        let mut buf = Vec::new();
        request.write(&mut buf).await.unwrap();
        let decoded = Request::read(&mut buf.as_slice()).await.unwrap();
        assert_eq!(decoded, request);
    }
}

#[tokio::test]
async fn response_variants_roundtrip() {
    let responses = [
        Response::Pong {
            seq: 3,
            sent_unix_nanos: 42,
        },
        Response::Received { bytes: 1024 },
        // The download go-ahead and the typed refusal frame: both must survive the wire so a client can
        // tell "here comes the payload" and "this method is refused" from each other and from a raw read.
        // Every method-refusal code is exercised, so a new code cannot reuse a tag unnoticed.
        Response::Sourcing,
        Response::Unsupported {
            code: MethodRefusal::WrongMethod,
            detail: RefusalDetail::bounded("this node serves ping, not speed"),
        },
        Response::Unsupported {
            code: MethodRefusal::RateLimited,
            detail: RefusalDetail::bounded("ping rate limited for this caller"),
        },
        Response::Unsupported {
            code: MethodRefusal::Busy,
            detail: RefusalDetail::bounded("a transfer slot is busy"),
        },
    ];
    for response in &responses {
        let mut buf = Vec::new();
        response.write(&mut buf).await.unwrap();
        let decoded = Response::read(&mut buf.as_slice()).await.unwrap();
        assert_eq!(&decoded, response);
    }
}

#[tokio::test]
async fn rejects_foreign_stream() {
    let mut buf = b"XXXXnonsense".as_slice();
    assert!(matches!(
        Request::read(&mut buf).await,
        Err(ProtocolError::BadMagic)
    ));
}

#[tokio::test]
async fn rejects_unknown_request_tag() {
    let mut buf = b"DG02\x7f".as_slice();
    assert!(matches!(
        Request::read(&mut buf).await,
        Err(ProtocolError::UnknownRequest(0x7f))
    ));
}

#[tokio::test]
async fn rejects_an_unknown_refusal_code() {
    // An unsupported response whose code byte selects nothing we know: rejected as itself, never
    // misread as a known method.
    let buf = [super::resp_tag::UNSUPPORTED, super::refusal_tag::BUSY + 1];
    assert!(matches!(
        Response::read(&mut buf.as_slice()).await,
        Err(ProtocolError::UnknownRefusalCode(_))
    ));
}

#[tokio::test]
async fn rejects_an_over_cap_detail_claim_before_allocating() {
    // A hand-written frame claiming one byte past the cap: the reader rejects the claim without reading
    // (or allocating) a body at all, so a hostile length can never make the client allocate on demand.
    let mut buf = vec![
        super::resp_tag::UNSUPPORTED,
        super::refusal_tag::WRONG_METHOD,
    ];
    buf.extend_from_slice(&(RefusalDetail::MAX_LEN as u32 + 1).to_be_bytes());
    assert!(matches!(
        Response::read(&mut buf.as_slice()).await,
        Err(ProtocolError::BadDetail(RefusalDetailError::TooLong(_)))
    ));
}

#[tokio::test]
async fn rejects_a_detail_that_is_not_utf8() {
    // The bytes are in-cap but not UTF-8: a corrupt frame is rejected, never repaired with replacement
    // characters the way a lossy decode would.
    let mut buf = vec![
        super::resp_tag::UNSUPPORTED,
        super::refusal_tag::WRONG_METHOD,
    ];
    let invalid = [0xffu8, 0xfe];
    buf.extend_from_slice(&(invalid.len() as u32).to_be_bytes());
    buf.extend_from_slice(&invalid);
    assert!(matches!(
        Response::read(&mut buf.as_slice()).await,
        Err(ProtocolError::BadDetail(RefusalDetailError::NotUtf8))
    ));
}
