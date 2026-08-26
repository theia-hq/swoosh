use super::{ProtocolError, Request, Response};

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
    ];
    for response in responses {
        let mut buf = Vec::new();
        response.write(&mut buf).await.unwrap();
        let decoded = Response::read(&mut buf.as_slice()).await.unwrap();
        assert_eq!(decoded, response);
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
    let mut buf = b"DG01\x7f".as_slice();
    assert!(matches!(
        Request::read(&mut buf).await,
        Err(ProtocolError::UnknownRequest(0x7f))
    ));
}
