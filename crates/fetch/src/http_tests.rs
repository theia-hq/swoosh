use crate::http::{FetchRequest, FetchResponse};

#[tokio::test]
async fn request_roundtrips_with_headers_and_query() {
    let request = FetchRequest {
        method: "GET".to_string(),
        url: "https://example.com/big.iso?token=abc".to_string(),
        headers: vec![
            ("Range".to_string(), "bytes=0-1023".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
        ],
    };
    let mut buf = Vec::new();
    request.write(&mut buf).await.expect("write");
    let mut slice: &[u8] = &buf;
    let read = FetchRequest::read(&mut slice).await.expect("read");
    assert_eq!(read, request);
}

#[tokio::test]
async fn response_ok_roundtrips_and_carries_range_status() {
    let response = FetchResponse::Ok {
        status: 206,
        headers: vec![
            ("Content-Range".to_string(), "bytes 0-1023/4096".to_string()),
            ("Accept-Ranges".to_string(), "bytes".to_string()),
        ],
    };
    let mut buf = Vec::new();
    response.write(&mut buf).await.expect("write");
    let mut slice: &[u8] = &buf;
    let read = FetchResponse::read(&mut slice).await.expect("read");
    assert_eq!(read, response);
}

#[tokio::test]
async fn response_error_roundtrips() {
    let response = FetchResponse::Error("origin unreachable".to_string());
    let mut buf = Vec::new();
    response.write(&mut buf).await.expect("write");
    let mut slice: &[u8] = &buf;
    let read = FetchResponse::read(&mut slice).await.expect("read");
    assert_eq!(read, response);
}

#[tokio::test]
async fn a_foreign_stream_is_rejected() {
    let buf = b"XXXXnope".to_vec();
    let mut slice: &[u8] = &buf;
    assert!(FetchRequest::read(&mut slice).await.is_err());
}
