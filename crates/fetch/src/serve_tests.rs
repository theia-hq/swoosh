use core::future::Future;
use core::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::http::FetchResponse;
use crate::serve::{
    FETCH_MAX_BYTES, Limits, allowed_method, forward_headers, is_public, stream_response,
};

#[test]
fn get_and_head_allowed_others_refused() {
    assert!(allowed_method("GET").is_ok());
    assert!(allowed_method("HEAD").is_ok());
    assert!(allowed_method("POST").is_err());
    assert!(allowed_method("CONNECT").is_err());
}

#[test]
fn forward_drops_hop_by_hop_and_host_keeps_range() {
    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("Connection".to_string(), "keep-alive".to_string()),
        ("Range".to_string(), "bytes=0-1023".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
    ];
    let names: Vec<&str> = forward_headers(&headers)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(names.contains(&"Range"));
    assert!(names.contains(&"Accept"));
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("host")));
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case("connection")));
}

#[test]
fn ssrf_guard_refuses_loopback_private_link_local_and_metadata() {
    // The addresses a slip-holder would use to pivot the node inward: all must be judged non-public so the
    // fetch is refused before any connection.
    for addr in [
        "127.0.0.1",              // loopback
        "10.0.0.5",               // RFC1918
        "172.16.0.1",             // RFC1918
        "192.168.1.1",            // RFC1918
        "169.254.169.254",        // cloud metadata (link-local)
        "100.64.0.1",             // CGNAT shared
        "0.0.0.0",                // unspecified
        "::1",                    // v6 loopback
        "fe80::1",                // v6 link-local
        "fc00::1",                // v6 unique-local
        "::ffff:169.254.169.254", // v4-mapped metadata must not slip past
        "64:ff9b::a9fe:a9fe",     // NAT64 well-known -> 169.254.169.254 on a DNS64 host
        "64:ff9b::a00:5",         // NAT64 well-known -> 10.0.0.5 (RFC1918)
        "::7f00:1",               // deprecated IPv4-compatible -> 127.0.0.1
        "::ffff:0:a9fe:a9fe",     // IPv4-translatable ::ffff:0:0/96 -> 169.254.169.254
    ] {
        let ip: IpAddr = addr.parse().expect("valid ip");
        assert!(!is_public(ip), "{addr} must be judged non-public");
    }
}

#[test]
fn ssrf_guard_allows_ordinary_public_addresses() {
    for addr in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:2800:220:1::1"] {
        let ip: IpAddr = addr.parse().expect("valid ip");
        assert!(is_public(ip), "{addr} must be judged public");
    }
}

/// The two limits carry the ratified caps: `metered` is the pair of bounds a scoped fetch enforces, and
/// `unmetered` is the member-only unscoped path with none.
#[test]
fn metered_limits_carry_the_fetch_caps() {
    assert!(Limits::metered().is_metered());
    assert!(!Limits::unmetered().is_metered());
}

/// An origin that never ends its body must not stream forever: the body stops exactly at the byte cap,
/// after a valid `Ok` header, and the write half closes.
#[tokio::test]
async fn an_infinite_origin_body_truncates_at_the_cap() {
    let (addr, origin) = spawn_origin(|mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .await
            .expect("response head");
        let chunk = vec![0x5au8; 64 * 1024];
        // Serve forever; the client's cap ends the read long before this loop ends.
        while stream.write_all(&chunk).await.is_ok() {}
    })
    .await;

    let response = local_get(addr).await;
    let mut wire = Vec::new();
    stream_response(&mut wire, response, Some(FETCH_MAX_BYTES))
        .await
        .expect("the capped stream closes cleanly");

    let mut cursor: &[u8] = &wire;
    let frame = FetchResponse::read(&mut cursor).await.expect("frame");
    assert!(
        matches!(frame, FetchResponse::Ok { status: 200, .. }),
        "a valid header precedes the truncated body"
    );
    assert_eq!(
        cursor.len() as u64,
        FETCH_MAX_BYTES,
        "the body stops exactly at the cap"
    );
    origin.abort();
}

/// Spawn a one-shot local origin: accept ONE connection, read its request head, then let `reply` write
/// the response. The engine's SSRF guard refuses loopback by design, so the body-bound test speaks to
/// this origin directly, through the same `reqwest::Response` a vetted fetch would produce.
async fn spawn_origin<F, Fut>(reply: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let addr = listener.local_addr().expect("bound address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_request_head(&mut stream).await;
        reply(stream).await;
    });
    (addr, task)
}

/// A reqwest client for the test's own local origin: no proxy, no redirects, no resolve pinning (the
/// engine's SSRF-vetted client cannot reach loopback by design).
fn local_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

/// Request `addr` through a plain local client and hand back the real origin response.
async fn local_get(addr: SocketAddr) -> reqwest::Response {
    local_client()
        .get(format!("http://{addr}/"))
        .send()
        .await
        .expect("origin response")
}

/// Read a request head off `stream` so the origin answers a real request, not an empty connection.
async fn read_request_head(stream: &mut TcpStream) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).await.is_err() {
            return;
        }
        head.push(byte[0]);
    }
}
