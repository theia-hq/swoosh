//! The origin-fetch handler: read a [`FetchRequest`] off the stream, perform
//! the HTTP GET/HEAD at the origin with a real HTTPS client (TLS terminates HERE, not at the requester),
//! and stream the response back (status + headers, then the body to stream close). This is the smallest
//! honest instance of "run this at a keyed node": a fetch, not a general proxy.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use futures::StreamExt as _;
use tokio::io::{self, AsyncWriteExt as _};

use crate::http::{FetchRequest, FetchResponse, MAX_HEADERS};
use crate::origin::OriginAllowlist;

/// How long to wait for a connector to send its fetch frame before dropping the stream. The exposer's
/// pre-gate request timeout does not cover this frame (it is read AFTER admission), so an admitted peer
/// could otherwise open a stream and dribble length prefixes forever. Same bound as the pre-gate one.
const FETCH_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Read one [`FetchRequest`], fetch the origin, write the [`FetchResponse`] + body, then close the write
/// half so the requester sees the body's end. The handler the composing consumer injects into the tunnel's
/// handler registry calls this with the admitted stream's halves.
///
/// `allow` is the operator's origin scope for this service, set at expose time: if it
/// is non-empty and the request's origin is not in it, the fetch is refused with a typed
/// [`FetchResponse::Error`] BEFORE any connection, IN FRONT of the SSRF guard, not instead of it. An empty
/// allowlist is unconstrained (an unscoped service), so today's any-public-origin behavior is unchanged.
pub async fn serve_fetch<W, R>(
    writer: &mut W,
    reader: &mut R,
    allow: &OriginAllowlist,
) -> io::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    // Bound the frame read: an admitted peer must send its request promptly, not hold a stream open by
    // stalling mid-frame. A timeout maps to a clean drop of this one stream.
    let request = match tokio::time::timeout(FETCH_READ_TIMEOUT, FetchRequest::read(reader)).await {
        Ok(result) => result?,
        Err(_) => return Err(io::Error::other("fetch request read timed out")),
    };
    let served = match fetch_origin(&request, allow).await {
        Ok(response) => stream_response(writer, response).await,
        Err(message) => FetchResponse::Error(message).write(writer).await,
    };
    // Always close the write half, even if the body errored mid-stream, so the requester sees a clean
    // EOF and can distinguish a complete response from a truncated one.
    let closed = writer.shutdown().await;
    served.and(closed)
}

/// Perform the origin request. Redirects are forwarded to the requester verbatim (not followed here), so
/// the client decides; TLS terminates at this node.
///
/// The origin is vetted before any connection: only `http`/`https`, and the host must resolve ENTIRELY to
/// public addresses. This stops a slip-holder from turning the node into an SSRF pivot: fetching its
/// loopback, its LAN (RFC1918), or the cloud metadata endpoint (`169.254.169.254`) to steal instance
/// credentials. The vetted address is pinned into the client so a DNS rebind between the check and the
/// connect cannot swap a public answer for a private one.
async fn fetch_origin(
    request: &FetchRequest,
    allow: &OriginAllowlist,
) -> Result<reqwest::Response, String> {
    let method = allowed_method(&request.method)?;
    let url = reqwest::Url::parse(&request.url).map_err(|error| format!("invalid url: {error}"))?;
    // Enforce the operator's origin scope BEFORE the SSRF guard and any connection: a request outside the
    // declared origin is refused here, reading its origin from the SAME parse the guard vets below, so the
    // allowlist and the connection cannot see different hosts. An empty allowlist admits any public origin.
    if !allow.admits(&url) {
        return Err(format!(
            "origin {} not allowed by this fetch service",
            url.origin().ascii_serialization()
        ));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme {} not allowed (http/https only)",
            url.scheme()
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| "url has no host".to_owned())?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "url has no port".to_owned())?;
    let vetted = resolve_public(&host, port).await?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // Pin resolution to the vetted address: reqwest connects here and nowhere else for this host, so a
        // rebind cannot move the target after the check. The pin key is `host_str()`, which for a rooted
        // FQDN keeps its trailing dot (`api.github.com.`); an observed probe (delib-13 MINOR-2, reqwest
        // 0.12.28) confirms reqwest keys its resolve override on that SAME dotted host it connects for, so
        // the pin HOLDS for the trailing-dot form (no desync, no fresh connect-time lookup) and needs no
        // dot-stripping here.
        .resolve(&host, vetted)
        .build()
        .map_err(|error| format!("http client: {error}"))?;
    let mut outgoing = client.request(method, url);
    for (name, value) in forward_headers(&request.headers) {
        outgoing = outgoing.header(name, value);
    }
    outgoing
        .send()
        .await
        .map_err(|error| format!("origin request failed: {error}"))
}

/// Write the response frame (origin status + headers verbatim) then stream the body to the writer until
/// the origin body ends. Never buffers the whole body, so a large download does not grow the node's memory.
async fn stream_response<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    response: reqwest::Response,
) -> io::Result<()> {
    let status = response.status().as_u16();
    // Cap the forwarded headers at the same bound the reader enforces, so a hostile origin cannot return a
    // frame the requester would then reject as over-count (or force an unbounded write).
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), v.to_string()))
        })
        .take(MAX_HEADERS)
        .collect();
    FetchResponse::Ok { status, headers }.write(writer).await?;
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| io::Error::other(format!("origin body: {error}")))?;
        writer.write_all(&chunk).await?;
    }
    Ok(())
}

/// The origin method for a request method: GET and HEAD only (a fetch, not a general HTTP proxy).
pub(crate) fn allowed_method(method: &str) -> Result<reqwest::Method, String> {
    match method {
        "GET" => Ok(reqwest::Method::GET),
        "HEAD" => Ok(reqwest::Method::HEAD),
        other => Err(format!(
            "method {other} not allowed (fetch is GET/HEAD only)"
        )),
    }
}

/// The request headers to forward to the origin: everything except hop-by-hop headers and `Host` (the
/// client derives Host from the URL). `Range` and the rest pass through, so a ranged/resumable GET works.
pub(crate) fn forward_headers(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    const SKIP: [&str; 7] = [
        "host",
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    ];
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            !SKIP.contains(&lower.as_str())
        })
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// Resolve `host:port` and require EVERY resolved address to be public, returning the first. A host that
/// resolves to any non-public address is refused wholesale (that mix is the classic SSRF / DNS-rebinding
/// shape), while a legitimately public host resolves only to public IPs. The returned address is what the
/// client is pinned to, so the connection lands on a vetted IP.
async fn resolve_public(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| format!("resolve {host}: {error}"))?
        .collect();
    let first = *addrs
        .first()
        .ok_or_else(|| format!("{host} resolved to no addresses"))?;
    if let Some(bad) = addrs.iter().find(|addr| !is_public(addr.ip())) {
        return Err(format!(
            "refusing to fetch {host}: it resolves to the non-public address {}",
            bad.ip()
        ));
    }
    Ok(first)
}

/// Whether an IP is a public (globally routable) unicast address: the only kind this service will reach.
/// Conservative: loopback, private, link-local, shared (CGNAT), unspecified, and multicast are all NOT
/// public. Any IPv6 that EMBEDS an IPv4 address (mapped, NAT64, or the deprecated compatible form) is
/// unwrapped and judged as IPv4, so `::ffff:169.254.169.254` AND the NAT64 `64:ff9b::169.254.169.254`
/// (which a DNS64/NAT64 host routes straight to the cloud metadata IP) cannot slip past.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => match embedded_ipv4(v6) {
            Some(v4) => is_public_v4(v4),
            None => {
                let seg = v6.segments();
                let unique_local = seg[0] & 0xfe00 == 0xfc00; // fc00::/7
                let link_local = seg[0] & 0xffc0 == 0xfe80; // fe80::/10
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || unique_local
                    || link_local)
            }
        },
    }
}

/// Extract an IPv4 address embedded in an IPv6 one, so an internal target wearing IPv6 clothing is judged
/// by its real IPv4. Covers the three embeddings a translating host will actually route to that v4:
/// IPv4-mapped `::ffff:0:0/96` (via `to_ipv4_mapped`), NAT64 well-known `64:ff9b::/96` (RFC 6052, the
/// standard DNS64 prefix), and deprecated IPv4-compatible `::/96` (`::a.b.c.d`). `::` and `::1` are left
/// for the caller to refuse as unspecified/loopback. Returns `None` for a native IPv6 address.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = v6.segments();
    let low = |a: u16, b: u16| Ipv4Addr::new((a >> 8) as u8, a as u8, (b >> 8) as u8, b as u8);
    // NAT64 well-known prefix 64:ff9b::/96.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        return Some(low(seg[6], seg[7]));
    }
    // IPv4-translatable `::ffff:0:0/96` (RFC 6052): the `ffff` sits in seg[4] (seg[5]==0), so
    // `to_ipv4_mapped` (which matches `ffff` in seg[5]) does not catch it.
    if seg[0..4] == [0, 0, 0, 0] && seg[4] == 0xffff && seg[5] == 0 {
        return Some(low(seg[6], seg[7]));
    }
    // Deprecated IPv4-compatible ::/96, excluding :: and ::1 (handled as unspecified/loopback).
    if seg[0..6] == [0, 0, 0, 0, 0, 0] && !(seg[6] == 0 && (seg[7] == 0 || seg[7] == 1)) {
        return Some(low(seg[6], seg[7]));
    }
    None
}

/// The IPv4 half of [`is_public`]. `is_shared` (100.64.0.0/10, CGNAT) is not yet stable in std, so it is
/// checked by hand; the rest use std predicates. `is_link_local` covers `169.254.0.0/16`, which includes
/// the cloud metadata endpoint `169.254.169.254`.
fn is_public_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    let shared = octets[0] == 100 && (octets[1] & 0xc0) == 64;
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
        || shared)
}
