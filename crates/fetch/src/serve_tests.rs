use core::net::IpAddr;

use crate::serve::{allowed_method, forward_headers, is_public};

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
