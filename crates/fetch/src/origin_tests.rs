//! The origin allowlist host matcher: the whole security value of an origin-scoped `fetch:` service. Each
//! test is an evasion the matcher must refuse, or a legitimate variant it must admit (delib-13 footgun): the
//! matcher gates the normalized (scheme, host, port) triple, never a suffix, and is not fooled by userinfo,
//! case, a trailing dot, or a scheme/port mismatch. An empty allowlist stays unconstrained (back-compat).

use crate::origin::{Origin, OriginAllowlist, compose_url};

/// Parse a request URL through the SAME `reqwest::Url` parse the SSRF guard and the matcher both use, so the
/// test asks the matcher exactly what the handler asks it.
fn admits(allow: &OriginAllowlist, url: &str) -> bool {
    let url = reqwest::Url::parse(url).expect("valid request url");
    allow.admits(&url)
}

/// The one allowlist every scope test runs against: a single `https://api.github.com` origin.
fn github() -> OriginAllowlist {
    OriginAllowlist::parse(["https://api.github.com"]).expect("valid origin")
}

#[test]
fn the_allowed_origin_passes() {
    assert!(admits(&github(), "https://api.github.com/repos/x/y"));
}

#[test]
fn a_different_origin_is_refused() {
    assert!(!admits(&github(), "https://evil.example/"));
}

#[test]
fn userinfo_masquerading_as_the_host_is_refused() {
    // The real host is `evil.example` (the part after the `@`); the userinfo `api.github.com` must not fool
    // the allowlist while the connection lands on `evil.example`.
    assert!(!admits(&github(), "https://api.github.com@evil.example/"));
}

#[test]
fn userinfo_is_refused_even_when_the_real_host_is_the_allowed_one() {
    // The reverse of the masquerade: the userinfo is junk and the real host IS the allowed origin
    // (`https://evil.example@api.github.com/`). Parsing AROUND the userinfo would ADMIT this; rejecting a
    // URL that carries userinfo at all (the spec's reading) refuses it, failing closed.
    assert!(!admits(&github(), "https://evil.example@api.github.com/"));
}

#[test]
fn an_origin_with_userinfo_fails_to_parse() {
    // An operator's declared origin must not carry userinfo either: it fails at parse, at expose time, not
    // silently at dial time.
    assert!(Origin::parse("https://user:pass@api.github.com").is_err());
}

#[test]
fn host_case_is_ignored() {
    assert!(admits(&github(), "https://API.GitHub.COM/"));
}

#[test]
fn a_single_trailing_dot_is_ignored() {
    // The rooted-FQDN form `api.github.com.` names the same host as `api.github.com`.
    assert!(admits(&github(), "https://api.github.com./"));
}

#[test]
fn a_suffix_of_the_allowed_host_is_refused() {
    // The classic suffix trick: an attacker-owned domain that ends in the allowed host as a label.
    assert!(!admits(&github(), "https://api.github.com.evil.example/"));
}

#[test]
fn a_prefix_of_the_allowed_host_is_refused() {
    assert!(!admits(&github(), "https://evil-api.github.com/"));
}

#[test]
fn a_scheme_mismatch_is_refused() {
    // An allow of `https://x` does not admit `http://x`.
    assert!(!admits(&github(), "http://api.github.com/"));
}

#[test]
fn a_port_mismatch_is_refused() {
    // `https://x` normalizes to port 443, so an explicit `:8443` is a different origin.
    assert!(!admits(&github(), "https://api.github.com:8443/"));
}

#[test]
fn the_known_default_port_matches_the_implicit_one() {
    // `https://x` and `https://x:443` are one origin, so an explicit `:443` still passes.
    assert!(admits(&github(), "https://api.github.com:443/"));
}

#[test]
fn an_empty_allowlist_admits_any_origin() {
    // A bare `fetch:` (no operator scope) fetches any public origin: today's behavior, unchanged.
    let unconstrained = OriginAllowlist::default();
    assert!(unconstrained.is_unconstrained());
    assert!(admits(&unconstrained, "https://anything.example/"));
    assert!(admits(&unconstrained, "http://other.example:8080/x"));
}

#[test]
fn multiple_origins_each_admit_their_own() {
    // A service may name several origins; each request must match ONE of them exactly.
    let allow =
        OriginAllowlist::parse(["https://news.example", "https://apple.example"]).expect("valid");
    assert!(admits(&allow, "https://news.example/story"));
    assert!(admits(&allow, "https://apple.example/mac"));
    assert!(!admits(&allow, "https://other.example/"));
}

#[test]
fn compose_url_merges_paths_without_doubling_the_slash() {
    // A trailing slash on the base and a leading slash on the target compose to ONE slash: the join merges
    // per the URL grammar, never the `//` a string concatenation would produce.
    assert_eq!(
        compose_url("https://api.example.com/", "/users?id=5").expect("composes"),
        "https://api.example.com/users?id=5"
    );
}

#[test]
fn compose_url_joins_a_path_onto_a_bare_origin() {
    assert_eq!(
        compose_url("https://api.example.com", "/users").expect("composes"),
        "https://api.example.com/users"
    );
}

#[test]
fn compose_url_refuses_a_malformed_base() {
    assert!(compose_url("not a url", "/x").is_err());
}
