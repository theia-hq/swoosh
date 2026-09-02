//! The operator-set origin scope for a `fetch:` service: an allowlist of origins an admitted requester
//! may fetch, and the normalized (scheme, host, port) [`Origin`] the check compares against.
//!
//! The operator bakes this in at expose time (`serve news=fetch:https://news.example`); the handler checks
//! each request's origin against it BEFORE the fetch (in front of the SSRF guard, not instead of it). An
//! EMPTY allowlist is unconstrained: a bare `fetch:` fetches any public origin, today's behavior. This is
//! an origin allowlist, never a URL-rewriting policy engine: it gates the (scheme, host, port) triple and
//! says nothing about the path or query.

/// The scheme, host, and port a `fetch:` service may reach, normalized so a request origin and an allowed
/// origin compare as the SAME kind of thing regardless of how each was written. Derived from the SAME
/// `reqwest::Url` parse the SSRF guard uses, so the origin the allowlist checks and the origin the
/// connection lands on cannot diverge.
///
/// Normalization, so a legitimate variant is not spuriously refused and an evasion cannot masquerade as the
/// allowed origin:
/// - **host:** lowercased, with a single trailing dot stripped (`Api.GitHub.COM.` == `api.github.com`).
///   Compared as EXACT equality, never a suffix, so `evil-api.github.com` and `api.github.com.evil.example`
///   both fail against `api.github.com`.
/// - **scheme:** exact, so an allow of `https://x` does not admit `http://x`.
/// - **port:** the URL's `port_or_known_default`, so `https://x` and `https://x:443` are one origin.
///
/// A URL with userinfo (`https://api.github.com@evil.example/`) yields the host `evil.example` here (the
/// part after the `@`), so the userinfo cannot fool the allowlist into matching the text before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// Parse an origin from a URL string, keeping only the (scheme, host, port) triple. Errors if the URL
    /// does not parse, carries no host, or has no port and no known default for its scheme. Used both to
    /// build the allowlist from the operator's declared origins and to derive the request's origin from the
    /// same `reqwest::Url` the SSRF guard vets, so both sides of the check see one canonical form.
    pub fn parse(url: &str) -> Result<Self, String> {
        let url =
            reqwest::Url::parse(url).map_err(|error| format!("invalid origin url: {error}"))?;
        Self::of(&url)
    }

    /// The origin of an already-parsed URL: the same source the SSRF `resolve_public` reads its host from,
    /// so the allowlist check and the connection cannot see different hosts (no parse-differential).
    pub fn of(url: &reqwest::Url) -> Result<Self, String> {
        let host = url.host_str().ok_or_else(|| "url has no host".to_owned())?;
        // Lowercase, then strip a SINGLE trailing dot so the rooted-FQDN form `host.` equals `host`; do not
        // strip more than one (`host..` is not `host`).
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "url has no port".to_owned())?;
        Ok(Self {
            scheme: url.scheme().to_ascii_lowercase(),
            host,
            port,
        })
    }
}

/// The operator's origin scope for one `fetch:` service: the set of origins an admitted requester may reach.
/// Empty means unconstrained (a bare `fetch:` fetches any public origin, today's behavior); non-empty means
/// a request origin absent from the set is refused BEFORE the fetch.
#[derive(Debug, Clone, Default)]
pub struct OriginAllowlist(Vec<Origin>);

impl OriginAllowlist {
    /// Build an allowlist from the operator's declared origin strings (`https://news.example`), parsing each
    /// to its normalized [`Origin`]. A malformed origin fails HERE, at expose time, not at dial time as an
    /// opaque refusal.
    pub fn parse<I, S>(origins: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        origins
            .into_iter()
            .map(|origin| Origin::parse(origin.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// Whether this allowlist is unconstrained (empty): a bare `fetch:` with no operator-set scope, which
    /// fetches any public origin. Non-empty scopes every request to the listed origins.
    pub fn is_unconstrained(&self) -> bool {
        let Self(origins) = self;
        origins.is_empty()
    }

    /// Whether an admitted requester may reach `url`: true when the allowlist is unconstrained (empty), or
    /// when `url`'s normalized origin EXACTLY matches a listed one. The check is over the (scheme, host,
    /// port) triple only; the path and query are the requester's to choose. Pass the SAME `reqwest::Url` the
    /// SSRF guard vets, so the check and the connection agree on the host.
    pub fn admits(&self, url: &reqwest::Url) -> bool {
        let Self(origins) = self;
        if origins.is_empty() {
            return true;
        }
        match Origin::of(url) {
            Ok(request) => origins.contains(&request),
            // A URL with no host / no port cannot match a listed origin; refuse rather than admit. The SSRF
            // guard rejects it too, but the allowlist must not fall open on a shape it cannot normalize.
            Err(_) => false,
        }
    }
}

/// Compose the request URL to fetch by resolving `target` (an inbound request path and query) against
/// `base` (the origin the caller named), joining them per the URL grammar rather than concatenating strings.
/// A join merges the two paths correctly, so a base with a trailing slash and a target with a leading one
/// (`https://x/` + `/a`) compose to `https://x/a`, never the `https://x//a` a raw concatenation yields, and a
/// malformed base or target is a typed error here rather than a broken URL sent to the origin.
///
/// A pure edge helper that marshals two strings through the `reqwest::Url` parser (the same parser the SSRF
/// guard and the origin allowlist use), so the composed URL is well-formed by the same grammar the fetch
/// then vets. The caller decides how a root request (`/`) is treated; this always joins.
pub fn compose_url(base: &str, target: &str) -> Result<String, String> {
    let base = reqwest::Url::parse(base).map_err(|error| format!("invalid fetch url: {error}"))?;
    let joined = base
        .join(target)
        .map_err(|error| format!("invalid request path {target}: {error}"))?;
    Ok(joined.into())
}

#[cfg(test)]
#[path = "origin_tests.rs"]
mod origin_tests;
