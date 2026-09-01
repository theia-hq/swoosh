//! fetch: an HTTP origin fetch behind a keyed node's `fetch:` service.
//!
//! The node acts as an HTTP client on the requester's behalf: it reads a [`FetchRequest`] off an admitted
//! stream, performs the GET/HEAD at the origin (TLS terminated HERE, not at the requester), vets the target
//! against SSRF, and streams the response back with `Range` intact so a resumable download works. This is
//! the smallest honest instance of "run this at a keyed node": a fetch scoped to one origin, not a general
//! proxy or an open VPN.
//!
//! **Origin allowlist (designed, not yet built).** Today the REQUESTER names the URL and the node fetches
//! any origin that passes the SSRF guard (public addresses only). An OPERATOR-side origin allowlist,
//! `serve fetch=fetch:https://api.github.com`, that constrains this handler to a fixed set of origins is
//! designed (theia deliberation 13) and coming: it is the control that makes `--public fetch:` safe and
//! narrows an admitted delegate's egress. Until it lands, scope a `fetch:` service by handing its capability
//! only to peers you trust to egress from your public IP.
//!
//! It is a service crate: it knows what to DO with an admitted stream, never how the peer was reached or
//! gated. A caller that owns composition (swoosh) wraps [`serve_fetch`] in a handler and injects it into
//! tightbeam's registry; the [`http`] framing is public so the same caller's client side speaks the wire.

pub mod http;
mod serve;

#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod serve_tests;

pub use crate::http::{FetchRequest, FetchResponse};
pub use crate::serve::serve_fetch;
