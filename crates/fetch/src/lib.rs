//! fetch: an HTTP origin fetch a keyed node performs on an admitted requester's behalf.
//!
//! The node acts as an HTTP client on the requester's behalf: it reads a [`FetchRequest`] off an admitted
//! stream, performs the GET/HEAD at the origin (TLS terminated HERE, not at the requester), vets the target
//! against SSRF, and streams the response back with `Range` intact so a resumable download works. This is
//! the smallest honest instance of "run this at a keyed node": a fetch scoped to one origin, not a general
//! proxy or an open VPN.
//!
//! **Origin allowlist.** An operator scopes the service to a fixed set of origins at expose time, and
//! [`serve_fetch`] refuses any request whose origin is not in
//! that [`OriginAllowlist`] before it connects. This is the control that makes an OPEN (unauthenticated)
//! origin-fetch service safe and narrows an admitted delegate's egress. An unscoped service builds an EMPTY
//! allowlist, which is unconstrained: it fetches any origin that passes the SSRF guard.
//!
//! It is a service crate: it knows what to DO with an admitted stream, never how the peer was reached or
//! gated. The composing consumer wraps [`serve_fetch`] in a handler and injects it into the tunnel's handler
//! registry; the [`http`] framing is public so the same caller's client side speaks the wire.

pub mod http;
mod origin;
mod serve;

#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod serve_tests;

pub use crate::http::{FetchRequest, FetchResponse};
pub use crate::origin::{Origin, OriginAllowlist, compose_url};
pub use crate::serve::serve_fetch;
