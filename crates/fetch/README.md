# fetch

An HTTP origin fetch behind a keyed node's `fetch:` service. The node acts as an HTTP client on a
requester's behalf: it reads a request off an already-authorized stream, performs the `GET`/`HEAD` at the
origin (TLS terminates HERE, at the node, not at the requester), and streams the response back with `Range`
intact so a resumable download works. It is the smallest honest instance of "run this at a keyed node": a
fetch, not a general proxy or an open VPN.

## What it protects against

The origin is vetted before any connection: only `http`/`https`, and the host must resolve ENTIRELY to
public addresses. This stops a caller from turning the node into an SSRF pivot, reaching its loopback, its
LAN, or the cloud metadata endpoint (`169.254.169.254`) to steal instance credentials. The vetted address
is pinned into the client, so a DNS rebind between the check and the connect cannot swap a public answer for
a private one. Requests are `GET`/`HEAD` only; redirects are forwarded to the requester verbatim rather than
followed here, so the client decides.

## Origin allowlist (designed, not yet built)

Today the REQUESTER names the URL, and the node fetches any origin that passes the SSRF guard above. An
OPERATOR-side origin allowlist, `serve fetch=fetch:https://api.github.com`, that constrains a `fetch:`
handler to a fixed set of origins is designed (theia deliberation 13) and coming: it is the control that
makes `--public fetch:` safe and narrows an admitted delegate's egress (every fetch leaves from your IP, so
you may not want to hand a delegate your whole public reach). Until it lands, scope a `fetch:` service by
handing its capability only to peers you trust to egress from your public IP.

## How it composes

`fetch` is a service crate: it knows what to DO with an admitted stream, never how the peer was reached or
gated. A caller that owns composition ([swoosh](https://github.com/theia-hq/swoosh)) wraps `serve_fetch` in
a handler and injects it into [tightbeam](https://github.com/theia-hq/tightbeam)'s registry; the `http`
framing is public so the same caller's client side speaks the wire.

## License

Licensed under either of Apache-2.0 or MIT at your option.
