# measure

Reach diagnostics over the bifrost overlay: an RTT to a peer addressed by their public key, and throughput
over the session that reaches them. They are the cheapest high-signal proofs of the thesis, a `ping` and a
`speedtest` that work by key across NAT with no coordinator.

Both ride a tiny versioned protocol on bifrost streams and are transport-blind (generic over the session),
so the identical test runs over iroh, the in-process transport, and any future one. That is the payoff:
speed is `iperf`, but over any transport, a built-in transport dyno.

## Two independent services

`ping` (cheap RTT) and `speed` (bandwidth-eating throughput) are separate services, so a node may advertise
one without the other. A node answers them with `answer_ping` / `answer_speed` (each refuses the other's
method at the wire), or serves both over one session with a `Responder`. A client constructs a `Ping` or a
`Speedtest`, runs it against a session, and reads back a report.

## How it composes

`measure` is a service crate: it knows what to DO with an admitted stream, never how the peer was reached or
gated. A caller that owns composition ([swoosh](https://github.com/theia-hq/swoosh)) injects the answer
handlers into [tightbeam](https://github.com/theia-hq/tightbeam)'s registry and drives the client side from
its `ping` / `speed` verbs.

## License

Licensed under either of Apache-2.0 or MIT at your option.
