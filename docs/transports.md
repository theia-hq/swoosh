# Transports

swoosh carries most connections three ways, chosen with `--transport`. The key is the same either way, so
switching transports reaches the same peer. `swoosh ssh` is the one exception: it is iroh-only today
and takes no `--transport`.

## iroh (the default)

`iroh` is what you get with no flag. It finds and reaches peers across the internet, punching through
NATs. You give it a key; it does the rest. Nothing to configure, no addresses to pass.

This is the transport for everyday use. Every [use case](use-cases/README.md) and the
[getting-started](getting-started.md) walkthrough use it.

Finding a peer and the relay fallback are iroh's: a serving node publishes where it can be reached to
n0's public discovery service, and when a direct path fails, n0's public relays forward encrypted bytes
they cannot read. Pointing swoosh at a relay and a resolver you run is not wired today.

## <a id="quirk"></a>quirk (our own transport)

`quirk` is a transport we wrote from scratch over UDP. It is shaped like QUIC and is not QUIC: one stream
per connection, no congestion control, not interoperable with anything else. It is direct-only: it does
no internet discovery and no NAT traversal, so it reaches a peer only at an address you hand it with
`--peer` (below).

Two spellings share that backend:

- `quirk` never proves the far side holds the key it presents; the key travels in plaintext. A
  [gate](keys.md#the-gate) admits a peer by its key, so without that proof anyone could claim it;
  `swoosh serve` therefore refuses over it, and swoosh never writes a credential over it. It is the base
  `quirk+noise` builds on; run `swoosh serve --transport quirk` to see the refusal.
- `quirk+noise` runs a Noise handshake before any byte flows: the far side proves the key it presents,
  and the session is encrypted. Gated services work over it. It is still direct-only, so hand the peer's
  address over with `--peer` (below).

Both ends must use the same spelling: a `quirk+noise` peer cannot talk to a bare `quirk` peer, and
there is no fallback.

Because it is direct-only, a `quirk+noise` `serve` prints the address the peer needs:

<!-- capture: swoosh serve --transport quirk+noise -->
```console
$ swoosh serve --transport quirk+noise
swoosh ready

    bf01lezchywdg2izx5bvyaka433iqzg4oxbt7j2aoxp7tjtyq2a7jjqq

how peers reach you
  local    automatic; local mDNS, or direct, no NAT traversal
  direct   reachable on this machine only:
           127.0.0.1:58476

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (never public)

ctrl-c to stop
```

Hand that address to the peer with `--peer` (below).

**Bare `quirk` cannot serve.** It never carries a credential: it does not prove the peer's key.
`quirk+noise` proves the key and encrypts the session, but it is direct-only: use
iroh when you need NAT traversal.

## <a id="peer"></a>Advanced: `--peer`, when discovery cannot reach them

`--peer <key>=<addr>` gives a peer's address by hand. You need it only when discovery cannot reach the
peer: mainly a quirk dial across networks, or a locked-down network where automatic discovery is
blocked. Take the `direct` line a peer's `serve` printed and pass it back:

<!-- manual: needs a direct peer and its address -->
```console
$ swoosh ping bf01hcq6… --transport quirk+noise --peer bf01hcq6…=127.0.0.1:50902 -c 4
```

`quirk+noise` is the quirk dial; use it when the peer gates its services.

Over iroh you almost never need this: iroh discovers the peer from its key. If an iroh dial cannot
reach a peer, the peer is likely offline or discovery is down, not missing an address.

## Next

- [Getting started](getting-started.md) the iroh happy path.
- [Demo](demo.md) the same key over iroh and quirk+noise.
- [Troubleshooting](troubleshooting.md) when a dial cannot reach.
