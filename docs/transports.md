# Transports

swoosh carries most connections three ways, chosen with `--transport`. The key is the same either way, so
switching transports reaches the same peer. `swoosh ssh` is the one exception: it is iroh-only today
and takes no `--transport`.

## <a id="iroh"></a>iroh (the default)

`iroh` is what you get with no flag. It finds and reaches peers across the internet, punching through
NATs. You give it a key; it does the rest. Nothing to configure, no addresses to pass.

This is the transport for everyday use. Every [use case](use-cases/README.md) and the
[getting-started](getting-started.md) walkthrough use it.

Finding a peer and the relay fallback are iroh's: a serving node publishes where it can be reached to
n0's public discovery service, and when a direct path fails, n0's public relays forward encrypted bytes
they cannot read.

A relayed path is not a settled one. A session can start relayed and upgrade to direct the moment a hole
punch lands, so the same peer can read `relayed` on one run of
[`swoosh status`](reference/commands/status.md) and `direct` on the next. That is the punch landing, not
a fault, and either path is encrypted end to end.

## <a id="self-run"></a>Run the relay and the resolver yourself

Both are programs from the iroh project. Run them on a host with a certificate the public trusts:
swoosh accepts `https` only, and a self-signed certificate is refused.

- `iroh-relay` forwards encrypted bytes between peers that cannot reach each other directly.
- `iroh-dns-server` stores and serves the signed address records a node publishes and a dialer reads.

Point swoosh at them with `--relay <url>` and `--resolver <url>`. The resolver URL is the server's
`/pkarr` path, not its bare host:

<!-- pending live-run: needs iroh-relay and iroh-dns-server on a host with a public certificate -->
```console
$ swoosh serve --relay https://relay.example --resolver https://dns.example/pkarr
```

`serve` remembers each URL it was given under the node home, so every later command under that home
reaches the same two servers with no flags to repeat. A flag on a dial overrides the remembered one for
that run.

**A resolver is a fleet setting; a relay is a node setting.** Two peers find each other only if both
resolve through the same resolver, so every node in a fleet names the same one. A relay travels in the
record a node publishes, and you dial a peer through whatever relay the peer's record names, so each node
names its own.

Either flag stands alone. `--relay` without `--resolver` leaves finding a peer to n0, and the banner says
so:

<!-- pending live-run: needs iroh-relay on a host with a public certificate -->
```text
how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  records    n0's public discovery: your addresses, for anyone with your key
  relay      https://relay.example/
  local      automatic; your devices just need the key (mDNS), announced at:
             192.168.1.24:58131
```

An `iroh-relay` relays for anyone by default. Its `access` setting names the node ids allowed to relay;
its `limits` settings cap connections and bandwidth per client.

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

<!-- The `direct` lane below is stale: the bind-truth fix deleted the "reachable on this machine
     only" line and a wildcard bind now announces real addresses. Re-capture needs the harness to
     normalize a host address the way it already normalizes keys and ports. -->
<!-- pending live-run: swoosh serve --transport quirk+noise -->
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
