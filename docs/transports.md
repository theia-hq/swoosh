# Transports

swoosh carries most connections three ways, chosen with `--transport`. The key is the same either way, so
switching transports reaches the same peer. `swoosh ssh` is the one exception: it is iroh-only today
and takes no `--transport`.

## iroh (the default)

`iroh` is what you get with no flag. It finds and reaches peers across the internet, punching through
NATs, and discovers peers on your LAN automatically. You give it a key; it does the rest. Nothing to
configure, no addresses to pass.

This is the transport for everyday use. Every [use case](use-cases/README.md) and the
[getting-started](getting-started.md) walkthrough use it.

`iroh` falls back to public relays when a direct path fails; the relays forward encrypted bytes and
cannot read them. Self-hosting the relays is not wired through swoosh today.

## <a id="quirk"></a>quirk (our own QUIC)

`quirk` is our own QUIC, written from scratch over UDP. It is direct-only: it does no internet discovery
and no NAT traversal, so it reaches a peer only on the same LAN or at an address you give it.

Two spellings share that backend:

- `quirk` announces the reached key in plaintext. It is for public services and diagnostics: a
  signet-rooted gate refuses to arm over it.
- `quirk+noise` wraps quirk in a Noise handshake that proves the reached key before any byte flows, and
  encrypts the session. Gated services work over it. It is still direct-only, so it is for a LAN or a
  known address.

Both ends must use the same spelling: a `quirk+noise` peer cannot talk to a bare `quirk` peer (the
wrapper tag fails closed, with no fallback).

Because it does no discovery, a `quirk+noise` `serve` prints the address it is reachable at:

<!-- capture: swoosh serve --transport quirk+noise -->
```console
$ swoosh serve --transport quirk+noise
swoosh ready

    bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q

how peers reach you
  LAN      automatic; your devices just need the key (mDNS)
  direct   reachable on this machine only:
           127.0.0.1:50902

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (never public)

ctrl-c to stop
```

On a shared LAN, peers still find each other automatically over either spelling. Off-LAN, you feed the
address back with `--peer` (below).

**The honest limit.** Bare `quirk` identity is self-announced, so it is for diagnostics and closed
networks, not for anything gated or for reaching a peer across the untrusted internet. `quirk+noise`
proves the peer's key and encrypts the session, but it is direct-only: use iroh when you need NAT
traversal.

## <a id="peer"></a>Advanced: `--peer`, when discovery cannot reach them

`--peer <key>=<addr>` gives a peer's address by hand. You need it only when discovery cannot reach the
peer: mainly a quirk dial across networks, or a locked-down network where automatic discovery is
blocked. Take the `direct` line a peer's `serve` printed and pass it back:

```console
$ swoosh ping bf01hcq6… --transport quirk+noise --peer bf01hcq6…=127.0.0.1:50902 -c 4
```

Bare `quirk` takes the same hint; use `quirk+noise` when the peer gates its services.

Over iroh you almost never need this: iroh discovers the peer from its key. If an iroh dial cannot
reach a peer, the peer is likely offline or discovery is down, not missing an address.

## Next

- [Getting started](getting-started.md) the iroh happy path.
- [Demo](demo.md) the same key over iroh and quirk+noise.
- [Troubleshooting](troubleshooting.md) when a dial cannot reach.
