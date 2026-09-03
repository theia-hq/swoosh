# Transports

swoosh carries a connection two ways, chosen with `--transport`. The key is the same either way, so
switching transports reaches the same peer.

## iroh (the default)

`iroh` is what you get with no flag. It finds and reaches peers across the internet, punching through
NATs, and discovers peers on your LAN automatically. You give it a key; it does the rest. Nothing to
configure, no addresses to pass.

This is the transport for everyday use. Every [use case](use-cases/README.md) and the
[getting-started](getting-started.md) walkthrough use it.

## <a id="quirk"></a>quirk (the diagnostic transport)

`quirk` is our own QUIC, written from scratch over UDP. It is direct-only: it does no internet discovery
and no NAT traversal, so it reaches a peer only on the same LAN or at an address you give it. Reach for
it to test the overlay against a second transport, or on a closed network where you know the address.

Because it does no discovery, a quirk `serve` prints the address it is reachable at:

<!-- capture: swoosh serve --transport quirk -->
```console
$ swoosh serve --transport quirk
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
    control.*   node control (always family-gated)

ctrl-c to stop
```

On a shared LAN, peers still find each other automatically over quirk. Off-LAN, you feed the address
back with `--peer` (below).

**The honest limit.** quirk has no Noise handshake yet, so over quirk the reached identity is
self-announced rather than cryptographically proven. It is for diagnostics and closed networks, not for
reaching a peer across the untrusted internet. Use iroh for that.

## <a id="peer"></a>Advanced: `--peer`, when discovery cannot reach them

`--peer <key>=<addr>` gives a peer's address by hand. You need it only when discovery cannot reach the
peer: mainly a quirk dial across networks, or a locked-down network where automatic discovery is
blocked. Take the `direct` line a peer's `serve` printed and pass it back:

```console
$ swoosh ping bf01hcq6… --transport quirk --peer bf01hcq6…=127.0.0.1:50902 -c 4
```

Over iroh you almost never need this: iroh discovers the peer from its key. If an iroh dial cannot
reach a peer, the peer is likely offline or discovery is down, not missing an address.

## Next

- [Getting started](getting-started.md) the iroh happy path.
- [Demo](demo.md) the same command over both transports, same key.
- [Troubleshooting](troubleshooting.md) when a dial cannot reach.
