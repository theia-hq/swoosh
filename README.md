# swoosh

One command, one identity, every p2p operation as a verb.

A public key is something you can reach, name, and run code at, over any transport and across any NAT.
`swoosh` is the unified front door to that overlay: you address _who_, not _where_, and every verb
speaks from the same persisted identity, so this machine has one address for everything it does.

> Experimental. The CLI, wire protocol, and identity format will change; not ready for production use.

## What it is

`swoosh` is a multitool (git / cargo / kubectl shaped): one binary, one `cargo install`, one `--help`,
one config dir. The verbs share a single ed25519 identity at `~/.config/swoosh/identity.key`
(override with `SWOOSH_KEY`), so "what is my address?" has one answer no matter which verb you run.
Under the hood it rides `bifrost`, the pubkey-addressed overlay, and is transport-blind: the same
operation runs over iroh today and over our own QUIC next, unchanged.

## The verbs

### `swoosh serve`

Be online. Prints this node's address, then answers reach diagnostics for any peer that dials it.

```sh
swoosh serve
# swoosh ready. peers can reach this node at:
#     bf01hy...            <- share this key
```

### `swoosh ping <key>`

Reach a peer by their public key and measure the round-trip time, `ping(8)` shaped. The most legible
possible proof of reach: an RTT to a person by their key, no IP, no port, no account.

```sh
swoosh ping bf01hy... -c 8 -i 0.5
# rtt min/avg/max/mdev = 21.4/24.8/33.1/3.2 ms
```

- `-c, --count <N>` how many probes to send (default 4)
- `-i, --interval <SECS>` seconds between probes (default 1.0)

### `swoosh speed <key>`

Measure throughput to a peer: iperf, but over the overlay. Because it rides the transport interface,
it benchmarks the _transport itself_, so the identical test over iroh vs our own QUIC is a head-to-head
transport dyno.

```sh
swoosh speed bf01hy... --down -t 5
# 612.00 MiB in 5.00s = 122.40 MiB/s (down)
```

- `--up` / `--down` which direction to measure (default down)
- `-t, --secs <SECS>` run for a fixed time (default 5)
- `-n, --bytes <N>` transfer a fixed number of bytes instead

## Try it locally

In one terminal, be online and copy the printed key:

```sh
swoosh serve
```

In another, reach that key:

```sh
swoosh ping <key>
swoosh speed <key> --down
```

## Layout

- `crates/diag` the reach-diagnostics engine (ping + speed): a tiny versioned protocol on bifrost
  streams, a responder, and the two clients. Transport-blind (generic over `bifrost::Session`), so it
  runs over iroh, the in-process mem transport, and any future transport unchanged.
- `crates/swoosh` the CLI: the composition root binds one bifrost node with the shared identity, then
  dispatches to a verb.

## Future work

This is the flagship skeleton plus its first two diagnostic verbs. Coming next, behind the same
identity and front door: `send` / `recv` (verified file transfer, powered by iris), `tunnel`
(private p2p tunnels, powered by tightbeam), and `status` (connection-path visibility, direct vs
relayed). The built-in responder will become always-on and nauthy-gated once nauthy is extracted.

## License

MIT OR Apache-2.0.
