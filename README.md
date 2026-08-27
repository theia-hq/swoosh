# swoosh

One command, every p2p operation as a verb.

A public key is something you can reach, name, and run code at, over any transport and across any NAT.
`swoosh` is the unified front door to that overlay: you address _who_, not _where_.

> Experimental. The CLI, wire protocol, and identity format will change; not ready for production use.

## What it is

`swoosh` is a multitool (git / cargo / kubectl shaped): one binary, one `cargo install`, one `--help`.
Under the hood it rides `bifrost`, the pubkey-addressed overlay, and is transport-blind: the same
operation runs over iroh today and over our own QUIC next, unchanged.

Identity is chosen by intent. `swoosh serve` must be reachable at one address, so it binds a persisted
ed25519 identity at `~/.config/swoosh/identity.key`: restart the node, keep the address. The reach-
outward verbs (`ping`, `speed`, `status`) address a peer and are never dialed back, so they mint a fresh
random ephemeral key each run, no key file to provision and nothing left on disk. Pin any run to a
persisted identity with `--key <path>` (or `SWOOSH_KEY`) when you do want a stable address.

## The verbs

### `swoosh serve`

Be online. Prints this node's address, then answers reach diagnostics for any peer that dials it.

```sh
swoosh serve
# swoosh ready. peers can reach this node at:
#     bf01hy...            <- share this key
```

### `swoosh ping <key-or-name>`

Reach a peer by their public key and measure the round-trip time, `ping(8)` shaped. The most legible
possible proof of reach: an RTT to a person by their key, no IP, no port, no account. The peer can be a
raw key or a saved petname (see [Contacts](#swoosh-contact-name-a-peer)), so `swoosh ping alice` works.

```sh
swoosh ping bf01hy... -c 8 -i 0.5
# rtt min/avg/max/mdev = 21.4/24.8/33.1/3.2 ms
```

- `-c, --count <N>` how many probes to send (default 4)
- `-i, --interval <SECS>` seconds between probes (default 1.0)

### `swoosh speed <key-or-name>`

Measure throughput to a peer: iperf, but over the overlay. Because it rides the transport interface,
it benchmarks the _transport itself_, so the identical test over iroh vs our own QUIC is a head-to-head
transport dyno. Like `ping`, the peer can be a raw key or a saved petname.

```sh
swoosh speed bf01hy... --down -t 5
# 612.00 MiB in 5.00s = 122.40 MiB/s (down)
```

- `--up` / `--down` which direction to measure (default down)
- `-t, --secs <SECS>` run for a fixed time (default 5)
- `-n, --bytes <N>` transfer a fixed number of bytes instead

### `swoosh contact`: name a peer

Reaching a key means naming it. A public key is something you can reach, **name**, and run code at, so
`swoosh` keeps a local address book: save a petname for a peer once, then reach them by name instead of
pasting base32 every time.

```sh
swoosh contact add alice bf01hy...   # save alice -> that key
swoosh contact ls                    # alice (1 device)
swoosh ping alice                    # reach her by name
swoosh contact rm alice              # forget her
```

- `contact add <name> <key>` save (or re-point) a petname. Re-adding the same name replaces the key.
- `contact ls [name]` (alias `list`) list every contact, or the devices under one name.
- `contact rm <name>` (alias `remove`) forget a contact or one of its devices.

The names are **local and self-sovereign**: your address book, stored in plain TOML at
`~/.config/swoosh/contacts.toml`, no registry, no consensus, no one else's permission. `alice` means
whoever _you_ pointed it at.

A contact is a **person** with one or more **devices**. `contact add alice <key>` files that key under
`alice`'s `default` device; add more with a `name/device` slash, e.g. `contact add alice/laptop <key>`,
and `contact ls alice` lists them. Reaching a bare `alice` when she has several devices tries each in
turn and takes the first that answers (first-reachable-wins); reach a specific one with
`swoosh ping alice/laptop`.

## Try it locally

In one terminal, be online and copy the printed key:

```sh
swoosh serve
```

In another, reach that key, or save it a name first and reach it by name:

```sh
swoosh ping <key>
swoosh speed <key> --down

swoosh contact add alice <key>   # name it once
swoosh ping alice                # then reach it by name
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
