# swoosh

`swoosh` connects to another machine by its public key instead of its IP address, and measures the
connection. You give it a peer's key (a short base32 string), and it dials that peer directly, wherever
the peer is on the internet, across home routers and NATs, without you knowing or caring about their
address. Then it tells you useful things about that connection: the round-trip time, the throughput,
and whether the link is direct or bouncing through a relay.

```sh
swoosh serve                 # on one machine: print this machine's key, stay reachable
swoosh ping bf01hy...        # on another: reach that key, measure the round trip
swoosh speed bf01hy...       # measure throughput to it
swoosh status bf01hy...      # is the link direct, or relayed?
```

> Experimental. The CLI, wire protocol, and identity format will change; not ready for production use.

## Why a key instead of an address

A machine's IP address changes: it moves networks, sits behind a router, gets a new lease. Its public
key does not. Addressing a peer by key means you reach the same peer every time, and the connection is
authenticated end to end by that key, so you know you reached the machine you meant and no one is in the
middle. `swoosh serve` prints a key; anyone with that key can reach the machine, from anywhere.

## Commands

### `swoosh serve`

Stay online and reachable. Prints this machine's key, then answers `ping`, `speed`, and `status` from
any peer that dials it. The key is stable across restarts, so peers can save it once.

```sh
swoosh serve
# swoosh ready, reachable at:
#     bf01hy...            (share this key)
```

### `swoosh ping <peer>`

Dial a peer and measure the round-trip time, like `ping(8)` but addressed by key.

```sh
swoosh ping bf01hy... -c 8 -i 0.5
# rtt min/avg/max/mdev = 21.4/24.8/33.1/3.2 ms
```

- `-c, --count <N>` how many probes to send (default 4)
- `-i, --interval <SECS>` seconds between probes (default 1.0)

### `swoosh speed <peer>`

Measure throughput to a peer, like `iperf` but addressed by key.

```sh
swoosh speed bf01hy... --down -t 5
# 612.00 MiB in 5.00s = 122.40 MiB/s (down)
```

- `--up` / `--down` which direction to measure (default down)
- `-t, --secs <SECS>` run for a fixed time (default 5)
- `-n, --bytes <N>` transfer a fixed number of bytes instead

### `swoosh status <peer>`

Dial a peer and report the connection path: direct or relayed, the remote address, and a live RTT.
Answers the one question a p2p connection always raises: am I actually talking to the peer directly, or
bouncing through a relay?

```sh
swoosh status bf01hy...
# alice via iroh: direct to 203.0.113.7:41641, rtt 24.8 ms
```

### `swoosh contact`: name your peers

Keys are unwieldy to type. Save a peer's key under a short name once, then use the name anywhere a
command wants a peer: `swoosh ping alice` instead of pasting base32. Names are yours alone, stored in
plain TOML at `~/.config/swoosh/contacts.toml`. `alice` means whoever you pointed it at, no registry
and no one else's permission.

```sh
swoosh contact add alice bf01hy...   # save alice -> that key
swoosh contact ls                    # list your contacts
swoosh ping alice                    # reach her by name
swoosh contact rm alice              # forget her
```

- `contact add <name> <key>` save (or re-point) a name. Re-adding the same name replaces the key.
- `contact ls [name]` list every contact, or the devices saved under one name.
- `contact rm <name>` forget a contact or one of its devices.

One person can have several machines. `contact add alice/laptop <key>` files a key under `alice`'s
`laptop`; `swoosh ping alice` then tries each of alice's machines and takes the first that answers, or
reach a specific one with `swoosh ping alice/laptop`.

## Identity

Every `swoosh` command runs under a key of its own. `serve` needs to be reachable at one stable address,
so it saves its key at `~/.config/swoosh/identity.key` and reuses it across runs. The outward commands
(`ping`, `speed`, `status`) only dial out and are never dialed back, so they generate a throwaway key
each run, nothing to set up and nothing left on disk. Pass `--key <path>` (or set `SWOOSH_KEY`) to pin
any command to a saved key when you want a stable address.

## Transports

`swoosh` can carry a connection two ways, chosen with `--transport`:

- `iroh` (default) finds and reaches peers across the internet, punching through NATs.
- `quirk` is a from-scratch QUIC implementation, direct or same-LAN only.

The key is the same either way, so switching transports reaches the same peer. On a shared LAN, peers
find each other automatically. Across networks, feed a peer the address its `swoosh serve` printed with
`--peer <key>=<addr>`.

## Try it locally

In one terminal, be reachable and copy the printed key:

```sh
swoosh serve
```

In another, reach that key:

```sh
swoosh ping <key>
swoosh speed <key> --down
swoosh status <key>

swoosh contact add alice <key>   # or name it once
swoosh ping alice                # then reach it by name
```

## Layout

- `crates/diag` the measurement engine (ping, speed): a small versioned protocol, a responder, and the
  two clients.
- `crates/swoosh` the CLI: binds one node under the chosen key and transport, then runs a command.

## License

MIT OR Apache-2.0.
