# swoosh

`swoosh` works with another machine addressed by its public key instead of its IP: reach it, measure
the link, and (as the tool grows) send files, open tunnels, share access, and fetch through it. You give
it a peer's key (a short base32 string) and it dials that peer directly, wherever the peer is on the
internet, across home routers and NATs, without you knowing or caring about the peer's address. No
address to look up, no server in the middle.

```sh
swoosh serve                 # on one machine: print this machine's key, stay reachable
swoosh ping alice            # on another: reach that key, measure the round trip
swoosh speed alice           # measure throughput to it
swoosh status alice          # is the link direct, or relayed?
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/theia-hq/swoosh/main/scripts/install.sh | sh
```

Downloads the right binary for your platform from the [latest release](https://github.com/theia-hq/swoosh/releases),
verifies its SHA-256 checksum (and, if you have the GitHub CLI, its build-provenance attestation), and
installs it to `~/.local/bin`. Set `INSTALL_DIR` to change where it lands. Prefer to do it yourself? Grab a
binary from the releases page; each carries a checksum and a keyless signature you can verify with
`gh attestation verify <binary> --repo theia-hq/swoosh`.

Powered by [bifrost](https://github.com/theia-hq/bifrost) for the keyed connection and
[tightbeam](https://github.com/theia-hq/tightbeam) for the tunnels behind `ssh` and `fetch`.

**The name.** *swoosh* is the sound of something sent across: this is the one command you type to
reach a machine by its key and do things with it, from measuring the link to opening a shell to
sending a file.

> Experimental. The CLI, wire protocol, and identity format will change; not ready for production use.

## Why a key instead of an address

A machine's IP address changes: it moves networks, sits behind a router, gets a new lease. Its public
key does not. Addressing a peer by key means you reach the same peer every time, and the connection is
authenticated end to end by that key, so you know you reached the machine you meant and no one is in the
middle. `swoosh serve` prints a key; anyone with that key can reach the machine, from anywhere.

## A real run

On one machine, be reachable and copy the printed key:

```sh
$ swoosh serve
swoosh ready. Reachable at:

    bf01hy…                     (share this key)

answering ping + speed. ctrl-c to stop.
```

On another, save the key under a name once, then reach it by name:

```sh
$ swoosh contact add alice bf01hy…
$ swoosh ping alice -c 4
pinging alice (4 probes)
4 sent, 4 received, 0% loss
rtt min/avg/max/mdev = 21.4/24.8/33.1/3.2 ms

$ swoosh status alice
alice via iroh: direct to 203.0.113.7:41641, rtt 24.8 ms
```

## Commands

### `swoosh serve`

Stay online and reachable. Prints this machine's key, then answers `ping`, `speed`, and `status` from
any peer that dials it. The key is stable across restarts, so peers can save it once.

### `swoosh ping <peer>`

Dial a peer and measure the round-trip time, like `ping(8)` but addressed by key.

- `-c, --count <N>` how many probes to send (default 4)
- `-i, --interval <SECS>` seconds between probes (default 1.0)

### `swoosh speed <peer>`

Measure throughput to a peer, like `iperf` but addressed by key.

- `--up` / `--down` which direction to measure (default down)
- `-t, --secs <SECS>` run for a fixed time (default 5)
- `-n, --bytes <N>` transfer a fixed number of bytes instead

### `swoosh status <peer>`

Dial a peer and report the connection path: direct or relayed, the remote address, and a live RTT.
Answers the one question a p2p connection always raises: am I actually talking to the peer directly, or
bouncing through a relay?

### `swoosh ssh <peer>`

Open an ssh session to a peer over the overlay, by name or key: `swoosh ssh alice/desk`. It resolves the
peer and points the system `ssh` at it through a private tunnel, then hands off, so anything after works
as usual: `swoosh ssh alice/desk -- ls`, or `swoosh ssh alice/desk -p 2222`. Auth is your normal ssh keys.
The peer exposes its sshd once with [tightbeam](https://github.com/theia-hq/tightbeam)
(`tightbeam expose ssh=127.0.0.1:22`), which also carries the tunnel.

### `swoosh fetch <url>`

Fetch a URL through a node you name, handed out as a plain local URL. `swoosh fetch
https://example.com/big.iso --via usa` prints `http://127.0.0.1:PORT/`; whatever pulls from that (curl,
xget) is served by `usa`'s machine fetching the origin and streaming it back, `Range` intact so a
resumable download resumes. The exit is a node *you* run (your own overlay HTTP proxy, no vendor): expose
it there with `tightbeam expose fetch=fetch:` (gated to your signet) and hand out a `sheer:` cap to `--via`. Scoped to
the one origin you name, not an open proxy.

### `swoosh tunnel`

Expose a local service to peers, or bind a peer's exposed service to a local port (the `ssh -L` shape,
but pubkey-addressed and p2p).

- `tunnel expose <name=addr>...` publish local services under this node's key, gated by your signet.
- `tunnel connect <peer> --to <port>` reach a peer's exposed service and bind it to a local port.

### `swoosh grant`

Mint, narrow, or revoke a `sheer:` capability link: a signed, expiring grant to one exposed service,
rooted at this node's key. It carries its own authority, so a holder connects with no allowlist to keep in
sync, and it is minted, narrowed, and revoked entirely offline.

- `grant issue <service>` mint a link granting one service, expiring, attenuable, delegable.
- `grant narrow <link>` narrow an existing link (only ever adds constraints), before handing it on.
- `grant revoke <link>` refuse a link at this node at once, without waiting for its expiry.

### `swoosh identity`

Print this machine's key (its NodeId), minting one if there is none. A local command: it stands up no
transport, it just resolves the key `--key`/`SWOOSH_KEY` points at (or the default) and prints the key a
node bound under it will present. Use it to provision an identity ahead of time: mint a key here, save
its NodeId as a contact, then hand the key file to the machine that will adopt it (a CI runner, say) so
you can reach it by a name you already know.

### `swoosh mint` and `swoosh adopt`

Provision a second machine under an identity you control, without copying a key by hand. On the machine
that holds your signet, `swoosh mint <label>` derives a device identity and emits a one-time authkey; on
the new machine, `swoosh adopt <authkey>` becomes that device identity and trusts the signet that minted
it. The two ends of one handshake: use them to bring a laptop or a CI runner onto your overlay.

### `swoosh contact`: name your peers

Keys are unwieldy to type. Save a peer's key under a short name once, then use the name anywhere a
command wants a peer: `swoosh ping alice` instead of pasting base32. Names are yours alone, stored in
plain TOML at `~/.config/swoosh/contacts.toml`. `alice` means whoever you pointed it at, no registry
and no one else's permission.

```sh
swoosh contact add alice bf01hy…   # save alice -> that key
swoosh contact ls                  # list your contacts
swoosh contact rm alice            # forget her
```

- `contact add <name> <key>` save (or re-point) a name. Re-adding the same name replaces the key.
- `contact ls [name]` list every contact, or the devices saved under one name.
- `contact rm <name>` forget a contact or one of its devices.

One person can have several machines. `contact add alice/laptop <key>` files a key under `alice`'s
`laptop`; `swoosh ping alice` then tries each of alice's machines and takes the first that answers, or
reach a specific one with `swoosh ping alice/laptop`.

### `swoosh tree`

Print the command tree with each verb's one-line summary, read straight from the parser, so it can never
drift from `--help`.

## Identity

Every `swoosh` command runs under a key of its own. `serve` needs to be reachable at one stable address,
so it saves its key at `~/.config/swoosh/identity.key` and reuses it across runs. The outward commands
(`ping`, `speed`, `status`) only dial out and are never dialed back, so they generate a throwaway key
each run, nothing to set up and nothing left on disk. Pass `--key <path>` (or set `SWOOSH_KEY`) to pin
any command to a saved key when you want a stable address.

## Transports

`swoosh` can carry a connection two ways, chosen with `--transport`:

- `iroh` (default) finds and reaches peers across the internet, punching through NATs.
- [`quirk`](https://github.com/theia-hq/quirk) is a from-scratch QUIC implementation, direct or same-LAN
  only.

The key is the same either way, so switching transports reaches the same peer. On a shared LAN, peers
find each other automatically. Across networks, feed a peer the address its `swoosh serve` printed with
`--peer <key>=<addr>`.

## Roadmap

`swoosh` is one umbrella for doing things with a machine addressed by its key. Every planned verb is the
same primitive underneath (a cap-gated byte-stream to a key) with a thin front door per job, so the
surface stays broad while the core stays one thing. Shipped today is ticked; the rest is planned and
lands as it is built.

- [x] `serve`: be online, answer reach diagnostics under a persisted key
- [x] `ping`: round-trip time to a peer, `ping(8)`-shaped
- [x] `speed`: throughput to a peer, `iperf`-shaped
- [x] `status`: connection path to a peer: direct vs relayed
- [x] `contact`: a local, self-sovereign address book (`add` / `ls` / `rm`), petname resolution in every
  reach verb, several devices under one name
- [x] `tree`: print the command tree, read from the parser
- [x] `identity`: print this machine's key, minting one if absent, to provision a node ahead of time
- [x] `mint` / `adopt`: provision a second machine under an identity you control, via a one-time authkey
- [x] `ssh`: open an ssh session to a peer over the overlay (`swoosh ssh alice/desk`)
- [x] `tunnel expose` / `tunnel connect`: expose a local service under a name; reach a peer's service on
  a local port (with `--stdio` for `ssh` `ProxyCommand`)
- [x] `grant issue`: mint a `sheer:` capability link (a signed, expiring, attenuable, delegable grant with
  no server) to an exposed service
- [x] `grant narrow`: narrow a capability link offline and print a tighter one
- [x] `grant revoke`: refuse a capability link at this node at once, without waiting for its expiry
- [x] `fetch`: mint a local URL whose fetch egresses at a remote node you reach (choose the exit region)
- [ ] `send` / `recv`: push a file or directory to a peer, verified end to end
- [ ] `beam`: one verb for "get this over there": a file, piped stdin, the clipboard, or a fetched URL's
  result, delivered to a key
- [ ] `ssh config`: emit `ssh` `Host` aliases for devices that advertise ssh (waits on advertised services)
- [ ] `cluster` + `grant issue cluster`: name a local set of machines; share the whole group as one capability
- [ ] `run`: run code at a peer addressed by its key (the north star)
- [ ] MagicDNS `.theia` names: type `ssh desk.alice` or `http://blog.alice.theia` into any app

## Layout

- `crates/diag` the measurement engine (ping, speed): a small versioned protocol, a responder, and the
  two clients.
- `crates/swoosh` the CLI: binds one node under the chosen key and transport, then runs a command.

## License

MIT OR Apache-2.0.
