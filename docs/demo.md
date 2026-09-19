# Demo: swap the transport, keep the identity

Admit a second machine to a node you run. Reach it by its public key. Then swap the entire transport
stack under the identical command, for one we wrote ourselves, and watch the address stay the same. A
stranger who was never admitted is refused at the door, over either transport.

You address *who* (an ed25519 public key), never *where*, so the transport under the reach can be pulled
out and replaced. swoosh runs `ping` and `speed` over iroh (real QUIC, NAT traversal, relays)
and over **quirk+noise**, a QUIC-shaped transport we wrote from scratch over UDP, with a Noise handshake that proves
the key, at the same peer, from the same member identity. Same key, same NodeId, different transport. And
the gate holds across both.

Bare `quirk`, the base `quirk+noise` builds on, is refused: it sends peer keys in plaintext, so `swoosh
serve` refuses over it. Part 2 stages that refusal.

Reproduce the whole thing:

<!-- manual: runs the full demo including the network leg -->
```console
$ cargo build
$ scripts/demo.sh
```

Everything below is captured from that script.

> Read the captions before the numbers:
>
> - **quirk's throughput is not a speed claim.** quirk is young; its loopback throughput varies run to
>   run and is nowhere near a mature stack. The point is that the SAME command runs over a transport we
>   wrote, not that it is fast.
> - **bare `quirk` is refused, not used.** Bare `quirk` never proves the peer holds its key, so `swoosh
>   serve` refuses over it; `quirk+noise` proves the key before any byte flows. Do not read bare `quirk`
>   as a crypto mode.
> - **The wow is the swap and the gate, not the number.** iroh's numbers and quirk's numbers are apples
>   to oranges (one is a mature stack over the internet, one is a phase-0 loopback). They sit side by
>   side only to prove the same verb rides both and the same gate admits or refuses across both.

## The cast

Three identities, each in its own key directory, so this is a real membership story and not a node
talking to itself:

- **the server** the node you run. It stays reachable and answers `ping`/`speed` behind its signet gate.
  A node with no provisioned signet is its own root, so it admits itself and any device it vouches for,
  and refuses everyone else.
- **the member** a second machine the server admits. The server signs an invite for it; the member
  `adopt`s that invite to become a device the server's signet trusts.
- **the stranger** a third identity that is never admitted. It dials and is refused. Membership is real
  only if a non-member is actually turned away.

## Part 1: admit the member

The server derives a device identity for the member and prints an invite to hand off:

<!-- capture: scripts/demo.sh invite-add -->
```console
$ swoosh invite add laptop
invite:….bf01jsmb…
```

The member adopts it. On its own machine (a distinct key dir), `adopt` writes the derived seed as the
member's identity AND records the server's signet as trusted:

<!-- capture: scripts/demo.sh adopt -->
```console
$ swoosh adopt @invite.txt
adopted this machine as bf01ntwii5ojl5fk  [mine]
trusting signet bf01jsmbbj7p3sjv: `swoosh serve` now admits its members and delegates.
stored your membership badge: this device now reaches your gated services.
```

The member is a distinct identity (its own key, its own NodeId) that the server trusts. That
distinctness is what lets the iroh leg below work: a node cannot connect to its own NodeId, so a
one-key demo could never run over iroh.

## Part 2: bare quirk refuses the gate

Bare `quirk` never proves the peer holds the key it presents; the key travels in plaintext, so `swoosh
serve` refuses over it. The serve exits before printing a banner:

<!-- capture: scripts/demo.sh quirk-refusal -->
```console
$ swoosh serve --transport quirk
Error: bare quirk cannot serve: it does not prove the peer's key; use `--transport quirk+noise`: this node gates on a signet, but the bound transport declares announced peer proof, so a gated dial could never be admitted; bind a transport that proves the peer (the default iroh transport does), or serve with an open gate (`Gate::Open`), which needs no peer proof
```

Exit status 1. That is the refusal, live: a transport that does not prove the key cannot root-admit, so a
credential is never written to it. The `quirk+noise` spelling, below, is the opt-in that proves the key.

## Part 3: quirk+noise admits the gate

`quirk+noise` runs a Noise handshake over the same backend and proves the reached key, so the SAME
rooted gate arms here. It is still direct-only, so `serve` lists every address it is dialable at. Both
nodes in this demo run on this machine, so the loopback line is the one to copy:

<!-- live-run: the NodeId is the demo server's, carried from part 4 so the same key reads the same on both; the port is this bind's, and 192.168.x.x and 100.x.x.x stand in for this host's network and tunnel addresses, with the mark column measured over the stand-ins -->
```console
$ swoosh serve --transport quirk+noise
swoosh ready

    bf01tldy5zh5nvbqhfbvk46ijdppyay6ma6nkh76axuoh2tu7dpz6rfq

how peers reach you
  local    automatic; local mDNS, or direct, no NAT traversal
  direct   hand a peer one of these:
           192.168.x.x:63872  (this network)
           100.x.x.x:63872    (this tunnel)
           127.0.0.1:63872    (this machine)

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (never public)

ctrl-c to stop
```

The member dials, presenting the membership the server's signet signed for it, and passes the address
back with `--peer`:

<!-- capture: scripts/demo.sh ping-quirk-noise -->
```console
$ swoosh ping $SERVER --transport quirk+noise --peer $SERVER=127.0.0.1:63254 -c 5 -i 0.2
bf01jsmbbj7p3sjv via quirk+noise: direct to 127.0.0.1:63254
  5 sent, 5 received, 0% loss
  rtt min/avg/max/mdev = 0.545/0.725/0.839/0.074 ms
```

Real RTTs at 0% loss, from an admitted member, over a QUIC we wrote ourselves, behind a Noise handshake
that proves the key.

## Part 4: swap the transport, keep the identity

Now start `serve` again from the SAME server key, over iroh. iroh self-discovers over the internet, so
no `--peer` is needed. The NodeId is byte-for-byte identical:

<!-- live-run: the announced LAN address is this host's, one line each; 192.168.x.x stands in for yours -->
```console
$ swoosh serve --transport iroh
swoosh ready

    bf01tldy5zh5nvbqhfbvk46ijdppyay6ma6nkh76axuoh2tu7dpz6rfq

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  records    n0's public discovery: your addresses, for anyone with your key
  local      automatic; your devices just need the key (mDNS), announced at:
             192.168.x.x:58131

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (never public)

ctrl-c to stop
```

The ed25519 NodeId is derived from the persisted secret, so it is the same across transports by
construction, not coincidence (pinned in CI: one secret over both backends asserts equal NodeIds). The
member runs the identical commands, now over iroh with no `--peer`:

<!-- live-run: iroh reach over the internet observed 2026-09-15 (a GitHub runner reached a home node across NAT); RTT, path, and throughput vary per run, and 143.105.x.x masks the peer's address -->
```console
$ swoosh ping  $SERVER --transport iroh -c 5 -i 0.2
bf01f62wtyapessv via iroh: mixed (direct to 143.105.x.x:41125 and relayed)
  5 sent, 5 received, 0% loss
  rtt min/avg/max/mdev = 193.685/233.854/306.825/45.510 ms
$ swoosh speed $SERVER --transport iroh --down -t 3
speed test to bf01f62wtyapessv via iroh (down)
    1.0s  0.01 MiB/s
    2.0s  0.17 MiB/s
    3.0s  0.61 MiB/s
path: mixed (direct to 143.105.x.x:41125 and relayed)
down  0.91 MiB in 3.01s = 0.30 MiB/s
```

Same member, same server key, same verbs, real reach over the internet path. Add `-v` to `ping` to
watch a relayed link hole-punch to direct in real time.

## Part 5: the stranger is refused

A third identity, never adopted, dials the same server. Its self-signed membership roots at its own key,
which the server's signet has never trusted, so the gate turns it away:

<!-- capture: scripts/demo.sh stranger-refused -->
```console
$ swoosh ping $SERVER --transport quirk+noise --peer $SERVER=127.0.0.1:63254 -c 3 -i 0.2
bf01jsmbbj7p3sjv via quirk+noise: reached, but refused (not admitted: no member badge or capability for this service was accepted)
Error: bf01jsmbbj7p3sjv: reached, but refused
```

Exit status 1. The member is in; the stranger is out. The script runs the same check over iroh when n0
discovery is reachable. That refusal is the most important line: the gate is real, not decorative, and it
holds no matter which transport carried the dial.

## Why this matters

Reach is replaceable, and membership is real. Because you address a public key and the verbs are generic over
the transport, the whole transport stack is a swappable component under an unchanged command with an
unchanged identity, and the same signet gate admits your devices and refuses everyone else across every
transport. No incumbent (ssh, cloudflared, tailscale, plain iroh tooling) can pull its transport out
from under the same address and command while proving the same membership gate holds.

## The limits

- Bare `quirk` never proves the peer's key, so swoosh refuses to serve gated traffic over it; `quirk+noise`
  runs a Noise handshake over the same direct-only backend and proves the key.
- quirk is direct-only (no NAT traversal), which is exactly enough for this host-to-host demo.
- The iroh leg needs n0 discovery reachable. When it is down, an iroh dial reports "unreachable" and the
  bare-quirk refusal plus the `quirk+noise` leg carry the show.

## Next

- [Transports](transports.md) iroh versus quirk+noise, in depth.
- [Contractor access](use-cases/contractor-access.md) admit an outsider by a capability link, then revoke.
- [Keys](keys.md) the model the gate enforces.
