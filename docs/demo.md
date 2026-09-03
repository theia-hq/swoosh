# Demo: swap the transport, keep the identity

Admit a second machine to a node you run. Reach it by its public key. Then swap the entire transport
stack under the identical command, for one we wrote ourselves, and watch the address stay the same. A
stranger who was never admitted is refused at the door, over either transport.

You address *who* (an ed25519 public key), never *where*, so the transport under the reach is a seam you
can pull out and replace. swoosh runs `ping` and `speed` over iroh (real QUIC, NAT traversal, relays)
and over **quirk**, our own QUIC written from scratch over UDP, at the same peer, from the same member
identity. Same key, same NodeId, different transport. And the gate holds across both.

Reproduce the whole thing:

```console
$ cargo build
$ scripts/demo.sh
```

Everything below is captured from that script.

> Honest captions, read them before the numbers:
>
> - **quirk's throughput is not a speed claim.** quirk is young; its loopback throughput varies run to
>   run and is nowhere near a mature stack. The point is that the SAME command runs over a transport we
>   wrote, not that it is fast.
> - **quirk's identity is plaintext-nominal until Noise.** Over iroh the reached identity is
>   cryptographically proven; over quirk it is a self-announced key. Do not read the quirk half as proven
>   crypto.
> - **The wow is the swap and the gate, not the number.** iroh's numbers and quirk's numbers are apples
>   to oranges (one is a mature stack over the internet, one is a phase-0 loopback). They sit side by
>   side only to prove the same verb rides both and the same gate admits or refuses across both.

## The cast

Three identities, each in its own key directory, so this is a real membership story and not a node
talking to itself:

- **the server** the node you run. It stays reachable and answers `ping`/`speed` behind its signet gate.
  A node with no provisioned signet is its own root, so it admits itself and any device it vouches for,
  and refuses everyone else.
- **the member** a second machine the server admits. The server `mint`s an authkey for it; the member
  `adopt`s that authkey to become a device the server's signet trusts.
- **the stranger** a third identity that is never admitted. It dials and is refused. Membership is real
  only if a non-member is actually turned away.

## Part 1: admit the member

The server derives a device identity for the member and prints an authkey to hand off:

<!-- capture: scripts/demo.sh (mint) -->
```console
$ swoosh mint laptop
authkey:zb5p7c2fda6fg2znhsjxqm7ywumwyrl6sdlwspdercdglm43dsgq.bf01hwtt…
```

The member adopts it. On its own machine (a distinct key dir), `adopt` writes the derived seed as the
member's identity AND records the server's signet as trusted:

<!-- capture: scripts/demo.sh (adopt) -->
```console
$ swoosh adopt @authkey.txt
adopted this machine as bf01n7xynfd7dsms  [mine]
trusting signet bf01hwttmgsklixr: `swoosh serve` now admits its members and delegates.
stored your membership badge: this device now reaches your gated services.
```

The member is a distinct identity (its own key, its own NodeId) that the server trusts. That
distinctness is what lets the iroh leg below work: a node cannot connect to its own NodeId, so a
one-key demo could never run over iroh.

## Part 2: reach the server over quirk (our own QUIC)

quirk is direct-only, so `serve` prints the address it is reachable at. The client feeds it back with
`--peer`:

<!-- capture: scripts/demo.sh (quirk serve) -->
```console
$ swoosh serve --transport quirk
swoosh ready

    bf01hwttmgsklixrdr6f6nrsuefz6es77cebjvamv3jzlip7eiixbkma

how peers reach you
  LAN      automatic; your devices just need the key (mDNS)
  direct   reachable on this machine only:
           127.0.0.1:52364

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (always family-gated)

ctrl-c to stop
```

The member dials, presenting the badge the server's signet minted for it, so the gate admits it:

<!-- capture: scripts/demo.sh (quirk ping + speed) -->
```console
$ swoosh ping  $SERVER --transport quirk --peer $SERVER=127.0.0.1:52364 -c 5 -i 0.2
bf01hwttmgsklixr via quirk: direct to 127.0.0.1:52364
  5 sent, 5 received, 0% loss
  rtt min/avg/max/mdev = 0.107/0.273/0.353/0.068 ms

$ swoosh speed $SERVER --transport quirk --peer $SERVER=127.0.0.1:52364 --down -t 3
speed test to bf01hwttmgsklixr via quirk (down)
    1.0s  24.15 MiB/s
    2.0s  23.58 MiB/s
    3.0s  24.58 MiB/s
path: direct to 127.0.0.1:52364
down  72.33 MiB in 3.00s = 24.11 MiB/s
```

Real RTTs at 0% loss and real bytes moved, from an admitted member, over a QUIC we wrote ourselves.

## Part 3: swap the transport, keep the identity

Now start `serve` again from the SAME server key, over iroh. iroh self-discovers over the internet, so
no `--peer` is needed. The NodeId is byte-for-byte identical:

<!-- capture: scripts/demo.sh (iroh serve) -->
```console
$ swoosh serve --transport iroh
swoosh ready

    bf01hwttmgsklixrdr6f6nrsuefz6es77cebjvamv3jzlip7eiixbkma

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  LAN        automatic; your devices just need the key (mDNS)

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (always family-gated)

ctrl-c to stop
```

The ed25519 NodeId is derived from the persisted secret, so it is the same across transports by
construction, not coincidence (pinned in CI: one secret over both backends asserts equal NodeIds). The
member runs the identical commands, now over iroh with no `--peer`:

<!-- pending live-run: iroh reach over the internet, non-deterministic; needs n0 discovery reachable -->
```console
$ swoosh ping  $SERVER --transport iroh -c 5 -i 0.2
$ swoosh speed $SERVER --transport iroh --down -t 3
```

Same member, same server key, same verbs, real reach over the internet path. Add `-v` to `ping` to
watch a relayed link hole-punch to direct in real time.

## Part 4: the stranger is refused

A third identity, never adopted, dials the same server. Its self-signed badge roots at its own key,
which the server's signet has never trusted, so the gate turns it away:

<!-- capture: scripts/demo.sh (stranger refused) -->
```console
$ swoosh ping $SERVER --transport quirk --peer $SERVER=127.0.0.1:52364 -c 3 -i 0.2
bf01hwttmgsklixr via quirk: reached, but refused (not admitted: not a member of this node's family, and no capability for this service)
```

Exit status 1. The member is in; the stranger is out. That refusal is the most important line: the gate
is real, not decorative, and it holds no matter which transport carried the dial.

## Why this matters

Reach is a seam, and membership is real. Because you address a public key and the verbs are generic over
the transport, the whole transport stack is a swappable component under an unchanged command with an
unchanged identity, and the same signet gate admits your devices and refuses everyone else across every
transport. No incumbent (ssh, cloudflared, tailscale, plain iroh tooling) can pull its transport out
from under the same address and command while proving the same membership gate holds.

## The honest limitations

- quirk has no Noise handshake yet, so the quirk identity is nominal, not proven crypto.
- quirk is direct-only (no NAT traversal), which is exactly enough for this host-to-host demo.
- The iroh leg needs n0 discovery reachable. When it is down, an iroh dial reports "unreachable" and the
  quirk leg plus the membership gate carry the show.

## Next

- [Transports](transports.md) iroh versus quirk, in depth.
- [Contractor access](use-cases/contractor-access.md) admit an outsider by a slip, then revoke.
- [Keys](keys.md) the model the gate enforces.
