# Demo: swap the transport, keep the identity

Admit a second machine to a node you run. Reach it by its public key. Then swap the entire transport
stack under the identical command, for one we wrote ourselves, and watch the address stay the same. A
stranger who was never admitted is refused at the door, over either transport.

You address *who* (an ed25519 public key), never *where*, so the transport under the reach can be pulled
out and replaced. swoosh runs `ping` and `speed` over iroh (real QUIC, NAT traversal, relays)
and over **quirk+noise**, our own QUIC written from scratch over UDP behind a Noise wrapper, at the same
peer, from the same member identity. Same key, same NodeId, different transport. And the gate holds
across both.

Bare `quirk`, the announced base of that backend, is refused: it sends peer keys in plaintext, so a
signet-rooted gate refuses to arm over it. Part 2 stages that refusal.

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
> - **the announced base is refused, not used.** Bare `quirk` announces the reached key, so a
>   signet-rooted gate never arms over it; `quirk+noise` proves the key before any byte flows. Do not
>   read the announced base as a crypto mode.
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

<!-- capture: scripts/demo.sh (invite add) -->
```console
$ swoosh invite add laptop
invite:kxc3drkfdbpq24kaqas7uopt33lprpfutrdqfdfgtx73xqubuuda.bf01jsmb…
```

The member adopts it. On its own machine (a distinct key dir), `adopt` writes the derived seed as the
member's identity AND records the server's signet as trusted:

<!-- capture: scripts/demo.sh (adopt) -->
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

Bare `quirk` announces the reached key in plaintext, so the server's signet-rooted gate refuses to arm
over it. The serve exits before printing a banner:

<!-- capture: scripts/demo.sh (quirk refusal) -->
```console
$ swoosh serve --transport quirk
Error: use `--transport quirk+noise` to serve gated quirk traffic: this node gates on a signet, but the bound transport declares announced peer proof, so a gated dial could never be admitted; bind a transport that proves the peer (the default iroh transport does), or serve with an open gate (`Gate::Open`), which needs no peer proof
```

Exit status 1. That is the enforcement, live: an announced transport cannot root-admit, so a credential
is never written to it. The sealed spelling, below, is the opt-in that proves the key.

## Part 3: quirk+noise admits the gate

`quirk+noise` runs a Noise handshake over the same backend and proves the reached key, so the SAME
rooted gate arms here. It is still direct-only, so `serve` prints the address it is reachable at:

<!-- capture: scripts/demo.sh (quirk+noise serve) -->
```console
$ swoosh serve --transport quirk+noise
swoosh ready

    bf01jsmbbj7p3sjvcflap6bgmpbf64pf3bjsijk7fv7x44sjkcbtcnvq

how peers reach you
  LAN      automatic; your devices just need the key (mDNS)
  direct   reachable on this machine only:
           127.0.0.1:63254

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (never public)

ctrl-c to stop
```

The member dials, presenting the membership the server's signet signed for it, and passes the address
back with `--peer`:

<!-- capture: scripts/demo.sh (quirk+noise ping) -->
```console
$ swoosh ping $SERVER --transport quirk+noise --peer $SERVER=127.0.0.1:63254 -c 5 -i 0.2
bf01jsmbbj7p3sjv via quirk+noise: direct to 127.0.0.1:63254
  5 sent, 5 received, 0% loss
  rtt min/avg/max/mdev = 0.545/0.725/0.839/0.074 ms
```

Real RTTs at 0% loss, from an admitted member, over a QUIC we wrote ourselves and sealed.

## Part 4: swap the transport, keep the identity

Now start `serve` again from the SAME server key, over iroh. iroh self-discovers over the internet, so
no `--peer` is needed. The NodeId is byte-for-byte identical:

<!-- capture: scripts/demo.sh (iroh serve) -->
```console
$ swoosh serve --transport iroh
swoosh ready

    bf01jsmbbj7p3sjvcflap6bgmpbf64pf3bjsijk7fv7x44sjkcbtcnvq

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  LAN        automatic; your devices just need the key (mDNS)

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

<!-- pending live-run: iroh reach over the internet, non-deterministic; needs n0 discovery reachable -->
```console
$ swoosh ping  $SERVER --transport iroh -c 5 -i 0.2
$ swoosh speed $SERVER --transport iroh --down -t 3
```

Same member, same server key, same verbs, real reach over the internet path. Add `-v` to `ping` to
watch a relayed link hole-punch to direct in real time.

## Part 5: the stranger is refused

A third identity, never adopted, dials the same server. Its self-signed membership roots at its own key,
which the server's signet has never trusted, so the gate turns it away:

<!-- capture: scripts/demo.sh (stranger refused) -->
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

## The honest limitations

- Bare quirk announces its key, so swoosh refuses to serve gated traffic over it; `quirk+noise` wraps the
  same direct-only backend and proves the key.
- quirk is direct-only (no NAT traversal), which is exactly enough for this host-to-host demo.
- The iroh leg needs n0 discovery reachable. When it is down, an iroh dial reports "unreachable" and the
  bare-quirk refusal plus the sealed leg carry the show.

## Next

- [Transports](transports.md) iroh versus quirk+noise, in depth.
- [Contractor access](use-cases/contractor-access.md) admit an outsider by a capability link, then revoke.
- [Keys](keys.md) the model the gate enforces.
