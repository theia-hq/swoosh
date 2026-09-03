# The membership + transport-swap demo

Admit a second machine to a node you run. Reach it by its public key. Then swap the entire transport
stack underneath the identical command, for one we wrote ourselves, and watch the address stay the same.
A stranger who was never admitted is refused at the door.

This is the thing no incumbent tool can show in one run. You do not reconfigure, re-register, or
re-address. You address _who_ (an ed25519 public key), never _where_, so the transport under the reach is
a seam you can pull out and replace. `swoosh` runs `ping` and `speed` over iroh (real QUIC, NAT traversal,
relays) and over **quirk**, our own QUIC written from scratch over UDP, at the same peer, from the same
member identity. Same key, same NodeId, different transport. And the gate holds across both: the member is
admitted, the stranger is refused, whichever transport carried the dial.

> Honest captions, read them before the numbers:
>
> - **quirk's throughput is not a speed claim.** quirk phase 0 is stop-and-wait (one un-acked frame in
>   flight), so it tops out around 14 MiB/s. Multi-stream and a real congestion window are future work.
>   The dyno's point is that the SAME command runs over a transport we wrote, not that it is fast.
> - **quirk's identity is plaintext-nominal until Noise.** Over iroh the reached identity is
>   cryptographically proven; over quirk phase 0 it is a self-announced key (a `dialed != reached` check
>   closes accidental mismatch, but a plaintext MITM still defeats it). Noise is phase 1. Do not read the
>   quirk half as proven crypto.
> - **The wow is the swap and the gate, not the number.** iroh's MiB/s and quirk's MiB/s are apples to
>   oranges (one is a mature stack over the internet, one is our phase-0 loopback). We show them side by
>   side only to prove the same verb rides both and the same gate admits or refuses across both.

## The cast

Three identities, each in its own key directory, so this is a real membership story and not a node talking
to itself:

- **the server** (`/tmp/swoosh-demo/server`): the node you run. It stays reachable and answers reach
  diagnostics (`ping`/`speed`) behind its signet gate. A node with its own key and no provisioned signet
  is its OWN signet root (person-zero self-trusts), so it admits itself and any device it later vouches
  for, and refuses everyone else. No `--public` anywhere in this demo.
- **the member** (`/tmp/swoosh-demo/member`): a second machine the server admits. The server `mint`s an
  authkey for it; the member `adopt`s that authkey to become a device identity the server's signet trusts.
- **the stranger** (`/tmp/swoosh-demo/stranger`): a third identity that is never admitted. It dials the
  server and is refused at the gate. This is the security-load-bearing line: membership is real only if a
  non-member is actually turned away.

```sh
export SERVER=/tmp/swoosh-demo/server/identity.key
export MEMBER=/tmp/swoosh-demo/member/identity.key
export STRANGER=/tmp/swoosh-demo/stranger/identity.key
mkdir -p /tmp/swoosh-demo/server /tmp/swoosh-demo/member /tmp/swoosh-demo/stranger
```

`--key` (or `SWOOSH_KEY`) pins the whole identity directory: the key, the address book, the signet it
trusts, and the badge it carries all live beside each other under that dir, so three dirs is three
sovereign identities on one host.

## Part 1: admit the member

The server derives a device identity for the member and prints an `authkey` to hand off. The `mint` runs
under the server's own key (its signet), and records the member under the reserved `me/` petname so the
server can address it by name later.

```sh
# on the server
SWOOSH_KEY=$SERVER swoosh mint laptop
```

```
authkey:qiwtxtu3gal4j4svr73gvf2yeboab3sbwwfp3tpdqvyrvekxdsja.bf01dqd6hpuofhyhfxccpluqrkttqw4zmfx5oi3gcqfm7nlh5nswntgq.sheer:...

recorded me/laptop -> bf01ldn6r2gjooph  [derived]
hand this authkey to the machine (a SECRET: adopting it becomes this identity and trusts your signet).
```

The member adopts it. On the member's machine (here, a distinct key dir), `adopt` writes the derived seed
as the member's own identity AND records the server's signet as trusted, so the member both becomes the
minted device and knows whose gate it can enter.

```sh
# on the member
SWOOSH_KEY=$MEMBER swoosh adopt "authkey:qiwtxtu3gal4j4svr73gvf2yeboab3sbwwfp3tpdqvyrvekxdsja...."
```

```
adopted this machine as bf01hspw63gouabd  [mine]
trusting signet bf01dqd6hpuofhyh: `swoosh serve` now admits its members and delegates.
stored your membership badge: this device now reaches your gated services.
```

The member's own NodeId is now `bf01hspw63gouabd`, which is exactly the id the server recorded as
`me/laptop`. The member is a distinct identity (its own key, its own NodeId) that the server trusts. That
distinctness is the whole reason the iroh leg below works: a node cannot connect to its own NodeId, so the
old one-key demo could never have run over iroh. Two identities is the honest showcase.

## Part 2: the member reaches the server over quirk (our own QUIC)

quirk is direct-only (no NAT traversal yet), so `serve` prints the node's key and the machine address
it is reachable at. The client feeds both back as `--peer <key>=<addr>`. That address is quirk's
discovery.

```sh
# on the server
SWOOSH_KEY=$SERVER swoosh serve --transport quirk
```

```
swoosh ready

    bf01dqd6hpuofhyhfxccpluqrkttqw4zmfx5oi3gcqfm7nlh5nswntgq

how peers reach you
  LAN      automatic; your devices just need the key (mDNS)
  direct   reachable on this machine only:
           127.0.0.1:61110

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (always family-gated)

ctrl-c to stop
```

The member dials, feeding back the printed key and hint. It presents the badge the server's signet minted
for it, so the gate admits it.

```sh
# on the member
SERVER_KEY=bf01dqd6hpuofhyhfxccpluqrkttqw4zmfx5oi3gcqfm7nlh5nswntgq
SWOOSH_KEY=$MEMBER swoosh ping  $SERVER_KEY --transport quirk --peer $SERVER_KEY=127.0.0.1:61110 -c 5 -i 0.2
SWOOSH_KEY=$MEMBER swoosh speed $SERVER_KEY --transport quirk --peer $SERVER_KEY=127.0.0.1:61110 --down -t 3
SWOOSH_KEY=$MEMBER swoosh speed $SERVER_KEY --transport quirk --peer $SERVER_KEY=127.0.0.1:61110 --up   -t 3
```

Real captured output:

```
bf01dqd6hpuofhyh via quirk: direct to 127.0.0.1:61110
  5 sent, 5 received, 0% loss
  rtt min/avg/max/mdev = 0.249/0.908/1.349/0.377 ms

speed test to bf01dqd6hpuofhyh via quirk (down)
    1.0s  13.95 MiB/s
    2.0s  13.37 MiB/s
    3.0s  13.71 MiB/s
path: direct to 127.0.0.1:61110
down  41.05 MiB in 3.00s = 13.68 MiB/s

speed test to bf01dqd6hpuofhyh via quirk (up)
    1.0s  13.49 MiB/s
    2.0s  13.88 MiB/s
    3.0s  14.12 MiB/s
path: direct to 127.0.0.1:61110
up    41.56 MiB in 3.02s = 13.77 MiB/s
```

Real RTTs at 0% loss and real bytes moved in both directions, from an admitted member, over a QUIC we
wrote ourselves. The ~14 MiB/s is the honest phase-0 stop-and-wait ceiling, not a speed claim.

Tired of pasting the key? Name it once and reach it by name (`swoosh contact add server $SERVER_KEY`, then
`swoosh ping server`). The name is local and self-sovereign, your address book, not a registry. See the
README's Contacts section.

## Part 3: swap the transport, keep the identity

Now stop the quirk server and start `serve` again from the same server key, over iroh. Nothing else
changes. iroh self-discovers over the internet (n0 pkarr/DNS plus relays), so no `--peer` is needed.

```sh
# on the server, SAME key, different transport
SWOOSH_KEY=$SERVER swoosh serve --transport iroh
```

The server's NodeId is byte-for-byte identical across the two transports:

```
quirk:  bf01dqd6hpuofhyhfxccpluqrkttqw4zmfx5oi3gcqfm7nlh5nswntgq
iroh:   bf01dqd6hpuofhyhfxccpluqrkttqw4zmfx5oi3gcqfm7nlh5nswntgq
```

The ed25519 NodeId is derived deterministically from the persisted secret, so it is the same across
transports by construction, not by coincidence (pinned in CI: a bifrost-quirk test binds one secret over
both backends and asserts equal NodeIds). Swap the transport, keep the key, keep the address.

The identical member commands, now over iroh (no `--peer`, iroh finds the peer itself):

```sh
# on the member, SAME member key, no --peer: iroh self-discovers.
SERVER_KEY=bf01dqd6hpuofhyhfxccpluqrkttqw4zmfx5oi3gcqfm7nlh5nswntgq
SWOOSH_KEY=$MEMBER swoosh ping  $SERVER_KEY --transport iroh -c 5 -i 0.2
SWOOSH_KEY=$MEMBER swoosh speed $SERVER_KEY --transport iroh --down -t 3
```

Real captured output:

```
bf01dqd6hpuofhyh via iroh: mixed (direct to 129.222.206.36:57307 and relayed)
  5 sent, 5 received, 0% loss
  rtt min/avg/max/mdev = 46.508/105.022/219.497/57.241 ms

speed test to bf01dqd6hpuofhyh via iroh (down)
    1.0s  0.10 MiB/s
    2.0s  0.52 MiB/s
    3.0s  0.27 MiB/s
path: mixed (direct to 129.222.206.36:57307 and relayed)
down  0.99 MiB in 3.01s = 0.33 MiB/s
```

Add `-v` to `ping` to WATCH that path settle: it prints a line per probe as it lands (like `tailscale
ping`), sampling the path beside each pong, so the exact probe where a relayed link hole-punches to
direct reads `(upgraded from relayed)` in real time. The `ping(8)` summary still follows.

Same member, same server key, same verbs, real reach over the internet path. Because the member is a
distinct identity, there is no self-connect: iroh accepts the dial (the one-key demo could not, iroh
forbids connecting to your own NodeId). The numbers across quirk and iroh are not comparable and are not
meant to be: the proof is that `swoosh ping <key>` and `swoosh speed <key>` are the exact same command
whether the bytes ride iroh or ride quirk.

## Part 4: the stranger is refused

A third identity, never adopted, dials the same server. Its self-signed badge roots at its own key, which
the server's signet has never trusted, so the gate turns it away, over either transport.

```sh
# on the stranger (never adopted)
SERVER_KEY=bf01dqd6hpuofhyhfxccpluqrkttqw4zmfx5oi3gcqfm7nlh5nswntgq
SWOOSH_KEY=$STRANGER swoosh ping $SERVER_KEY --transport quirk --peer $SERVER_KEY=127.0.0.1:50255 -c 3 -i 0.2
```

Real captured output:

```
Error: read frame: stream: service refused: capability does not grant this service
```

Exit status 1. The member is in; the stranger is out. That refusal is the demo's most important line: the
gate is real, not decorative, and it holds no matter which transport carried the dial.

## Tear it down from the member

The member stops the server it was admitted to, no shell on the box. `stop` dials the server's gated
`control.stop` service, the member's badge admits it, and the node stops serving.

```sh
# on the member
SWOOSH_KEY=$MEMBER swoosh stop $SERVER_KEY
```

The stranger cannot: the same gate that refused its ping refuses its stop. Membership gates the whole
node, teardown included.

## Why this matters

Reach is a seam, and membership is real. Because you address a public key and the verbs are generic over
the transport, the entire transport stack is a swappable component under an unchanged command with an
unchanged identity, and the same signet gate admits your devices and refuses everyone else across every
transport. We demonstrated the swap by dropping in a QUIC we wrote from scratch. No incumbent (ssh,
cloudflared, tailscale, plain iroh tooling) can pull its transport out from under the same address and
command while proving the same membership gate holds. That is the dyno.

## Reproduce it

```sh
cargo build
scripts/demo.sh
```

`scripts/demo.sh` runs the whole arc end to end against fresh throwaway key dirs: mint + adopt the member,
reach over quirk and over iroh, and refuse the stranger, printing the same-NodeId check. The quirk half is
direct-only over loopback and needs no network; the iroh half needs reachability to n0 discovery and
relays. If iroh is unreachable, the script says so and the quirk half (the novel part, our own transport,
plus the membership gate) still stands on its own.

## The honest limitations

- quirk phase 0 is plaintext (Noise is phase 1), so the quirk identity is nominal, not proven crypto.
- quirk phase 0 is stop-and-wait (~14 MiB/s ceiling); multi-stream and a congestion window come later.
- quirk is direct-only (no NAT traversal), which is exactly enough for this host-to-host demo and nothing
  more; NAT traversal is future work (maggie/derpie).
- The iroh leg depends on n0 discovery being reachable. When discovery is down, an iroh dial reports
  "unreachable" rather than reaching; that is a network condition, not a demo defect, and the quirk leg
  plus the membership gate carry the show.
