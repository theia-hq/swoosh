# The transport-swap demo

Reach a peer by its public key. Then swap the entire transport stack underneath the identical command,
for one we wrote ourselves, and watch the address stay the same.

This is the thing no incumbent tool can show. You do not reconfigure, re-register, or re-address. You
address _who_ (an ed25519 public key), never _where_, so the transport under the reach is a seam you can
pull out and replace. `swoosh` runs `ping` and `speed` over iroh (real QUIC, NAT traversal, relays) and
over **quirk**, our own QUIC written from scratch over UDP, from the SAME persisted identity. Same key,
same NodeId, different transport. That is the whole show.

> Honest captions, read them before the numbers:
>
> - **quirk's throughput is not a speed claim.** quirk phase 0 is stop-and-wait (one un-acked frame in
>   flight), so it tops out around 16 MiB/s. Multi-stream and a real congestion window are future work.
>   The dyno's point is that the SAME command runs over a transport we wrote, not that it is fast.
> - **quirk's identity is plaintext-nominal until Noise.** Over iroh the reached identity is
>   cryptographically proven; over quirk phase 0 it is a self-announced key (a `dialed != reached` check
>   closes accidental mismatch, but a plaintext MITM still defeats it). Noise is phase 1. Do not read the
>   quirk half as proven crypto.
> - **The wow is the swap, not the number.** iroh's MiB/s and quirk's MiB/s are apples to oranges (one is
>   a mature stack over the internet, one is our phase-0 loopback). We show them side by side only to prove
>   the same verb rides both.

## The setup

Two processes, two distinct persisted key files, host-local. Each `SWOOSH_KEY` file is one ed25519
secret; the server's yields one NodeId that we will see printed identically over both transports.

```sh
export SERVER_KEY=/tmp/swoosh-demo/server.key   # the peer we reach
export CLIENT_KEY=/tmp/swoosh-demo/client.key   # the one reaching
```

## Part 1: reach over quirk (our own QUIC)

quirk is direct-only (no NAT traversal yet), so `serve` prints a copy-pasteable `--peer <key>=<addr>`
hint that the client feeds back. That hint is quirk's discovery.

```sh
# terminal 1
SWOOSH_KEY=$SERVER_KEY swoosh --transport quirk serve
```

```
swoosh ready. peers can reach this node at:

    bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma

    --peer bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma=127.0.0.1:53487

answering ping and speed. press ctrl-c to stop.
```

```sh
# terminal 2, feed back the printed key and hint
KEY=bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma
SWOOSH_KEY=$CLIENT_KEY swoosh --transport quirk ping  $KEY --peer $KEY=127.0.0.1:53487 -c 5 -i 0.2
SWOOSH_KEY=$CLIENT_KEY swoosh --transport quirk speed $KEY --peer $KEY=127.0.0.1:53487 --down -t 3
SWOOSH_KEY=$CLIENT_KEY swoosh --transport quirk speed $KEY --peer $KEY=127.0.0.1:53487 --up   -t 3
```

Real captured output:

```
pinging bf01rwbkys5qovt4 (5 probes)
5 probes sent, 5 replies, 0% loss
rtt min/avg/max/mdev = 0.575/1.342/2.326/0.432 ms

speed test to bf01rwbkys5qovt4 (down)
49.57 MiB in 3.00s = 16.52 MiB/s (down)

speed test to bf01rwbkys5qovt4 (up)
49.44 MiB in 3.00s = 16.46 MiB/s (up)
```

Real RTTs at 0% loss and real bytes moved in both directions, over a QUIC we wrote ourselves. The
~16 MiB/s is the honest phase-0 stop-and-wait ceiling, not a speed claim.

## Part 2: swap the transport, keep the identity

Now stop the quirk node and start `serve` again from the **same key file**, over iroh. Nothing else
changes. iroh self-discovers over the internet (n0 pkarr/DNS plus relays), so no `--peer` is needed.

```sh
# terminal 1, SAME SERVER_KEY, different transport
SWOOSH_KEY=$SERVER_KEY swoosh --transport iroh serve
```

```
swoosh ready. peers can reach this node at:

    bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma

    --peer bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma=127.0.0.1:56901

    --peer bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma=[::]:60061

answering ping and speed. press ctrl-c to stop.
```

Look at the NodeId:

```
quirk:  bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma
iroh:   bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma
```

Byte for byte identical. The ed25519 NodeId is derived deterministically from the persisted secret, so
it is the same across transports by construction, not by coincidence (pinned in CI: a bifrost-quirk test
binds one secret over both backends and asserts equal NodeIds). Swap the transport, keep the key, keep
the address. That is what makes this a swap and not a new node.

The identical client commands, now over iroh (no `--peer`, iroh finds the peer itself):

```sh
# terminal 2
KEY=bf01rwbkys5qovt4kartnbxawkezyom2ngl64tzkrla44e53jb5xg3ma
SWOOSH_KEY=$CLIENT_KEY swoosh --transport iroh ping  $KEY -c 5 -i 0.2
SWOOSH_KEY=$CLIENT_KEY swoosh --transport iroh speed $KEY --down -t 3
```

Real captured output:

```
pinging bf01rwbkys5qovt4 (5 probes)
5 probes sent, 5 replies, 0% loss
rtt min/avg/max/mdev = 84.658/201.660/583.714/152.822 ms

speed test to bf01rwbkys5qovt4 (down)
0.54 MiB in 3.00s = 0.18 MiB/s (down)
```

Same verbs, same key, real reach over the internet path (these two processes discovered each other
through n0 relays rather than a direct hole-punch, which is why the RTT and throughput reflect the relay
path, not loopback). The numbers across the two parts are not comparable and are not meant to be: the
proof is that `swoosh ping <key>` and `swoosh speed <key>` are the exact same command whether the bytes
ride iroh or ride quirk.

## Why this matters

Reach is a seam. Because you address a public key and the verbs are generic over the transport, the
entire transport stack is a swappable component under an unchanged command with an unchanged identity. We
demonstrated it by swapping in a QUIC we wrote from scratch. No incumbent (ssh, cloudflared, tailscale,
plain iroh tooling) can pull its transport out from under the same address and command. That is the
transport dyno.

## Reproduce it

```sh
cargo build
scripts/demo.sh
```

`scripts/demo.sh` runs both halves end to end against fresh throwaway key files and prints the same-NodeId
check. The quirk half is direct-only over loopback and needs no network; the iroh half needs
reachability to n0 discovery and relays. If iroh is unreachable, the quirk half (the novel part, our own
transport) still stands on its own.

## The honest limitations

- quirk phase 0 is plaintext (Noise is phase 1), so the quirk identity is nominal, not proven crypto.
- quirk phase 0 is stop-and-wait (~16 MiB/s ceiling); multi-stream and a congestion window come later.
- quirk is direct-only (no NAT traversal), which is exactly enough for this host-to-host demo and nothing
  more; NAT traversal is future work (maggie/derpie).
- The built-in responder answers any peer (no nauthy gating yet).
