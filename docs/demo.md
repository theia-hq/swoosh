# Demo: admit a machine, refuse a stranger

Admit a second machine to a node you run. Reach it by its public key. A stranger who was never admitted is
refused at the door.

You address *who* (an ed25519 public key), never *where*. swoosh runs `ping` and `speed` from the member
over iroh (QUIC, NAT traversal, relays), and the gate holds: the member is in, the stranger is out.

Reproduce it:

<!-- manual: runs the full demo including the network leg -->
```console
$ cargo build
$ scripts/demo.sh
```

The script prints each step. It needs n0 discovery reachable. The transcripts below are from earlier runs and
are not re-checked against the current build.

## The cast

Three identities, each in its own home, so this is a real membership story and not a node talking to
itself:

- **the server** the node you run. It stays reachable and answers `ping`/`speed` behind its gate. A node
  with no provisioned root is its own root, so it admits itself and any device it vouches for, and refuses
  everyone else.
- **the member** a second machine the server admits. The server makes an invite for it; the member
  joins with that invite and becomes a device the server's root trusts.
- **the stranger** a third identity that is never admitted. It dials and is refused. Membership is real
  only if a non-member is actually turned away.

## Part 1: admit the member

The server makes an invite for a new device, `laptop`, and the member joins with it:

<!-- manual: needs a terminal for the root passphrase and an invite handed between homes -->
```console
$ swoosh invite laptop --new-key
$ swoosh join
```

`join` reads the invite from standard input. The member is a distinct identity (its own key) that the
server trusts. A node cannot connect to its own key, so a one-key demo could not run over iroh.

## Part 2: reach it by its key

Start `serve` on the server. iroh self-discovers over the internet, so the member needs no address:

<!-- live-run: the announced LAN address is this host's, one line each; 192.168.x.x stands in for yours -->
```console
$ swoosh serve
swoosh ready

    ed01tldy5zh5nvbqhfbvk46ijdppyay6ma6nkh76axuoh2tu7dpz6rfq

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  records    n0's public discovery: your addresses, for anyone with your key
  local      automatic; your devices just need the key (mDNS), announced at:
             192.168.x.x:58131

serving
  family-gated   your devices + peers you've granted
    ping    round-trip probe
    speed   throughput test

ctrl-c to stop
```

The member runs `ping` and `speed` against the server's key:

<!-- live-run: iroh reach over the internet observed 2026-09-15 (a GitHub runner reached a home node across NAT); RTT, path, and throughput vary per run, and 143.105.x.x masks the peer's address -->
```console
$ swoosh ping $SERVER -c 5 -i 0.2
ed01f62wtyapessv
  path: direct
  5 sent, 5 received, 0% loss
  rtt min/avg/max/mdev = 193.685/233.854/306.825/45.510 ms
$ swoosh speed $SERVER --down -t 3
speed test to ed01f62wtyapessv (down)
    1.0s  0.01 MiB/s
    2.0s  0.17 MiB/s
    3.0s  0.61 MiB/s
path: mixed (direct to 143.105.x.x:41125 and relayed)
down  0.91 MiB in 3.01s = 0.30 MiB/s
```

Add `-v` to `ping` to watch a relayed link hole-punch to direct in real time.

## Part 3: the stranger is refused

A third identity, never admitted, dials the same server. Its membership roots at its own key, which the
server has never trusted, so the gate turns it away:

<!-- manual: needs a second home that was never admitted -->
```console
$ swoosh ping $SERVER -c 3 -i 0.2
```

It exits 1 with a refusal. The member is in; the stranger is out.

## The limits

- The demo needs n0 discovery reachable. When it is down, a dial reports "unreachable" and the script says so.

## Next

- [Transports](transports.md) how swoosh reaches a machine.
- [Contractor access](use-cases/contractor-access.md) admit an outsider by a capability link, then revoke.
- [Keys](keys.md) the model the gate enforces.
