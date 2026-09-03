# Getting started

Reach one machine from another by its public key, across the internet, in a couple of minutes. No
account, no server to set up. Start with the frictionless win: open a service to anyone, reach it from
another machine, done. Auth, names, and sharing come after, each a small addition on this.

You will need two machines (your laptop and a desktop, a home box, or a cheap VPS).

## 1. Install

```console
$ curl -fsSL https://raw.githubusercontent.com/theia-hq/swoosh/main/scripts/install.sh | sh
```

This downloads the right binary for your platform, verifies its checksum, and installs it to
`~/.local/bin`. Do it on both machines. (Prefer to do it yourself? Grab a binary from the
[releases page](https://github.com/theia-hq/swoosh/releases); each carries a checksum and a signature.)

## 2. Open a service to anyone (machine A)

On the machine you want to reach, open two diagnostics to anyone and note the key it prints:

<!-- capture: swoosh serve --public ping,speed -->
```console
$ swoosh serve --public ping,speed
swoosh ready

    bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  LAN        automatic; your devices just need the key (mDNS)

serving
  family-gated   your devices + peers you've granted
    control.*   node control (never public)
  public !   anyone, unauthenticated
    ping    round-trip probe   unmetered: a stranger can drain your uplink
    speed   throughput test   unmetered: a stranger can drain your uplink

ctrl-c to stop
```

That base32 string is machine A's public key. Copy it. Leave this running.

## 3. Reach it (machine B)

On the other machine, ping and speed-test machine A by its key. There is nothing to set up on B and no
credential to present:

<!-- live-run: real iroh RTT over the internet, non-deterministic; re-capture before release -->
```console
$ swoosh ping bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q -c 4
bf01hcq6balrlxwa via iroh: mixed (direct to 192.168.1.64:51778 and relayed)
  4 sent, 4 received, 0% loss
  rtt min/avg/max/mdev = 0.532/0.739/0.888/0.103 ms
```

<!-- live-run: real iroh throughput over the internet, non-deterministic; re-capture before release -->
```console
$ swoosh speed bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q --down -t 5
speed test to bf01hcq6balrlxwa via iroh (down)
    1.0s  38.24 MiB/s
    2.0s  60.25 MiB/s
    3.0s  60.18 MiB/s
    4.0s  59.46 MiB/s
    5.0s  59.63 MiB/s
path: mixed (direct and relayed)
down  297.79 MiB in 5.00s = 59.56 MiB/s
```

That is a real round trip and real throughput to another machine, reached by key alone, across the
internet, with no account anywhere. That is your first success.

## Where to go next: climb the ladder

You just did the zero-auth version. Each step from here adds exactly one thing:

- **Add a gate.** Drop `--public` and the same services admit only your own devices, refusing strangers.
  A machine is its own root of trust. See [Keys: the gate](keys.md#the-gate).
- **Reach by name.** Save a key under a petname once, then use the name everywhere:
  `swoosh contact add desk <key>`, then `swoosh ping desk`. See [contact](reference/commands.md#contact).
- **Enroll your own machines.** `swoosh mint` / `swoosh adopt` bring a laptop or server under your one
  identity, so they all reach each other with no per-service step. See
  [Reach your own devices](use-cases/reach-your-own-devices.md).
- **Let other people in.** Issue a [slip](keys.md#slip) to one service, for one person or their whole
  fleet, revocable. See [use cases](use-cases/README.md).

## Next

- [Keys](keys.md) the model in five nouns: read this next.
- [Use cases](use-cases/README.md) pick the situation that matches yours.
- [Commands](reference/commands.md) every verb and flag.
