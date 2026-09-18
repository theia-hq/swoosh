# Getting started

Reach one machine from another by its public key, across the internet, in a couple of minutes. No
account, no server to set up. Start with the frictionless win: open a service to anyone, reach it from
another machine, done. Auth, names, and sharing come after, each a small addition on this.

You will need two machines (your laptop and a desktop, a home box, or a cheap VPS).

> **Only one machine?** Run both ends on it over `quirk+noise`: start `swoosh serve --transport
> quirk+noise` in one terminal, then reach it from another with `swoosh ping <key> --transport
> quirk+noise --peer <key>=<addr>`, using the key and the `direct` address `serve` prints. See
> [transports](transports.md#quirk).

## 1. Install

<!-- manual: installs a released binary over the network -->
```console
$ curl -fsSL https://raw.githubusercontent.com/theia-hq/swoosh/main/scripts/install.sh | sh
```

This downloads the right binary for your platform, verifies its checksum, and installs it to
`~/.local/bin`. Do it on both machines. Prefer to do it yourself? Grab a binary from the
[releases page](https://github.com/theia-hq/swoosh/releases); each carries a checksum and a
build-provenance attestation (`gh attestation verify`).

## 2. Open a service to anyone (machine A)

On the machine you want to reach, open two diagnostics to anyone and note the key it prints:

<!-- live-run: the announced LAN address is this host's, one line each; 192.168.x.x stands in for yours -->
```console
$ swoosh serve --public ping,speed
swoosh ready

    bf01lezchywdg2izx5bvyaka433iqzg4oxbt7j2aoxp7tjtyq2a7jjqq

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  records    n0's public discovery: your addresses, for anyone with your key
  local      automatic; your devices just need the key (mDNS), announced at:
             192.168.x.x:58131

serving
  family-gated   your devices + peers you've granted
    control.*   node control (never public)
  public !   anyone, unauthenticated
    ping    round-trip probe
    speed   throughput test

ctrl-c to stop
```

The key it prints is machine A's public key. Copy it. Leave this running.

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

<!-- live-run: real iroh throughput; a public route is metered, so the run may stop before -t -->
```console
$ swoosh speed bf01uyi7g54bpea45hafea4gohlnay5bs23p3ck4z4g24dvcpeldkczq --down -t 5
speed test to bf01uyi7g54bpea4 via iroh (down)
path: direct to 127.0.0.1:50769
down  64.00 MiB in 0.58s = 110.87 MiB/s
```

An open route is metered: 64 MiB per direction per stream, so the test may stop before `-t`.

That is a real round trip and real throughput to another machine, reached by key alone, across the
internet, with no account anywhere. That is your first success.

## Where to go next: climb the ladder

You just did the zero-auth version. Each step from here adds exactly one thing:

- **Enroll your own machines.** `swoosh invite add` / `swoosh adopt` bring a laptop or server under your
  one identity, so they all reach each other with no per-service step. See
  [Reach your own devices](use-cases/reach-your-own-devices.md).
- **Add a gate.** Drop `--public` and the same services admit only your own devices, refusing strangers.
  A machine is its own root of trust. See [Keys: the gate](keys.md#the-gate).
- **Reach by name.** Save a key under a petname once, then use the name everywhere:
  `swoosh contact add desk <key>`, then `swoosh ping desk`. See [contact](reference/commands.md#contact).
- **Let other people in.** Issue a `sheer:` capability link to one service, for one person or their
  whole fleet, revocable. [Capabilities](capabilities.md) walks the whole loop in a minute.

## Next

- [Keys](keys.md) the model in five nouns: read this next.
- [Use cases](use-cases/README.md) pick the situation that matches yours.
- [Commands](reference/commands.md) every verb and flag.
