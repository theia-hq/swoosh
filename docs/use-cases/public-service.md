# Public service

You want to offer a service to anyone, no credential: a public ping target, a speed-test endpoint, a
fetch relay. By default swoosh refuses strangers, so opening a service to the world is a deliberate,
named opt-out.

## Open named services

Name the services you want public. Everything else stays [gated](../keys.md#the-gate):

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

Anyone with the key reaches the two public services and nothing else. There is no link to hand out and
nothing to present:

<!-- live-run: real iroh RTT over the internet, non-deterministic; 135.129.x.x masks the peer's address; re-capture before release -->
```console
$ swoosh ping bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q -c 4
bf01hcq6balrlxwa via iroh: mixed (direct to 135.129.x.x:56141 and relayed)
  4 sent, 4 received, 0% loss
  rtt min/avg/max/mdev = 41.843/113.534/299.872/93.169 ms
```

## The rules on `--public`

- **You must name the services.** There is no `all` or `*`.
- **Not every service opens.** A keyless shell ([`sshd:`](../reference/services.md#sshd)) has no
  public form. `control.stop` and `control.services` are member-only: only your own devices can stop
  or inspect the node.
- **Public streams share a node-wide pool of four.** Four connected public streams fill it, on any mix
  of public services; each holds its slot until its stream ends, even if idle. A fifth public dial is
  refused until a slot frees, and gated services are outside the pool.

## The limit

An open `ping` or `speed` is metered: one run per caller per second, and a stream caps at 60 s/1 GiB
(ping) or 64 MiB/15 s (speed). Keep diagnostics gated if you need the full link.

## Next

- [Keys](../keys.md#the-gate) why the default is refuse, and what the gate checks.
- [Family media center](family-media-center.md) admit a known group instead of everyone.
- [Commands](../reference/commands.md#serve) serve, and every service form.
