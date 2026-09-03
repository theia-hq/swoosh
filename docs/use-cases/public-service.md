# Public service

You want to offer a service to anyone, no credential: a public ping target, a speed-test endpoint, a
fetch relay. By default swoosh refuses strangers, so opening a service to the world is a deliberate,
named opt-out.

## Open named services

Name the services you want public. Everything else stays [gated](../keys.md#the-gate):

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
    control.*   node control (always family-gated)
  public !   anyone, unauthenticated
    ping    round-trip probe   unmetered: a stranger can drain your uplink
    speed   throughput test   unmetered: a stranger can drain your uplink

ctrl-c to stop
```

Anyone with the key reaches the two public services and nothing else. There is no slip to hand out and
nothing to present:

<!-- live-run: real iroh RTT over the internet, non-deterministic; re-capture before release -->
```console
$ swoosh ping bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q -c 4
bf01hcq6balrlxwa via iroh: mixed (direct to 135.129.124.149:56141 and relayed)
  4 sent, 4 received, 0% loss
  rtt min/avg/max/mdev = 41.843/113.534/299.872/93.169 ms
```

## The rules on `--public`

- **You must name the services.** Bare `--public` is an error, and there is no `all` or `*`. You open
  exactly what you list.
- **Some services can never be public.** A keyless shell (`sshd:`) is refused by name, and
  `control.stop` / `control.services` are always gated. The gate will not let you open a service that
  has no safe public form.
- **`control.*` stays gated.** Even with public diagnostics, only your own devices can stop or inspect
  the node.

## The honest limit

`ping` and `speed` have no responder-side rate limit yet, so an open one lets an anonymous caller drain
this node's uplink (an amplifier). The banner says so. Only open services you are willing to let a
stranger hammer.

## Next

- [Keys](../keys.md#the-gate) why the default is refuse, and what the gate checks.
- [Family media center](family-media-center.md) admit a known group instead of everyone.
- [Commands](../reference/commands.md#serve) serve, and every service form.
