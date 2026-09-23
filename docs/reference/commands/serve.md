Back to [Commands index](../commands.md).

# <a id="serve"></a>`swoosh serve`

Be a node: publish named services behind your signet gate. Bare, it answers reach diagnostics.

<!-- generated: usage from `swoosh serve -h`; option lines curated -->
```
Usage: swoosh serve [OPTIONS] [name=target]...
  [name=target]...       publish a service, e.g. ssh=sshd:, tv=tcp:127.0.0.1:8096 (bare = ping + speed)
  --public <svc>         open named services to anyone (comma-list, repeatable)
  --public-unsafe <svc>  open named raw-stream services (file:, fifo:, stdin:) to anyone
  --expires <duration>   serve for a bounded time, then stop (30m, 2h, 1d)
  --quiet                suppress the readiness banner and activity lines
  --resident             stay resident: hold the home's lock and serve the local control socket
```

**Example.** `swoosh serve ssh=sshd: tv=tcp:127.0.0.1:8096` publishes a shell and a local TCP service, both
gated to your signet.

**Things to know.** A service form is `name=target`: `ping=ping:` / `speed=speed:` (built-in diagnostics),
`ssh=sshd:` (a keyless shell), `inbox=recv:<dir>` (receive pushed files into `<dir>`, `inbox=recv:` uses `.`),
`news=fetch:<origin>` (fetch URLs for callers), or `web=tcp:<host>:<port>`
(front any local TCP service). Every entry must be `name=target` and every target carries a scheme: a bare
`ping` or `ping:` is refused with a message naming this form, a scheme nothing serves is refused by name,
and a scheme that takes no argument refuses a tail (`ping=ping:80` is an error, not a forward).
`control.stop` and `control.services` are always served, and member-only.
Each file a receive service lands prints one line on stderr, such as `inbox: received notes.txt (1500 bytes)`.
The sender chooses the name, so control characters in it are shown escaped. If stderr falls behind, some
lines are dropped and a line says how many. `--quiet` turns these lines off, and `RUST_LOG` cannot turn
them back on.
A raw-stream service (`file:`, `fifo:`, `stdin:`) has no auth of its own, so `--public` refuses it and
points at `--public-unsafe`; that flag prints the resolved absolute path in the readiness banner, so name
only a file you mean to hand out. `--resident` holds the home's lock and serves the local control socket
a bare `swoosh service ls` reads; backgrounding is the supervisor's job.

See also [Services](../services.md) for every service form and its gate, [Commands index](../commands.md),
and [Common options](../commands.md#common-options).
