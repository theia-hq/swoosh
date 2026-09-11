Back to [Commands index](../commands.md).

# <a id="serve"></a>`swoosh serve`

Be a node: publish named services behind your signet gate. Bare, it answers reach diagnostics.

<!-- generated: usage from `swoosh serve -h`; option lines curated -->
```
Usage: swoosh serve [OPTIONS] [name=svc]...
  [name=svc]...          publish a service, e.g. ssh=sshd:, tv=127.0.0.1:8096 (empty = ping + speed)
  --public <svc>         open named services to anyone, unauthenticated (comma-list, repeatable)
  --public-unsafe <svc>  open named raw-stream services (file:, fifo:, stdin:) to anyone
  --expires <duration>   serve for a bounded time, then stop (30m, 2h, 1d)
  --quiet                suppress the readiness banner (for unattended/CI use)
  --resident             stay resident: hold the home's lock and serve the local control socket
```

**Example.** `swoosh serve ssh=sshd: tv=127.0.0.1:8096` publishes a shell and a local TCP service, both
gated to your signet.

**Things to know.** A service form is `name=target`: `ping=ping:` / `speed=speed:` (built-in diagnostics),
`ssh=sshd:` (a keyless shell), `inbox=recv:<dir>` (receive pushed files into `<dir>`, `inbox=recv:` uses `.`),
`news=fetch:<origin>` (fetch URLs for callers), or `web=127.0.0.1:8080`
(front any local TCP service). Every entry must be `name=target`: a bare `ping` or `ping:` is refused with a
message naming this form.
`control.stop` and `control.services` are always served and always gated.
A raw-stream service (`file:`, `fifo:`, `stdin:`) has no auth of its own, so `--public` refuses it and
points at `--public-unsafe`; that flag prints the resolved absolute path in the readiness banner, so name
only a file you mean to hand out. `--resident` holds the home's lock and serves the local control socket
a bare `swoosh service ls` reads; backgrounding is the supervisor's job.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
