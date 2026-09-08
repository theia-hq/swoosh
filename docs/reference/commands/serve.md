Back to [Commands index](../commands.md).

# <a id="serve"></a>`swoosh serve`

Be a node: publish named services behind your signet gate. Bare, it answers reach diagnostics.

<!-- generated: usage from `swoosh serve -h`; option lines curated -->
```
Usage: swoosh serve [OPTIONS] [name=svc]...
  [name=svc]...          publish a service, e.g. ssh=sshd:, tv=127.0.0.1:8096 (empty = ping + speed)
  --public <svc>         open named services to anyone, unauthenticated (comma-list, repeatable)
  --expires <duration>   serve for a bounded time, then stop (30m, 2h, 1d)
  --quiet                suppress the readiness banner (for unattended/CI use)
```

**Example.** `swoosh serve ssh=sshd: tv=127.0.0.1:8096` publishes a shell and a local TCP service, both
gated to your signet.

**Things to know.** A service form is `name=target`: `ping=ping:` / `speed=speed:` (built-in diagnostics),
`ssh=sshd:` (a keyless shell), `inbox=recv:<dir>` (receive pushed files into `<dir>`, `inbox=recv:` uses `.`),
`news=fetch:<origin>` (fetch URLs for callers), or `web=127.0.0.1:8080`
(front any local TCP service). Every entry must be `name=target`: a bare `ping` or `ping:` is refused with a
message naming this form.
`control.stop` and `control.services` are always served and always gated.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
