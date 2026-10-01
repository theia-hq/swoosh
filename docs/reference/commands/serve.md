Back to [Commands index](../commands.md).

# <a id="serve"></a>`swoosh serve`

Be a node: publish named services behind your gate. Bare, it serves what this home last served, or `ping`
and `speed` if it never named any.

<!-- generated: usage from `swoosh serve -h`; option lines curated -->
```
Usage: swoosh serve [OPTIONS] [name=target]...
  [name=target]...       publish services as `name=target` (bare: the last list, else `ping` and `speed`)
  --public <svc>         open named services to anyone (comma-list, repeatable)
  --public-unsafe <svc>  open named raw-stream services (file:, fifo:, stdin:) to anyone
  --expires <duration>   serve for a bounded time, then stop (30m, 2h, 1d)
  --quiet                suppress the readiness banner and activity lines
  --admit <root key>     For this run, let in the devices of another root without joining it (CI).
```

**Example.** `swoosh serve ssh=sshd: tv=tcp:127.0.0.1:8096` publishes a shell and a local TCP service, both
gated to your signet.

**Things to know.** A service form is `name=target`: `ping=ping:` / `speed=speed:` (built-in diagnostics),
`ssh=sshd:` (a keyless shell), `inbox=recv:<dir>` (receive pushed files into `<dir>`, `inbox=recv:` uses the inbox,
`~/Library/Application Support/swoosh/inbox` on macOS and `~/.local/share/swoosh/inbox` on Linux),
`news=fetch:<origin>` (fetch URLs for callers), or `web=tcp:<host>:<port>`
(front any local TCP service). `ssh`, `ping` and `speed` may be named alone (`swoosh serve ssh ping`); every
other entry must be `name=target` and every target carries a scheme: a bare name or a bare `ping:` is refused
with a message naming this form, a scheme nothing serves is refused by name,
and a scheme that takes no argument refuses a tail (`ping=ping:80` is an error, not a forward).
`control.stop` and `control.services` are always served, and member-only.
Each file a receive service lands prints one line on stderr, such as `inbox: received notes.txt (1500 bytes)`.
The sender chooses the name, so control characters in it are shown escaped. If stderr falls behind, some
lines are dropped and a line says how many. `--quiet` turns these lines off, and `RUST_LOG` cannot turn
them back on.
A raw-stream service (`file:`, `fifo:`, `stdin:`) has no auth of its own, so `--public` refuses it and
points at `--public-unsafe`, so name only a file you mean to hand out.
Every `serve` holds its home's lock and control socket, so `swoosh stop`, `swoosh status` and a bare
`swoosh service ls` find it, and a second `serve` for the same home refuses; backgrounding is the
supervisor's job. On Linux it needs `XDG_RUNTIME_DIR` set to a private directory.
Only the services are kept for the next bare `serve`, in `<home>/serving`: `--public`, `--public-unsafe`,
`--admit` and `--expires` apply only to the run that types them.
`--admit root:<key>` lets in the devices of that root for this run only, on a machine that trusts no
root; it writes nothing, and this machine does not get that root's revoked keys. It refuses this machine's
own key, a root revoked here, and a root saved as a person's, and `swoosh join` refuses while it runs.

See also [Services](../services.md) for every service form and its gate, [Commands index](../commands.md),
and [Common options](../commands.md#common-options).
