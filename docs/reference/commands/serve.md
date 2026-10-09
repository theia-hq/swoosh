Back to [Commands index](../commands.md).

# <a id="serve"></a>`swoosh serve`

Be a node: publish named services behind your gate. A `serve` that names services sets this
machine's list; a bare `serve` serves that list, or `ping` and `speed` if no list was ever set.

<!-- generated: usage from `swoosh serve -h`; option lines curated -->
```
Usage: swoosh serve [OPTIONS] [service]...
  [service]...               Serve exactly these, saved as this machine's list
  --public <service>         Open these services to anyone (comma-separated, repeatable)
  --public-unsafe <service>  Open these raw-stream services (file:, fifo:, stdin:) to anyone
  --expires <d>              Serve for this long, then stop (30m, 2h, 1d)
  --admit <root key>         For this run, let in the devices of another root without joining it (CI)
```

**Example.** `swoosh serve ssh tv=tcp:127.0.0.1:8096` publishes a shell and a local TCP service, both
gated to your signet.

**Things to know.**

```
Built in, served under their own names:
  ssh                     a shell on this machine
  ping                    round-trip probe
  speed                   throughput test
  proxy:<url>             requests to one site, made from this machine
  recv:<dir>              files sent here, saved in <dir>, else the inbox

Under a name you give (web=tcp:localhost:3000):
  tcp:<address>:<port>    a TCP service this machine reaches
  unix:<path>             a Unix socket on this machine
  file:<path>             a file's bytes
  fifo:<path>             a named pipe, live
  stdin:                  this process's stdin
  echo:                   sends back whatever it receives
```

[Services](../services.md) has the rest.
Each file a receive service lands prints one line on stderr, such as
`inbox: received notes.txt (1500 bytes) from ed01uyi7g54bpea45hafea4gohlnay5bs23p3ck4z4g24dvcpeldkczq`.
The key after `from` is the machine that sent the file.
The sender chooses the name, so control characters in it are shown escaped. If stderr falls behind, some
lines are dropped and a line says how many.
`--quiet` (or `SWOOSH_QUIET`) prints no banner and no per-file lines; refusals and warnings still print.
A raw-stream service (`file:`, `fifo:`, `stdin:`) has no auth of its own, so `--public` refuses it and
points at `--public-unsafe`, so name only a file you mean to hand out.
Every `serve` holds its home's lock and control socket, so `swoosh stop` and
`swoosh status` find it, and a second `serve` for the same home refuses; backgrounding is the
supervisor's job. On Linux it needs `XDG_RUNTIME_DIR` set to a private directory.
Only the services are kept for the next bare `serve`: `--public`, `--public-unsafe`,
`--admit` and `--expires` apply only to the run that types them.
`--admit root:<key>` lets in the devices of that root for this run only, on a machine that trusts no
root; it writes nothing, and this machine does not get that root's revoked keys. It refuses this machine's
own key, a root revoked here, and a root saved as a person's, and `swoosh join` refuses while it runs.

See also [Services](../services.md) for every service form and its gate, [Commands index](../commands.md),
and [Common options](../commands.md#common-options).
