Back to [Commands index](../commands.md).

# <a id="serve"></a>`swoosh serve`

Be a node: publish named services behind your gate. A `serve` that names services sets this
machine's list; a bare `serve` serves that list, or `ping` and `speed` if no list was ever set.

<!-- generated: usage from `swoosh serve -h`; option lines curated -->
```
Usage: swoosh serve [OPTIONS] [service]...
  [service]...               Serve exactly these for this run, without saving them
  --public <service>         Open these services to anyone, comma-separated
  --public-unsafe <service>  Open these raw streams to anyone
  --expires <d>              Serve for this long, then stop (30m, 2h, 1d)
  --admit <root key>         Admit another root's devices, for this run
```

**Example.** `swoosh serve ssh tv=tcp:127.0.0.1:8096` publishes a shell and a local TCP service.

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
Every `serve` also answers a few internal routes no service list names, such as `control.serve`, which your
devices use to stop it. Bare `swoosh status` lists them under `internal routes` while `serve` runs.
Each file a receive service lands prints one line on stderr, such as
`00:47  me/laptop sent 1.5 KiB: notes.txt`: the time, the sender, the size, then the file name. A sender with
no name here shows its whole key, and the file name goes on the next line.
The sender chooses the name, so control characters in it are shown escaped. If stderr falls behind, some
lines are dropped and a line says how many.
The banner gives this machine's name, when it has one, and its key, how peers reach it under `reach`, and what it serves. With
`--expires` it then says when `serve` stops (`Serving until 15:04 (1h 30m).`). At a terminal, with no service
manager running `serve`, it ends with `Press ctrl-c to stop.` To start `serve` at login, see
[Run a node at login](../../use-cases/run-at-login.md).
`--quiet` (or `SWOOSH_QUIET`) prints no banner and no per-file lines; refusals, warnings, the `Stopped by`
line and `Stopped serving.` still print.
However `serve` ends (`--expires`, `swoosh stop`, ctrl-c, a service manager's stop), it prints a blank line
and `Stopped serving.` on stderr.
A raw-stream service (`file:`, `fifo:`, `stdin:`) has no auth of its own, so `--public` refuses it and
points at `--public-unsafe`, so name only a file you mean to hand out. A `file:` path you type that does not
exist, or sits under something that is not a directory, refuses the start with `error: <path> does not exist`
and exit 1; a target saved in `serve.toml` is not checked.
Every `serve` holds its home's lock and control socket, so `swoosh stop` and
`swoosh status` find it, and a second `serve` for the same home refuses; backgrounding is the
supervisor's job. On Linux it needs `XDG_RUNTIME_DIR` set to a private directory.
Only the services are kept for the next bare `serve`: `--public`, `--public-unsafe`,
`--admit` and `--expires` apply only to the run that types them.
`--admit root:<key>` lets in the devices of that root for this run only, on a machine that trusts no
root; it writes nothing. Before `serve` starts, it prints on stderr `Admitting the devices of this root for
this run:`, the root's key, `This machine does not get the keys that root revoked.` and `A device that root
revoked still gets in.` It refuses this machine's
own key, a root revoked here, and a root saved as a person's, and `swoosh join` refuses while it runs.

See also [Services](../services.md) for every service form and its gate, [Commands index](../commands.md),
and [Common options](../commands.md#common-options).
