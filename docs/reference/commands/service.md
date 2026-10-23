Back to [Commands index](../commands.md).

# <a id="service"></a>`swoosh service`

Show or change what this machine serves

<!-- generated: usage from `swoosh service -h`; option lines curated -->
```
Usage: swoosh service [OPTIONS] [COMMAND]
  add <service>...   Add services to what this machine serves
  rm <service>...    Remove services from what this machine serves
  on <service>       Turn a service on here
  off <service>      Turn a service off here
```

**Example.** With `web=tcp:localhost:3000` configured and serving:
<!-- capture: swoosh service -->
```console
$ swoosh service
  web  tcp:localhost:3000  on
```

**Things to know.** Bare output lists the saved services in configured order. A bound service shows its startup target; a changed target appears in the state column for the next start. `off` comes from the saved file, and `from the next start` marks an added service that is not yet bound. These are local snapshots, not health checks; the saved list and running state can change between reads. Targets are escaped and printed whole. Expanded rows put the target and state below the service name.

If detail exceeds its display limits, the listing fails without partial rows. Those limits do not apply to [`swoosh status`](status.md), which reports names without targets.

`add` and `rm` change this machine's list, which a bare `swoosh serve` serves; `add` takes
`serve`'s forms ([Services](../services.md)). A running `serve` serves an added service from its next start and
stops serving a removed one at once. `off` and `on` turn a listed service off and back on, live, and `off` holds across
restarts. None of them ends a session already open: `swoosh stop` or a [revoke](revoke.md) does. They act on
this machine only; for another of your machines, run them there: `swoosh ssh me/nas -- swoosh service off ssh`.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
