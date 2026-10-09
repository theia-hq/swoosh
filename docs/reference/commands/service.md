Back to [Commands index](../commands.md).

# <a id="service"></a>`swoosh service`

Change what this machine serves: add or remove a service, or turn one off and back on.

<!-- generated: usage from `swoosh service -h`; option lines curated -->
```
Usage: swoosh service [OPTIONS] <COMMAND>
  add <service>...   Add services to what this machine serves
  rm <service>...    Remove services from what this machine serves
  on <service>       Turn a service on here
  off <service>      Turn a service off here
```

**Example.**
<!-- capture: swoosh service add web=tcp:localhost:3000 -->
```console
$ swoosh service add web=tcp:localhost:3000
Added web; it is served when swoosh serve next starts.
```

**Things to know.** `add` and `rm` change this machine's list, which a bare `swoosh serve` serves; `add` takes
`serve`'s forms ([Services](../services.md)). A running `serve` serves an added service from its next start and
stops serving a removed one at once. `off` and `on` turn a listed service off and back on, live, and `off` holds across
restarts. None of them ends a session already open: `swoosh stop` or a [revoke](revoke.md) does. They act on
this machine only; for another of your machines, run them there: `swoosh ssh me/nas -- swoosh service off ssh`.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
