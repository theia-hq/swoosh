Back to [Commands index](../commands.md).

# <a id="proxy"></a>`swoosh proxy`

Get a local URL that reaches a site through a machine you name.

<!-- generated: usage from `swoosh proxy -h`; option lines curated -->
```
Usage: swoosh proxy [OPTIONS] <machine> <url>
  <machine>      me/<name>, <person>/<name>, a person, key or link
  <url>          The origin URL; request path and query go after it
  --port <n>     The local port to listen on (default: any free port)
```

**Example.** On `nas`: `swoosh serve proxy:https://example.com`. Then, here:

<!-- manual: needs a live peer -->
```console
$ swoosh proxy me/nas https://example.com/big.iso
```

It prints a local URL, `http://127.0.0.1:<port>/<token>/`, on stdout. Point curl or a browser at it: the
request leaves from `nas`, and `Range` passes through, so a stopped download resumes.

If `swoosh serve` is running here, `proxy` runs through it. If `serve` stops, `proxy` ends, and the request in
flight gets a `502` whose body is one line: `proxy failed: swoosh serve stopped here and ended the connection to
me/nas`. Any other failed request gets the same shape, `proxy failed: <what went wrong>`, and `proxy` keeps listening. A request waiting when the run ends gets a `502` whose body is one line, `proxy failed: <what went wrong>`, whether `proxy` runs through `serve` or not. When
the connection to the machine could not open, it prints a warning on stderr,
`warning: a connection to me/nas failed: <why>`, with `Still listening for new connections.` under it, and no more
until a request works again. A host cut does not end `proxy`: the request waiting on it gets its own `502`, and one mid-body
resets the client. If the machine refuses you after you started, the request gets a `403` and `proxy` ends with the
refusal. A listener stays up across a dropped connection. It ends with an error when the machine refuses a new connection
(the service was turned off there, or it no longer admits you) or when `swoosh serve` stops. See
[troubleshooting](../../troubleshooting.md#warning-a-connection-to-menas-failed).

**Things to know.** The machine must serve a proxy for that site (`swoosh serve proxy:<url>` there). If it does not,
the first request gets a `403` and `swoosh proxy` ends with an error.

The port is open to every account on this computer. Without your URL's token another account cannot fetch through it, but on a shared machine it can fill the connections `proxy` allows, so your own requests wait or fail until they close.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
