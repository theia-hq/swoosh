Back to [Commands index](../commands.md).

# <a id="forward"></a>`swoosh forward`

Forward a machine's service to a local port, or to stdout.

<!-- generated: usage from `swoosh forward -h`; option lines curated -->
```
Usage: swoosh forward [OPTIONS] <machine> <service> <port | unix:<path> | ->
  <machine>                 A machine: me/<name>, <person>/<name>, a person, a key, or a link
  <service>                 the service, by the name the machine serves it under
  <port | unix:<path> | ->  where the bytes go: a local port, or - for stdout
```

**Example.** On `nas`, serve the database: `swoosh serve db=tcp:localhost:5432`. On your laptop:

<!-- manual: long-running port bind -->
```console
$ swoosh forward me/nas db 5432
Forwarding db on me/nas to 127.0.0.1:5432.
Press ctrl-c to stop.
```

A client on the laptop connects to `127.0.0.1:5432`. `swoosh forward me/nas logs - | less` puts the stream on
stdout instead.

**Things to know.** The local end is required: nothing defaults to the terminal or to the served port.
`unix:<path>` is not built yet. A [link you were given](../../keys.md#using-a-grant-you-were-given) goes where
the machine goes: `swoosh forward swoosh:ed01… tv 8096`.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
