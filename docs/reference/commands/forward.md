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

A client on the laptop connects to `127.0.0.1:5432`. If `swoosh serve` is running here, `forward` runs through it;
if `serve` stops, `forward` ends with `error: swoosh serve stopped here and ended the connection to me/nas`. `swoosh forward me/nas logs - | less` puts the stream on
stdout instead.

When one connection to the port fails to open, `forward` keeps listening and prints one line on stderr:
`warning: a connection to me/nas failed: <why>`. It prints no more until a connection works again. A
connection that opened never warns. If the machine refuses you after you started, or cuts the session,
`forward` ends instead (`error: connection lost` for a cut). See [troubleshooting](../../troubleshooting.md#warning-a-connection-to-menas-failed).

**Things to know.** The local end is required: nothing defaults to the terminal or to the served port.
`unix:<path>` is not built yet. A [link you were given](../../keys.md#using-a-grant-you-were-given) goes where
the machine goes: `swoosh forward swoosh:ed01… tv 8096`.

With `-`, `forward` exits 0 only when the other side ends cleanly and, if you sent anything, the other machine
holds it. Any other end prints `error: connection lost` and exits 1; stdout keeps what arrived. If the other side
finishes first, a terminal stdin ends the upload. A file or pipe on stdin is sent in full, and `forward` exits 0
once the other machine holds it. There is no time limit; if the other machine stops answering, the connection
ends after about 30 seconds.
A `forward -` the machine refuses ends with one line, the same with or without `swoosh serve`: `error: stream refused: <why>`,
or `error: me/nas refused <service>` and the reason when it does not serve you that service.
A revoke or an expiry ends the run at once with `error: connection lost`, even while stdin is idle. With
`2>&1`, stdout and stderr share one pipe, so the reader sees the end only when `forward` exits.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
