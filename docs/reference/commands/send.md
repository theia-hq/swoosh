Back to [Commands index](../commands.md).

# <a id="send"></a>`swoosh send`

Push a file or directory to a machine.

<!-- generated: usage from `swoosh send -h`; option lines curated -->
```
Usage: swoosh send [OPTIONS] <path>... <machine>
  <path>...           The files or directories to push
  <machine>           me/<name>, <person>/<name>, a person, key or link
```

**Example.**
<!-- capture: swoosh send app.tar me/deploybox -->
```console
$ swoosh send app.tar me/deploybox
Sent app.tar (200.0 KiB) to me/deploybox.
```

**Things to know.** The receiver stays online with `swoosh serve recv:/srv/releases` (saving into that
directory).
Each file is hashed with BLAKE3 and checked again as it arrives, so a file corrupted or changed while it was
sent does not land.
A name the receiver already holds is refused, never replaced.
The `Sent` line is on stderr, and stdout stays empty. A path that does not exist, or cannot be read, ends `send`
before it dials anything.
A file that does not land prints `skip <file>: <reason>`; a reason the machine gave goes on its own row,
`  reason   <text>`. Then `send` ends with `error: 1 item could not be sent` (or `error: <n> items could not be sent`), with `The others were sent.` under it when some landed, and exits non-zero.
If the machine refuses or cannot be reached, or the same failure would hit every file, `send` stops with one line instead.
If `swoosh serve` here has stopped answering, `send` stops with `error: swoosh serve did not answer here`.
If `swoosh serve` here stops during a `send`, `send` ends with `error: swoosh serve stopped here and ended the connection to <machine>`.
Run it again without the files already marked `sent`; if every file was marked `sent`, there is nothing to send.
If the receiver does not answer a file within 10 minutes, `send` prints a `skip` line, and the file may have arrived.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
