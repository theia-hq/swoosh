Back to [Commands index](../commands.md).

# <a id="send"></a>`swoosh send`

Push a file or directory to a peer.

<!-- generated: usage from `swoosh send -h`; option lines curated -->
```
Usage: swoosh send [OPTIONS] <path>... <machine>
  <path>...           the files or directories to push
  <machine>           A machine: me/<name>, <person>/<name>, a person, a key, or a link
```

**Example.**
<!-- capture: swoosh send app.tar me/deploybox -->
```console
$ swoosh send app.tar me/deploybox
sending to ed01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q...
sent app.tar (204800 bytes)
```

**Things to know.** The receiver stays online with `swoosh serve recv:/srv/releases` (saving into that
directory).
Each file is hashed with BLAKE3 and checked again as it arrives, so a file corrupted or changed while it was
sent does not land.
A name the receiver already holds is refused, never replaced.
A file that does not land prints a `skip` line, and `send` exits non-zero.
If the receiver does not answer a file within 10 minutes, `send` prints a `skip` line, and the file may have arrived.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
