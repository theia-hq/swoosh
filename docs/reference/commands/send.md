Back to [Commands index](../commands.md).

# <a id="send"></a>`swoosh send`

Push a file or directory to a peer, verified end to end.

<!-- generated: usage from `swoosh send -h`; option lines curated -->
```
Usage: swoosh send [OPTIONS] <path>... <peer>
  <path>...           the files or directories to push
  <peer>              a petname, a raw node id, or a sheer: link
  --service <name>    which served service to reach [default: recv]
```

**Example.**
```console
$ swoosh send app.tar deploybox
sending to bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q...
sent app.tar (204800 bytes)
```

**Things to know.** The receiver stays online with `swoosh serve inbox=recv:/srv/releases` (saving into that
directory). Each file is hashed with BLAKE3 and re-checked on arrival, so a truncated
or tampered transfer is rejected, never written.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
