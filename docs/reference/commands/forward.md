Back to [Commands index](../commands.md).

# <a id="forward"></a>`swoosh forward`

Put a peer's served service on a local port, stdout, or a unix socket (the `ssh -L` shape, keyed).

<!-- generated: usage from `swoosh forward -h`; option lines curated -->
```
Usage: swoosh forward [OPTIONS] --to <port | - | unix:PATH> <peer>
  <peer>              a petname, a raw node id, or a sheer: link
  --to <port|-|unix:PATH>   where to put the stream: a local port, - for stdout, or unix:<path>
  --service <name>    which served service to reach [default: default]
```

**Example.** `swoosh forward desk --service tv --to 8096` puts the peer's `tv` service on
`127.0.0.1:8096`, so a local client talks to it as if it were local.

**Things to know.** `--to -` streams to stdout, to compose with the shell (`--to - | mpv -`).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
