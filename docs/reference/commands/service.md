Back to [Commands index](../commands.md).

# <a id="service"></a>`swoosh service`

Read a peer's served services: a `SERVICE  GATE` table of what it offers.

<!-- generated: usage from `swoosh service -h`; option lines curated -->
```
Usage: swoosh service [OPTIONS]
  --at <peer>   the peer to read: a petname, a raw node id, or a sheer: link
```

**Example.**
```console
$ swoosh service --at desk
SERVICE           GATE
control.services  gated
control.stop      gated
ping              gated
speed             gated
```

**Things to know.** Omitting `--at` reports that reading your *own* node needs the daemon (not built
yet).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
