Back to [Commands index](../commands.md).

# <a id="speed"></a>`swoosh speed`

Measure throughput to a peer, like `iperf` but addressed by key.

<!-- generated: usage from `swoosh speed -h`; option lines curated -->
```
Usage: swoosh speed [OPTIONS] <peer>
  <peer>          a petname, a raw node id, or a sheer: link
  --up / --down   which direction to measure (default: down)
  --bidir         measure both at once, full-duplex on one stream
  -t, --secs <seconds>   run for a fixed time (default: 5)
  -n, --bytes <N>        transfer a fixed number of bytes instead
```

**Example.** `swoosh speed desk --bidir -t 5` measures upload and download at once.

**Things to know.** `--bidir` works over quirk too. Numbers over iroh depend on the live path (direct
vs relayed) and are not comparable to a local quirk run.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
