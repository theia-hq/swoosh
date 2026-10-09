Back to [Commands index](../commands.md).

# <a id="speed"></a>`swoosh speed`

Measure throughput to a peer, like `iperf` but addressed by key.

<!-- generated: usage from `swoosh speed -h`; option lines curated -->
```
Usage: swoosh speed [OPTIONS] <machine>
  <machine>       A machine: me/<name>, <person>/<name>, a person, a key, or a link
  --up / --down   which direction to measure (default: down)
  --bidir         measure both at once, full-duplex on one stream
  -t, --secs <s>         How long to run, in seconds (5 unless -n is given)
  -n, --bytes <N>        transfer a fixed number of bytes instead
```

**Example.** `swoosh speed desk --bidir -t 5` measures upload and download at once.

**Things to know.** `--bidir` works over `quirk+noise` too. Numbers over iroh depend on the live path
(direct vs relayed) and are not comparable to a local `quirk+noise` run. A `--public` speed route
binds the metered engine: one transfer at a time, a 64 MiB per-direction and 15-second per-stream cap.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
