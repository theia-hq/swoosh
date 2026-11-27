Back to [Commands index](../commands.md).

# <a id="speed"></a>`swoosh speed`

Measure throughput to a machine, like `iperf` but addressed by key.

<!-- generated: usage from `swoosh speed -h`; option lines curated -->
```
Usage: swoosh speed [OPTIONS] <machine>
  <machine>            me/<name>, <person>/<name>, a person, key or link
  --up                 Measure the upload direction (this machine sends)
  --down               Measure the download direction (this machine receives)
  --bidir              Measure upload and download at once
  -t, --secs <s>       How long to run, in seconds (5 unless -n is given)
  -n, --bytes <bytes>  Transfer this many bytes, not a fixed time
```

**Example.** `swoosh speed me/desk --bidir -t 5` measures upload and download at once.

**Things to know.** Numbers depend on the live path (direct vs relayed). The `path:` line comes from a
reading taken after the run; if that fails, `speed` warns on stderr that it could not read the path and
exits as it would have. It reads the same with `swoosh serve` running. A `--public` speed route
binds the metered engine: one transfer at a time, a 64 MiB per-direction and 15-second per-stream cap.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
