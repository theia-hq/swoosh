Back to [Commands index](../commands.md).

# <a id="ping"></a>`swoosh ping`

Measure the round-trip time to a peer, like `ping(8)` but addressed by key.

<!-- generated: usage from `swoosh ping -h`; option lines curated -->
```
Usage: swoosh ping [OPTIONS] <peer>
  <peer>            a petname, a raw node id, or a sheer: link
  -c, --count <N>   how many probes to send [default: 4]
  -i, --interval <seconds>   seconds between probes [default: 1]
  -v, --verbose     print a line per probe as it lands, showing the path
```

**Example.** `swoosh ping desk -v -c 4` prints a line per probe. Over iroh a session often starts
relayed and hole-punches to direct mid-run, so the probe that lands direct reads `(upgraded from
relayed)`.

**Things to know.** If the peer refuses the service or never admitted you, `ping` says so and exits
non-zero, rather than reporting a healthy line or 100% loss.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
