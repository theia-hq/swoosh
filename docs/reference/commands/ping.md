Back to [Commands index](../commands.md).

# <a id="ping"></a>`swoosh ping`

Measure the round-trip time to a peer, like `ping(8)` but addressed by key.

<!-- generated: usage from `swoosh ping -h`; option lines curated -->
```
Usage: swoosh ping [OPTIONS] <machine>
  <machine>         A machine: me/<name>, <person>/<name>, a person, a key, or a link
  -c, --count <n>   how many probes to send [default: 4]
  -i, --interval <s>   seconds between probes [default: 1]
  -v, --verbose     print a line per probe, and one when the path changes
```

**Example.** `swoosh ping me/desk -v -c 4` prints `<device>, path: <path>` first, then a
line per probe, and the path line again if the path changes mid-run: a session that starts
`relayed through <relay>` prints `direct` when a hole punch lands. Without `-v`, `path:` is one row
under the device, read after the run.
[Why a path changes](../../transports.md#iroh).

**Things to know.** If the peer refuses the service or never admitted you, `ping` says so and exits
non-zero, rather than reporting a healthy line or 100% loss. `ping` works the same through
`swoosh serve`. If the path cannot be read after the run, there is no `path:` row, stderr says
`warning: could not read the path of this run`, and the exit code is unchanged.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
