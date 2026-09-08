Back to [Commands index](../commands.md).

# <a id="fetch"></a>`swoosh fetch`

Mint a local URL that fetches an origin through a node you name.

<!-- generated: usage from `swoosh fetch -h`; option lines curated -->
```
Usage: swoosh fetch [OPTIONS] --via <peer> <url>
  <url>             the origin URL to fetch
  --via <peer>      the node to fetch through
  --service <name>  which served service to reach [default: fetch]
  --port <port>     pin the local listener port (default: an OS-assigned free port)
```

**Example.** `swoosh fetch https://example.com/big.iso --via usa` prints a `http://127.0.0.1:PORT/`;
whatever pulls from that (curl, a browser) is served by `usa`'s machine fetching the origin and
streaming it back, `Range` intact so a resumable download resumes.

**Things to know.** The exit is a node *you* run (serve `fetch=fetch:` on it). It is scoped to the one
origin you name, not an open proxy.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
