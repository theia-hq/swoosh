Back to [Commands index](../commands.md).

# <a id="status"></a>`swoosh status`

Show the connection path to a peer: direct or relayed, the remote address, and a live RTT.

<!-- generated: usage from `swoosh status -h`; option lines curated -->
```
Usage: swoosh status [OPTIONS] <peer>
  <peer>   a petname, a raw node id, or a sheer: link
```

**Example.** `swoosh status desk` answers the one question a p2p link always raises: am I talking to
the peer directly, or bouncing through a relay?

**Things to know.** `mixed` means some paths are direct and some relayed while a session settles.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
