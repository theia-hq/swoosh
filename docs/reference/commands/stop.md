Back to [Commands index](../commands.md).

# <a id="stop"></a>`swoosh stop`

Stop a peer's node (stop it serving), by its key or a `sheer:` link.

<!-- generated: usage from `swoosh stop -h`; option lines curated -->
```
Usage: swoosh stop [OPTIONS]
  --at <peer>   the peer to stop: a petname, a raw node id, or a sheer: link
```

**Example.** `swoosh stop --at me/box` gracefully stops a node you started with `serve --expires`, early.

**Things to know.** This stops the serving node, not the machine it runs on. `control.stop` is member-only:
a stranger is refused at the gate, and a `sheer:` grant naming it is refused at the route, so only your own
devices can stop a node. A bare `stop` stops your own node, which needs a resident `serve`
(`serve --resident`).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
