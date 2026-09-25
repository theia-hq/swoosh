Back to [Commands index](../commands.md).

# <a id="stop"></a>`swoosh stop`

Stop a node, meaning stop it serving: your own by default, or a peer's with `--at`.

<!-- generated: usage from `swoosh stop -h`; option lines curated -->
```
Usage: swoosh stop [OPTIONS]
  --at <peer>   stop a peer's node rather than your own: a petname, a raw node id, or a swoosh: link
```

**Example.** `swoosh stop --at me/box` gracefully stops a node you started with `serve --expires`, early.

**Things to know.** This stops the serving node, not the machine it runs on. `control.stop` is member-only:
a stranger is refused at the gate, and a `swoosh:` grant naming it is refused at the route, so only your own
devices can stop a node. Stopping your own node needs a resident one (`serve --resident`).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
