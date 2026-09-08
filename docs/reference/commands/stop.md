Back to [Commands index](../commands.md).

# <a id="stop"></a>`swoosh stop`

Stop a peer's node (stop it serving), by its key or a `sheer:` link.

<!-- generated: usage from `swoosh stop -h`; option lines curated -->
```
Usage: swoosh stop [OPTIONS]
  --at <peer>   the peer to stop: a petname, a raw node id, or a sheer: link
```

**Example.** `swoosh stop --at me/box` gracefully stops a node you started with `serve --expires`, early.

**Things to know.** This stops the serving node, not the machine it runs on. `control.stop` is gated, so
for a single-owner node only your own devices can stop it. Omitting `--at` reports that stopping your
*own* node needs the daemon (not built yet).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
