Back to [Commands index](../commands.md).

# <a id="service"></a>`swoosh service`

List, enable, or disable a node's services: read a peer's menu as a `SERVICE  GATE` table, or toggle a
service on your own node.

<!-- generated: usage from `swoosh service -h`; option lines curated -->
```
Usage: swoosh service [OPTIONS] <COMMAND>
  ls [--at <peer>]     list the served menu; a petname, a raw node id, or a sheer: link
  enable <service>     re-enable a disabled service
  disable <service>    disable a service
```

**Example.**
<!-- capture: swoosh service ls --at desk -->
```console
$ swoosh service ls --at desk
SERVICE           GATE
control.services  gated
control.stop      gated
ping              gated
speed             gated
```

**Things to know.** The `GATE` column reads `gated` or `open`. `open` is anyone, unauthenticated, through
either public opt-in (`--public` or `--public-unsafe`; the serve banner names which). `gated` is behind
the gate; `control.*` rows are member-only, stricter than `gated`. `enable` and `disable` are local
writes on your own node: `disable <service>` adds the name to `<home>/disabled` and `enable <service>`
removes it. A running `serve` honors the change on the next connection, no restart, and the file is
fail-closed: if it is deleted or unreadable, the last-known disabled set stays in force. A name is an
address, not an authority ([Services](../services.md#names)): `disable` and `enable` act on the name you
pass, so a target served under two names must be disabled under both. `--at` applies to `ls` only. A bare
`ls` reads your own node, which needs a resident `serve` (`serve --resident`).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
