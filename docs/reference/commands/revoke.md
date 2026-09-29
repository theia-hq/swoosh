Back to [Commands index](../commands.md).

# <a id="revoke"></a>`swoosh revoke`

Take back a link, one of your devices, or everything you shared with a contact.

<!-- generated: usage from `swoosh revoke -h`; option lines curated -->
```
Usage: swoosh revoke [OPTIONS] <link | path | - | me/<name> | <person> | <person>/<name> | key | root key>
  <link>             that link, and every link narrowed from it
  <path> | -         the link held in that file, or on stdin
  me/<name>          one of your devices: its key, and the links this machine gave it
  <person>           every link this machine gave any of that contact's devices, or bound to their root
  <person>/<name>    every link this machine gave that device's key
  <key>              every link this machine gave that key
  --root <dir>       Act on your root, or on the root kept in `<dir>`
```

**Example.** `swoosh revoke me/laptop` on the machine that keeps your root blocks the laptop here, asks
for your root's passphrase, and then tells you which of your devices took the revoke. `swoosh revoke
swoosh:ed01…` takes back one link this machine gave out.

**Things to know.** Every form blocks on this machine first, and a running `swoosh serve` picks the block
up without a restart. A link this machine made, and a link it gave a key, were only ever admitted here, so
that block is the whole revoke. A device is admitted by all your devices: where your root is kept (or with
`--root <dir>`), the revoke asks for the root's passphrase after the block is written and then passes it to
your other devices. Without the root, it stays on this machine and prints when your other devices stop
admitting the device. A revoked device's key can never be your device again: that machine
runs `swoosh leave --new-key` at its console to be invited back. A stolen device can stop your other
machines (`swoosh stop --at me/<name>`) until they learn it is revoked.

See also [`swoosh leave`](leave.md), [`swoosh grant`](grant.md), [Commands index](../commands.md) and
[Common options](../commands.md#common-options).
