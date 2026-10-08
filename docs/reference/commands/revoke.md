Back to [Commands index](../commands.md).

# <a id="revoke"></a>`swoosh revoke`

Take back a link, one of your devices, or everything you shared with a contact; or end a root for good.

<!-- generated: usage from `swoosh revoke -h`; option lines curated -->
```
Usage: swoosh revoke [OPTIONS] <link | path | - | me/<name> | <person> | <person>/<name> | key | root key>
  <link>             that link, and every link narrowed from it
  <path> | -         the link held in that file, or on stdin
  me/<name>          one of your devices: its key, and the links this machine gave it
  <person>           every link this machine gave any of that contact's devices, or bound to their root
  <person>/<name>    every link this machine gave that device's key
  <key>              every link this machine gave that key
  root:<key>         that root, for good, on this machine
  --root <dir>       use the copy of your root in <dir>
```

**Example.** `swoosh revoke me/laptop` on the machine that keeps your root blocks the laptop here, asks
for your root's passphrase, and then tells you which of your devices took the revoke. `swoosh revoke
swoosh:ed01…` takes back one link this machine gave out.

**Things to know.** Every form but `root:<key>` blocks on this machine first, and a running `swoosh serve`
picks the block up without a restart. A link this machine made, and a link it gave a key, were only ever
admitted here, so that block is the whole revoke. A device is admitted by all your devices: where your root
is kept (or with `--root <dir>`), the revoke asks for the root's passphrase after the block is written and
then passes it to your other devices. If it cannot use your root, it says the device is blocked on this
machine only, names how to finish, and exits 1. A revoked device's key can never be your device again: that
machine runs `swoosh leave --new-key` at its console to be invited back. A stolen device can stop your
other machines (`swoosh stop --at me/<name>`) until they learn it is revoked.

**Ending a root.** `swoosh revoke root:<key>` cannot be undone, so it runs only at a terminal. It says
what this machine is to that root, then asks you to type the key's first six characters
(`Type ed01… to revoke this root for good:`). Then:

- where the root is kept, it asks for the root's passphrase, then deletes the root from this machine;
  your next `swoosh invite` makes a new one;
- on one of that root's devices, the machine leaves it for good;
- for a contact's root, or a root this machine does not know, this machine never trusts it.

Given the key of a device this machine knows, yours or a contact's, and no root it knows, it refuses and names the command to use instead.
If it stops partway, run it again to finish.
`swoosh revoke --help` lists the steps to replace your root.

See also [`swoosh leave`](leave.md), [`swoosh grant`](grant.md), [Commands index](../commands.md) and
[Common options](../commands.md#common-options).
