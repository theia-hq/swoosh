Back to [Commands index](../commands.md).

# <a id="adopt"></a>`swoosh adopt`

Adopt an invite: join a signet's family as this machine.

<!-- generated: usage from `swoosh adopt -h`; option lines curated -->
```
Usage: swoosh adopt [OPTIONS] [invite]
  [invite]   the invite to adopt (a secret for a derived invite; - stdin, @<path> file, or SWOOSH_AUTHKEY)
```

**Example.** `swoosh adopt @invite.txt` reads the invite from a file. `swoosh adopt` alone reads
`SWOOSH_AUTHKEY` from the environment.

**Things to know.** A derived invite (`invite add` with no `--for`) carries a device seed: adopting it
replaces this home's identity and becomes that device. A bound invite (`invite add --for <key>`) carries
no secret: adopting it keeps this machine's identity and only writes the trusted signet and the badge. A
bare invite argument warns you, because `ps` and `/proc` can read argv; prefer `-` (stdin), `@<path>` (a
file), or the env var. Reading a file keeps the token out of the process list.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
