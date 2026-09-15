Back to [Commands index](../commands.md).

# <a id="adopt"></a>`swoosh adopt`

Adopt an invite: join a signet's family as this machine.

<!-- generated: usage from `swoosh adopt -h`; option lines curated -->
```
Usage: swoosh adopt [OPTIONS] [invite]
  [invite]   the invite to adopt (a secret for a derived invite; - stdin, @<path> file, or SWOOSH_INVITE)
  --force    re-root this machine when the invite names a different signet, or replace a differing stored badge
```

**Example.** `swoosh adopt @invite.txt` reads the invite from a file. `swoosh adopt` alone reads
`SWOOSH_INVITE` from the environment.

**Things to know.** A derived invite (`invite add` with no `--for`) carries a device seed: adopting it
replaces this home's identity and becomes that device. A bound invite (`invite add --for <key>`) carries
no secret, so it is safe in transit, but it is not signed by the signet it names: `adopt` verifies the
badge is bound to this machine's key and unexpired before it writes anything, then prints the full signet
to compare with the owner out of band before serving. Adopting an invite whose signet differs from the
one this machine already trusts, or whose badge differs from the one it already stores, is refused
unless you pass `--force`. A bare invite argument warns you
only when it carries a secret (the derived shape), because `ps` and `/proc` can read argv; prefer `-`
(stdin), `@<path>` (a file), or the env var. Reading a file keeps the token out of the process list.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
