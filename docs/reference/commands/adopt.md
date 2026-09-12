Back to [Commands index](../commands.md).

# <a id="adopt"></a>`swoosh adopt`

Adopt a minted authkey: become that device identity and trust the signet that minted it.

<!-- generated: usage from `swoosh adopt -h`; option lines curated -->
```
Usage: swoosh adopt [OPTIONS] [authkey]
  [authkey]   the authkey (a device secret; - stdin, @<path> file, or SWOOSH_AUTHKEY)
```

**Example.** `swoosh adopt @authkey.txt` reads the secret from a file. `swoosh adopt` alone reads
`SWOOSH_AUTHKEY` from the environment.

**Things to know.** Passing the authkey as a bare argument warns you, because `ps` and `/proc` can read
argv. Prefer `-` (stdin), `@<path>` (a file), or the env var. Adopting over a home that already holds an
identity replaces that identity, with no prompt: `identity` provisions a key in an empty home, and a
later `adopt` overwrites it.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
