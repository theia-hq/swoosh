Back to [Commands index](../commands.md).

# <a id="identity"></a>`swoosh identity`

Back up this machine's key, restore it, and set how it is protected. `swoosh status --key` prints the key.

<!-- generated: usage from `swoosh identity -h`; option lines curated -->
```
Usage: swoosh identity [OPTIONS] <COMMAND>

Commands:
  export   Write a sealed backup of this identity to <path>
  restore  Restore this home's key from a backup file (the key only, not revocations)
  protect  Set how this identity is protected
```

**Things to know.** `swoosh status` says how the key file protects the key on its `lock:` line: `none`, or
`passphrase` once `swoosh identity protect passphrase` has sealed it.

- `swoosh identity protect <plain|passphrase>` rewrites the key file under that method; the key does not
  change. On a home with no key it creates one already sealed.
- `swoosh identity export <path> [--force]` writes a sealed backup to a file, never to the terminal.
- `swoosh identity restore <path> [--force]` puts a backup's key into this home. Only the key comes back:
  a fresh home has no revocation list, so grants you revoked work again. It refuses while a node serves the
  home, and `--force` is needed to replace a different key.

See [Backing up your signet](../../signet-backup.md).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
