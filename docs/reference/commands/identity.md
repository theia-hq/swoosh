Back to [Commands index](../commands.md).

# <a id="identity"></a>`swoosh identity`

Print this machine's key (its NodeId), minting one if there is none. Its three leaves back the key up,
restore it, and set how it is protected.

<!-- generated: usage from `swoosh identity -h`; option lines curated -->
```
Usage: swoosh identity [OPTIONS] [COMMAND]

Commands:
  export   Write a sealed backup of this identity to <path>
  restore  Restore this home's key from a backup file (the key only, not revocations)
  protect  Set how this identity is protected
```

**Example.**
<!-- capture: swoosh identity -->
```console
$ swoosh identity
ed01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
key: ~/.config/swoosh/key
protection: plain
signet: none
```

**Things to know.** On an adopted device this prints that *device's* key, not your signet. A fleet grant
needs the person's signet, read on their signet-holding machine. Use `identity` to provision a key ahead
of time: make one here, save its NodeId as a contact, then hand the key file to the machine that adopts it.

`protection:` says how the key file protects the key: `plain`, or `passphrase` once `swoosh identity protect
passphrase` has sealed it. Printing never asks for the passphrase.

- `swoosh identity protect <plain|passphrase>` rewrites the key file under that method; the key does not
  change. On a home with no key it creates one already sealed.
- `swoosh identity export <path> [--force]` writes a sealed backup to a file, never to the terminal.
- `swoosh identity restore <path> [--force]` puts a backup's key into this home. Only the key comes back:
  a fresh home has no revocation list, so grants you revoked work again. It refuses while a node serves the
  home, and `--force` is needed to replace a different key.

See [Backing up your signet](../../signet-backup.md).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
