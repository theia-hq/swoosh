Back to [Commands index](../commands.md).

# <a id="identity"></a>`swoosh identity`

Print this machine's key (its NodeId), minting one if there is none.

<!-- generated: usage from `swoosh identity -h`; option lines curated -->
```
Usage: swoosh identity [OPTIONS]
```

**Example.**
```console
$ swoosh identity
bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
key: ~/.config/swoosh/identity.key
```

**Things to know.** On an adopted device this prints that *device's* key, not your signet. A fleet grant
needs the person's signet, read on their signet-holding machine. Use `identity` to provision a key ahead
of time: mint it here, save its NodeId as a contact, then hand the key file to the machine that adopts
it.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
