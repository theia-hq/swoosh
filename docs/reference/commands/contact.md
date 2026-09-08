Back to [Commands index](../commands.md).

# <a id="contact"></a>`swoosh contact`

Manage local petnames: name your peers so you never paste a key. Names are yours alone, stored in plain
TOML beside the identity they belong to. `alice` means whoever you pointed it at, no registry.

<!-- generated: usage from `swoosh contact -h`; option lines curated -->
```
Usage: swoosh contact <add | signet | ls | rm>
  add <name> <key>       save (or re-point) a name: alice, or alice/laptop for a device
  signet <petname> <key> record a person's signet root, so --for fleet:<petname> binds their fleet
  ls [petname]           list contacts, or one contact's devices (-q for names only)
  rm <name>              forget a contact or one of its devices
```

**Example.**
```console
$ swoosh contact add desk bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
added desk -> bf01hcq6balrlxwa
```

**Things to know.** One person can have several machines: `contact add alice/laptop <key>` files a key
under `alice`. `swoosh ping alice` then tries each of alice's machines and takes the first that answers.
`contact signet` is different: it records a person's *signet* (not a device key), which is what
`--for fleet:<petname>` needs.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
