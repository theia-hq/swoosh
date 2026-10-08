Back to [Commands index](../commands.md).

# <a id="contact"></a>`swoosh contact`

Save another person's key under a name, so you never paste it. Names are yours alone, kept beside this
machine's key: `alice` means whoever you pointed it at.

<!-- generated: usage from `swoosh contact -h`; option lines curated -->
```
Usage: swoosh contact [OPTIONS] <COMMAND>
  add <name> <key>   save a person's root key (alice), or one machine of theirs (alice/laptop)
  rm <name>          remove a contact, or one of its machines
```

**Example.**
<!-- capture: swoosh contact add alice/desk ed01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q -->
```console
$ swoosh contact add alice/desk ed01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
added alice/desk -> ed01hcq6balr…
```

**Things to know.** The name's shape decides what is saved. `alice/laptop` is one machine: `swoosh ping
alice/laptop` reaches it, and `swoosh ping alice` tries each of alice's machines. `alice` alone saves her
root, the key that vouches for her machines: `swoosh share ssh alice` makes a link all of them can use, and
a root is never dialed. `contact rm` refuses while links you shared with that contact are live; `swoosh
revoke <name>` ends them. `swoosh status` lists your contacts.

See also [`swoosh share`](share.md), [Commands index](../commands.md) and
[Common options](../commands.md#common-options).
