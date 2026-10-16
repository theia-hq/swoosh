Back to [Commands index](../commands.md).

# <a id="contact"></a>`swoosh contact`

Save another person's key under a name, so you never paste it. Names are yours alone, kept beside this
machine's key: `alice` means whoever you pointed it at.

<!-- generated: usage from `swoosh contact -h`; option lines curated -->
```
Usage: swoosh contact [OPTIONS] <COMMAND>
  add <person | person/name> <key | root key>   save a person's root, or one machine of theirs
  rm <person | person/name>                     remove a saved person, or one machine of theirs
```

**Example.**
<!-- capture: swoosh contact add alice/desk ed01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q -->
```console
$ swoosh contact add alice/desk ed01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
added alice/desk -> ed01hcq6balr…
```

**Things to know.** The name's shape decides what is saved. `alice/laptop` is one machine: `swoosh ping
alice/laptop` reaches it, and so does `swoosh ping alice` while it is the only machine of hers saved. `alice`
alone saves her root, typed `root:ed01…`: the line that starts `root:` in her `swoosh status`. `swoosh share
ssh alice` makes a link her machines can use; a root is never dialed. swoosh can also learn her root from
one of her machines you saved, and asks before saving it. `contact rm` refuses while
links you shared with that contact are live; `swoosh revoke <name>` ends them. `swoosh status` lists your
contacts. Replacing a person's saved root needs a terminal: you type the code shown, and the links you
gave the old root end. A saved machine's key is never replaced; a different key names how to free the name.

See also [`swoosh share`](share.md), [Commands index](../commands.md) and
[Common options](../commands.md#common-options).
