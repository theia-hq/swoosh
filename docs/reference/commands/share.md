Back to [Commands index](../commands.md).

# <a id="share"></a>`swoosh share`

Make a link to one service for a person, one of their machines, a key, or anyone; or a shorter copy of a
link.

<!-- generated: usage from `swoosh share -h`; option lines curated -->
```
Usage: swoosh share [OPTIONS] <service | link> [who]
  <service> <who>        a link to that service on this machine
    <person>             every machine of the root you saved for them
    <person>/<name>      that one machine
    <key>                the machine with that key
    anyone               whoever holds the link
  <link> | <path> | -    a shorter copy of that link, typed, from a file, or on stdin
  --expires <d>          how long it works, 1h to 365d (default 1h, or the copied link's end)
  --save <file>          write the link to a new private file and print only the path
```

**Example.**
<!-- manual: the end time and the link differ per run -->
```console
$ swoosh share ssh bob/laptop
bob/laptop can open a shell on this machine until 15:04 (1h).
the link dials this machine: it works while this machine serves ssh.
swoosh:ed01…
```

**Things to know.** Only the link goes to stdout, so `swoosh share ssh anyone > ssh.link` captures it
alone. A link for a person, a machine or a key works only there and cannot be copied; a link for `anyone`
works for whoever holds it, so send it privately. A copy never outlives its link. `swoosh share ssh bob`
needs bob's root saved first: `swoosh contact add bob <root key>`. Take a link back with
[`swoosh revoke`](revoke.md).

See also [`swoosh contact`](contact.md), [Commands index](../commands.md) and
[Common options](../commands.md#common-options).
