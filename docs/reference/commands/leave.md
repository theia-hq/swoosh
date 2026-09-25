Back to [Commands index](../commands.md).

# <a id="leave"></a>`swoosh leave`

Stop being one of your devices. `--new-key` also gives this machine a new key.

<!-- generated: usage from `swoosh leave -h`; option lines curated -->
```
Usage: swoosh leave [OPTIONS]
  --new-key  Make a new key: inside the invite, or for this machine.
```

**Example.** `swoosh leave` on a machine you no longer use as a device. `swoosh leave --new-key` after
you revoked it, to use it again: it prints the new key, which `swoosh invite <name> <key>` takes where
your root is kept.

**Things to know.** `leave` removes this machine's record from your root and its list of your devices,
and keeps every revocation it learned. Your root still lists the machine until you revoke it there with
`swoosh revoke me/<name>`. `--new-key` keeps the old key and its links file beside the new key, dated,
and the links this machine made under the old key stop working. It refuses while `swoosh serve` runs. A
server you reach only through swoosh needs its console after `leave --new-key`, unless it first issued you
a link. On the machine that keeps your root, `leave` refuses: move the root off first.

See also [`swoosh join`](join.md), [Commands index](../commands.md) and
[Common options](../commands.md#common-options).
