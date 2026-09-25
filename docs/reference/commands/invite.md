Back to [Commands index](../commands.md).

# <a id="invite"></a>`swoosh invite`

Add one of your devices, or renew it. Bare `invite` lists what is due.

Run it where your root is kept, or add `--root <dir>` to use a copy of your root from a device. It asks
for your root's passphrase once, then prints the invite on stdout for the device to join.

<!-- generated: usage from `swoosh invite -h`; option lines curated -->
```
Usage: swoosh invite [OPTIONS] [name] [key]
  [name]   the device, as it is named among your devices (me/<name>)
  [key]    the key the device made (`swoosh join` on it shows it)
  --new-key   Make a new key: inside the invite, or for this machine
  --expires <d>   How long: `2h`, `90d`
  --root <dir>   where your root is, when it is not kept on this machine
```

**The forms.**

- `swoosh invite <name> <key>` adds the device that made `<key>` as `me/<name>`. The invite carries no
  secret. If `me/<name>` is already that key, this renews it.
- `swoosh invite <name> --new-key` adds a machine with no console: the invite carries a new key, so
  anyone holding it becomes `me/<name>`. Send it privately. On a device whose key came in its invite, it
  hands that device a new key; the old invite works until its own date.
- `swoosh invite <name>` renews that device, whatever its date, one whose date has passed included.
- `swoosh invite` lists each device due to renew as a `swoosh invite <name>` line. It never asks for the
  passphrase and writes nothing.

**Things to know.** The first `swoosh invite <name> <key>` on a machine with no root makes your root here.
`--expires` sets how long a device runs, 1h to 365d; the default is 90 days, and every invite says which it
used. Each time your root is used, it also renews every device in the last half of its time, except one
whose key came in its invite or one that runs under 30 days: those end on their date. A device renewed
under a day ago, or already holding four renewals in force, is not signed again: `invite` prints the
invite it already has. A name that is a contact's, a key that is already one of your devices, and a revoked
key are refused before the passphrase is asked for. A device is removed with `swoosh revoke me/<name>`.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
