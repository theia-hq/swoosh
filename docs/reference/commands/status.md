Back to [Commands index](../commands.md).

# <a id="status"></a>`swoosh status`

Show this machine: its key, lock, root, devices, contacts, links and services. `status <machine>` shows
how you reach one.

<!-- generated: usage from `swoosh status -h`; option lines curated -->
```
Usage: swoosh status [OPTIONS] [machine]
  [machine]  A machine: me/<name>, <person>/<name>, a person, a key, or a link
  --key    print this machine's key and nothing else
```

**Example.** With a key, no saved service list and nothing running, `swoosh status` includes this row:

<!-- live-run: local status with a key, no saved service list and no running serve; only the serving row captured -->
```console
serving: ping, speed, when swoosh serve runs
```

**Things to know.** Bare `status` reads this machine's own files and never dials, so it runs with nothing
serving and never asks for a passphrase. The report is on stdout; a line such as `made this machine's key`
is on stderr. `swoosh status --key` prints the key alone, for a script. Sections with no row are left out.
On a device, `devices:` is your root's list as of the last sync.

`serving:` appears on every home with a key. It shows service names, with `(off)` beside those turned off.
Use those names with `swoosh service on` or `swoosh service off`. While serving, names added or removed
since start are left out; retargeted names still refer to the old route. When nothing runs, the row says
what `swoosh serve` would start. An emptied list says `nothing, even when swoosh serve runs`. If
`serve.toml` cannot be read or its service list is invalid, the row says `unknown`; stderr names the file
and the reason, and `status` still exits 0. When admitting devices, `admitting root:` and the root key
follow the service list.

With a machine, `status` dials it and prints one line. A healthy line has the path and a round-trip time, and
for one of your own devices ends with what it serves (`; serving: ssh, web`). Otherwise `status` exits non-zero
and the line reads `unreachable`, a refusal (`reached, but …`), or `reached, but the probe failed / went
unanswered`. The path is read after the probe, so one machine can show `relayed` on one run and `direct` on the
next. [Why a path changes](../../transports.md#iroh).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
