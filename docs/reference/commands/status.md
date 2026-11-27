Back to [Commands index](../commands.md).

# <a id="status"></a>`swoosh status`

Show this machine: its key, lock, root, devices, contacts, links and services. `status <machine>` shows
how you reach one.

<!-- generated: usage from `swoosh status -h`; option lines curated -->
```
Usage: swoosh status [OPTIONS] [machine]
  [machine]  me/<name>, <person>/<name>, a person, key or link
  --key    Print this machine's key and nothing else
```

**Example.** With a key, no saved service list and nothing running, `swoosh status` starts with this block:

<!-- live-run: local status with a key, no saved service list and no running serve; only the first block captured -->
```console
this machine     not one of your devices yet
  key            ed01slc6uxmtglqlm77rtvyq6mkcwkd5nhumkipcpkgoemdmxchhoa6a
  lock           none
  serving        ping, speed, when swoosh serve runs
  home           /home/ada/.local/state/swoosh
```

**Things to know.** Bare `status` reads this machine's own files and never dials, so it runs with nothing
serving and never asks for a passphrase. The report is on stdout; a line such as `made this machine's key`
is on stderr. `swoosh status --key` prints the key alone, for a script.

The report is blocks a blank line apart: `this machine`, `your root`, `reach`, `internal routes`, `devices`,
`contacts` and `links you shared`, in that order. A block with no row is left out, and `this machine` always
ends with its `home` row. On a device, `devices` is your root's list, and its title reads
`devices (as of the last sync, …)`. A contact saved as one machine reads `one machine` beside its key.

The `serving` row appears on every home with a key. It shows service names, with `(off)` beside those turned off.
Use those names with `swoosh service on` or `swoosh service off`. While serving, it names what is bound: a bound service that is not saved is listed after the saved ones, and a saved one not yet bound is left out. A name the serve is refusing reads `(refusing new connections)`; retargeted names still refer to the old route. When nothing runs, the row says
what `swoosh serve` would start. An emptied list says `nothing, even when swoosh serve runs`. If
`serve.toml` cannot be read or its service list is invalid, the row says `unknown`; stderr names the file
and the reason, and `status` still exits 0. When admitting devices, `admitting root:` and the root key
follow the service list.
With `swoosh serve` running here, bare `status` also lists how it is reached under `reach`, with the public, tunnel and
this computer addresses the banner can leave out, and the routes it answers under `internal routes`, and who reaches each.
Both are left out when the serving row says `unknown`.

With a machine, `status` dials it. A healthy machine prints one line: `me/nas   reachable, direct, 12.0 ms`. That is
the name, the path and the round-trip time, and for one of your own devices the line ends with what it serves
(`; serving ssh, web`, or `; serving nothing`). Otherwise `status` exits non-zero. An unreachable machine prints
`me/nas: unreachable`, and one that answered the dial but did not answer the probe prints `reached, but the probe
went unanswered`, with the count. A refusal prints `me/nas: reached, but refused (<its reason>)`. Two refusals have their own words: `me/nas: reached, but nas does not count this machine as one of your devices`, and `bob/nas: reached, but it does not answer ping for you`. For the first kind, when the name
leaves too little room, the line ends at `refused` and the reason follows on its own row, `  reason   <text>`.
A failed probe prints `me/nas: reached, but the probe failed`, then either a sentence of swoosh's own or the
machine's words on a `  reason   <text>` row. The path
is read after the probe, so one machine can show `relayed through <host>` on one run and `direct` on the
next. [Why a path changes](../../transports.md#iroh). It works the same through `swoosh serve`. If the path
cannot be read, the line has no path, stderr says `warning: could not read the path of this run`, and the
exit code is unchanged. One of your devices that answers its list with anything but the list fails, and the
line says what it sent, or that it ended the request without an answer.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
