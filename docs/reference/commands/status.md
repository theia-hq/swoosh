Back to [Commands index](../commands.md).

# <a id="status"></a>`swoosh status`

Show this machine: its key, lock, root, devices, contacts, links and services. `status <machine>` shows
how you reach one.

<!-- generated: usage from `swoosh status -h`; option lines curated -->
```
Usage: swoosh status [OPTIONS] [peer]
  [peer]   a petname, a raw node id, or a swoosh: link
  --key    print this machine's key and nothing else
```

**Example.** On a new machine, the first run makes its key:

<!-- live-run: the key and its path differ per machine -->
```console
$ swoosh status
made this machine's key (first run): /home/me/.config/swoosh/key
key: ed01hskmy456mldlsiqv4vuno7t37jzj2rqt3ipnnq4wvd5h67ahnk7q
lock: none
root: none yet.
  to join yours: swoosh join
  to make one here: swoosh invite <name> <key>

serving: nothing (swoosh serve is not running)
```

**Things to know.** Bare `status` reads this machine's own files and never dials, so it runs with nothing
serving and never asks for a passphrase. The report is on stdout; a line such as `made this machine's key`
is on stderr. `swoosh status --key` prints the key alone, for a script. Sections with no row are left out,
except `serving:`. On a device, `devices:` is your root's list as of the last sync.

With a peer, `status` dials each of its devices and prints one line each: a path and a round-trip time,
`unreachable`, `reached, but refused (...)`, or `reached, but the probe failed / went unanswered`. Only the
first is healthy; the last three each exit non-zero. The path is read after the probe, so the same peer can
read `relayed` on one run and `direct` on the next. [Why a path changes](../../transports.md#iroh).

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
