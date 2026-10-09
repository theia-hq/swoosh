Back to [Commands index](../commands.md).

# <a id="ssh"></a>`swoosh ssh`

Reach a peer's sshd over the overlay; runs the system ssh.

<!-- generated: usage from `swoosh ssh -h`; option lines curated -->
```
Usage: swoosh ssh [OPTIONS] <machine> [-- <ssh args>...]
  <machine>       A machine: me/<name>, <person>/<name>, a person, a key, or a link
  [ssh args]...   forwarded verbatim to ssh, after --
```

**Example.** `swoosh ssh me/desk -- ls` runs a one-off command; `swoosh ssh me/desk -- -p 2222` passes ssh
flags through.

**Things to know.** The built-in shell (`swoosh serve ssh`) needs no key setup; swoosh pins the peer on first
connection. Point at an existing sshd (`serve ssh=tcp:127.0.0.1:22`) to use your normal ssh keys. `swoosh ssh` uses iroh only.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
