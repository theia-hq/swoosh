Back to [Commands index](../commands.md).

# <a id="ssh"></a>`swoosh ssh`

Reach a peer's sshd over the overlay; runs the system ssh.

<!-- generated: usage from `swoosh ssh -h`; option lines curated -->
```
Usage: swoosh ssh [OPTIONS] <peer> [ssh args]...
  <peer>          a petname, a raw node id, or a sheer: link
  [ssh args]...   forwarded verbatim to ssh, after --
  --service <name>   the exposed service name to reach [default: ssh]
```

**Example.** `swoosh ssh desk -- ls` runs a one-off command; `swoosh ssh desk -p 2222` passes ssh flags
through.

**Things to know.** Auth is your normal ssh keys. The peer serves its shell with `swoosh serve
ssh=sshd:` (a keyless shell it stands up) or points at an existing sshd with `serve ssh=127.0.0.1:22`.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
