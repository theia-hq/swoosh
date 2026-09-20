Back to [Commands index](../commands.md).

# <a id="reach"></a>`swoosh reach`

Reach any service a peer serves. The stream lands on stdout unless you send it somewhere else.

<!-- generated: usage from `swoosh reach -h`; option lines curated -->
```
Usage: swoosh reach [OPTIONS] <peer> <service>
  <peer>              a petname, a raw node id, or a sheer: link
  <service>           the served service to reach, under the name the host bound it
  --to <port|-|unix:PATH>   where to put the stream: a local port, - for stdout [default: -]
  --present <link>    a sheer: capability link to present to a gated peer
```

**Example.** `swoosh reach desk tv --to 8096` puts the peer's `tv` service on `127.0.0.1:8096`, so a
local client talks to it as if it were local. `swoosh reach desk logs` streams that service straight to
your terminal.

**Things to know.** Most services need no command of their own, so this is the front door for all of
them: name the peer, name the service, and the bytes are yours. The sink defaults to `-` (stdout), so
the common case takes no flags and composes with the shell (`swoosh reach desk cam | mpv -`). Both the
peer and the service are required; there is no default service name, because a name the peer does not
serve is refused by the peer rather than by you.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
