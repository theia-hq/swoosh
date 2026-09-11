# Commands

Every verb, with a real example and the one thing to know about it. This is a lookup, not a read: if you
are going top to bottom, you probably want a [use case](../use-cases/README.md) instead.

The `Usage` line under each command is generated from the parser, so it cannot drift from `--help`. Run
`swoosh <command> --help` for the full text of any flag.

## Common options

These apply to most commands and are omitted from the per-command signatures below:

- `--home <dir>` (or `SWOOSH_HOME`) use a specific node home directory. The home is the whole profile: the
  key lives at `<home>/identity.key`, and its contacts, the signet it trusts, and its badge all live
  beside it, so one `--home` moves the whole identity. Without it the default `~/.config/swoosh` applies.
- `--transport <iroh|quirk>` which backend to bind. `iroh` (default) reaches peers across the internet;
  `quirk` is direct-only for diagnostics. See [transports](../transports.md).
- `--peer <key=addr>` a direct address hint, for when discovery cannot reach a peer (mainly quirk). See
  [transports](../transports.md#quirk).
- `--present <link>` present a `sheer:` slip when reaching a gated peer you are not a member of.

## Commands

Each command lives in its own file. The per-command pages hold the full text relocated from this index,
with only the heading level adjusted and relative links repointed for the new location.

Note: the `<a id>` anchors below preserve the old per-command anchors, so existing links of the form
`commands.md#<command>` keep resolving to this index, which then links to the focused page.

- <a id="serve"></a>[`swoosh serve`](commands/serve.md): be a node, publish named services behind your signet gate
- <a id="stop"></a>[`swoosh stop`](commands/stop.md): stop a peer's node by its key or a `sheer:` link
- <a id="service"></a>[`swoosh service`](commands/service.md): list a peer's menu, or enable/disable a service on your node
- <a id="ping"></a>[`swoosh ping`](commands/ping.md): measure round-trip time to a peer, addressed by key
- <a id="speed"></a>[`swoosh speed`](commands/speed.md): measure throughput to a peer, addressed by key
- <a id="status"></a>[`swoosh status`](commands/status.md): show the connection path to a peer (direct or relayed)
- <a id="fetch"></a>[`swoosh fetch`](commands/fetch.md): mint a local URL that fetches an origin through a named node
- <a id="forward"></a>[`swoosh forward`](commands/forward.md): put a peer's served service on a local port, stdout, or unix socket
- <a id="send"></a>[`swoosh send`](commands/send.md): push a file or directory to a peer, verified end to end
- <a id="fleet"></a>[`swoosh fleet`](commands/fleet.md): pull the signed roster from a coordination node into your contacts
- <a id="contact"></a>[`swoosh contact`](commands/contact.md): manage local petnames for peers (yours alone, plain TOML)
- <a id="identity"></a>[`swoosh identity`](commands/identity.md): print this machine's key, minting one if there is none
- <a id="mint"></a>[`swoosh mint`](commands/mint.md): derive a device identity and emit a one-time authkey to adopt
- <a id="adopt"></a>[`swoosh adopt`](commands/adopt.md): adopt a minted authkey as this device identity
- <a id="ssh"></a>[`swoosh ssh`](commands/ssh.md): reach a peer's sshd over the overlay using the system ssh
- <a id="grant"></a>[`swoosh grant`](commands/grant.md): issue, list, narrow, or revoke `sheer:` slips
- <a id="tree"></a>[`swoosh tree`](commands/tree.md): print the command tree read straight from the parser

## Next

- [Use cases](../use-cases/README.md) these verbs in real tasks.
- [Keys](../keys.md) the model the gated commands assume.
- [Troubleshooting](../troubleshooting.md) when a command refuses or cannot reach.
