# Commands

Every verb, with a real example and the one thing to know about it. This is a lookup, not a read: if you
are going top to bottom, you probably want a [use case](../use-cases/README.md) instead.

The `Usage` line under each command is hand-copied from the parser's `-h` output. Run
`swoosh <command> --help` for the full text of any flag.

## Common options

These apply to most commands and are omitted from the per-command signatures below:

- `--home <dir>` (or `SWOOSH_HOME`) use a specific node home directory. The home is the whole profile: the
  key lives at `<home>/key`, and its contacts, the signet it trusts, and its membership all live
  beside it, so one `--home` moves the whole identity. Without it the default `~/.config/swoosh` applies.
- `--transport <iroh|quirk|quirk+noise>` which backend to bind. See [transports](../transports.md).
- `--peer <key=addr>` a direct address hint, for when discovery cannot reach a peer (mainly quirk). See
  [transports](../transports.md#quirk).
- `--relay <url>` the relay peers reach this node through (per node). See
  [run the relay and the resolver yourself](../transports.md#self-run).
- `--resolver <url>` where address records are published and read (fleet-wide). See
  [run the relay and the resolver yourself](../transports.md#self-run).
- `--present <link>` present a `swoosh:` capability link when reaching a gated peer you are not a member of.

## Commands

Each command lives in its own file. The per-command pages hold the full text relocated from this index,
with only the heading level adjusted and relative links repointed for the new location.

Note: the `<a id>` anchors below preserve the old per-command anchors, so existing links of the form
`commands.md#<command>` keep resolving to this index, which then links to the focused page.

- <a id="serve"></a>[`swoosh serve`](commands/serve.md): be a node, publish named services behind your signet gate
- <a id="stop"></a>[`swoosh stop`](commands/stop.md): stop a peer's node by its key or a `swoosh:` link
- <a id="service"></a>[`swoosh service`](commands/service.md): list a peer's menu, or enable/disable a service on your node
- <a id="ping"></a>[`swoosh ping`](commands/ping.md): measure round-trip time to a peer, addressed by key
- <a id="speed"></a>[`swoosh speed`](commands/speed.md): measure throughput to a peer, addressed by key
- <a id="status"></a>[`swoosh status`](commands/status.md): show this machine: its key, lock, root, devices, contacts, links and services
- <a id="fetch"></a>[`swoosh fetch`](commands/fetch.md): mint a local URL that fetches an origin through a named node
- <a id="reach"></a>[`swoosh reach`](commands/reach.md): reach any service a peer serves, on stdout or a local port
- <a id="send"></a>[`swoosh send`](commands/send.md): push a file or directory to a peer, verified end to end
- <a id="sync"></a>[`swoosh sync`](commands/sync.md): bring your device list up to date with your other devices, both ways
- <a id="contact"></a>[`swoosh contact`](commands/contact.md): manage local petnames for peers (yours alone, plain TOML)
- <a id="identity"></a>[`swoosh identity`](commands/identity.md): back up, restore, or protect this machine's key
- <a id="invite"></a>[`swoosh invite`](commands/invite.md): add one of your devices, or renew it; bare `invite` lists what is due
- <a id="join"></a>[`swoosh join`](commands/join.md): make this machine one of your devices, from an invite
- <a id="leave"></a>[`swoosh leave`](commands/leave.md): stop being one of your devices; `--new-key` also gives this machine a new key
- <a id="ssh"></a>[`swoosh ssh`](commands/ssh.md): reach a peer's sshd over the overlay using the system ssh
- <a id="grant"></a>[`swoosh grant`](commands/grant.md): issue, narrow, or revoke `swoosh:` capability links
- <a id="tree"></a>[`swoosh tree`](commands/tree.md): print the command tree read straight from the parser

## Next

- [Use cases](../use-cases/README.md) these verbs in real tasks.
- [Keys](../keys.md) the model the gated commands assume.
- [Troubleshooting](../troubleshooting.md) when a command refuses or cannot reach.
