# Commands

Every verb, with a real example and the one thing to know about it. This is a lookup, not a read: if you
are going top to bottom, you probably want a [use case](../use-cases/README.md) instead.

The `Usage` line under each command is hand-copied from the parser's `-h` output. Run
`swoosh <command> --help` for the full text of any flag.

## Common options

These apply to most commands and are omitted from the per-command signatures below:

- `--home <dir>` (or `SWOOSH_HOME`) use another home. The home holds this machine's key (`machine/key`), its
  root, contacts and links, so one `--home` moves the whole identity. Without it the default applies:
  `~/Library/Application Support/swoosh` on macOS, `$XDG_STATE_HOME/swoosh` or `~/.local/state/swoosh` on
  Linux. Backups leave `machine/` out, because a copy of the key would act as this machine: on macOS
  Time Machine skips it, and on Linux it holds a `CACHEDIR.TAG`, which tools such as restic and borg skip.
- `<machine>` is `me/<name>` (one of yours), `<person>/<name>`, a key (`ed01…`), a `swoosh:` link, or a path to
  a file holding one. A person alone works when only one of their machines is saved; with several, name one.

## Commands

Each command lives in its own file. The per-command pages hold the full text relocated from this index,
with only the heading level adjusted and relative links repointed for the new location.

Note: the `<a id>` anchors below preserve the old per-command anchors, so existing links of the form
`commands.md#<command>` keep resolving to this index, which then links to the focused page.

- <a id="serve"></a>[`swoosh serve`](commands/serve.md): serve services on this machine for those you admit
- <a id="stop"></a>[`swoosh stop`](commands/stop.md): stop swoosh serve here or on one of your own devices
- <a id="service"></a>[`swoosh service`](commands/service.md): show or change what this machine serves
- <a id="ping"></a>[`swoosh ping`](commands/ping.md): measure the round-trip time to a machine
- <a id="speed"></a>[`swoosh speed`](commands/speed.md): measure throughput to a machine
- <a id="status"></a>[`swoosh status`](commands/status.md): show this machine, or how you reach another machine
- <a id="proxy"></a>[`swoosh proxy`](commands/proxy.md): mint a local URL that reaches an origin through a machine you name
- <a id="forward"></a>[`swoosh forward`](commands/forward.md): forward a machine's service to a local port or stdout
- <a id="send"></a>[`swoosh send`](commands/send.md): push a file or directory to a machine
- <a id="sync"></a>[`swoosh sync`](commands/sync.md): bring your device list up to date with your other devices, both ways
- <a id="contact"></a>[`swoosh contact`](commands/contact.md): save or remove another person's key under a name
- <a id="identity"></a>[`swoosh identity`](commands/identity.md): back up, restore, or protect this machine's key
- <a id="invite"></a>[`swoosh invite`](commands/invite.md): add one of your devices, or renew it; bare invite lists what is due
- <a id="join"></a>[`swoosh join`](commands/join.md): make this machine one of your devices, from an invite
- <a id="leave"></a>[`swoosh leave`](commands/leave.md): stop being one of your devices
- <a id="revoke"></a>[`swoosh revoke`](commands/revoke.md): take back a share or a device, or end a root for good
- <a id="ssh"></a>[`swoosh ssh`](commands/ssh.md): reach a machine's sshd; runs the system ssh
- <a id="share"></a>[`swoosh share`](commands/share.md): make a link to a service for a person, a device, a key, or anyone

## Next

- [Use cases](../use-cases/README.md) these verbs in real tasks.
- [Keys](../keys.md) the model the gated commands assume.
- [Troubleshooting](../troubleshooting.md) when a command refuses or cannot reach.
