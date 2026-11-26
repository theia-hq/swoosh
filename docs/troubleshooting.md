# Troubleshooting

What the common failures mean and how to fix them. Every command that cannot do its job exits non-zero
and says why, rather than reporting a healthy-looking result.

## "reached, but the probe failed" / "reached, but the probe went unanswered"

```
desk: reached, but the probe failed (read frame: stream: peer went away)
nas: reached, but the probe failed (it sent an unknown reply to the list request)
nas: reached, but the probe failed (it ended the list request without an answer)
nas: reached, but the probe went unanswered (1 sent, 0 back)
Error: desk: reached, but the probe failed
```

The dial landed and the exchange did not finish. Two shapes: a `failed` line names what broke, and an `unanswered` line
means the probe went out and nothing came back. Either way the node is up enough to answer a dial and not up enough to
answer a service, which is usually a service task that died while the node kept running.

These are not healthy lines and they do not hold the exit code green. Neither reports a round-trip time,
because nothing was measured; the path estimate the transport keeps is not a measurement of your probe.

Fix one of:

- On your own device, check it still serves the name: `swoosh status me/<name>`.
- Restart the node if it lists the service and the probe still fails.

## "me/nas refused ssh"

<!-- manual: needs one of your devices that refuses ssh -->
```
error: me/nas refused ssh
```

Your own device refused. The line under the error, if there is one, says why: ssh was turned off or removed
there, nas is busy, or nas does not count this machine as one of your devices. To tell the first two apart, or
when no line says why, run `swoosh status` on nas.

## "refused ssh" from someone else's machine

<!-- manual: needs another person's machine that refuses ssh -->
```
error: bob/nas refused ssh
```

bob/nas does not serve `ssh`, or its owner has not shared `ssh` with you. The reply does not say which. Ask its
owner.

## "reached, but it does not answer ping for you"

```
bob/nas: reached, but it does not answer ping for you
```

`swoosh status` reached the machine, and it refused the probe: it does not serve `ping`, or it does not admit you
to it. The reply does not say which. Ask its owner to share `ping` with you.

## "could not reach" with `--local`

<!-- manual: needs a --local dial to a machine on another network -->
```
error: could not reach me/nas
  With --local or SWOOSH_LOCAL, swoosh looks on this network only.
  Give its address with --peer <key>=<address>, or drop --local and unset SWOOSH_LOCAL.
```

The address `--peer` takes is an address the machine's `serve` printed under `local`
([transports](transports.md#peer)).

## "could not reach"

<!-- manual: needs an offline machine -->
```
error: could not reach me/nas
```

You give no address, so this usually means the machine is offline or discovery is down. Check
that its `swoosh serve` is running and that both sides can reach the internet. If you run your own
resolver, a line under the error names it (`resolver asked: <url>`); check that it is up
and that the machine publishes to the same one.

## "warning: a connection to me/nas failed"

<!-- manual: needs a live peer -->
```
warning: a connection to me/nas failed: unreachable
  Still listening for new connections.
```

One connection through `forward <port>` or `proxy` could not open; the others are not affected. The text
after the colon is the cause:

- `reached, but refused (unavailable: <why>)` or `(bad request: <why>)`: the machine answered and said no.
- `unreachable`: no path to the machine, or it did not answer in time.
- `interrupted`, or `interrupted (<why>)`: the stream broke as it opened.
- `too many connections here`: wait for one to close.

The name is the machine's, or `that machine` or `the link's machine` if it has none. The line prints once;
it prints again only after a later connection works. A connection that opened never warns, whatever ends it.
To stop, press ctrl-c.

## A revoke did not take effect

A revoke lands live: the gate re-reads the denylist when its file changes
(mtime-watched), so a revoke written while a node runs takes effect on the next dial, typically within a
couple of seconds, no restart. It does not cut a session already in progress; the held connection
drains. See [revocation](keys.md#revocation).

- A link is admitted only by the machine that made it: revoke it there. Revoke a device where your root is
  kept (or with `--root <dir>`); anywhere else it is blocked on that machine only.
- A fleet-bound grant stays usable from any device that person still holds until it expires or you
  revoke it. Keep fleet grants short-lived.

## "a value is required for '--public <service>'"

```
error: a value is required for '--public <service>' but none was supplied
```

Bare `--public` names nothing to open. List the services you want public:
`swoosh serve --public ping,speed`.

## A public ping or speed is being hammered

The open `ping` and `speed` routes bind the metered engine: one ping run per caller per second, one
transfer at a time, and byte plus wall-clock stream caps. An anonymous caller hits those caps rather than
draining the uplink. Only `--public` the services you are willing to let a stranger use. `swoosh service
off <name>` stops serving it to anyone, live, no restart; to keep it for your own devices while
taking it off the public menu, restart `serve` without the flag.

## "does not apply while swoosh serve runs here"

<!-- manual: needs a running swoosh serve and a reach flag -->
```
error: --relay or SWOOSH_RELAY does not apply while swoosh serve runs here
  Commands here connect through swoosh serve.
  Set it on swoosh serve, or stop swoosh serve and run this command again.
```

While `swoosh serve` runs on this machine, the commands that reach a machine go through it, so `--local`, `--relay` and `--resolver` (and their `SWOOSH_` variables) belong on `serve`.

## "swoosh serve on this machine is a different version" / "swoosh serve did not answer here"

<!-- manual: needs a serve of another build, or one that is stuck -->
```
error: swoosh serve on this machine is a different version
  Restart it with this version.
error: swoosh serve did not answer here
  Restart it.
```

The command went through the `serve` running here and it could not take the request. When `revoke` prints this,
its change is already made on this machine; restarting `serve` tells your devices, because the sync `serve` runs as it
starts does. When `root restore` prints it, the root is restored on this machine, and the error does not say a restart tells your devices.
The same holds for a `revoke` a newer list held back: it was not published, so run `swoosh sync`, then `revoke` again.

## "swoosh serve's socket is not private to you"

```
error: swoosh serve's socket is not private to you
  <path> is not yours alone.
  Nothing was sent through it.
```

The socket or its directory is owned by another user, is open to others, or is a symbolic link. Nothing was sent. Make the path
yours alone, or stop whatever put it there. When the second line reads `The process answering at <path> is not known
to be yours.`, the path is fine and the process answering is another user's or could not be identified; stop it.

## Next

- [Keys](keys.md#the-gate) how the gate decides who gets in.
- [Transports](transports.md) how swoosh reaches a machine, and `--peer`.
- [Commands](reference/commands.md) every verb and flag.
