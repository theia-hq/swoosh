# Troubleshooting

What the common failures mean and how to fix them. Every command that cannot do its job exits non-zero
and says why, rather than reporting a healthy-looking result.

## "the transport does not prove the peer"

```
Error: the transport does not prove the peer (declared: announced); presenting a credential would send it to whoever answers
```

Bare `quirk` never proves the peer holds the key it presents, so swoosh refuses to write a credential over
it: the dial never reaches the gate. Use `--transport quirk+noise`, which proves the key before any byte
flows. See [transports](transports.md#quirk).

## "reached, but the probe failed" / "reached, but the probe went unanswered"

```
desk via iroh: reached, but the probe failed (read frame: stream: peer went away)
nas via iroh: reached, but the probe went unanswered (1 sent, 0 back)
Error: desk: reached, but the probe failed
```

The dial landed and the exchange did not finish. Two shapes: the first names what broke, the second means
the probe went out and nothing came back. Either way the node is up enough to answer a dial and not up
enough to answer a service, which is usually a service task that died while the node kept running.

These are not healthy lines and they do not hold the exit code green. Neither reports a round-trip time,
because nothing was measured; the path estimate the transport keeps is not a measurement of your probe.

Fix one of:

- On your own device, check it still serves the name: `swoosh status me/<name>`.
- Restart the node if it lists the service and the probe still fails.
- Try `--transport quirk+noise` if only one transport shows it, which points at the path rather than the
  node.

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
bob/nas via iroh: reached, but it does not answer ping for you
```

`swoosh status` reached the machine, and it refused the probe: it does not serve `ping`, or it does not admit you
to it. The reply does not say which. Ask its owner to share `ping` with you.

## "could not reach" over quirk or with `--local`

<!-- manual: needs a quirk dial with no address -->
```
error: could not reach me/nas
  quirk finds no machine by itself.
  Give its address with --peer <key>=<address>, or add --transport iroh.
```

With `--local`, the lines under the error start `With --local or SWOOSH_LOCAL, swoosh looks on this network
only.` and end with how to turn it off. Either way, the address `--peer` takes is the `direct` line the
machine's `serve` printed ([transports](transports.md#peer)).

## "could not reach" over iroh

<!-- manual: needs an offline machine -->
```
error: could not reach me/nas
```

Over iroh you give no address, so this usually means the machine is offline or discovery is down. Check
that its `swoosh serve` is running and that both sides can reach the internet. If you run your own
resolver, a line under the error names it (`resolver asked: <url>`); check that it is up
and that the machine publishes to the same one.

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

## Next

- [Keys](keys.md#the-gate) how the gate decides who gets in.
- [Transports](transports.md) iroh versus quirk, and `--peer`.
- [Commands](reference/commands.md) every verb and flag.
