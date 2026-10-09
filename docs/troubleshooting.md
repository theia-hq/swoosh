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

## "reached, but refused (not admitted)"

```
ed01hcq6balrlxwa via quirk+noise: reached, but refused (not admitted: no member badge or capability for this service was accepted)
Error: ed01hcq6balrlxwa: reached, but refused
```

You reached the peer, but its gate turned you away. You are not one of its devices and you presented no
grant that covers this service. This is the gate working as designed.

The same message also covers an unserved service: a node that admits you but does not serve the name you
asked for refuses with the same words, because the reply cannot tell "not admitted" from "admitted, not
served". On your own device, `swoosh status me/<name>` lists what it serves.

Fix one of:

- If it is your own node, enroll this machine: `swoosh invite add <label>` on the machine that holds your
  signet, then `swoosh adopt` here.
- If someone else runs it, ask them for a [capability link](keys.md#grant) and use it where the machine
  goes: `swoosh ping swoosh:…`.
- If the service is meant to be public, the owner opens it with `swoosh serve --public <service>`.
- If it is your own device and `swoosh status me/<name>` does not list the service, add it there:
  `swoosh service add <service>`.

## "reached, but it does not answer ping for you"

```
bob/nas via iroh: reached, but it does not answer ping for you
```

`swoosh status` reached the machine, and it refused the probe: it does not serve `ping`, or it does not admit you
to it. The reply does not say which. Ask its owner to share `ping` with you.

## "quirk is direct-only: pass --peer"

```
Error: quirk is direct-only: pass --peer <key>=<addr> (the line the peer's `swoosh serve`
printed), or use --transport iroh: could not reach <key>
```

Over quirk, either spelling, there is no discovery, so swoosh needs the peer's address. Either pass it
with `--peer <key>=<addr>` (the `direct` line the peer's `serve` printed), or use `--transport iroh`,
which discovers the peer from its key. See [transports](transports.md#quirk).

## An iroh dial cannot reach the peer

Over iroh you do not pass an address, so an unreachable dial usually means the peer is offline or
discovery is down, not a missing hint. Check that the peer's `swoosh serve` is running, and that both
sides can reach the internet. `swoosh status <peer>` reports the path once a link is up.

## A revoke did not take effect

A revoke lands live: the gate re-reads the denylist when its file changes
(mtime-watched), so a revoke written while a node runs takes effect on the next dial, typically within a
couple of seconds, no restart. It does not cut a session already in progress; the held connection
drains. See [revocation](keys.md#revocation).

- A link is admitted only by the machine that made it: revoke it there. Revoke a device where your root is
  kept (or with `--root <dir>`); anywhere else it is blocked on that machine only.
- A fleet-bound grant stays usable from any device that person still holds until it expires or you
  revoke it. Keep fleet grants short-lived.

## "a value is required for '--public <svc>'"

```
error: a value is required for '--public <svc>' but none was supplied
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
