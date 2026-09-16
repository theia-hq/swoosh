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

## "reached, but refused (not admitted)"

```
bf01hcq6balrlxwa via quirk+noise: reached, but refused (not admitted: no member badge or capability for this service was accepted)
Error: bf01hcq6balrlxwa: reached, but refused
```

You reached the peer, but its gate turned you away. You are not one of its devices and you presented no
grant that covers this service. This is the gate working as designed.

The same message also covers an unserved service: a node that admits you but does not serve the name you
asked for refuses with the same words, because the reply cannot tell "not admitted" from "admitted, not
served". Check the menu with `swoosh service ls --at <peer>`: if it lists the menu without your service,
the node is not serving it.

Fix one of:

- If it is your own node, enroll this machine: `swoosh invite add <label>` on the machine that holds your
  signet, then `swoosh adopt` here.
- If someone else runs it, ask them for a [capability link](keys.md#grant) and add `--present sheer:…` to
  your command.
- If the service is meant to be public, the owner opens it with `swoosh serve --public <service>`.
- If the menu from `swoosh service ls --at <peer>` is missing the service, the node is not serving it:
  serve that name on the node, or reach one it does serve.

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

A revoke is **node-local** and lands live: the gate re-reads the denylist when its file changes
(mtime-watched), so a revoke written while a node runs takes effect on the next dial, typically within a
couple of seconds, no restart. It does not cut a session already in progress; the held connection
drains. See [revocation](keys.md#revocation).

- It applies to the node you ran it on. If you serve from more than one node, revoke on each.
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
disable <name>` stops serving it to anyone, live, no restart; to keep it for your own devices while
taking it off the public menu, restart `serve` without the flag.

## Next

- [Keys](keys.md#the-gate) how the gate decides who gets in.
- [Transports](transports.md) iroh versus quirk, and `--peer`.
- [Commands](reference/commands.md) every verb and flag.
