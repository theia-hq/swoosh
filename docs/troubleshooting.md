# Troubleshooting

What the common failures mean and how to fix them. Every command that cannot do its job exits non-zero
and says why, rather than reporting a healthy-looking result.

## "reached, but refused (not admitted)"

```
via quirk: reached, but refused (not admitted: not a member of this node's family,
and no capability for this service)
```

You reached the peer, but its gate turned you away. You are not one of its devices and you presented no
slip that grants this service. This is the gate working as designed.

Fix one of:

- If it is your own node, enroll this machine: `swoosh mint <label>` on the machine that holds your
  signet, then `swoosh adopt` here.
- If someone else runs it, ask them for a [slip](keys.md#slip) and add `--present sheer:…` to your
  command.
- If the service is meant to be public, the owner opens it with `swoosh serve --public <service>`.

## "quirk is direct-only: pass --peer"

```
Error: quirk is direct-only: pass --peer <key>=<addr> (the line the peer's `swoosh serve`
printed), or use --transport iroh: could not reach <key>
```

Over quirk there is no discovery, so swoosh needs the peer's address. Either pass it with
`--peer <key>=<addr>` (the `direct` line the peer's `serve` printed), or drop `--transport quirk` to use
iroh, which discovers the peer from its key. See [transports](transports.md#quirk).

## An iroh dial cannot reach the peer

Over iroh you do not pass an address, so an unreachable dial usually means the peer is offline or
discovery is down, not a missing hint. Check that the peer's `swoosh serve` is running, and that both
sides can reach the internet. `swoosh status <peer>` reports the path once a link is up.

## A revoke did not take effect

A revoke is **node-local** and takes effect on the node's **next `serve`**, not on a running one:

- The gate loads the denylist once, when `swoosh serve` starts. A revoke you make while the node is serving
  does not bite until you restart it, so restart `serve` on the node to apply it. (Live revocation, cutting
  a held slip without a restart, lands with the daemon.)
- It applies to the node you ran it on. If you serve from more than one node, revoke on each.
- A fleet slip stays usable from any device that person still holds until it expires or you revoke it.
  Keep fleet slips short-lived.

## A public ping or speed is being hammered

`ping` and `speed` have no responder-side rate limit yet, so an open one lets an anonymous caller drain
your uplink. Only `--public` the services you are willing to let a stranger use, and take them back by
restarting `serve` without them.

## Next

- [Keys](keys.md#the-gate) how the gate decides who gets in.
- [Transports](transports.md) iroh versus quirk, and `--peer`.
- [Commands](reference/commands.md) every verb and flag.
