Back to [Commands index](../commands.md).

# <a id="grant"></a>`swoosh grant`

Issue, list, narrow, or revoke `sheer:` slips: signed grants to one of your services, checked offline
with no server and no allowlist. See [keys](../../keys.md#slip) for when to reach for each.

<!-- generated: usage from `swoosh grant -h`; option lines curated -->
```
Usage: swoosh grant <issue | ls | narrow | revoke>
  issue <service>   mint a slip for one service
    --expires <duration>   how long the slip is valid [default: 1h]
    --for <who>            bind to a device (person/device or a key) or a fleet (fleet:<person>)
    --delegable           let the holder narrow and re-share it (bearer only, not with a bind)
  ls                list the grants you have issued, grouped by service
  narrow <link>     narrow a slip offline before handing it on (only ever tightens)
    --service <name>       restrict to this service
    --expires <duration>   shorten the life
  revoke <peer|link>   refuse a slip, or every grant to a device or person, on this node
```

**Example.**
```console
$ swoosh grant issue ssh --for fleet:alice
issued a fleet-bound grant for `ssh` to fleet signet bf01o6vqymgz727g…
  every device that signet vouches for can use it (theft-resistant); expires in 1h
  revoke: swoosh grant revoke bf01o6vqymgz727g…
sheer:bf01hcq6…
```

**Things to know.** A bare person (`--for alice`) is refused: you must type `fleet:alice` to widen, so a
device bind never silently becomes a fleet bind. A bind is theft-resistant and cannot be delegated; a
bearer slip can be delegated but is meant to be short-lived (the [one trade](../../keys.md#the-one-trade)).
A revoke is node-local: see [revocation](../../keys.md#revocation). Revoke on each node you run.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
