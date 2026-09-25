Back to [Commands index](../commands.md).

# <a id="grant"></a>`swoosh grant`

Issue, narrow, or revoke `swoosh:` capability links: signed grants to one of your services, checked
offline with no server and no allowlist. See [keys](../../keys.md#grant) for when to reach for each.

<!-- generated: usage from `swoosh grant -h`; option lines curated -->
```
Usage: swoosh grant [OPTIONS] <COMMAND>
  issue <service>   mint a capability link for one service
    --expires <duration>   how long the link is valid [default: 1h]
    --for <who>            bind to a device (person/device or a key) or a fleet (fleet:<person>)
    --delegable           let the holder narrow and re-share it (bearer only, not with a bind)
  narrow <link>     narrow a link offline before handing it on (only ever tightens)
    --service <name>       restrict to this service
    --expires <duration>   shorten the life
  revoke <peer|link>   revoke a grant (a link, or a peer you granted) on this node
```

**Example.**
<!-- capture: swoosh grant issue ssh --for fleet:alice -->
```console
$ swoosh grant issue ssh --for fleet:alice
issued a fleet-bound grant for `ssh` to fleet signet ed01o6vqymgz727g…
  every device that signet vouches for can use it (theft-resistant); expires in 1h
  revoke: swoosh grant revoke ed01o6vqymgz727g…
swoosh:ed01hcq6…
```

**Things to know.** A bare person (`--for alice`) is refused: you must type `fleet:alice` to widen, so a
device bind never silently becomes a fleet bind. A bind is theft-resistant and cannot be delegated; a
bearer grant can be delegated but is meant to be short-lived (the [one trade](../../keys.md#the-one-trade)).
A revoke is node-local: see [revocation](../../keys.md#revocation). Revoke on each node you run.
`swoosh status` lists what you issued under `links you shared:`, with when each ends. A name is an address, not an authority
([Services](../services.md#names)): grants are per name, so two names over one target need a grant each,
and revoking one does not touch the other.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
