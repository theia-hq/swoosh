Back to [Commands index](../commands.md).

# <a id="mint"></a>`swoosh mint`

Derive a device identity from your signet and emit a one-time authkey for a machine to adopt.

<!-- generated: usage from `swoosh mint -h`; option lines curated -->
```
Usage: swoosh mint [OPTIONS] <label>
  <label>   the device label, e.g. ci-runner or desk (recorded as me/<label>)
  --expires <duration>   how long the minted badge stays valid [default: 90d]
```

**Example.** `swoosh mint laptop` prints an authkey and records `me/laptop`. Run it on the machine that
holds your signet. `swoosh mint qat --expires 365d` mints a year-long badge for a long-lived box.

**Things to know.** The authkey is a device secret. Hand it to the new machine over something private;
`adopt` reads it without putting it on the command line. The badge expiry is the leak window: a leaked
authkey stays adoptable until the badge expires, and the gate checks expiry on dial, so mint immediately
before the machine adopts.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
