Back to [Commands index](../commands.md).

# <a id="invite"></a>`swoosh invite`

Create, list, and cancel invites: one device per invite.

An invite admits one device at your signet's whole gate. Create it on the machine that holds your signet;
the machine you invite runs `swoosh adopt`.

## `swoosh invite add`

Create an invite: label names the row, `--for` binds the key it admits.

<!-- generated: usage from `swoosh invite add -h`; option lines curated -->
```
Usage: swoosh invite add [OPTIONS] <label>
  <label>   the device label, e.g. ci-runner or desk (recorded as me/<label>)
  --for <who>   the key it admits; omit to derive a device identity
  --expires <duration>   how long the invite's badge stays valid [default: 90d]
```

**Example.** `swoosh invite add laptop` derives a device identity and prints an invite for it. To keep
the secret from travelling, make the key on the device first (`swoosh identity` prints it) and sign only
its public half: `swoosh invite add laptop --for <key>` prints an invite with no secret in it.
`--for alice/laptop` binds a device from your contacts; `swoosh invite add qat --for <key> --expires 365d`
signs a year-long badge.

**Things to know.** A derived invite (`--for` omitted) carries the device seed, so hand it over something
private; a bound invite (`--for`) carries no secret and is safe over any channel. The badge expiry is the
leak window for a derived invite, and the gate checks it on dial, not at adopt time: create the invite
just before the machine adopts. An invite admits one device at the whole gate; to open one service to a
device or a whole fleet, use `swoosh grant issue`.

## `swoosh invite ls`

List the invites you have issued: one line per badge, with the label it was recorded under, the key it
admits, and the badge's remaining lifetime.

## `swoosh invite rm`

Cancel an invite by revoking its badge now, offline. The label you gave `invite add` (or the raw device
key) selects it; the ledger row stays for audit. To cut a service grant instead, use `swoosh grant revoke`.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
