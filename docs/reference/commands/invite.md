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
`--for alice/laptop` binds a device from your contacts; `swoosh invite add ci --for <key> --expires 365d`
signs a year-long badge.

**Things to know.** A derived invite (`--for` omitted) carries the device seed, so hand it over something
private. A bound invite (`--for`) carries no secret, so it is safe in transit. It is not signed by the
signet it names, so compare the full signet and the full admitted key that `invite add` prints out of band
before admission: the invite is a token, not proof of who sent it. The badge expiry is the leak window for
a derived invite, and `adopt` checks the badge is bound to the machine's own key and is unexpired before
storing it. An invite admits one device at the whole gate; to open one service to a device or a whole
fleet, use `swoosh grant issue`. A label already recorded for a different key is refused; `invite rm <label>`
cuts the old badge and `swoosh contact rm me/<label>` frees the name.

## `swoosh invite ls`

List the invites you have issued: one line per badge, with the label it was recorded under, the key it
admits, and the badge's remaining lifetime.

## `swoosh invite rm`

Cancel an invite by revoking its badge now, offline. The label you gave `invite add` (or the raw device
key) selects it; the ledger row stays for audit. To cut a service grant instead, use `swoosh grant revoke`.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
