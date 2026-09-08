Back to [Commands index](../commands.md).

# <a id="fleet"></a>`swoosh fleet`

Learn your fleet: pull the signed roster from a coordination node and fold it into your contacts.

<!-- generated: usage from `swoosh fleet -h`; option lines curated -->
```
Usage: swoosh fleet [OPTIONS] --pull <peer>
  --pull <peer>   pull the roster from this coordination node (a member serving roster:)
```

**Example.** `swoosh fleet --pull me/hub` verifies the roster against your signet and records each
member as a `me/<device>` contact.

**Things to know.** The roster is verified against your signet before anything is folded in, so a node
cannot inject a contact you did not vouch for.

See also [Commands index](../commands.md) and [Common options](../commands.md#common-options).
