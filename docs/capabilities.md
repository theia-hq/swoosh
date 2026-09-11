# Capabilities: hand out one service, expiring and revocable

Give someone access to exactly one service on your machine: a **capability link** (a `sheer:` link). It
expires on its own, and you can revoke it while your node runs. No account for them, no password to
rotate, nothing to clean up after.

The loop below uses `ping`, the one service that needs no setup, so you can run it on one machine in a
minute. Any service works the same way; [contractor access](use-cases/contractor-access.md) runs it for
ssh. You need a running node: `swoosh serve` prints the key the link carries, so the holder needs
nothing from you but the link itself ([getting started](getting-started.md)).

## 1. Issue the link

On the machine that serves:

<!-- capture: swoosh grant issue ping --expires 15m -->
```console
$ swoosh grant issue ping --expires 15m
issued a bearer grant for `ping`
  anyone holding the link can use it; expires in 15m.
  revoke: paste the link to `swoosh grant revoke <link>`, or let it expire
sheer:bf01hcq6…
```

Hand that last line over any channel (chat, a QR code). It names the node, the one service it grants,
and the authority to reach it. The default life is one hour; `--expires` shortens or extends it. Add
`--for` to bind the link to one device or a whole fleet, so a stolen copy is useless (see
[the one trade](keys.md#the-one-trade)).

## 2. Present it

The holder presents the link when they dial. The link alone names the node and the service:

<!-- live-run: real iroh reach, non-deterministic; re-capture before release -->
```console
$ swoosh ping sheer:bf01hcq6…
bf01hcq6balrlxwa via iroh: mixed (direct to 192.168.1.115:51445 and relayed)
  3 sent, 3 received, 0% loss
  rtt min/avg/max/mdev = 0.891/1.075/1.277/0.135 ms
```

If they already reach the node another way (a petname they saved, say), they name the peer and present
the link separately:

```console
$ swoosh ping bf01hcq6… --present sheer:bf01hcq6…
```

The gate checks the link offline, against your key. The holder gets that one service and nothing else.

## 3. It expires, or you revoke it

The link stops working at its expiry; `swoosh grant ls` then marks it `expired`. To cut access early,
revoke it on the node that issued it:

<!-- capture: swoosh grant revoke sheer:bf01hcq6… -->
```console
$ swoosh grant revoke sheer:bf01hcq6…
revoked link (…/revoked)
```

Either way the next dial is refused, with no restart:

<!-- capture: swoosh ping sheer:bf01hcq6… (revoked) -->
```console
$ swoosh ping sheer:bf01hcq6…
bf01hcq6balrlxwa via iroh: reached, but refused (not admitted: not a member of this node's family, and no capability for this service)
Error: bf01hcq6balrlxwa: reached, but refused
```

## The honest limit

A bearer link is a bearer token: whoever holds an unexpired, un-revoked one gets that one service until
it expires or you revoke it. Keep bearer links short-lived, or bind them with `--for`. A revoke is
node-local and lands on the next dial, no restart; it does not cut a session already in progress. See
[revocation](keys.md#revocation).

## Next

- [Keys](keys.md#grant) the model: grants, fleets, and the one trade.
- [Contractor access](use-cases/contractor-access.md) the same loop for ssh, bound to a fleet.
- [Commands](reference/commands.md#grant) issue, ls, narrow, and revoke.
