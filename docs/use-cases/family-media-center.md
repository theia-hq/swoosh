# Family media center

You have a media box the whole household should reach: a shell to manage it, a media UI to watch. It
belongs to no one person. One person sets it up and admits everyone else; nobody's phone becomes "the
owner."

The box is its own node with its own [signet](../keys.md#signet). One person is its **custodian**: they
hold its key and do the admitting. Every family member reaches it by presenting a [slip](../keys.md#slip),
and registers nothing on their end.

## On the box (the custodian runs this)

Publish the box's services behind its own gate:

<!-- capture: swoosh serve ssh=sshd: tv=127.0.0.1:8096 -->
```console
$ swoosh serve ssh=sshd: tv=127.0.0.1:8096
swoosh ready

    bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  LAN        automatic; your devices just need the key (mDNS)

serving
  family-gated   your devices + peers you've granted
    ssh -> sshd            a shell on this machine
    tv -> 127.0.0.1:8096   local TCP service
    control.*              node control (always family-gated)

ctrl-c to stop
```

Then, per family member, record their signet and grant their whole [fleet](../keys.md#fleet) the service
they need. Granting a fleet covers every device that person owns, now or later, so mum's new phone works
with no new grant:

<!-- capture: swoosh grant issue tv --for fleet:mum -->
```console
$ swoosh contact signet mum bf01o6vqymgz727gazsni37uoify447gropuhsuduzd6lbn4q5iscxfq
recorded mum's signet -> bf01o6vqymgz727g

$ swoosh grant issue tv --for fleet:mum
issued a fleet-bound grant for `tv` to fleet signet bf01o6vqymgz727g…
  every device that signet vouches for can use it (theft-resistant); expires in 1h
  revoke: swoosh grant revoke bf01o6vqymgz727g…
sheer:bf01hcq6…
```

The last line is the slip. Hand it to mum over any channel (chat, AirDrop, a QR code). Repeat the two
commands per member. (Mum reads her signet once with `swoosh identity` on her own machine and sends it
to you.)

## On mum's end

She registers nothing: no signet to record, no grant. Her device just presents the slip when it reaches
the box:

```console
$ swoosh forward mediacenter --service tv --to 8096 --present sheer:bf01hcq6…
```

Then she opens `http://127.0.0.1:8096` and watches. Any device her signet vouches for can present that
one slip, so her laptop and her phone both work.

## No allowlist

The box keeps no list of who is allowed. When a device dials, the gate checks the signature on the
presented slip, offline, against the box's own key, and admits on a valid signature. The only list it
keeps is the denylist a revoke writes.

Take mum's household off in one step:

<!-- capture: swoosh grant revoke bf01o6vqymgz727g -->
```console
$ swoosh grant revoke bf01o6vqymgz727gazsni37uoify447gropuhsuduzd6lbn4q5iscxfq
revoked 1 grant(s) to bf01o6vqymgz727g… (…/revoked)
```

## Two honest limits

- **No family group yet.** You grant each member one by one. A named group that holds people (grant it
  once, everyone in it is covered) is [planned](../roadmap.md).
- **Revoke is per household.** Revoking mum's signet drops her whole fleet at once. There is no way yet
  to drop one of her devices while keeping the rest, so keep fleet slips short-lived.

## Next

- [Keys](../keys.md#slip) what a slip and a fleet are.
- [Contractor access](contractor-access.md) the same idea, one person, timed.
- [Commands](../reference/commands.md#grant) issue, list, and revoke slips.
