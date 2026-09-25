# Contractor access

You are bringing in a contractor for a few weeks. They need one service on one machine, say ssh to a
build box, and nothing else. When the engagement ends, access ends. No shared password to rotate, no VPN
account to remember to delete.

Give them a [grant](../keys.md#grant) bound to their [fleet](../keys.md#fleet) with a short life. It is
theft-resistant (only their machines can use it), it covers whatever laptop they work from, and it goes
away on its own.

## Grant one service, timed

Record the contractor's signet (they read it with `swoosh status --key` on their machine and send it), then
grant their fleet the one service, with an expiry:

<!-- capture: swoosh grant issue ssh --for fleet:contractor --expires 14d -->
```console
$ swoosh contact signet contractor ed01o6vqymgz727gazsni37uoify447gropuhsuduzd6lbn4q5iscxfq
recorded contractor's signet -> ed01o6vqymgz727g

$ swoosh grant issue ssh --for fleet:contractor --expires 14d
issued a fleet-bound grant for `ssh` to fleet signet ed01o6vqymgz727g…
  every device that signet vouches for can use it (theft-resistant); expires in 14d
  revoke: swoosh grant revoke ed01o6vqymgz727g…
swoosh:ed01hcq6…
```

Hand them the `swoosh:` link. On the build box, serve the shell gated:

<!-- manual: long-running serve -->
```console
$ swoosh serve ssh=sshd:
```

## What the contractor does

They present the link when they ssh in. Any machine their signet vouches for can use it, so their work
laptop and their spare both reach the box, with the same link:

<!-- manual: interactive ssh -->
```console
$ swoosh ssh buildbox --present swoosh:ed01hcq6…
```

They reach `ssh` and nothing else. The link names one service; the gate refuses everything it does not
name.

## What you have issued

<!-- live-run: this machine's key and the link's id and end differ per run -->
```console
$ swoosh status
key: ed01slc6uxmtglqlm77rtvyq6mkcwkd5nhumkipcpkgoemdmxchhoa6a
lock: none
root: none yet.
  to join yours: swoosh join
  to make one here: swoosh invite <name> <key>

contacts:
  alice  root:ed01o6vqymgz  root
links you shared:
  a4a0e014  ssh  ed01o6vqymgz  until 2026-10-08
serving: nothing (swoosh serve is not running)
```

## Cut them off

The link expires on its own at the end of the engagement. To cut access early, revoke their fleet:

<!-- capture: swoosh grant revoke ed01o6vqymgz727g -->
```console
$ swoosh grant revoke ed01o6vqymgz727gazsni37uoify447gropuhsuduzd6lbn4q5iscxfq
revoked 1 grant(s) to ed01o6vqymgz727g… (…/revoked)
```

## The limit

A revoke is node-local and lands live: it takes effect on the box's next dial, typically within a couple
of seconds, no restart. It does not cut a session already in progress. If you serve the box from more
than one node, revoke on each. A fleet-bound grant also stays usable from any device the contractor still
holds until it expires or you revoke it, so keep the expiry short. See
[revocation](../keys.md#revocation).

## Next

- [Keys](../keys.md#the-one-trade) bound versus delegable, and why.
- [CI runner](ci-runner.md) a machine credential you can revoke, for automation.
- [Commands](../reference/commands.md#grant) issue, narrow, list, and revoke.
