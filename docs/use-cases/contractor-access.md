# Contractor access

You are bringing in a contractor for a few weeks. They need one service on one machine, say ssh to a
build box, and nothing else. When the engagement ends, access ends. No shared password to rotate, no VPN
account to remember to delete.

Give them a [slip](../keys.md#slip) bound to their [fleet](../keys.md#fleet) with a short life. It is
theft-resistant (only their machines can use it), it covers whatever laptop they work from, and it goes
away on its own.

## Grant one service, timed

Record the contractor's signet (they read it with `swoosh identity` on their machine and send it), then
grant their fleet the one service, with an expiry:

<!-- capture: swoosh grant issue ssh --for fleet:contractor --expires 14d -->
```console
$ swoosh contact signet contractor bf01o6vqymgz727gazsni37uoify447gropuhsuduzd6lbn4q5iscxfq
recorded contractor's signet -> bf01o6vqymgz727g

$ swoosh grant issue ssh --for fleet:contractor --expires 14d
issued a fleet-bound grant for `ssh` to fleet signet bf01o6vqymgz727g…
  every device that signet vouches for can use it (theft-resistant); expires in 14d
  revoke: swoosh grant revoke bf01o6vqymgz727g…
sheer:bf01hcq6…
```

Hand them the `sheer:` slip. On the build box, serve the shell gated:

```console
$ swoosh serve ssh=sshd:
```

## What the contractor does

They present the slip when they ssh in. Any machine their signet vouches for can use it, so their work
laptop and their spare both reach the box, with the same slip:

```console
$ swoosh ssh buildbox --present sheer:bf01hcq6…
```

They reach `ssh` and nothing else. The slip names one service; the gate refuses everything it does not
name.

## Cut them off

The slip expires on its own at the end of the engagement. To cut access early, revoke their fleet:

<!-- capture: swoosh grant revoke bf01o6vqymgz727g -->
```console
$ swoosh grant revoke bf01o6vqymgz727gazsni37uoify447gropuhsuduzd6lbn4q5iscxfq
revoked 1 grant(s) to bf01o6vqymgz727g… (…/revoked)
```

Check what is outstanding any time:

<!-- capture: swoosh grant ls -->
```console
$ swoosh grant ls
ssh
  fleet   bf01o6vqymgz727gazsni37uoify447gropuhsuduzd6lbn4q5iscxfq  13d  fleet-bound
```

## The honest limit

A revoke is node-local and takes effect on the box's next `serve`: the gate loads the denylist at startup,
so a revoke made while the box is serving applies when you restart it (live revocation lands with the
daemon). If you serve the box from more than one node, revoke on each. A fleet slip also stays usable from
any device the contractor still holds until it expires or you revoke it, so keep the expiry short.

## Next

- [Keys](../keys.md#the-one-trade) bound versus delegable, and why.
- [CI runner](ci-runner.md) a machine credential you can revoke, for automation.
- [Commands](../reference/commands.md#grant) issue, narrow, list, and revoke.
