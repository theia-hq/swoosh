# CI runner

A CI job needs to reach one of your machines: ship a build artifact to a deploy box, or ssh in to
restart a service. You want the runner to hold a credential you can revoke, not a long-lived SSH key
copied into a secret store forever.

Enroll the runner as a [device](../keys.md#device) of your [signet](../keys.md#signet). It reaches your
machines like any of your own, and you cut it off by revoking that one device.

## Provision the runner

From your own machine, mint a device authkey for the runner:

<!-- capture: swoosh mint ci-runner -->
```console
$ swoosh mint ci-runner
authkey:jm3cahyz2nbywedca3vzjrjfp65kbnli752in7oa2e4ouakfq5na.bf01hcq6…

recorded me/ci-runner -> bf01imv3ljql6kjn  [derived]
hand this authkey to the machine (a SECRET: adopting it becomes this identity and trusts your signet).
```

Store that authkey as a CI secret named `SWOOSH_AUTHKEY`. The runner adopts it at the start of a job.
`adopt` reads the secret from the environment, so it never lands in the process list:

```yaml
# in your CI job
- run: curl -fsSL https://raw.githubusercontent.com/theia-hq/swoosh/main/scripts/install.sh | sh
- run: swoosh adopt          # reads SWOOSH_AUTHKEY from the environment
  env:
    SWOOSH_AUTHKEY: ${{ secrets.SWOOSH_AUTHKEY }}
```

After `adopt`, the runner is a device your signet trusts.

## Reach your machine from the job

On the deploy box, receive pushed files behind the gate:

```console
$ swoosh serve beam=beam: --out /srv/releases
```

In the job, push the artifact to it by name. The runner's badge admits it:

<!-- capture: swoosh beam app.tar deploybox -->
```console
$ swoosh beam app.tar deploybox
beaming to bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q...
sent app.tar (204800 bytes)
```

Each file is hashed with BLAKE3 and re-checked on arrival, so a truncated or tampered transfer is
rejected, never written. To ssh in instead, serve `ssh=sshd:` on the target and run `swoosh ssh
deploybox -- <command>` from the job.

## Cut the runner off

Revoke the runner's device on each machine it reaches, then restart `serve` there so the gate reloads its
denylist and stops admitting the badge:

```console
$ swoosh grant revoke me/ci-runner
```

To rotate instead of revoke, mint a fresh authkey, update the CI secret, and revoke the old device.

## The honest limit

Anyone who can read the `SWOOSH_AUTHKEY` secret can adopt that device identity, so scope the secret to
the job that needs it and rotate it like any credential. A revoke is node-local and applies on the node's
next `serve` (the gate loads the denylist at startup, so restart `serve` to apply it; live revocation lands
with the daemon): revoke on every machine the runner reaches.

## Next

- [Keys](../keys.md#device) what a device and a badge are.
- [Contractor access](contractor-access.md) a timed slip for a person, not a machine.
- [Commands](../reference/commands.md#beam) beam, ssh, and the mint/adopt handshake.
