# CI runner

A CI job needs to reach one of your machines: ship a build artifact to a deploy box, or let you ssh into
the runner itself to poke at a failure. You want the runner to hold a credential you can revoke, not a
long-lived SSH key copied into a secret store forever.

Enroll the runner as a [device](../keys.md#device) of your [signet](../keys.md#signet). It reaches your
machines like any of your own, and you cut it off by revoking that one device.

## Enroll the runner

From your own machine, mint a device authkey for the runner:

<!-- capture: swoosh mint ci-runner -->
```console
$ swoosh mint ci-runner
authkey:jm3cahyz2nbywedca3vzjrjfp65kbnli752in7oa2e4ouakfq5na.bf01hcq6…

recorded me/ci-runner -> bf01imv3ljql6kjn  [derived]
hand this authkey to the machine (a SECRET: adopting it becomes this identity and trusts your signet).
```

Store that authkey as a CI secret named `SWOOSH_AUTHKEY`. On GitHub Actions, use the flagship action: it
installs swoosh, adopts the authkey, and serves the runner's default services (a keyless shell plus
`ping`/`speed` diagnostics), all gated to your signet:

```yaml
# in your CI job
- uses: theia-hq/swoosh-action@v2
  with:
    authkey: ${{ secrets.SWOOSH_AUTHKEY }}
```

After this step, the runner is a device your signet trusts, reachable over the overlay as `me/ci-runner`.

Not on GitHub Actions? Install swoosh directly and adopt by hand:

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/theia-hq/swoosh/main/scripts/install.sh | sh
- run: swoosh adopt          # reads SWOOSH_AUTHKEY from the environment
  env:
    SWOOSH_AUTHKEY: ${{ secrets.SWOOSH_AUTHKEY }}
```

## Ssh into the runner

To reach the runner interactively (poke at a live failure, say), hold the job open with `minutes` so it
stays up after the rest of the job finishes:

```yaml
- uses: theia-hq/swoosh-action@v2
  with:
    authkey: ${{ secrets.SWOOSH_AUTHKEY }}
    minutes: "15"
```

From your own machine:

```console
$ swoosh ssh me/ci-runner
```

The hold ends after 15 minutes, or early if you `touch $RUNNER_TEMP/theia-release` over that ssh session.

## Push an artifact out from the runner

On the deploy box, receive pushed files behind the gate:

```console
$ swoosh serve recv=recv:/srv/releases
```

Omit `minutes` on the runner's step so the job advances straight to the next step instead of holding
open; the node keeps serving in the background until the job ends. Push the artifact to the deploy box by
name, the runner's badge admits it:

<!-- capture: swoosh send app.tar deploybox -->
```console
$ swoosh send app.tar deploybox
sending to bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q...
sent app.tar (204800 bytes)
```

Each file is hashed with BLAKE3 and re-checked on arrival, so a truncated or tampered transfer is
rejected, never written. To ssh into the deploy box instead, serve `ssh=sshd:` there and run `swoosh ssh
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
- [Commands](../reference/commands.md#send) send, ssh, and the mint/adopt handshake.
