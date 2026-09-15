# Reach your own devices

You have a laptop, a desktop, and maybe a home server. You want to reach any of them from any of the
others, wherever you are, without a public IP, a VPN, or a port forward. Enroll each machine under your
one identity once; after that they all reach each other by name.

This uses your [signet, devices, and membership](../keys.md#identity-your-signet-and-your-devices). Nothing
here is per-service: a device you enroll gets into everything you run.

## Enroll a second device

Your **signet** lives on the first machine you ran swoosh on. From it, create an invite for the new
machine:

<!-- capture: swoosh invite add laptop -->
```console
$ swoosh invite add laptop
invite:….bf01hcq6…

recorded me/laptop -> bf01imv3ljql6kjn  [derived]
hand this invite to the machine (a SECRET: adopting it becomes this identity and trusts your signet).
```

A derived invite is a secret. Move it to the new machine over something private and save the whole printed
line to a file, the `invite:` prefix included. The file must be `0600` (`chmod 600 invite.txt`), or
`adopt` refuses it. Reading from a file keeps the secret out of the process list:

<!-- capture: swoosh adopt @invite.txt -->
```console
$ swoosh adopt @invite.txt
adopted this machine as bf01imv3ljql6kjn  [mine]
trusting signet bf01hcq6…: `swoosh serve` now admits its members and delegates.
stored your membership badge: this device now reaches your gated services.
```

The laptop is now a device your signet vouches for. Repeat once per machine. To keep the secret from
travelling at all, make the key ON the new machine first (`swoosh identity` prints it) and sign for that
key with `swoosh invite add laptop --for <key>` instead.

## Reach any of them

On the machine you want to reach, stay online:

<!-- pending live-run: banner wording -->
```console
$ swoosh serve
```

Save its key under a name once, then reach it by name from any of your devices. Because both machines
carry your membership, the gate admits you with nothing to present:

<!-- capture: swoosh contact add desk bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q -->
```console
$ swoosh contact add desk bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
added desk -> bf01hcq6balrlxwa
```

<!-- live-run: real iroh RTT over the internet, non-deterministic; re-capture before release -->
```console
$ swoosh ping desk -c 4
desk/default via iroh: mixed (direct to 135.129.124.149:56141 and relayed)
  4 sent, 4 received, 0% loss
  rtt min/avg/max/mdev = 41.843/113.534/299.872/93.169 ms
```

Reach output names the contact and the device (`desk/default`); a key saved without a device name is
filed as `default`.

## ssh in, keyless setup

If the desktop serves its shell, ssh to it by name over the overlay. It uses your normal ssh keys; there
is no public IP or port to expose:

<!-- manual: interactive ssh -->
```console
$ swoosh ssh desk
```

The desktop offers its shell once with `swoosh serve ssh=sshd:` (a keyless shell, gated to your signet)
or points at an existing sshd with `swoosh serve ssh=127.0.0.1:22`.

## The honest limit

A device carrying your membership reaches every gated service on any node you run. If a device is lost or
stolen, revoke it (`swoosh grant revoke me/laptop`) on each node you run. A revoke is node-local and
lands live: it takes effect on the next dial, typically within a couple of seconds, no restart. It does
not cut a session already in progress; the held connection drains. See
[revocation](../keys.md#revocation).

## Next

- [Keys](../keys.md#device) what a device and membership are.
- [Family media center](family-media-center.md) a box the whole household reaches, owned by no one.
- [Commands](../reference/commands.md#ssh) ssh, forward, and send over the overlay.
