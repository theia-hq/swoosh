# Reach your own devices

You have a laptop, a desktop, and maybe a home server. You want to reach any of them from any of the
others, wherever you are, without a public IP, a VPN, or a port forward. Enroll each machine under your
one identity once; after that they all reach each other by name.

This uses your [signet, devices, and badges](../keys.md#identity-your-signet-and-your-devices). Nothing
here is per-service: a device you enroll gets into everything you run.

## Enroll a second device

Your **signet** lives on the first machine you ran swoosh on. From it, mint a one-time authkey for the
new machine:

<!-- capture: swoosh mint laptop -->
```console
$ swoosh mint laptop
authkey:jm3cahyz2nbywedca3vzjrjfp65kbnli752in7oa2e4ouakfq5na.bf01hcq6…

recorded me/laptop -> bf01imv3ljql6kjn  [derived]
hand this authkey to the machine (a SECRET: adopting it becomes this identity and trusts your signet).
```

The authkey is a secret. Move it to the new machine over something private, save it to a file, and
adopt it there (reading from a file keeps it out of the process list):

<!-- capture: swoosh adopt @authkey.txt -->
```console
$ swoosh adopt @authkey.txt
adopted this machine as bf01imv3ljql6kjn  [mine]
trusting signet bf01hcq6…: `swoosh serve` now admits its members and delegates.
stored your membership badge: this device now reaches your gated services.
```

The laptop is now a device your signet vouches for. Repeat once per machine.

## Reach any of them

On the machine you want to reach, stay online:

<!-- capture: swoosh serve -->
```console
$ swoosh serve
swoosh ready

    bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  LAN        automatic; your devices just need the key (mDNS)

serving
  family-gated   your devices + peers you've granted
    ping        round-trip probe
    speed       throughput test
    control.*   node control (never public)

ctrl-c to stop
```

Save its key under a name once, then reach it by name from any of your devices. Because both machines
carry your badge, the gate admits you with nothing to present:

```console
$ swoosh contact add desk bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
added desk -> bf01hcq6balrlxwa
```

<!-- live-run: real iroh RTT over the internet, non-deterministic; re-capture before release -->
```console
$ swoosh ping desk -c 4
desk via iroh: mixed (direct to 135.129.124.149:56141 and relayed)
  4 sent, 4 received, 0% loss
  rtt min/avg/max/mdev = 41.843/113.534/299.872/93.169 ms
```

## ssh in, keyless setup

If the desktop serves its shell, ssh to it by name over the overlay. It uses your normal ssh keys; there
is no public IP or port to expose:

```console
$ swoosh ssh desk
```

The desktop offers its shell once with `swoosh serve ssh=sshd:` (a keyless shell, gated to your signet)
or points at an existing sshd with `swoosh serve ssh=127.0.0.1:22`.

## The honest limit

A device carrying your badge reaches every gated service on any node you run. If a device is lost or
stolen, revoke it (`swoosh grant revoke me/laptop`) on each node you run, then restart `serve` there. A
revoke is node-local and takes effect on the node's next `serve` (the gate loads the denylist at startup),
not instantly and not everywhere at once; live revocation lands with the daemon.

## Next

- [Keys](../keys.md#device) what a device and a badge are.
- [Family media center](family-media-center.md) a box the whole household reaches, owned by no one.
- [Commands](../reference/commands.md#ssh) ssh, forward, and beam over the overlay.
