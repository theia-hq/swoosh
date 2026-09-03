# Remote IT for a relative

You are the family tech support. A relative has a computer you want to fix remotely, without walking
them through anything, without a paid remote-desktop account, and without their machine needing a public
IP. Set it up once, in person or on one guided call, then reach it whenever it breaks. After setup they
never run a command again.

The trick: enroll their machine as a [device](../keys.md#device) of *your* [signet](../keys.md#signet),
so it trusts you and you can reach its shell any time.

## Set it up once (on their machine)

From your own machine, mint a device authkey:

<!-- capture: swoosh mint grandma-pc -->
```console
$ swoosh mint grandma-pc
authkey:jm3cahyz2nbywedca3vzjrjfp65kbnli752in7oa2e4ouakfq5na.bf01hcq6…

recorded me/grandma-pc -> bf01imv3ljql6kjn  [derived]
hand this authkey to the machine (a SECRET: adopting it becomes this identity and trusts your signet).
```

On their machine (during your visit, or one screen-share), install swoosh, adopt that authkey, and
start a gated shell that comes back on reboot:

<!-- capture: swoosh adopt @authkey.txt -->
```console
$ swoosh adopt @authkey.txt
adopted this machine as bf01imv3ljql6kjn  [mine]
trusting signet bf01hcq6…: `swoosh serve` now admits its members and delegates.
stored your membership badge: this device now reaches your gated services.
```

<!-- capture: swoosh serve ssh=sshd: -->
```console
$ swoosh serve ssh=sshd:
swoosh ready

    bf01imv3ljql6kjnkw2cunbihhceq4ktg4yrcm7bygshuj6u27cciviq

how peers reach you
  internet   automatic; peers reach you by the key above, even across NATs
  LAN        automatic; your devices just need the key (mDNS)

serving
  family-gated   your devices + peers you've granted
    ssh -> sshd   a shell on this machine
    control.*     node control (never public)

ctrl-c to stop
```

Set that `swoosh serve ssh=sshd:` to run at login (a launchd or systemd unit, or a startup item), so the
machine is reachable whenever it is on. That is the last thing they ever have to touch.

## Fix it from home, any time

Their machine is now `me/grandma-pc` in your contacts. ssh straight in over the overlay, using your own
ssh keys, no public IP:

```console
$ swoosh ssh me/grandma-pc
```

Run a one-off command without a full session:

```console
$ swoosh ssh me/grandma-pc -- sudo apt upgrade -y
```

The gate admits you because your machine carries the badge that signet trusts. Nobody else gets in.

## The honest limit

Their machine trusts your signet fully: adoption makes it one of your devices, so you can reach every
gated service on it. That is the point here, but it means you should only do this on a machine you are
meant to administer. If you stop being their IT, revoke the device on their machine to sever it.

## Next

- [Keys](../keys.md#the-gate) how the gate decides who gets in.
- [Reach your own devices](reach-your-own-devices.md) the same enrollment, for your own machines.
- [Commands](../reference/commands.md#ssh) ssh over the overlay, and one-off commands.
