# Keys: the whole model, on one page

Read this first. Every other page assumes it. It is short on purpose: five nouns, one gate, and one
trade the math forces on you. Once you hold these, the rest of swoosh is just verbs.

## You are your key

swoosh reaches a machine by its **public key**, not its IP address. A key is a short base32 string like
`bf01hcq6…`. You hand someone your key; they reach you, wherever you are, across home routers and NATs,
with no address to look up and no server in the middle.

An IP address changes: you move networks, your router hands out a new lease. A key does not. Reach a
key and you reach the same machine every time, and the link is authenticated end to end by that key, so
you know you reached the machine you meant and no one sits in the middle.

That is the whole promise: **an identity nothing can take from you.** No account, no registrar, no
provider that can revoke your name. The key is yours because you hold the secret behind it.

## Identity: your signet and your devices

Two nouns cover who you are.

### Signet

Your **signet** is your root identity: one key that means "me." It is the key on the machine where you
first ran swoosh. Everything else you own is signed by it. You keep it; you do not hand it out.

### Device

Each machine you own is a **device**, with its own key. Your laptop, your desktop, a server: each is a
separate device with a separate key, all vouched for by your one signet.

You do not copy your signet onto every machine. Instead you enroll each new device from a machine that
already holds your signet:

<!-- capture: swoosh mint laptop -->
```console
$ swoosh mint laptop
authkey:jm3cahyz2nbywedca3vzjrjfp65kbnli752in7oa2e4ouakfq5na.bf01hcq6…

recorded me/laptop -> bf01imv3ljql6kjn  [derived]
hand this authkey to the machine (a SECRET: adopting it becomes this identity and trusts your signet).
```

The new machine adopts that one-time authkey and becomes a device your signet trusts:

<!-- capture: swoosh adopt @authkey.txt -->
```console
$ swoosh adopt @authkey.txt
adopted this machine as bf01imv3ljql6kjn  [mine]
trusting signet bf01hcq6…: `swoosh serve` now admits its members and delegates.
stored your membership badge: this device now reaches your gated services.
```

### Badge

The proof a device gets in adoption is a **badge**: a signature, made by your signet and locked to that
device's key, that says "this machine is mine." A device carrying your badge reaches every gated
service on any node you run, with no per-service step. That is how your laptop, your desktop, and a
server all get in at once.

## The gate

`swoosh serve` puts a **gate** in front of every service it publishes. When a machine dials, the gate
answers one question: *are you allowed?* It phones no server to decide. The answer is a signature it
checks on the spot, against your key.

By default the gate admits your own devices (they carry your badge) and turns everyone else away. A
plain node is its own root of trust: it trusts itself and whom you delegate, and refuses strangers.
Opening a service to the public is a deliberate, named opt-out (see [public services](use-cases/public-service.md)).

The only list the gate ever keeps is a **denylist** a revoke writes. There is no allowlist to maintain:
a valid signature gets in, so a new device you enroll or a new person you grant just works, with nothing
to sync.

A revoke takes effect on the node's next `serve`: the gate reads the denylist at startup, so a revoke made
while a node is running applies when you restart it. Live revocation, cutting a held slip without a
restart, lands with the daemon.

## Sharing access: fleets and slips

Two more nouns cover letting other people in.

### Fleet

A **fleet** is one person's devices: everything their signet vouches for. Grant a fleet and every
machine that person owns, now or later, is covered. To grant someone's fleet you first record their
signet, which they read with `swoosh identity` on their own machine and send you.

### Slip

A **slip** is a grant to one of your services. Its shareable form is a `sheer:` link: a signed token,
rooted at your key, that a gate checks offline with no server and no allowlist to sync. You issue a slip
with `swoosh grant issue`, hand it over any channel (chat, a QR code), and the holder presents it when
they dial.

There are five ways in, tightest first:

1. **Your own devices.** They adopt your signet once (above). Whole-node, standing, nothing per service.
2. **One device, one service:** `swoosh grant issue ssh --for alice/laptop`. A slip locked to one
   machine's key. A stolen copy is useless to anyone else; it cannot be passed on.
3. **A whole person, one service:** `swoosh grant issue ssh --for fleet:alice`. A slip locked to a
   person's signet, so every machine they own can use it. Revoke it once and their whole fleet loses
   access.
4. **Whoever holds the link:** `swoosh grant issue ssh`. A bearer slip: anyone with a copy may use it.
   Short-lived by default; expiry is how it goes away. Add `--delegable` to let the holder narrow it and
   pass it on.
5. **Anyone:** `swoosh serve --public ping,speed`. The named services answer everyone, no credential.

## The one trade

There is one rule the crypto forces, and it is the whole security model in a sentence:

> A slip is **bound** (theft-proof, cannot be passed on) OR **delegable** (can be narrowed and handed
> on, so kept short-lived). Never both.

A slip locked to a device or a fleet is theft-resistant: a stolen copy is worthless because it only
works from the key it is bound to. A bearer slip can be freely handed on, which is exactly why it should
expire soon. You pick binding or delegation per slip; the math will not give you both at once.

**The honest limit.** A bearer slip is a bearer token: whoever holds an unexpired, un-revoked one gets
that one service until it expires or you revoke it. Keep bearer slips short-lived.

## Glossary

| Noun | What it is |
| --- | --- |
| [signet](#signet) | your root identity; one key that means "me" |
| [device](#device) | one machine you own; its own key, vouched for by your signet |
| [badge](#badge) | the signature that proves a device is yours; admits it to your gated services |
| [fleet](#fleet) | one person's devices; everything their signet vouches for |
| [slip](#slip) | a signed grant to one service (`sheer:` link); checked offline, no server |

## Next

- [Getting started](getting-started.md) run your first reach.
- [Use cases](use-cases/README.md) pick the situation that matches yours.
- [Commands](reference/commands.md) every verb and flag.
