# Services: what a node can serve

A service is a named target your node publishes: `name=target`. `swoosh serve` puts every service behind
one [gate](../keys.md#the-gate). A peer the gate admits gets a byte stream to the target it named: the
name is what a dialer asks for, the target is what the bytes come from. A <a id="names"></a>name is an
address, not an authority. Two names can point at the same target (`a=sshd: b=sshd:`); each carries its
own grant, toggle, and posture, and neither is a second service nor a second authority.

This page is the catalog: every target you can put after `name=`, what it does, and how it is gated.

## Available today

Bare `swoosh serve` publishes `ping=ping: speed=speed:`, gated. Every entry after the verb must be
`name=target`; a bare `ping` or `ping:` is refused with a message naming that form. Every target carries a
scheme, including a TCP forward (`tcp:<host>:<port>`), so a scheme nothing serves is refused by name and a
scheme that takes no argument refuses a tail: `ping=ping:80` is an error, not a forward to a host called
`ping`. [`swoosh serve`](commands/serve.md) has the flags.

### `ping:`

Round-trip time probe. A peer runs `swoosh ping <peer>` against it.

- Posture: family-gated. `--public ping` opens it; the open route binds the metered engine (one ping run
  per caller per second, a 60-second/1 GiB per-stream cap). A family-gated route binds the owner engine
  instead, uncapped.
- Example: `swoosh serve ping=ping:`
- Limits: [measure](https://github.com/theia-hq/services/blob/main/crates/measure/README.md).

### `speed:`

Throughput test. A peer runs `swoosh speed <peer>` against it.

- Posture: family-gated. `--public speed` opens it; the open route binds the metered engine (one transfer
  at a time, a 64 MiB per-direction and 15-second per-stream cap). A family-gated route binds the owner
  engine instead, uncapped.
- Example: `swoosh serve speed=speed:`
- Limits: [measure](https://github.com/theia-hq/services/blob/main/crates/measure/README.md).

### `sshd:`

A keyless shell on this machine, run as the serving process's user. Serve it under the conventional name
`ssh`, the name `swoosh ssh` requests by default.

- Posture: family-gated, and no public form: `--public ssh` is refused by name at startup.
- Example: `swoosh serve ssh=sshd:`
- To front an existing sshd instead, use a forward: `swoosh serve ssh=tcp:127.0.0.1:22` keeps SSH's own
  auth.
- Limits: [sshh](https://github.com/theia-hq/services/blob/main/crates/sshh/README.md).

### `recv:<dir>`

Receive pushed files into a directory, each verified end to end.

- Posture: family-gated, no public form.
- Example: `swoosh serve inbox=recv:/srv/releases`; `inbox=recv:` saves into `.`.
- Limits: [transfer](https://github.com/theia-hq/services/blob/main/crates/transfer/README.md).

### `fetch:<origin>`

The node performs an HTTP `GET`/`HEAD` for the caller and streams the origin response back.

- Posture: family-gated. `--public news` is allowed only when the fetch is origin-scoped; an
  unconstrained public fetch is refused at startup as an open relay. A bare `fetch:` (any public origin)
  is fine gated.
- Example: `swoosh serve news=fetch:https://news.example`
- Limits: [fetch](https://github.com/theia-hq/services/blob/main/crates/fetch/README.md).

### `tcp:<host>:<port>` and `unix:<path>`

Front an existing local socket; tightbeam connects it and splices bytes, so the service keeps its own
protocol and auth. The two are siblings, a TCP socket and a Unix socket, and a forward carries bytes either
way.

- Posture: family-gated. `--public web` is allowed: you stood the socket up, and opening it hands that
  socket to anyone.
- Example: `swoosh serve web=tcp:127.0.0.1:8080` or `swoosh serve db=unix:/run/db.sock`
- Limits: [tightbeam](https://github.com/theia-hq/tightbeam#what-a-forward-carries).

### The raw streams: `file:`, `fifo:`, `stdin:`

Serve bytes out of a path or this process's stdin. A `stdin:` or `fifo:` source serves one consumer by
default; append `+lossy` to fan out to many, dropping bytes for a consumer that falls behind (a live
feed, never exact bytes).

- Posture: no auth of its own, so `--public` refuses it and points at `--public-unsafe`, which names the
  resolved absolute path (or the piped stdin) in the readiness banner.
- Example: `swoosh serve logs=file:/var/log/app.log`, then `--public-unsafe logs` to open it.
- `+lossy` is refused on any other scheme, `file:` included.
- Limits: [tightbeam](https://github.com/theia-hq/tightbeam#what-a-forward-carries).

### `echo:`

tightbeam's loopback reflector: it returns the caller's own bytes and opens no host resource.

- Posture: family-gated. `--public demo` is allowed: nothing local is exposed. Metered by construction:
  it can only reflect the bytes the caller sent.
- Example: `swoosh serve demo=echo:`
- Limits: [tightbeam](https://github.com/theia-hq/tightbeam).

### `roster`

The signed membership snapshot of your fleet. Every `swoosh serve` serves it, whatever else you name; it
is not a target an entry can name. Another of your devices reads it with `swoosh fleet <peer>`.

- Posture: member-only, like `control.*`: a `swoosh:` grant naming it is refused at the route. Unmetered:
  the handler sets no cap, and no public form can ever open it.
- Limits: [fleet](commands/fleet.md).

### `control.stop` and `control.services`

Node control: `control.stop` ends the node, `control.services` lists what it serves. Both are always
served, whatever else you name.

- Posture: member-only, stricter than gated. A stranger is refused at the gate, and a `swoosh:` grant
  naming one is refused at the route, so only your own devices can stop or inspect a node.
- Client: `swoosh stop --at <peer>` and `swoosh service ls --at <peer>`.
- Limits: [stop](commands/stop.md) and [service](commands/service.md).

## Posture

Family-gated is the default: your own devices and peers you granted a capability.

- `--public <name>` opens a named service with a safe public form: `ping`, `speed`, an origin-scoped
  fetch, a forward, `echo`. `sshd:` is refused by name, and `control.*` is refused as member-only.
- `--public-unsafe <name>` is the separate, louder opt-in for a raw source (`file:`, `fifo:`, `stdin:`).
  `--public` refuses those and points here; a handler or forward named here is pointed back at
  `--public`.
- Each flag must name a service you serve; an unknown name fails at startup, before the node serves.

## Adding your own

swoosh serves the handlers it compiles in; there is no plugin loader. A new service is code in a program
that uses tightbeam:

- a tightbeam `Handler`: a name mapped to code that consumes one admitted stream. See
  [inject a named service](https://github.com/theia-hq/tightbeam#inject-a-named-service).
- one of the [services](https://github.com/theia-hq/services) engines: `measure`, `fetch`, `sshh`, and
  `transfer`, each with its own README.

## Limits

Every service row links the doc that owns its sharp edges. The engine limits live in the
[services repo](https://github.com/theia-hq/services); the raw-stream and forward rules live in the
[tightbeam README](https://github.com/theia-hq/tightbeam#what-a-forward-carries). On the command side:
[serve](commands/serve.md) for the flags, and [send](commands/send.md), [fetch](commands/fetch.md),
[ssh](commands/ssh.md), [reach](commands/reach.md), [service](commands/service.md),
[stop](commands/stop.md), and [fleet](commands/fleet.md) for the client verbs. The gate itself is
[Keys](../keys.md#the-gate). An open `ping` or `speed` is metered by the engine, per
[Public service](../use-cases/public-service.md#the-limit).

## Not built

The redemption doors (`redeem:`/`grant:`) are not built; this page documents only what `serve` can do
today. What is planned lives in the [roadmap](../roadmap.md).

## Next

- [`swoosh serve`](commands/serve.md) publish services behind the gate.
- [Keys](../keys.md#the-gate) how the gate decides who gets in.
- [Public service](../use-cases/public-service.md) open a named service to anyone, deliberately.
