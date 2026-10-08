# Roadmap

swoosh is one tool for working with a machine addressed by its key. Every verb is the same thing
underneath, a gated byte-stream to a key, with a thin front door per job. Shipped today is ticked; the
rest is planned and lands as it is built.

> Experimental. The CLI, wire protocol, and identity format will change; not ready for production use.

## Shipped

- [x] `serve` be online, publish gated services under a persisted key; `--expires` bounds its own life
- [x] `ping` round-trip time to a peer, `ping(8)`-shaped
- [x] `speed` throughput to a peer, `iperf`-shaped, one direction or `--bidir`
- [x] `status` connection path to a peer: direct vs relayed
- [x] `service` read a peer's served services and their gates
- [x] `contact` a local address book (`add` / `signet` / `ls` / `rm`), petname resolution everywhere
- [x] `status` print this machine's key and what it is, minting a key if absent
- [x] `invite add` / `adopt` enroll a second machine under your signet via a signed invite
- [x] `ssh` open an ssh session to a peer over the overlay
- [x] `forward` forward a machine's service to a local port or stdout
- [x] `send` push a file or directory to a peer
- [x] `proxy` get a local URL that reaches a site through a machine you name
- [x] `sync` bring your device list up to date with your other devices, both ways
- [x] `share` a link to one service, for anyone or bound to a machine or a person's root, and shorter copies of a link
- [x] `revoke` take back a link, one of your devices, or everything you shared with a contact
- [x] `stop` stop a peer's node over the gated `control.stop` service

## Planned

- [ ] **A daemon.** A background node so `service` can read your own node, names resolve without a
  running `serve`, and the grants a node was handed are remembered instead of presented each dial.
- [ ] **A people group.** Name a set of people and grant the whole group one service at once, instead of
  granting each member.
- [ ] `send` more sources: the same verb for piped stdin, the clipboard, or a fetched URL's result.
- [ ] `ssh config`: emit ssh `Host` aliases for devices that advertise ssh.
- [ ] A machine group (`cluster`): name a local set of machines and share the whole group as one capability link.
- [ ] `run`: run code at a peer addressed by its key.
- [ ] Names that resolve: type `ssh desk.alice` into any app.

## Next

- [Getting started](getting-started.md) what works today, in two minutes.
- [Use cases](use-cases/README.md) the shipped verbs in real tasks.
