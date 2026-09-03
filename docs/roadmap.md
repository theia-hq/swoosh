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
- [x] `identity` print this machine's key, minting one if absent, to provision a node ahead of time
- [x] `mint` / `adopt` enroll a second machine under your signet via a one-time authkey
- [x] `ssh` open an ssh session to a peer over the overlay
- [x] `forward` put a peer's served service on a local port, stdout, or a unix socket
- [x] `beam` push a file or directory to a peer, verified end to end
- [x] `fetch` mint a local URL whose fetch egresses at a node you name
- [x] `fleet` pull a signed fleet roster and fold it into your contacts
- [x] `grant issue` / `ls` / `narrow` / `revoke` `sheer:` slips, bearer or bound to a device or fleet
- [x] `stop` stop a peer's node over the gated `control.stop` service

## Planned

- [ ] **A daemon.** A background node so `service` can read your own node, names resolve without a
  running `serve`, and slips a node was handed are remembered instead of presented each dial.
- [ ] **A people group.** Name a set of people and grant the whole group one service at once, instead of
  granting each member.
- [ ] `beam` more sources: the same verb for piped stdin, the clipboard, or a fetched URL's result.
- [ ] `ssh config`: emit ssh `Host` aliases for devices that advertise ssh.
- [ ] A machine group (`cluster`): name a local set of machines and share the whole group as one slip.
- [ ] `run`: run code at a peer addressed by its key.
- [ ] MagicDNS names: type `ssh desk.alice` into any app and have it resolve.

## Next

- [Getting started](getting-started.md) what works today, in two minutes.
- [Use cases](use-cases/README.md) the shipped verbs in real tasks.
