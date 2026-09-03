# swoosh

swoosh reaches a machine by its public key instead of its IP address: ping it, measure the link, ssh
in, send files, forward ports, fetch through it, and share access. You give it a peer's key (a short
base32 string) and it dials that peer directly, wherever the peer is, across home routers and NATs. No
address to look up, no account, no server in the middle.

A key does not change when a machine moves networks, and the connection is authenticated end to end by
that key, so you reach the machine you meant and no one sits in the middle.

> Experimental. The CLI, wire protocol, and identity format will change; not ready for production use.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/theia-hq/swoosh/main/scripts/install.sh | sh
```

Downloads the right binary for your platform, verifies its checksum (and, with the GitHub CLI, its
build-provenance attestation), and installs it to `~/.local/bin`. Prefer to do it yourself? Grab a
binary from the [releases page](https://github.com/theia-hq/swoosh/releases); each carries a checksum
and a keyless signature.

## First reach

On the machine you want to reach, stay online and note the key it prints:

```sh
swoosh serve
```

From another machine, reach it by that key:

```sh
swoosh ping bf01hcq6…      # round trip, by key, across NATs
swoosh contact add desk bf01hcq6…   # name it once
swoosh ping desk           # then reach it by name
```

The [getting-started guide](docs/getting-started.md) walks this end to end in two minutes.

## Docs

- [Getting started](docs/getting-started.md) zero to your first reach.
- [Keys](docs/keys.md) the whole model: five nouns, one gate, one trade. Read it early.
- [Use cases](docs/use-cases/README.md) reach your own devices, admit a household, grant a contractor,
  and more.
- [Commands](docs/reference/commands.md) every verb and flag.
- [Transports](docs/transports.md) · [Troubleshooting](docs/troubleshooting.md) ·
  [Demo](docs/demo.md) · [Roadmap](docs/roadmap.md)

## Layout

- `crates/beam` the `beam:` service: receive a pushed file over one admitted stream, verified end to
  end.
- `crates/fetch` the `fetch:` service: fetch an origin URL on the requester's behalf, scoped to one
  origin.
- `crates/measure` the measurement engine (ping, speed): a small versioned protocol and its clients.
- `crates/swoosh` the CLI: binds one node under the chosen key and transport, then runs a command.

## License

MIT OR Apache-2.0.
