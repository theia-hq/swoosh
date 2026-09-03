# Commands

Every verb, with a real example and the one thing to know about it. This is a lookup, not a read: if you
are going top to bottom, you probably want a [use case](../use-cases/README.md) instead.

The `Usage` line under each command is generated from the parser, so it cannot drift from `--help`. Run
`swoosh <command> --help` for the full text of any flag.

## Common options

These apply to most commands and are omitted from the per-command signatures below:

- `--key <path>` (or `SWOOSH_KEY`) use a specific identity key file. This pins the whole identity: the
  key, its contacts, the signet it trusts, and its badge all live beside it, so one `--key` moves the
  whole identity.
- `--transport <iroh|quirk>` which backend to bind. `iroh` (default) reaches peers across the internet;
  `quirk` is direct-only for diagnostics. See [transports](../transports.md).
- `--peer <key=addr>` a direct address hint, for when discovery cannot reach a peer (mainly quirk). See
  [transports](../transports.md#quirk).
- `--present <link>` present a `sheer:` slip when reaching a gated peer you are not a member of.

---

## <a id="serve"></a>`swoosh serve`

Be a node: publish named services behind your signet gate. Bare, it answers reach diagnostics.

<!-- generated: usage from `swoosh serve -h`; option lines curated -->
```
Usage: swoosh serve [OPTIONS] [name=svc]...
  [name=svc]...          publish a service, e.g. ssh=sshd:, tv=127.0.0.1:8096 (bare = ping + speed)
  --public <svc>         open named services to anyone, unauthenticated (comma-list, repeatable)
  --out <dir>            where a beam: service saves pushed files [default: .]
  --expires <duration>   serve for a bounded time, then stop (30m, 2h, 1d)
  --quiet                suppress the readiness banner (for unattended/CI use)
```

**Example.** `swoosh serve ssh=sshd: tv=127.0.0.1:8096` publishes a shell and a local TCP service, both
gated to your signet.

**Things to know.** A service form is `name=target`: `ping:` / `speed:` (built-in diagnostics),
`sshd:` (a keyless shell), `beam:` (receive files), `fetch:` (fetch URLs for callers), or `host:port`
(front any local TCP service). `control.stop` and `control.services` are always served and always gated.

## <a id="stop"></a>`swoosh stop`

Stop a peer's node (stop it serving), by its key or a `sheer:` link.

<!-- generated: usage from `swoosh stop -h`; option lines curated -->
```
Usage: swoosh stop [OPTIONS] <peer>
  <peer>   a petname, a raw node id, or a sheer: link
```

**Example.** `swoosh stop me/box` gracefully stops a node you started with `serve --expires`, early.

**Things to know.** This stops the node serving; it does not power off the machine. `control.stop` is
gated, so for a single-owner node only your own devices can stop it.

## <a id="service"></a>`swoosh service`

Read a peer's served services: a `SERVICE  GATE` table of what it offers.

<!-- generated: usage from `swoosh service -h`; option lines curated -->
```
Usage: swoosh service [OPTIONS]
  --at <peer>   the peer to read: a petname, a raw node id, or a sheer: link
```

**Example.**
```console
$ swoosh service --at desk
SERVICE           GATE
control.services  gated
control.stop      gated
ping              gated
speed             gated
```

**Things to know.** Omitting `--at` reports that reading your *own* node needs the daemon (not built
yet).

## <a id="ping"></a>`swoosh ping`

Measure the round-trip time to a peer, like `ping(8)` but addressed by key.

<!-- generated: usage from `swoosh ping -h`; option lines curated -->
```
Usage: swoosh ping [OPTIONS] <peer>
  <peer>            a petname, a raw node id, or a sheer: link
  -c, --count <N>   how many probes to send [default: 4]
  -i, --interval <seconds>   seconds between probes [default: 1]
  -v, --verbose     print a line per probe as it lands, showing the path
```

**Example.** `swoosh ping desk -v -c 4` prints a line per probe. Over iroh a session often starts
relayed and hole-punches to direct mid-run, so the probe that lands direct reads `(upgraded from
relayed)`.

**Things to know.** If the peer refuses the service or never admitted you, `ping` says so and exits
non-zero, rather than reporting a healthy line or 100% loss.

## <a id="speed"></a>`swoosh speed`

Measure throughput to a peer, like `iperf` but addressed by key.

<!-- generated: usage from `swoosh speed -h`; option lines curated -->
```
Usage: swoosh speed [OPTIONS] <peer>
  <peer>          a petname, a raw node id, or a sheer: link
  --up / --down   which direction to measure (default: down)
  --bidir         measure both at once, full-duplex on one stream
  -t, --secs <seconds>   run for a fixed time (default: 5)
  -n, --bytes <N>        transfer a fixed number of bytes instead
```

**Example.** `swoosh speed desk --bidir -t 5` measures upload and download at once.

**Things to know.** `--bidir` works over quirk too. Numbers over iroh depend on the live path (direct
vs relayed) and are not comparable to a local quirk run.

## <a id="status"></a>`swoosh status`

Show the connection path to a peer: direct or relayed, the remote address, and a live RTT.

<!-- generated: usage from `swoosh status -h`; option lines curated -->
```
Usage: swoosh status [OPTIONS] <peer>
  <peer>   a petname, a raw node id, or a sheer: link
```

**Example.** `swoosh status desk` answers the one question a p2p link always raises: am I talking to
the peer directly, or bouncing through a relay?

**Things to know.** `mixed` means some paths are direct and some relayed while a session settles.

## <a id="fetch"></a>`swoosh fetch`

Mint a local URL that fetches an origin through a node you name.

<!-- generated: usage from `swoosh fetch -h`; option lines curated -->
```
Usage: swoosh fetch [OPTIONS] --via <peer> <url>
  <url>          the origin URL to fetch
  --via <peer>   the node to fetch through
  --port <port>  pin the local listener port (default: an OS-assigned free port)
```

**Example.** `swoosh fetch https://example.com/big.iso --via usa` prints a `http://127.0.0.1:PORT/`;
whatever pulls from that (curl, a browser) is served by `usa`'s machine fetching the origin and
streaming it back, `Range` intact so a resumable download resumes.

**Things to know.** The exit is a node *you* run (serve `fetch=fetch:` on it). It is scoped to the one
origin you name, not an open proxy.

## <a id="forward"></a>`swoosh forward`

Put a peer's served service on a local port, stdout, or a unix socket (the `ssh -L` shape, keyed).

<!-- generated: usage from `swoosh forward -h`; option lines curated -->
```
Usage: swoosh forward [OPTIONS] --to <port | - | unix:PATH> <peer>
  <peer>              a petname, a raw node id, or a sheer: link
  --to <port|-|unix:PATH>   where to put the stream: a local port, - for stdout, or unix:<path>
  --service <name>    which served service to reach [default: default]
```

**Example.** `swoosh forward desk --service tv --to 8096` puts the peer's `tv` service on
`127.0.0.1:8096`, so a local client talks to it as if it were local.

**Things to know.** `--to -` streams to stdout, to compose with the shell (`--to - | mpv -`).

## <a id="beam"></a>`swoosh beam`

Push a file or directory to a peer, verified end to end.

<!-- generated: usage from `swoosh beam -h`; option lines curated -->
```
Usage: swoosh beam [OPTIONS] <path>... <peer>
  <path>...   the files or directories to push
  <peer>      a petname, a raw node id, or a sheer: link
```

**Example.**
```console
$ swoosh beam app.tar deploybox
beaming to bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q...
sent app.tar (204800 bytes)
```

**Things to know.** The receiver stays online with `swoosh serve beam=beam:` (saving into the current
directory, or `--out <dir>`). Each file is hashed with BLAKE3 and re-checked on arrival, so a truncated
or tampered transfer is rejected, never written.

## <a id="fleet"></a>`swoosh fleet`

Learn your fleet: pull the signed roster from a coordination node and fold it into your contacts.

<!-- generated: usage from `swoosh fleet -h`; option lines curated -->
```
Usage: swoosh fleet [OPTIONS] --pull <peer>
  --pull <peer>   pull the roster from this coordination node (a member serving roster:)
```

**Example.** `swoosh fleet --pull me/hub` verifies the roster against your signet and records each
member as a `me/<device>` contact.

**Things to know.** The roster is verified against your signet before anything is folded in, so a node
cannot inject a contact you did not vouch for.

## <a id="contact"></a>`swoosh contact`

Manage local petnames: name your peers so you never paste a key. Names are yours alone, stored in plain
TOML beside the identity they belong to. `alice` means whoever you pointed it at, no registry.

<!-- generated: usage from `swoosh contact -h`; option lines curated -->
```
Usage: swoosh contact <add | signet | ls | rm>
  add <name> <key>       save (or re-point) a name: alice, or alice/laptop for a device
  signet <petname> <key> record a person's signet root, so --for fleet:<petname> binds their fleet
  ls [petname]           list contacts, or one contact's devices (-q for names only)
  rm <name>              forget a contact or one of its devices
```

**Example.**
```console
$ swoosh contact add desk bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
added desk -> bf01hcq6balrlxwa
```

**Things to know.** One person can have several machines: `contact add alice/laptop <key>` files a key
under `alice`. `swoosh ping alice` then tries each of alice's machines and takes the first that answers.
`contact signet` is different: it records a person's *signet* (not a device key), which is what
`--for fleet:<petname>` needs.

## <a id="identity"></a>`swoosh identity`

Print this machine's key (its NodeId), minting one if there is none.

<!-- generated: usage from `swoosh identity -h`; option lines curated -->
```
Usage: swoosh identity [OPTIONS]
```

**Example.**
```console
$ swoosh identity
bf01hcq6balrlxwadoj6w5kuws7teeydqwewgekucw2duevh72yu6k2q
key: ~/.config/swoosh/identity.key
```

**Things to know.** On an adopted device this prints that *device's* key, not your signet. A fleet grant
needs the person's signet, read on their signet-holding machine. Use `identity` to provision a key ahead
of time: mint it here, save its NodeId as a contact, then hand the key file to the machine that adopts
it.

## <a id="mint"></a>`swoosh mint`

Derive a device identity from your signet and emit a one-time authkey for a machine to adopt.

<!-- generated: usage from `swoosh mint -h`; option lines curated -->
```
Usage: swoosh mint [OPTIONS] <label>
  <label>   the device label, e.g. ci-runner or desk (recorded as me/<label>)
```

**Example.** `swoosh mint laptop` prints an authkey and records `me/laptop`. Run it on the machine that
holds your signet.

**Things to know.** The authkey is a device secret. Hand it to the new machine over something private;
`adopt` reads it without putting it on the command line.

## <a id="adopt"></a>`swoosh adopt`

Adopt a minted authkey: become that device identity and trust the signet that minted it.

<!-- generated: usage from `swoosh adopt -h`; option lines curated -->
```
Usage: swoosh adopt [OPTIONS] [authkey]
  [authkey]   the authkey (a device secret; - stdin, @<path> file, or SWOOSH_AUTHKEY)
```

**Example.** `swoosh adopt @authkey.txt` reads the secret from a file. `swoosh adopt` alone reads
`SWOOSH_AUTHKEY` from the environment.

**Things to know.** Passing the authkey as a bare argument warns you, because `ps` and `/proc` can read
argv. Prefer `-` (stdin), `@<path>` (a file), or the env var.

## <a id="ssh"></a>`swoosh ssh`

Reach a peer's sshd over the overlay; runs the system ssh.

<!-- generated: usage from `swoosh ssh -h`; option lines curated -->
```
Usage: swoosh ssh [OPTIONS] <peer> [ssh args]...
  <peer>          a petname, a raw node id, or a sheer: link
  [ssh args]...   forwarded verbatim to ssh, after --
  --service <name>   the exposed service name to reach [default: ssh]
```

**Example.** `swoosh ssh desk -- ls` runs a one-off command; `swoosh ssh desk -p 2222` passes ssh flags
through.

**Things to know.** Auth is your normal ssh keys. The peer serves its shell with `swoosh serve
ssh=sshd:` (a keyless shell it stands up) or points at an existing sshd with `serve ssh=127.0.0.1:22`.

## <a id="grant"></a>`swoosh grant`

Issue, list, narrow, or revoke `sheer:` slips: signed grants to one of your services, checked offline
with no server and no allowlist. See [keys](../keys.md#slip) for when to reach for each.

<!-- generated: usage from `swoosh grant -h`; option lines curated -->
```
Usage: swoosh grant <issue | ls | narrow | revoke>
  issue <service>   mint a slip for one service
    --expires <duration>   how long the slip is valid [default: 1h]
    --for <who>            bind to a device (person/device or a key) or a fleet (fleet:<person>)
    --delegable           let the holder narrow and re-share it (bearer only, not with a bind)
  ls                list the grants you have issued, grouped by service
  narrow <link>     narrow a slip offline before handing it on (only ever tightens)
    --service <name>       restrict to this service
    --expires <duration>   shorten the life
  revoke <peer|link>   refuse a slip, or every grant to a device or person, on this node
```

**Example.**
```console
$ swoosh grant issue ssh --for fleet:alice
issued a fleet-bound grant for `ssh` to fleet signet bf01o6vqymgz727g…
  every device that signet vouches for can use it (theft-resistant); expires in 1h
  revoke: swoosh grant revoke bf01o6vqymgz727g…
sheer:bf01hcq6…
```

**Things to know.** A bare person (`--for alice`) is refused: you must type `fleet:alice` to widen, so a
device bind never silently becomes a fleet bind. A bind is theft-resistant and cannot be delegated; a
bearer slip can be delegated but is meant to be short-lived (the [one trade](../keys.md#the-one-trade)).
A revoke is node-local: revoke on each node you run.

## <a id="tree"></a>`swoosh tree`

Print the command tree with each verb's one-line summary, read straight from the parser.

<!-- generated: usage from `swoosh tree -h`; option lines curated -->
```
Usage: swoosh tree [OPTIONS]
```

**Things to know.** It reads from the same parser `--help` does, so it can never drift from the real
command surface.

## Next

- [Use cases](../use-cases/README.md) these verbs in real tasks.
- [Keys](../keys.md) the model the gated commands assume.
- [Troubleshooting](../troubleshooting.md) when a command refuses or cannot reach.
