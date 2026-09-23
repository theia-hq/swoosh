# Changelog

All notable changes to swoosh, newest first.

## Unreleased

### Changed
- **A received file prints as one plain line, and `--quiet` turns it off.** Each file a receive service
  lands now prints `<service>: received <path> (<bytes> bytes)` on stderr, for example
  `inbox: received notes.txt (1500 bytes)`. The sender chooses the path, so control characters in it and
  letters that print as blank space are shown escaped, and a long path is cut short.

  This replaces the log event v0.12.0 added (`error,transfer=info`). The default log filter is back to
  `error`, and `RUST_LOG` no longer controls these lines.

  If stderr falls behind, swoosh drops lines rather than slowing a transfer down. The file still lands.
  Once stderr catches up, one line says how many were dropped. Lines still waiting when swoosh exits are
  lost.

## v0.12.0

A peer cannot decide how much of your memory to spend, and a size problem stops posing as a forgery.

### Fixed
- **`swoosh service ls --at <peer>` let the node you asked exhaust your own machine.** The reply was
  read with no bound at all, so a hostile node could stream until the client died, at one byte of
  its bandwidth per byte of your memory. This is the server attacking the client, which is the
  direction nobody looks. The serving side had no bound either, so an honest host did not even
  provide an accidental ceiling.

  Both ends now hold one bound, derived from what the decoder already accepts rather than chosen, so
  the reader's cap cannot drift away from the format. The encoder enforces the two field limits
  rather than a byte total, because a menu can sit far under any byte ceiling and still be refused
  by its own decoder, and an encoder that can emit a frame it cannot read is a defect in itself.

- **A full fleet's roster was reported as a forgery.** The read cap sat below the largest roster the
  parser accepts, so a legitimate roster at that size was truncated in transit and then failed its
  signature check. `swoosh fleet <peer>` answered "roster is not signed by your signet; refusing to
  hydrate": a size problem wearing a forgery's clothes, and an operator reading it would go looking
  for an attack that never happened.

  The cap is now derived from the same limits the parser enforces, including the signature envelope
  the first estimate of this missed, and a test pins the largest admissible roster to exactly that
  size so a framing change cannot quietly loosen it. A node that streams past the cap is now named
  as the thing that overran, in a sentence that tells you to check which node you meant.

### Changed
- Advances to bifrost v0.4.0, nauthy v0.4.0, tightbeam v0.11.0 and services v0.3.0, which between
  them close two remote CPU-exhaustion classes in capability verification, cap a framed read a peer
  could size to four gigabytes, and teach three wires to say which version they speak instead of
  closing the stream without a word.

## v0.11.4

A refusal this build cannot read is not an answer about you.

### Changed
- **Advances to bifrost v0.3.0, tightbeam v0.9.0 and services v0.2.0**, where the refusal type
  stopped being a closed set. Nothing on the wire moved, and nothing you run behaves differently
  today.

  One place had to decide something new. When an exit node refuses a fetch, swoosh turns that
  refusal into an HTTP status, and the split is between a ruling about YOU and a failure of
  THEIRS: not admitted serves `403`, and the node's own failures serve `502`, so a downloader can
  tell "you are not allowed through this node" from "the node or origin is having a bad day"
  without reading a log. A refusal from a newer node, of a class this build has no name for,
  carries no ruling this build can read. It serves `502`, because `502` claims nothing about the
  caller, and says so in the log rather than guessing: `403` would invent an authorization answer
  out of a message that carried none.

  You will only ever see that line if this binary is older than the node it dialed.

## v0.11.3

Ten changes, no new capability. The thing gets more honest, not bigger.

### Fixed
- **`forward` refused a member of your own fleet.** It dialed as a stranger while `ping`, `speed`,
  `ssh` and `fetch` presented the member badge, on the same runner, to the same peer, through the
  same gate. It was never adjudicated: it was transcribed out of a badge wildcard while the verb in
  the same arm was fixed. The fix is not the flip. The credential now rides the declaration that
  already answers whether a verb dials, so a serving verb holding a dial credential and a dialing
  verb holding none are both unrepresentable, and there is no spelling of "not applicable" left for
  the next verb to inherit.
- **`--service` defaulted to a name nothing could serve,** in three call sites, through four
  releases. Zero-config `forward` against zero-config `serve` had never once worked.
- **A device learned its fleet exactly once, ever.** The roster's version and the puller's
  anti-rollback floor were ONE field, and it advanced only on pulling, which a signet holder never
  does. So every cut was stamped epoch 0 and every pull after the first was silently refused as a
  same-epoch replay. Restarting did not help. They are two types now, version 0 is unrepresentable,
  and the cutter cannot read the floor.
- **An explicit `--home` decided WHETHER a key existed, not just where it lived,** so an outward
  dial created the signet its own doc promised never to create.
- **A failed dial from an unprovisioned home minted your fleet root.** The `swoosh ssh` bridge
  declared a persisting identity while every sibling did not, and a dial to a peer that was never
  there wrote the key a later `serve` would gate everything on.
- **`adopt` could silently destroy your signet.** The key write had no guard while the two siblings
  in the same transaction were both flag-gated. It refuses now, and `--force` deliberately does not
  reach it: what that flag waves through is re-issuable, and this key has no issuer and no second
  copy.

### Added
- **Every address the banner hands over says how far it reaches:** the internet, this network, this
  tunnel, this machine. One line per class, preferring v4. The widest mark used to PREDICT where
  the others CLASSIFY, and a firewall falsified it.
- **A badge says when it dies.** An expired one refuses locally instead of collecting the uniform
  refusal that names nothing, a warning lands 30 days out, and `swoosh identity` states the badge's
  life. Renewal stopped needing the flag that also disables the re-root guard, so re-running
  `invite add` is the whole of it.
- **A refused dial says what the peer would have to serve.** It cannot become an oracle: the
  function that writes the sentence takes no error, no session and no response, so the wire is not
  in scope and cannot be read even by accident.
- **`docs/signet-backup.md`.** No doc anywhere mentioned backing up a key. The gap was silence
  about loss, not a broken promise.

### Changed
- **`forward` is `reach <peer> <service>`,** both positional, stdout by default. A service earns a
  top-level verb only when its client is a program rather than a pipe, and this one's body was
  open-the-stream-and-copy. `echo hello | swoosh reach <key> echo` now works with no flags.
- **`fleet <peer>`.** A flag that is never optional is a positional in costume.
- **The hidden `tunnel-connect` leaf is gone.** `swoosh ssh` proxies through the public `reach`, so
  the exact line that carries an ssh session is one you can run by hand to debug a launch.
- **Pins:** bifrost v0.2.3, nauthy v0.3.1, tightbeam v0.8.2, services v0.1.8.

## v0.11.2

The lane hands a peer an address that works, and says how far it goes.

### Fixed
- **The `direct` lane reads the BIND's dialable set, not the mDNS announcement.** The announcement
  reports how far an ANNOUNCEMENT reached, which is a different fact from how far an ADDRESS goes: on
  a network that blocks multicast the report is empty while the host's addresses are exactly as
  dialable as ever, and the lane offered loopback alone.
- **A temporary IPv6 address is no longer offered** (bifrost v0.2.3). It was deprecated within about
  a day, so a peer's copy rotted; it was also the one address privacy addressing exists to keep
  unpublished, and it was being multicast onto every network this node joined.
- **A failed interface read no longer reads as "this host is loopback-only".** The lane says the list
  is short and why.
- **`swoosh status` reports the first dialable address** rather than loopback.

### Changed
- **One line per reach class, preferring v4.** Eight rows on an ordinary two-interface laptop offered
  at most four decisions, and the banner's job is a glance. No flag and no `+k more`: machinery for a
  case nobody has.
- **Every row states who can route to it:** `the internet`, `this network`, `this tunnel`,
  `this machine`. A bare line reads as a default and there is no default, because this host cannot
  know where the operator's peer is. The widest mark was `anywhere`, which PREDICTED where the other
  three CLASSIFY: this lane renders only for a bind with no relay and no NAT traversal, so a global
  v6 behind a default-deny inbound firewall is the common case and the promise was falsifiable by a
  firewall.
- **The gloss says why a short list is short,** in one clause, loudest first. When addresses were
  dropped but every class still has a row it says nothing: a count of hidden expiring addresses is a
  fact nobody acts on.
- **The tunnel mark names no link.** One row renders per class, so the name could no longer tell two
  overlays apart; it was redundant where it informed and empty where it did not. The banner now holds
  no externally sourced string, so the over-budget fallback, the runtime width check and the
  control-character guard are gone and the 80-column bound is arithmetic rather than a measurement.
- **Pins:** bifrost v0.2.3, tightbeam v0.8.1, services v0.1.7.

## v0.11.1

A direct-only bind hands over an address again, and a fan-out reports every device.

### Fixed
- **`ping` no longer abandons the rest of your devices for one broken peer.** A device that answered the
  dial and then broke mid-exchange ended the whole run with its error, so every device after it went
  untried and you learned nothing about them, while `swoosh status` reported all of them. It is a line
  now, beside the refused and unreachable lines it already had: it says the node was reached, names what
  broke rather than a round-trip time, and the run continues to the next device with a verdict that is
  not green.
- **A direct-only bind hands over an address again.** `serve --transport quirk+noise` printed no `direct`
  lane at all, so the banner gave the operator nothing to pass to a peer, on a transport that has no relay
  and no NAT traversal and where an address is the whole of its reach. The lane was not merely empty: a
  wildcard bind's dial hint is rewritten to loopback and the lane filtered loopback out, and swoosh binds
  wildcard always, so it could never render. It now lists every address the bind is dialable at, the ones
  that reach this host from another machine first and loopback last, marked as reaching only this machine.
  A direct-only `local` lane drops its own address list, so one banner carries one list.
- **The demo script runs the binary you just built.** It looked for one under this repo's own `target`
  directory, which is the wrong place whenever the build writes somewhere else, and the stale binary
  sitting there ran instead. The demo passed and proved nothing. It asks cargo where the binary lands now,
  always builds first, and refuses to run if one is missing. It also hands the second node the loopback
  address rather than the first address in the banner, because both nodes run on one machine.

## v0.11.0

Every service target carries a scheme, so a near-miss is a refusal rather than a different service.

### Changed
- **Every service target carries a scheme: a TCP forward is now `tcp:<host>:<port>`.** The bare
  `host:port` form is gone, not deprecated: `swoosh serve web=127.0.0.1:8080` becomes
  `swoosh serve web=tcp:127.0.0.1:8080`. It was the one target without a scheme, so a hostname followed by
  a colon and a number was indistinguishable from a scheme carrying an argument, and an entry that missed
  an engine's exact spelling silently became a forward to a host of that name. Now `ping=ping:80` is a
  parse error saying `ping:` takes no argument, a scheme nothing serves is refused by name, and the
  readiness banner tells a forward from an engine by its scheme rather than by sniffing for a port.
  `unix:<path>` is unchanged.
- **`swoosh serve --help` lists every target it accepts.** Both halves: the four engines swoosh serves
  (`ping:`, `speed:`, `roster:`, `sshd:`) and the six forms it forwards or streams. A refused target points
  there, because the tunnel grammar refuses by naming the forms it routes and cannot name the engines
  layered on top of it, so a mistyped `png:` used to be handed a legal set with no `ping:` in it.
- **The sibling pins follow tightbeam v0.7.0 and services v0.1.4,** which is where this grammar lives.

## v0.10.0

Reach a relay and a resolver you run yourself, and a banner that tells the truth about how peers find you.

### New
- **`--relay` and `--resolver` (reach family).** Point a node at a relay and a resolver you run
  (`iroh-relay` and `iroh-dns-server`). `serve` remembers each under the node home, so every later command
  under that home reaches the same two servers. Name one without the other; what you do not name stays
  n0's.

### Changed
- **A relayed path can turn direct, and the docs now say so.** No behaviour change: a session that starts
  through a relay upgrades to a direct path the moment a hole punch lands, so `swoosh status` can read
  `relayed` on one run and `direct` on the next. That read as a fault to a first-time reader.
- **The readiness banner discloses the address records it publishes.** A default internet bind now prints
  `records  n0's public discovery: your addresses, for anyone with your key`. It used to print that line
  only when you named your own relay or resolver, so the banner disclosed the mDNS announcement on your
  LAN and stayed quiet about the larger one. A node naming its own resolver reads the same consequence.
- **The sibling pins move forward together.** bifrost, nauthy, tightbeam, and the service engines (fetch,
  measure, sshh, transfer) are each pinned to a newer revision, so a build of this version records exactly
  the revision set the address fix below is built on.

### Fixed
- **`swoosh status` no longer prints a healthy line for a peer that answered nothing.** A node that took
  the dial and then broke mid-exchange rendered its path and the transport's own round-trip estimate, and
  held a fan-out's exit code green. A probe that fails and a probe that goes unanswered are each their own
  line now, both saying the node was reached, neither reporting a time, and neither counting as healthy.
  The unanswered case is the common one: the engine folds a broken exchange into loss and returns an empty
  report rather than an error.
- **The published checksum verifies with the command people actually type.** Each release asset's
  `.sha256` file now carries the standard two-field line (the hash, then the file it names), so
  `shasum -a 256 -c swoosh-<target>.sha256` works on a downloaded asset. It previously held a bare hash,
  which that command rejects; the installer had been rebuilding the line itself, so nothing here caught it.
- **`--at` says what it does.** Its help line gave only the value grammar, so the bare form of `stop` and
  `service ls` read as an omission rather than the default. The short line now names the flag's job and the
  long line keeps the grammar and states the bare form.
- **The readiness banner reports the addresses this node was actually announced at.** A node bound to every
  interface advertised the loopback rewrite of that bind, so a peer that heard it was sent back to its own
  machine, and the banner printed `reachable on this machine only` over an address it could not back.
  Discovery now takes the sockets the transport really bound: a bind to every interface is announced at this
  host's own addresses, a bind to `127.0.0.1` is announced exactly as bound, and the banner's `local` line
  names the outcome it observed, whether that is the addresses it announced at, this host alone, or finding
  peers while announcing nothing, with the cause. An address no peer could dial is no longer printed at all.
- **A corrupt stored membership badge fails closed.** A `<home>/badge` that is not a usable `sheer:` link now refuses every family dial and a plain `adopt` with the fix named (`swoosh adopt --force <invite>`, or move the file aside), instead of being carried to the peer and refused there.

## v0.9.1

`--home` keeps its ssh pins to itself, the installer names each reason a provenance check was skipped, a
dialing command no longer overwrites the serving node's address record, and the credential noun is `invite`
everywhere.

### Changed
- **BREAKING: the credential noun is `invite` everywhere.** `SWOOSH_INVITE` replaces `SWOOSH_AUTHKEY`, the
  action input is `invite`, and a pre-rename `authkey:` token is refused with a teaching error; no compat
  alias ships.

### Fixed
- **A dialing command no longer overwrites the node's address record.** Only `serve` publishes; every other
  reaching verb resolves without writing, so a short-lived process cannot send dialers to a dead relay path.
- **`ssh`'s host-key pins follow the selected home.** `--home <dir>` (or `SWOOSH_HOME`) now keeps
  `known_hosts` beside that home's identity, so an isolated run no longer appends to the default book,
  and a run with `HOME` unset works.
- **The installer names the cause when it skips provenance verification.** `gh not found`,
  `gh not authenticated`, and `verification failed` are distinct lines, each saying the checksum still
  holds, so a skipped check reads as a cause, not a mystery.

## v0.9.0

Invite replaces mint, a node is a home, quirk gets Noise, and revocation lands live.

### New
- **`--transport quirk+noise`.** quirk behind a Noise handshake that proves the peer's key and encrypts
  the session: the same direct-only backend, with the key proven before any byte flows. It is the only
  quirk spelling that serves gated traffic, and the only one that carries a credential.
- **`--local` (reach family).** No internet discovery or relays: dials and advertisements resolve over
  local mDNS or a `--peer` hint only. A no-op on `quirk`/`quirk+noise`, which are already direct-only.
- **`service enable <svc>` / `disable <svc>`.** Turn a served service off or on live, no restart: the change
  is written to `<home>/disabled` and the running node honors it on the next connection, the same
  mtime-watched, fail-closed mechanism as revocation.
- **`invite add --expires <duration>`.** Choose a device badge's lifetime (default 90 days, previously a hardcoded
  year); a controlled reused-secret case can opt into `--expires 365d`.
- **`adopt` verifies the badge, and `--force` re-roots.** Adoption checks the badge binds this machine's key
  and is unexpired before storing it; a differing badge, or an invite naming a different signet, is refused
  unless you pass `--force`.
- **`serve --resident`, and the bare control verbs.** A resident `serve` holds the home's lock and serves
  the local control socket, so a bare `stop`, `service ls`, or `status` acts on your own running node.

### Changed
- **BREAKING: bare `--transport quirk` refuses every serve and every credential-bearing dial.** quirk
  never proves the peer holds the key it presents; the key travels in plaintext, so `swoosh serve` refuses
  over it and a credential is never written to it. Use `--transport quirk+noise` for gated or
  credential-bearing quirk traffic; bare `quirk` stays the base `quirk+noise` builds on, and `iroh` stays
  the default.
- **BREAKING: `swoosh beam` is now `swoosh send`.** The file-push verb was renamed for clarity; the `beam`
  crate and internals are unchanged, and there is no back-compat alias.
- **BREAKING: the file-receive scheme `beam:` is now `recv:`, and its output dir rides the scheme.**
  `swoosh serve inbox=recv:<dir>` sets where arrivals land (a bare `recv:` writes to `.`); the node-wide
  `--out` flag is gone, since the output dir is a per-service fact. `send --service` defaults to `recv`.
- **BREAKING: `mint` is now `invite add`, and `authkey:` is now `invite:`.** One create verb: `invite add
  <label>` derives a device identity (the old `mint`), and `invite add <label> --for <key>` signs a
  membership badge for a key the device made (no secret in the token). `invite ls` and `invite rm <label>`
  list and cancel by the same ledger; legacy `authkey:` tokens still adopt, the old `--to` is `--for`, and
  a stale `mint` invocation errors forward.
- **`send` and `fetch` take `--service <name>`** to reach a receiver or exit published under a non-default
  name, matching `ssh` and `forward`.
- **BREAKING: `--key <file>` is now `--home <dir>` (env `SWOOSH_HOME`).** A node is selected by its home
  directory; the key lives at `<home>/identity.key` (the GNUPGHOME model). `--key` errors forward.
- **BREAKING: every `serve` entry must be `name=target`.** A bare entry no longer takes the `default` name;
  it is refused at startup with a message naming the form (`membership` and `cluster` are reserved, never
  service names).
- **BREAKING: `stop` and `service` reshaped for local-vs-peer.** A peer is now `--at <peer>`; a bare `stop`
  or `service ls` acts on your own node over its control socket, which needs a resident `serve`
  (`serve --resident`); `service` is a group: `ls` / `enable` / `disable`.
- **`control.stop` and `control.services` are member-only.** A delegated `sheer:` slip reaches the gate but
  is refused at the route, so only your own devices can stop or inspect a node.
- **Revocation lands live.** A revoke reaches a running node's next connection: the gate re-reads the
  denylist when the file changes (`(mtime, len)` stamp, fail-closed), not only when `serve` starts.
- **Diagnostic metering is exposure-coupled.** A family-gated `ping`/`speed` route binds the owner engine
  (no run interval, no transfer slot, no byte or wall-clock cap: a member speed run can saturate the
  link), while `--public ping`/`--public speed` binds the metered engine (ping: one run per caller per
  second, a 60-second/1 GiB stream cap; speed: one transfer at a time, a 64 MiB/15-second stream cap).
  The uncapped engine cannot be opened at all, so a public diagnostic is always capped by construction.
- **The serve engines now come from `theia-hq/services`.** The in-repo `fetch`, `measure`, `sshh`, and
  `transfer` copies are gone; the node consumes the services repo at a pinned rev. The `sshd` route keeps
  the same host key and ceilings, and the public diagnostics now carry their caps in shipped builds.
- **BREAKING: one spelling per act; the five convenience aliases no longer resolve.** `swoosh id`,
  `service list`, `grant list`, `contact list`, and `contact remove` are parse errors now; the canonical
  forms are `identity`, `service ls`, `grant ls`, `contact ls`, and `contact rm`.
- **BREAKING: `swoosh ssh` now requires `--` before ssh flags.** Everything after the separator goes
  to ssh verbatim; before it, every flag is swoosh's own. `swoosh ssh desk -p 2222` is now a parse
  error, and `swoosh ssh desk -- -p 2222` works.

### Fixed
- **`stop` no longer reports a false failure while landing.** A teardown race in the v0.8.0 client could
  print an error after the node had already stopped; a peer that vanishes mid-stop now reads as a
  completed stop, a live peer keeps the loud error, and a gate refusal is never probed away.
- **A hostile filename cannot forge a send line.** Every path `send` prints or wraps is escaped and capped,
  so a peer-supplied name cannot fake a skip or an error line.
- **The serve banner tells the truth about local discovery.** A blocked mDNS advertise now says so on the
  reach line instead of a hardcoded `automatic`.
- **A corrupt key file is an error, never replaced.** A present identity that does not decode is no longer
  overwritten by a freshly minted key, and the key file is written atomically (temp, fsync, rename).
- **Store files were world-readable.** The signet, membership badge, contacts book, and revocation denylist
  landed `0644` in a `0755` store dir; they are now written `0600` inside a `0700` store dir, so the trust
  graph and revocation metadata are not exposed to other local users.
- **Minted device badges are now revocable.** `invite add` records the badge in the grant ledger, so
  `swoosh invite rm <label>` cuts a lost or leaked device (it previously found no record and bailed).
  The default badge lifetime also dropped from 365 to 90 days.
- **Each `recv:<dir>` receives into its own dir.** Two receive services on one node no longer both write to
  the first-named directory.
- **A received file prints again, on stderr.** The `recv:` engine emits a structured info event (`path`,
  `bytes`) when a pushed file lands, and the default filter surfaces it (`error,transfer=info`), so
  `swoosh serve` no longer goes silent on a successful receive. The event rides stderr, so stdout keeps
  carrying only the verb's own output, and the peer-supplied path is escaped and capped before it reaches
  the line. `RUST_LOG=error` silences the event. The final activity shape is not settled yet.
- **A stale `SWOOSH_KEY` env errors forward** instead of silently selecting the default identity.

## v0.8.0

Try it in one line with echo, open raw streams only when you say so, clean shutdown on every verb.

### New
- **`echo:` service.** `swoosh serve demo=echo:` serves a symmetric reflector that sends back whatever a
  peer sends. It is safe to open to anyone with a plain `--public` (no `--public-unsafe`), so it is the
  easiest first thing to try across two machines. The serve banner names it plainly.
- **`swoosh serve --public-unsafe <names>`.** Open a named raw stream (`file:`, `fifo:`, `stdin:`) to
  strangers. `--public` alone opens handlers, forwards, and `echo:`; a raw byte source hands out bytes with
  no responder to gate them, so it stays gated unless you additionally name it here. Requires `--public`,
  and a keyless shell is still refused outright.

### Changed
- **Rooted on nauthy 0.1.0.** The authentication core is now the first standalone nauthy release, with its
  generic capability vocabulary and rooted gate. swoosh keeps its own signet and fleet vocabulary on top;
  no command changes.
- **Every reaching verb closes the node before exiting.** `ping`, `speed`, `beam`, `forward`, and the rest
  now tear the connection down cleanly instead of printing `Aborting ungracefully`, so the peer sees a
  clean close rather than a dropped connection it has to time out.
- **`swoosh service --at <your-own-node>` teaches instead of failing.** Reading your own node's services is
  not wired yet (it lands with the daemon); asking for it now says so plainly.

### Fixed
- **Serving a `file:` source to a Linux peer works.** A regular file cannot register with epoll on Linux,
  so `file:` sources failed to start there while working on macOS; fixed in the pinned tightbeam.

### Internal
- **Release robustness (Track C).** A lock-source guard and pre-commit hook keep the committed lock in
  shipping-form, cargo-deny checks dependency sources in CI, and the release build asserts the exact rev
  pins (decision (A)) and fills the GitHub release notes from this CHANGELOG. No behaviour change.

## v0.7.0

Grant one service to a device, a whole person, or anyone; a clearer serve banner.

### New
- **`swoosh grant issue <svc> --for <who>`** bind a slip to a device or a whole fleet, with the kind in a
  typed prefix: `--for <person>/<device>` or a raw key binds ONE device (standing access, locked to one
  machine's key, inert if stolen, non-delegable); `--for fleet:<person>` or `--for fleet:<signet-key>`
  binds a whole fleet (every device that person's signet vouches for, now or later, revocable at once). A
  bare `--for <person>` is refused: you type `fleet:` to widen, so a device bind never silently becomes a
  fleet bind. `fleet:<person>` binds that person's signet recorded with `swoosh contact signet`.
- **`swoosh contact signet <petname> <key>`** record a person's signet root under their petname, so
  `grant issue --for fleet:<petname>` binds their fleet by name instead of a pasted key.
- **`swoosh grant ls`** list the grants you have issued, grouped by service, each with its holder and
  remaining lifetime.
- **`swoosh grant revoke <peer>`** refuse every grant you issued to a device or person at once; the
  existing `revoke <link>` still refuses a single link. Both write a node-local denylist the gate loads
  when `serve` starts, so a revoke takes effect on the node's next `serve`, not on a running one (live
  revocation lands with the daemon).
- **`swoosh serve --public <svc>`** open named services to anyone, unauthenticated, per service: the
  deliberate opt-out from the signet gate. A service with no safe public form, such as a keyless shell,
  is refused by name.
- **`swoosh service --at <peer>`** read the services a peer serves and the gate on each, a `SERVICE  GATE`
  table; you see only what that peer's gate admits you for. Reading your OWN node's services is coming with
  the daemon.
- **`swoosh serve <name>=fetch:<origin>`** pin a fetch service to one origin: the node fetches only that
  origin and refuses any other before it connects. A bare `fetch:` is unconstrained, but opening one to the
  public (`--public`) now requires a scope, so an open fetch service can never be an anonymous any-origin
  relay. Origin URLs carrying userinfo are rejected.
- **`swoosh id`** a short alias for `swoosh identity`: print this node's key, minting one if there is none.

### Changed
- **`signet` is now a reserved device label.** A contact device literally labelled `signet` (added as
  `alice/signet` before this release) is now read as that person's signet root, not a device. Pre-release
  this is near-zero incidence; if you have one, re-add it under a different label.
- **`swoosh serve --for <duration>` is now `--expires <duration>`.** `--for` is reserved for naming WHO a
  grant binds (`grant issue --for`), so serve's bounded-time timer moved to `--expires`, matching
  `grant issue --expires`. Same local timer; `--for` no longer sets a duration.
- **Reformatted `swoosh serve` banner.** The node id stands alone, copy-clean; a `how peers reach you`
  section names each channel (internet, LAN, direct); services are grouped by who can reach them, safest
  first, with one escalating danger marker so an open service always reads louder than a gated one.
- **`swoosh adopt` no longer takes the authkey on argv.** The authkey is a device secret, and the command
  line is visible to other processes (`ps`, `/proc`). Pass it as `-` (stdin), `@<path>` (a file), or set
  `SWOOSH_AUTHKEY`; a literal still works but is discouraged.
- **Clearer `--present` help.** The `sheer:` link flag on the reach verbs (`ping`, `speed`, `status`,
  `beam`, `forward`, `service`, `stop`) now reads plainly: your own devices need no link, the dial
  presents your membership badge; pass a `sheer:` slip only to reach as a delegate.
- **`control.*` reads `never public` in the serve banner.** The always-gated node-control line is glossed
  `never public` (it can never be opened with `--public`, unlike the other gated services), instead of
  `always family-gated`.
- **A refused fan-out no longer reads as unreachable.** When `ping` or `status` reaches a peer but the gate
  refuses the probe, the error says `reached, but refused` and stops there. Over quirk it no longer also
  prints the `pass --peer` addressing hint, which applies only when the peer was never reached at all.
- **Reach verbs take petnames uniformly.** `stop` and the other reach verbs now resolve a petname
  (`alice`, `me/laptop`) the same way `ping` did, instead of taking only a raw key.
- **`swoosh serve` exits 0 on a graceful `control.stop`.** A requested stop is a success, so a stopped node
  no longer exits non-zero.

## v0.6.0

Push files to a key, stop a remote node, and honest failures.

### New
- **`swoosh beam <path>... <peer>`** push a file or directory to a peer, verified end to end. The
  receiver runs `swoosh serve beam=beam:` (files land in the cwd, or `--out <dir>`). A directory expands
  to every file, streamed concurrently and BLAKE3-checked on arrival, so a truncated or tampered transfer
  is rejected, never written. Gated by your signet: only members (or a `sheer:` cap you hand out with
  `--present`) can push.
- **`swoosh stop <peer>`** tell a peer's node to stop serving, by its key or a `sheer:` link. Same
  graceful stop as Ctrl-C, via the gated `control.stop` service; stops the node, not the machine. Gated
  like diagnostics, so a single-owner node stops only for its own devices.
- **`swoosh serve --for <duration>`** serve for a bounded time (`30m`, `2h`, `1d`), then stop by itself.
  A local timer; pairs with `swoosh stop` to tear a session down early.

### Changed
- **Loud failures.** `ping`, `speed`, `status`, and `fetch` now error and exit non-zero when a node
  refuses a service, instead of faking a healthy line, 100% loss, or 0.00 MiB/s.
- **`+lossy` fan-out** (tightbeam): a raw-stream source fans out to many receivers over unreliable
  datagrams, dropping frames under load rather than blocking. See tightbeam's README.
- **Library-contained CLI.** tightbeam's command structs moved into its binary; swoosh calls its grant
  logic (`mint_link` / `narrow_link` / `revoke_into`) directly. No behaviour change: same flags, same wire.
