# Changelog

All notable changes to swoosh, newest first.

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
