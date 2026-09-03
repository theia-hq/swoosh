# Changelog

All notable changes to swoosh, newest first.

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
  existing `revoke <link>` still refuses a single link. Both write a node-local denylist the gate checks
  on the next connect.
- **`swoosh serve --public <svc>`** open named services to anyone, unauthenticated, per service: the
  deliberate opt-out from the signet gate. A service with no safe public form, such as a keyless shell,
  is refused by name.

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
