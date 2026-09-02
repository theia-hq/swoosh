# Changelog

All notable changes to swoosh, newest first.

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
