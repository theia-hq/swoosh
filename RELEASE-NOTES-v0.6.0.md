# swoosh v0.6.0

Push files to a key, stop a remote node, and honest failures.

## New verbs

- **`swoosh beam <path>... <peer>`** push a file or directory to a peer, verified end to end. The
  receiver stays online with `swoosh serve beam=beam:` (files land in the current directory, or `--out
  <dir>`); you push to it. A directory expands to every file under it, files stream over concurrent
  streams, and each is hashed with BLAKE3 and re-checked on arrival, so a truncated or tampered transfer
  is rejected, never written. Gated by your signet: only members (or a `sheer:` cap you hand out with
  `--present`) can push to your node.

- **`swoosh stop <peer>`** tell a peer's node to stop serving, by its key or a `sheer:` link. It dials
  the node's gated `control.stop` service and, once admitted, triggers the same graceful stop a Ctrl-C
  gives. It stops the node, it does not power off the machine. Gated like the diagnostics, so for a
  single-owner node only your own devices can stop it.

- **`swoosh serve --for <duration>`** serve for a bounded time (`30m`, `2h`, `1d`), then stop by itself.
  A local timer: when the deadline passes the node stops gracefully. Pairs with `swoosh stop` to tear a
  bounded session down early.

## Changes

- **Loud failures.** `ping`, `speed`, `status`, and `fetch` now error and exit non-zero when a node
  refuses a service, instead of reporting a healthy line, 100% loss, or 0.00 MiB/s. A refusal is a
  refusal, said plainly.

- **`+lossy` fan-out** (tightbeam): a raw-stream source can fan out to many receivers over unreliable
  datagrams, dropping frames under load rather than blocking. See tightbeam's README.

## Under the hood

- tightbeam's CLI command structs moved into its binary; its library exports only grant logic. swoosh
  now calls that logic directly (`mint_link` / `narrow_link` / `revoke_into`) under its own clap surface.
  No behaviour change: same flags, same wire.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/theia-hq/swoosh/main/scripts/install.sh | sh
```

> Experimental. The CLI, wire protocol, and identity format will change; not ready for production use.
