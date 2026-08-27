#!/usr/bin/env bash
#
# The transport-swap demo: reach a peer by its public key, then swap the entire
# transport stack under the identical command for one we wrote ourselves.
#
# It runs `ping` and `speed` over BOTH transports against a `serve` node that
# keeps ONE persisted identity, so the SAME key yields the SAME NodeId over iroh
# and over our own QUIC (quirk). Reach is a seam; this proves it.
#
# Honest captions (see DEMO.md):
#   - quirk phase 0 is stop-and-wait (~16 MiB/s). That is not a speed claim; the
#     point is the swap, not the number.
#   - quirk identity is plaintext-nominal until Noise (phase 1). Not proven crypto.
#
# Usage: scripts/demo.sh
# Requires: a built `swoosh` binary. The iroh half needs network reachability
# (n0 discovery + relays); the quirk half is direct-only over loopback and needs
# no network. If iroh is unreachable, the quirk half still stands on its own.

set -euo pipefail

cd "$(dirname "$0")/.."

BIN="${SWOOSH_BIN:-./target/debug/swoosh}"
if [ ! -x "$BIN" ]; then
  echo "building swoosh..." >&2
  cargo build
fi

WORK="$(mktemp -d)"
trap 'kill "${SERVE_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

# Only the server needs a persisted key: it must stay reachable at one address. The client reaches
# outward, so each verb mints a fresh ephemeral identity with no key file.
SERVER_KEY="$WORK/server.key"

banner() { printf '\n=== %s ===\n' "$1"; }

# ---------------------------------------------------------------------------
# Part 1: quirk. Our own from-scratch QUIC, direct-only over loopback.
# ---------------------------------------------------------------------------
banner "quirk serve (our own QUIC)"
SWOOSH_KEY="$SERVER_KEY" "$BIN" --transport quirk serve >"$WORK/quirk-serve.out" 2>&1 &
SERVE_PID=$!

for _ in $(seq 1 40); do
  grep -q -- '--peer' "$WORK/quirk-serve.out" && break
  sleep 0.25
done
cat "$WORK/quirk-serve.out"

KEY="$(grep -m1 -oE 'bf01[a-z0-9]+' "$WORK/quirk-serve.out" | head -1)"
ADDR="$(grep -m1 -oE '127\.0\.0\.1:[0-9]+' "$WORK/quirk-serve.out" | head -1)"

banner "quirk ping (same command, our transport)"
"$BIN" --transport quirk ping "$KEY" --peer "$KEY=$ADDR" -c 5 -i 0.2

banner "quirk speed --down"
"$BIN" --transport quirk speed "$KEY" --peer "$KEY=$ADDR" --down -t 3

banner "quirk speed --up"
"$BIN" --transport quirk speed "$KEY" --peer "$KEY=$ADDR" --up -t 3

kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Part 2: iroh. The SAME server key file. Self-discovering across the internet.
# The printed NodeId must be byte-for-byte identical to the quirk one above:
# same key, same address, different transport.
# ---------------------------------------------------------------------------
banner "iroh serve (SAME key file, self-discovering)"
SWOOSH_KEY="$SERVER_KEY" "$BIN" --transport iroh serve >"$WORK/iroh-serve.out" 2>&1 &
SERVE_PID=$!

for _ in $(seq 1 60); do
  grep -q 'bf01' "$WORK/iroh-serve.out" && break
  sleep 0.5
done
cat "$WORK/iroh-serve.out"

IKEY="$(grep -m1 -oE 'bf01[a-z0-9]+' "$WORK/iroh-serve.out" | head -1)"
if [ "$KEY" = "$IKEY" ]; then
  echo
  echo "SAME NodeId over both transports: $KEY"
else
  echo
  echo "WARNING: NodeId differs: quirk=$KEY iroh=$IKEY" >&2
fi

banner "iroh ping (identical command, no --peer: iroh self-discovers)"
"$BIN" --transport iroh ping "$KEY" -c 5 -i 0.2

banner "iroh speed --down"
"$BIN" --transport iroh speed "$KEY" --down -t 3

kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
SERVE_PID=""

echo
echo "done. Same command, same key, different transport underneath."
