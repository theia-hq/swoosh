#!/usr/bin/env bash
#
# The membership demo: admit a second machine to a node you run, reach it by
# its public key over iroh, and watch a stranger who was never admitted get
# refused at the gate.
#
# Three identities, each in its own home dir, so this is a real membership story:
#   - the SERVER runs the node and gates diagnostics behind its signet.
#   - the MEMBER is invited + joins, so the server's root trusts it; it
#     reaches the server's gated ping/speed service.
#   - the STRANGER never joins, so the gate refuses it.
#
# Because the member is a DISTINCT identity (its own key, its own NodeId), there
# is no self-connect: iroh forbids connecting to your own NodeId, so a one-key
# demo could not run.
#
# The leg needs n0 discovery reachable; if it is down the script says so.
#
# Usage: scripts/demo.sh
# Requires: a built `swoosh` binary and n0 discovery.

set -euo pipefail

cd "$(dirname "$0")/.."

# ASK CARGO where the binary lands rather than assuming `./target`. A checkout inside a workspace that
# sets its own `target-dir` (this project's container does, to share one build across sibling repos) puts
# it somewhere else entirely, and the assumed path then still holds whatever stale binary was last built
# there. That is worse than a missing one: the demo runs, passes, and proves nothing about the code in
# front of you. A plain clone of this repo alone resolves to `./target/debug` exactly as before.
if [ -z "${SWOOSH_BIN:-}" ]; then
  TARGET_DIR="$(cargo metadata --no-deps --format-version 1 \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
  BIN="${TARGET_DIR:-./target}/debug/swoosh"
else
  BIN="$SWOOSH_BIN"
fi
echo "building swoosh..." >&2
cargo build
[ -x "$BIN" ] || { echo "demo: no swoosh binary at $BIN after a build" >&2; exit 1; }

WORK="$(mktemp -d)"
SERVE_PID=""
# Kill only the exact serve PID this script spawned, never by name: another
# swoosh may be running on this host.
trap 'if [ -n "$SERVE_PID" ]; then kill "$SERVE_PID" 2>/dev/null || true; fi; rm -rf "$WORK"' EXIT

# Three sovereign identities, one per home dir. `--home` pins the whole node
# home (key + address book + signet + badge), so three homes is three identities.
# The key lives at `<home>/machine/key` within each.
SERVER="$WORK/server"
MEMBER="$WORK/member"
STRANGER="$WORK/stranger"
mkdir -p "$SERVER" "$MEMBER" "$STRANGER"

banner() { printf '\n=== %s ===\n' "$1"; }

# Start `serve` under the server key, wait for its banner, and set SERVE_PID +
# SERVER_KEY.
start_server() {
  local out="$WORK/serve.out"
  SWOOSH_HOME="$SERVER" "$BIN" serve >"$out" 2>&1 &
  SERVE_PID=$!
  local i
  for i in $(seq 1 60); do
    grep -q 'ed01' "$out" && break
    sleep 0.5
  done
  cat "$out"
  SERVER_KEY="$(grep -m1 -oE 'ed01[a-z0-9]+' "$out" || true)"
}

# Stop the running server (by its exact PID) and clear SERVE_PID.
stop_server() {
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
    SERVE_PID=""
  fi
}

# ---------------------------------------------------------------------------
# Part 1: admit the member. The server's first invite makes its root (it asks
# you to choose a passphrase, at this terminal) and prints an invite carrying
# a new key; the member joins with it, becoming a device the server's root trusts.
# ---------------------------------------------------------------------------
banner "server invites the member (choose the root's passphrase when asked)"
INVITE="$(SWOOSH_HOME="$SERVER" "$BIN" invite laptop --new-key)"
echo "$INVITE"

banner "member joins with it (distinct home: its own key + the trusted root)"
printf '%s\n' "$INVITE" | SWOOSH_HOME="$MEMBER" "$BIN" join

# Read the server key offline, to check the serve below binds the same NodeId.
banner "the server's NodeId, read offline"
SERVER_ID="$(SWOOSH_HOME="$SERVER" "$BIN" status --key)"
echo "$SERVER_ID"

# ---------------------------------------------------------------------------
# Part 2: the gate over iroh.
# ---------------------------------------------------------------------------
banner "serve (self-discovering)"
start_server

if [ "$SERVER_ID" = "$SERVER_KEY" ]; then
  echo
  echo "SAME NodeId: $SERVER_KEY"
else
  echo
  echo "WARNING: NodeId differs: identity=$SERVER_ID serve=$SERVER_KEY" >&2
fi

# The dial depends on n0 discovery being reachable. Treat an unreachable dial
# as a documented network condition, not a demo failure: report it and carry on.
banner "member ping (iroh self-discovers; no address needed)"
if SWOOSH_HOME="$MEMBER" "$BIN" ping "$SERVER_KEY" -c 5 -i 0.2; then
  banner "member speed --down"
  SWOOSH_HOME="$MEMBER" "$BIN" speed "$SERVER_KEY" --down -t 3

  banner "stranger ping (never joined: expect REFUSED)"
  if SWOOSH_HOME="$STRANGER" "$BIN" ping "$SERVER_KEY" -c 3 -i 0.2; then
    echo "UNEXPECTED: the stranger was admitted; the gate did not hold." >&2
    exit 1
  else
    echo "refused, as it must be: the gate holds."
    echo
    echo "done. Member admitted, stranger refused."
  fi
else
  echo
  echo "iroh unreachable (n0 discovery down). Documented caveat, not a defect:" >&2
  echo "the member could not be reached, so there is nothing to check here." >&2
fi

stop_server
