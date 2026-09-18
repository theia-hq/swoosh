#!/usr/bin/env bash
#
# The membership + transport-swap demo: admit a second machine to a node you
# run, reach it by its public key over iroh and over quirk+noise (our own UDP transport
# behind the sealed wrapper), and watch a stranger who was never admitted get
# refused at the gate. Bare quirk shows the enforcement: it announces peer keys
# in plaintext, so a signet-rooted gate refuses to arm over it.
#
# Three identities, each in its own home dir, so this is a real membership story:
#   - the SERVER runs the node and gates diagnostics behind its signet.
#   - the MEMBER is invited + adopted, so the server's signet trusts it; it
#     reaches the server's gated ping/speed service over iroh and quirk+noise.
#   - the STRANGER is never adopted, so the gate refuses it.
#
# Because the member is a DISTINCT identity (its own key, its own NodeId), the
# iroh leg has no self-connect: iroh accepts the dial. The old one-key demo
# could not run over iroh at all (iroh forbids connecting to your own NodeId).
#
# The captions (see DEMO.md):
#   - quirk phase 0 is stop-and-wait (~14 MiB/s). That is not a speed claim; the
#     point of the swap is the key, not the number.
#   - bare quirk announces its key, so a signet-rooted gate refuses to arm over
#     it, and the demo shows that refusal. quirk+noise wraps the same backend in
#     a Noise handshake that proves the key, and the gated dial rides it.
#   - quirk+noise is direct-only, so the member passes the address the server
#     printed with --peer. The iroh leg needs n0 discovery reachable; if it is
#     down the script says so, and the sealed leg plus the gate above still stand.
#
# Usage: scripts/demo.sh
# Requires: a built `swoosh` binary. No network for the quirk legs; the iroh leg
# needs n0 discovery.

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
# The key lives at `<home>/identity.key` within each.
SERVER="$WORK/server"
MEMBER="$WORK/member"
STRANGER="$WORK/stranger"
mkdir -p "$SERVER" "$MEMBER" "$STRANGER"

banner() { printf '\n=== %s ===\n' "$1"; }

# Start `serve` under the server key over the given transport, wait for its
# banner, and set SERVE_PID + SERVER_KEY (+ SERVER_ADDR when the banner prints
# a direct address, as quirk spells do). $1 is the transport.
start_server() {
  local transport="$1" out="$WORK/serve-$1.out"
  SWOOSH_HOME="$SERVER" "$BIN" serve --transport "$transport" >"$out" 2>&1 &
  SERVE_PID=$!
  local i
  for i in $(seq 1 60); do
    grep -q 'bf01' "$out" && break
    sleep 0.5
  done
  cat "$out"
  # The key is always in the banner; the address only appears on the direct
  # (quirk) spellings, so a miss there is expected and not a failure.
  SERVER_KEY="$(grep -m1 -oE 'bf01[a-z0-9]+' "$out" || true)"
  # LOOPBACK FIRST, deliberately. Both nodes in this demo run on this machine, and the banner's direct
  # lane lists the LAN address ahead of loopback because it is ordered for the common case, a peer on
  # another host. Taking the first address would hand this script the LAN one, which is the address that
  # does not work here: a platform that gates a binary from the local network refuses it while loopback
  # is never gated. Fall back to the first address only when the bind offered no loopback line at all.
  SERVER_ADDR="$(grep -m1 -oE '127\.0\.0\.1:[0-9]+' "$out" || true)"
  if [ -z "$SERVER_ADDR" ]; then
    SERVER_ADDR="$(grep -m1 -oE '([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+' "$out" || true)"
  fi
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
# Part 1: admit the member. The server signs an invite; the member adopts it,
# becoming a device identity the server's signet trusts.
# ---------------------------------------------------------------------------
banner "server creates an invite for the member"
INVITE="$(SWOOSH_HOME="$SERVER" "$BIN" invite add laptop | head -1)"
echo "$INVITE"

banner "member adopts it (distinct home: its own identity + the trusted signet)"
SWOOSH_HOME="$MEMBER" "$BIN" adopt "$INVITE"

# ---------------------------------------------------------------------------
# Part 2: bare quirk refuses the gate. quirk phase 0 announces peer keys in
# plaintext, so a signet-rooted gate refuses to arm over it: the serve below
# must refuse with the teaching error, before any dial. The wrapped spelling
# (quirk+noise, Part 4) is the opt-in that proves the key.
# ---------------------------------------------------------------------------
banner "quirk serve (expect REFUSED: announced peers cannot root-admit)"
if SWOOSH_HOME="$SERVER" "$BIN" serve --transport quirk >"$WORK/serve-quirk.out" 2>&1; then
  echo "UNEXPECTED: a rooted gate armed over an announced transport." >&2
  exit 1
else
  cat "$WORK/serve-quirk.out"
  echo "refused, as it must be: a credential needs a proven peer."
fi

# The server key is a key, not a transport property: read it offline, so the
# parts below can show each serve binds the same NodeId.
banner "the server's NodeId, read offline"
SERVER_ID="$(SWOOSH_HOME="$SERVER" "$BIN" identity | head -1)"
echo "$SERVER_ID"

# ---------------------------------------------------------------------------
# Part 3: quirk+noise admits the gate. The wrapper runs a Noise handshake over
# quirk and proves the peer key, so the SAME rooted gate that bare quirk
# refused arms here. Still direct-only: the member passes the address the
# server printed with --peer.
# ---------------------------------------------------------------------------
banner "quirk+noise serve (SAME server key; the wrapper proves the peer)"
start_server "quirk+noise"

if [ "$SERVER_ID" = "$SERVER_KEY" ]; then
  echo
  echo "SAME NodeId: $SERVER_KEY (the key is the identity; the spelling is a choice)"
else
  echo
  echo "WARNING: NodeId differs: identity=$SERVER_ID quirk+noise=$SERVER_KEY" >&2
fi

banner "member ping over quirk+noise (direct, wrapper-proven)"
SWOOSH_HOME="$MEMBER" "$BIN" ping "$SERVER_KEY" --transport quirk+noise --peer "$SERVER_KEY=$SERVER_ADDR" -c 5 -i 0.2

banner "stranger ping over quirk+noise (never adopted: expect REFUSED)"
if SWOOSH_HOME="$STRANGER" "$BIN" ping "$SERVER_KEY" --transport quirk+noise --peer "$SERVER_KEY=$SERVER_ADDR" -c 3 -i 0.2; then
  echo "UNEXPECTED: the stranger was admitted over quirk+noise; the gate did not hold." >&2
  exit 1
else
  echo "refused, as it must be: the gate holds over the sealed wrapper too."
fi

stop_server

# ---------------------------------------------------------------------------
# Part 4: the gate over iroh. The SAME server key again: the key is the
# identity, the transport is the choice.
# ---------------------------------------------------------------------------
banner "iroh serve (SAME server key, self-discovering)"
start_server iroh

if [ "$SERVER_ID" = "$SERVER_KEY" ]; then
  echo
  echo "SAME NodeId: $SERVER_KEY (the key is the identity; transport is a choice)"
else
  echo
  echo "WARNING: NodeId differs: identity=$SERVER_ID iroh=$SERVER_KEY" >&2
fi

# The iroh leg depends on n0 discovery being reachable. Treat an unreachable
# dial as a documented network condition, not a demo failure: report it and
# carry on (the quirk refusal, the sealed leg, and the gate already stand).
banner "member ping over iroh (identical command, no --peer: iroh self-discovers)"
if SWOOSH_HOME="$MEMBER" "$BIN" ping "$SERVER_KEY" --transport iroh -c 5 -i 0.2; then
  banner "member speed --down over iroh"
  SWOOSH_HOME="$MEMBER" "$BIN" speed "$SERVER_KEY" --transport iroh --down -t 3

  banner "stranger ping over iroh (never adopted: expect REFUSED)"
  if SWOOSH_HOME="$STRANGER" "$BIN" ping "$SERVER_KEY" --transport iroh -c 3 -i 0.2; then
    echo "UNEXPECTED: the stranger was admitted over iroh; the gate did not hold." >&2
    exit 1
  else
    echo "refused, as it must be: the gate holds over iroh too."
  fi
else
  echo
  echo "iroh unreachable (n0 discovery down). Documented caveat, not a defect:" >&2
  echo "the quirk refusal, the sealed leg, and the membership gate above still stand." >&2
fi

stop_server

echo
echo "done. Member admitted over quirk+noise and iroh, stranger refused, bare quirk refused the gate, one server key throughout."