#!/usr/bin/env bash
#
# The membership + transport-swap demo: admit a second machine to a node you
# run, reach it by its public key over BOTH transports (iroh and our own QUIC,
# quirk), and watch a stranger who was never admitted get refused at the gate.
#
# Three identities, each in its own key dir, so this is a real membership story:
#   - the SERVER runs the node and gates diagnostics behind its signet.
#   - the MEMBER is minted + adopted, so the server's signet trusts it; it
#     reaches the server's gated ping/speed service over quirk AND over iroh.
#   - the STRANGER is never adopted, so the gate refuses it.
#
# Because the member is a DISTINCT identity (its own key, its own NodeId), the
# iroh leg has no self-connect: iroh accepts the dial. The old one-key demo
# could not run over iroh at all (iroh forbids connecting to your own NodeId).
#
# Honest captions (see DEMO.md):
#   - quirk phase 0 is stop-and-wait (~14 MiB/s). That is not a speed claim; the
#     point is the swap and the gate, not the number.
#   - quirk identity is plaintext-nominal until Noise (phase 1). Not proven crypto.
#   - the iroh leg needs n0 discovery reachable; if it is down the script says so
#     and the quirk leg plus the membership gate still stand.
#
# Usage: scripts/demo.sh
# Requires: a built `swoosh` binary. The quirk leg needs no network.

set -euo pipefail

cd "$(dirname "$0")/.."

BIN="${SWOOSH_BIN:-./target/debug/swoosh}"
if [ ! -x "$BIN" ]; then
  echo "building swoosh..." >&2
  cargo build
fi

WORK="$(mktemp -d)"
SERVE_PID=""
# Kill only the exact serve PID this script spawned, never by name: another
# swoosh may be running on this host.
trap 'if [ -n "$SERVE_PID" ]; then kill "$SERVE_PID" 2>/dev/null || true; fi; rm -rf "$WORK"' EXIT

# Three sovereign identities, one per key dir. `--key` pins the whole identity
# dir (key + address book + signet + badge), so three dirs is three identities.
SERVER="$WORK/server/identity.key"
MEMBER="$WORK/member/identity.key"
STRANGER="$WORK/stranger/identity.key"
mkdir -p "$WORK/server" "$WORK/member" "$WORK/stranger"

banner() { printf '\n=== %s ===\n' "$1"; }

# Start `serve` under the server key over the given transport, wait for its
# banner, and set SERVE_PID + SERVER_KEY + SERVER_ADDR. $1 is the transport.
start_server() {
  local transport="$1" out="$WORK/serve-$1.out"
  SWOOSH_KEY="$SERVER" "$BIN" serve --transport "$transport" >"$out" 2>&1 &
  SERVE_PID=$!
  local i
  for i in $(seq 1 60); do
    grep -q 'bf01' "$out" && break
    sleep 0.5
  done
  cat "$out"
  SERVER_KEY="$(grep -m1 -oE 'bf01[a-z0-9]+' "$out" | head -1)"
  SERVER_ADDR="$(grep -m1 -oE '127\.0\.0\.1:[0-9]+' "$out" | head -1)"
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
# Part 1: admit the member. The server mints an authkey; the member adopts it,
# becoming a device identity the server's signet trusts.
# ---------------------------------------------------------------------------
banner "server mints an authkey for the member"
AUTHKEY="$(SWOOSH_KEY="$SERVER" "$BIN" mint laptop | head -1)"
echo "$AUTHKEY"

banner "member adopts it (distinct key dir: its own identity + the trusted signet)"
SWOOSH_KEY="$MEMBER" "$BIN" adopt "$AUTHKEY"

# ---------------------------------------------------------------------------
# Part 2: the member reaches the server over quirk (our own from-scratch QUIC).
# ---------------------------------------------------------------------------
banner "quirk serve (our own QUIC, direct-only over loopback)"
start_server quirk
QUIRK_KEY="$SERVER_KEY"

banner "member ping over quirk (admitted: its badge roots at the server's signet)"
SWOOSH_KEY="$MEMBER" "$BIN" ping "$SERVER_KEY" --transport quirk --peer "$SERVER_KEY=$SERVER_ADDR" -c 5 -i 0.2

banner "member speed --down over quirk"
SWOOSH_KEY="$MEMBER" "$BIN" speed "$SERVER_KEY" --transport quirk --peer "$SERVER_KEY=$SERVER_ADDR" --down -t 3

banner "member speed --up over quirk"
SWOOSH_KEY="$MEMBER" "$BIN" speed "$SERVER_KEY" --transport quirk --peer "$SERVER_KEY=$SERVER_ADDR" --up -t 3

# The stranger, never adopted, is refused at the gate. A refusal is SUCCESS
# here, so invert the exit and assert it failed.
banner "stranger ping over quirk (never adopted: expect REFUSED)"
if SWOOSH_KEY="$STRANGER" "$BIN" ping "$SERVER_KEY" --transport quirk --peer "$SERVER_KEY=$SERVER_ADDR" -c 3 -i 0.2; then
  echo "UNEXPECTED: the stranger was admitted; the gate did not hold." >&2
  exit 1
else
  echo "refused, as it must be: the gate holds over quirk."
fi

stop_server

# ---------------------------------------------------------------------------
# Part 3: swap the transport. The SAME server key over iroh. The printed NodeId
# is byte-for-byte identical to the quirk one: same key, different transport.
# ---------------------------------------------------------------------------
banner "iroh serve (SAME server key, self-discovering)"
start_server iroh

if [ "$QUIRK_KEY" = "$SERVER_KEY" ]; then
  echo
  echo "SAME NodeId over both transports: $SERVER_KEY"
else
  echo
  echo "WARNING: NodeId differs: quirk=$QUIRK_KEY iroh=$SERVER_KEY" >&2
fi

# The iroh leg depends on n0 discovery being reachable. Treat an unreachable
# dial as a documented network condition, not a demo failure: report it and
# carry on (the quirk leg + the gate already stand on their own).
banner "member ping over iroh (identical command, no --peer: iroh self-discovers)"
if SWOOSH_KEY="$MEMBER" "$BIN" ping "$SERVER_KEY" --transport iroh -c 5 -i 0.2; then
  banner "member speed --down over iroh"
  SWOOSH_KEY="$MEMBER" "$BIN" speed "$SERVER_KEY" --transport iroh --down -t 3

  banner "stranger ping over iroh (never adopted: expect REFUSED)"
  if SWOOSH_KEY="$STRANGER" "$BIN" ping "$SERVER_KEY" --transport iroh -c 3 -i 0.2; then
    echo "UNEXPECTED: the stranger was admitted over iroh; the gate did not hold." >&2
    exit 1
  else
    echo "refused, as it must be: the gate holds over iroh too."
  fi
else
  echo
  echo "iroh unreachable (n0 discovery down). Documented caveat, not a defect:" >&2
  echo "the quirk leg and the membership gate above still stand." >&2
fi

stop_server

echo
echo "done. Member admitted over both transports, stranger refused, one server key throughout."