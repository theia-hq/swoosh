#!/bin/sh
# layering-gate.sh -- mechanical guard against layering leaks.
#
# A layer speaks only its OWN vocabulary and never reaches UP to name a consumer's crate
# or flags (STYLE.md "A library speaks only its OWN vocabulary"; audit at
# notes/reviews/layering-leak-audit.md). This gate FAILS CI when, in any crate's src/,
# tests/, or Cargo.toml, a crate:
#
#   1. KILLER CHECK -- names an UPWARD (consumer-tier) theia crate it does NOT declare as
#      a dependency. This is what catches `tightbeam` reappearing in `measure`/`fetch`/
#      `beam`, or `swoosh` in any library. A crate naming a sibling it DOES depend on is
#      fine (swoosh names tightbeam, and depends on it).
#
#   2. FLAG CHECK -- a prime library alludes to a consumer CLI flag
#      (`--for`/`--public`/`--peer`/`--authkey`/`--to`). A library owns a concept, never
#      the flag a CLI paints over it.
#
# Scope of the killer names (UPWARD_NAMES) is deliberately the distinctive consumer-tier
# names, NOT every theia crate:
#   * The substrate names (`bifrost`, `bifrost-core`, `nauthy`, `quirk`) are the shared
#     foundation that sibling transports and the identity layer legitimately reference by
#     name -- the audit marks exactly those cross-references CLEAN, so treating them as
#     leaks would make this gate red on a clean tree and defeat its purpose.
#   * The ordinary-word leaf names (`fetch`, `beam`, `measure`) collide with plain prose
#     and paths ("a public download (fetch)", "fifo:/tmp/beam", "a single measure ping"),
#     so a bare-word grep on them is false-positive-prone.
# `tightbeam`, `swoosh`, and `sshh` are non-words that no lower or sibling crate has any
# business naming; every crate-NAME leak the audit found was one of these. To exempt a
# legitimately-frozen domain constant that happens to contain such a token, put the marker
# `layering-gate:allow` in a comment on the SAME line.
#
# Dependency-free: POSIX sh + grep + sed. Run from a repo root (or pass a root path):
#   sh layering-gate.sh [ROOT]

set -eu

# Consumer-tier crate names whose appearance in a non-dependent crate is an upward leak.
UPWARD_NAMES="tightbeam swoosh sshh"
# Crates that ARE the consumer surface (or its injected handlers): the flag check does not
# apply to them -- they legitimately name the flags/handlers they implement.
FLAG_EXEMPT_CRATES="swoosh fetch beam measure sshh"
FLAG_TOKENS="--for --public --peer --authkey --to"
ALLOW_MARK="layering-gate:allow"

ROOT="${1:-.}"

# Identifier boundary: hyphen and underscore count as identifier chars, so a name never
# matches inside a longer one (`sshh` never inside a word, `swoosh` never as a substring).
BR='([^A-Za-z0-9_-]|$)'
BL='(^|[^A-Za-z0-9_-])'

fail=0
crates=0

# Crate dirs in this tree have no spaces; word-splitting the find output is safe.
for manifest in $(find "$ROOT" -name Cargo.toml -not -path '*/target/*' | sort); do
  grep -q '^\[package\]' "$manifest" || continue   # skip virtual workspace roots
  dir=$(dirname "$manifest")
  [ -d "$dir/src" ] || continue                     # a real crate has source
  crates=$((crates + 1))

  own=$(sed -n 's/^name[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$manifest" | head -n1)

  # Files this crate owns: its manifest + every .rs under src/ and tests/.
  set -- "$manifest"
  set -- "$@" $(find "$dir/src" -name '*.rs' 2>/dev/null)
  [ -d "$dir/tests" ] && set -- "$@" $(find "$dir/tests" -name '*.rs' 2>/dev/null)

  # 1. Killer check: name an upward crate that is NOT a declared dependency.
  for n in $UPWARD_NAMES; do
    [ "$n" = "$own" ] && continue
    # declared as a dependency? matches `n = ...`, `n.workspace = ...`, `n = { ... }`.
    if grep -Eq "^[[:space:]]*${n}[[:space:]=.]" "$manifest"; then continue; fi
    hits=$(grep -HEn "${BL}${n}${BR}" "$@" 2>/dev/null | grep -v "$ALLOW_MARK" || true)
    if [ -n "$hits" ]; then
      printf 'LEAK  crate %-14s names non-dependency crate %s:\n' "$own" "$n"
      printf '%s\n' "$hits" | sed 's/^/        /'
      fail=1
    fi
  done

  # 2. Flag check: a prime LIBRARY must not allude to a consumer CLI flag. A crate's own
  # `src/bin/` is a CLI surface, not library code -- it names its own flags legitimately
  # (the audit: "the bin's OWN flags are fine"), so it is excluded from THIS check only.
  case " $FLAG_EXEMPT_CRATES " in
    *" $own "*) : ;;
    *)
      libfiles=""
      for f in "$@"; do
        case "$f" in */src/bin/*) continue ;; esac
        libfiles="$libfiles $f"
      done
      for flag in $FLAG_TOKENS; do
        # -e so the leading `--` of a flag is not read as a grep option.
        hits=$(grep -HEn -e "${flag}${BR}" $libfiles 2>/dev/null | grep -v "$ALLOW_MARK" || true)
        if [ -n "$hits" ]; then
          printf 'LEAK  crate %-14s alludes to consumer flag %s:\n' "$own" "$flag"
          printf '%s\n' "$hits" | sed 's/^/        /'
          fail=1
        fi
      done
      ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  printf '\nlayering-gate: FAIL -- a crate reached outside its layer (see LEAK lines above).\n' >&2
  exit 1
fi
printf 'layering-gate: OK -- %s crate(s) clean.\n' "$crates"
