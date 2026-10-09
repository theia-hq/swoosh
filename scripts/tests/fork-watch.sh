#!/bin/sh
# fork-watch fixture: run scripts/fork-watch.sh against a throwaway repo and a fake advisory database,
# so each of its fail paths is exercised offline and a regression fails HERE instead of the watch
# passing silently in CI. Each case writes a lock and a list, then asserts the exit code plus a
# substring of the output.
# Dependency-free: POSIX sh + awk + grep + sed.

set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
watch="$here/../fork-watch.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

PIN='git+https://example.invalid/fork?rev=1111111111111111111111111111111111111111#1111111111111111111111111111111111111111'
REGISTRY='registry+https://github.com/rust-lang/crates.io-index'

# The fake database: two advisories against the upstream, none against anything else.
mkdir -p "$tmp/db/crates/upstream"
: > "$tmp/db/crates/upstream/RUSTSEC-0000-0001.md"
: > "$tmp/db/crates/upstream/RUSTSEC-0000-0002.md"

# A lock holding `fork` 1.0.0 from the given source, at the given version when one is named.
lock() {
  printf '[[package]]\nname = "fork"\nversion = "%s"\nsource = "%s"\n' "${2:-1.0.0}" "$1" > "$tmp/repo/Cargo.lock"
}

# Append a block to the lock.
also() {
  printf '%s\n' "$@" >> "$tmp/repo/Cargo.lock"
}

# A list made of the given rows.
list() {
  printf '%s\n' "$@" > "$tmp/repo/scripts/fork-watch.txt"
}

# case <name> <expected exit> <expected output substring>
case_() {
  name=$1 want=$2 needle=$3
  set +e
  out=$(ADVISORY_DB="$tmp/db" sh "$watch" "$tmp/repo" 2>&1)
  got=$?
  set -e
  if [ "$got" -eq "$want" ] && printf '%s' "$out" | grep -qF -- "$needle"; then
    pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got (want $want), output:" >&2
    printf '%s\n' "$out" >&2
    fail=$((fail + 1))
  fi
}

mkdir -p "$tmp/repo/scripts"

ONE="fork upstream RUSTSEC-0000-0001 ported 1.0.0"
TWO_PINNED="fork upstream RUSTSEC-0000-0002 pinned $PIN"
TWO_PORTED="fork upstream RUSTSEC-0000-0002 ported 1.0.0"

lock "$PIN"
list "# a comment" "$ONE # read at 1.0.0" "$TWO_PINNED"
case_ "every advisory has a row, the pin holds, a trailing comment is dropped" 0 "fork-watch: OK"

list "$ONE"
case_ "an advisory with no row" 1 "RUSTSEC-0000-0002 is filed against upstream and fork has no row"

list "fork upstream -"
case_ "a dash row is no wildcard for an upstream with advisories" 1 \
  "RUSTSEC-0000-0001 is filed against upstream and fork has no row"

lock "$REGISTRY"
list "$ONE" "$TWO_PINNED"
case_ "the patch was dropped" 1 "fork resolves from $REGISTRY, but RUSTSEC-0000-0002 is pinned"

lock "$REGISTRY" 1.0.1
list "$ONE" "$TWO_PORTED"
case_ "a ported row read against another version" 1 \
  "fork is 1.0.1 in the lock, but RUSTSEC-0000-0001 was read against 1.0.0"

lock "$REGISTRY"
list "$ONE" "$TWO_PORTED" "fork upstrem RUSTSEC-0000-0001 ported 1.0.0"
case_ "a misspelled upstream" 1 "names RUSTSEC-0000-0001 against upstrem, which the database does not file"

list "$ONE" "$TWO_PORTED" "fork upstream RUSTSEC-0000-0003 ported 1.0.0"
case_ "an advisory filed elsewhere" 1 "names RUSTSEC-0000-0003 against upstream"

list "$ONE" "$TWO_PORTED" "gone elsewhere -"
case_ "a listed fork not in the lock" 1 "gone is listed but not in Cargo.lock"

also '[[package]]' 'name = "noq"' 'version = "1.0.0"' "source = \"$REGISTRY\""
list "$ONE" "$TWO_PORTED"
case_ "a known fork in the lock with no rows" 1 "noq is in Cargo.lock but has no row"

lock "$REGISTRY"
also '[[patch.unused]]' 'name = "fork"' 'version = "9.9.9"' "source = \"$REGISTRY\""
case_ "a trailing patch.unused block is not read as a package" 0 "fork-watch: OK"

lock "$REGISTRY"
for row in "fork upstream RUSTSEC-0000-0002 maybe" "fork upstream RUSTSEC-0000-0002 pinned" \
  "fork upstream RUSTSEC-0000-0002 ported" "fork upstream RUSTSEC-0000-0002 ported 1.0.0 extra" \
  "fork upstream RUSTSEC-0000-0002 pinned $PIN extra"; do
  list "$ONE" "$row"
  case_ "a malformed row: $row" 1 "is malformed"
done

list "# only a comment"
case_ "a list with no rows" 1 "has no rows"

echo "fork-watch fixture: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
