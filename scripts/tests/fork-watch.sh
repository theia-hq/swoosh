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
  out=$(ADVISORY_DB="$tmp/db" "${TEST_SHELL:-sh}" "$watch" "$tmp/repo" 2>&1)
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

# Existing statuses keep their source, version and no-advisory semantics.
lock "$REGISTRY"
list "$ONE" "fork upstream RUSTSEC-0000-0002 pinned $REGISTRY"
case_ "pinned still accepts any exact lock source" 0 "fork-watch: OK"
also '[[package]]' 'name = "fork"' 'version = "1.0.0"' "source = \"$PIN\""
case_ "a later pinned entry has a different source" 1 \
  "fork resolves from $PIN, but RUSTSEC-0000-0002 is pinned"
lock "$REGISTRY"
also '[[package]]' 'name = "fork"' 'version = "2.0.0"' "source = \"$REGISTRY\""
list "$ONE" "$TWO_PORTED"
case_ "a later ported entry has a different version" 1 \
  "fork is 2.0.0 in the lock, but RUSTSEC-0000-0001 was read against 1.0.0"
lock "$REGISTRY"
list 'fork elsewhere -'
case_ "a dash row still accepts an upstream with no advisories" 0 "fork-watch: OK"

# Exact-source claims accept evidence comments and bind the source, not a version.
ONE_NOT_AFFECTED="fork upstream RUSTSEC-0000-0001 not-affected $PIN"
TWO_NOT_AFFECTED="fork upstream RUSTSEC-0000-0002 not-affected $PIN"
EVIDENCE="# https://rustsec.org/advisories/RUSTSEC-0000-0002.html https://example.invalid/fork/commit/1111111111111111111111111111111111111111"
lock "$PIN"
list "$ONE" "$EVIDENCE" "$TWO_NOT_AFFECTED $EVIDENCE"
case_ "an exact not-affected source with adjacent and trailing evidence" 0 "fork-watch: OK"

HEX_PIN='git+https://example.invalid/fork#aBcDeF0123aBcDeF0123aBcDeF0123aBcDeF0123'
lock "$HEX_PIN"
list "fork upstream RUSTSEC-0000-0001 not-affected $HEX_PIN" \
  "fork upstream RUSTSEC-0000-0002 not-affected $HEX_PIN"
case_ "a full mixed-case hex commit without a query" 0 "fork-watch: OK"

# Every matching package block must retain the reviewed source, including later versions.
lock "$PIN"
also '[[package]]' 'name = "fork"' 'version = "2.0.0"' "source = \"$PIN\""
list "$ONE_NOT_AFFECTED" "$TWO_NOT_AFFECTED"
case_ "all matching entries retain the reviewed source across versions" 0 "fork-watch: OK"
also '[[package]]' 'name = "fork"' 'version = "3.0.0"' "source = \"$REGISTRY\""
case_ "a later matching entry drifted after two matching entries" 1 \
  "fork resolves from $REGISTRY, but RUSTSEC-0000-0002 was reviewed as not-affected"

# Header comments and whitespace must not hide later packages or merge unrelated tables.
DRIFT="${PIN%#*}#2222222222222222222222222222222222222222"
for header in '[[package]] # duplicate matching package' '  [[ package ]]  # duplicate matching package'; do
  lock "$PIN"
  also "$header" 'name = "fork"' 'version = "2.0.0"' "source = \"$PIN\""
  case_ "a commented package retains the exact source: $header" 0 "fork-watch: OK"
  lock "$PIN"
  also "$header" 'name = "fork"' 'version = "2.0.0"' "source = \"$DRIFT\""
  case_ "a commented package cannot hide source drift: $header" 1 \
    "fork resolves from $DRIFT, but RUSTSEC-0000-0002 was reviewed as not-affected"
done
for header in '  [[patch.unused]] # unused package' '  [metadata] # not a package'; do
  lock "$PIN"
  also "$header" 'name = "fork"' 'version = "2.0.0"' "source = \"$DRIFT\""
  case_ "a commented non-package header still ends the package: $header" 0 "fork-watch: OK"
done

# Neither a changed commit nor a different source kind inherits the source review.
for source in "${PIN%#*}#2222222222222222222222222222222222222222" \
  "git+https://example.invalid/other#1111111111111111111111111111111111111111" \
  "$REGISTRY" 'path+file:///fork' 'git+https://example.invalid/fork'; do
  lock "$source"
  list "$ONE" "$TWO_NOT_AFFECTED"
  case_ "a not-affected source drifted: $source" 1 \
    "fork resolves from $source, but RUSTSEC-0000-0002 was reviewed as not-affected"
done
# A workspace/path entry has no source field at all.
printf '[[package]]\nname = "fork"\nversion = "1.0.0"\n' > "$tmp/repo/Cargo.lock"
case_ "a not-affected entry has no lock source" 1 \
  "fork resolves from none, but RUSTSEC-0000-0002 was reviewed as not-affected"

# A matching lock cannot make a malformed source claim or row valid.
for source in "$REGISTRY" 'path+file:///fork' 'none' 'git+https://example.invalid/fork' \
  'git+https://example.invalid/fork#' \
  'git+https://example.invalid/fork#1111111' \
  'git+https://example.invalid/fork#111111111111111111111111111111111111111' \
  'git+https://example.invalid/fork#11111111111111111111111111111111111111111' \
  'git+https://example.invalid/fork#111111111111111111111111111111111111111z' \
  "$PIN/suffix" "$PIN#1111111111111111111111111111111111111111" \
  'git+#1111111111111111111111111111111111111111'; do
  lock "$source"
  list "$ONE" "fork upstream RUSTSEC-0000-0002 not-affected $source"
  case_ "a malformed not-affected source: $source" 1 "is malformed"
done
lock "$PIN"
for row in 'fork upstream RUSTSEC-0000-0002 not-affected' \
  "fork upstream RUSTSEC-0000-0002 not-affected $PIN extra" \
  'fork upstream not-affected' "fork RUSTSEC-0000-0002 not-affected $PIN" \
  "fork upstream RUSTSEC-0000-0002 not-affected $PIN extra $EVIDENCE"; do
  list "$ONE" "$row"
  case_ "a malformed not-affected row: $row" 1 "is malformed"
done

# Source review does not bypass advisory identity, coverage or fork presence.
for id in RUSTSEC-0000-0003 RUSTSEC-0000-000X; do
  list "$ONE" "$TWO_NOT_AFFECTED" "fork upstream $id not-affected $PIN"
  case_ "a not-affected advisory absent from the database: $id" 1 "names $id against upstream"
done
list "$ONE" "$TWO_NOT_AFFECTED" "fork upstrem RUSTSEC-0000-0002 not-affected $PIN"
case_ "a not-affected row names the wrong upstream" 1 \
  "names RUSTSEC-0000-0002 against upstrem, which the database does not file"
list "$ONE" "$TWO_NOT_AFFECTED" "gone upstream RUSTSEC-0000-0002 not-affected $PIN"
case_ "a not-affected fork is absent from the lock" 1 "gone is listed but not in Cargo.lock"
list "$ONE_NOT_AFFECTED"
case_ "one not-affected row does not cover another advisory" 1 \
  "RUSTSEC-0000-0002 is filed against upstream and fork has no row"
list "$ONE_NOT_AFFECTED" "$TWO_NOT_AFFECTED"
: > "$tmp/db/crates/upstream/RUSTSEC-0000-0003.md"
case_ "a new advisory still needs a disposition beside not-affected rows" 1 \
  "RUSTSEC-0000-0003 is filed against upstream and fork has no row"
rm "$tmp/db/crates/upstream/RUSTSEC-0000-0003.md"
also '[[package]]' 'name = "noq"' 'version = "1.0.0"' "source = \"$PIN\""
case_ "not-affected rows for another fork do not cover a known fork" 1 \
  "noq is in Cargo.lock but has no row"

list "# only a comment"
case_ "a list with no rows" 1 "has no rows"

echo "fork-watch fixture: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
