#!/bin/sh
# fork-watch.sh -- fail when an upstream advisory has not been checked against our fork of the crate.
#
# WHY. cargo-deny reads advisories filed against the crates in the lock, so it says nothing about a
# fork: an advisory against quinn-proto never names noq-proto, though noq-proto is quinn-proto's code
# under another name. RUSTSEC-2026-0185 went unseen in our lock that way. A watch by date (fail when
# upstream has an advisory newer than the fork's release) would not have caught it either: the
# advisory predates the noq-proto release that still lacked the fix. So the watch is keyed by
# advisory ID: every upstream advisory must have a row saying how our fork stands against it.
#
# THE LIST. scripts/fork-watch.txt, one row per (fork, upstream advisory), whitespace-separated:
#
#   <fork> <upstream> <advisory-id> ported <fork version>
#   <fork> <upstream> <advisory-id> pinned <lock source>
#   <fork> <upstream> -
#
# `ported`: the fix is in the fork's code at <fork version>, checked by reading that version. The
# reading holds for that version only, so a lock that moves the fork to another version fails until
# each row is read again and its version recorded. `pinned`: the fix is not in a release of the fork
# yet, and the lock takes it from <lock source> (the exact `source =` string in Cargo.lock). A `-` row
# names a fork whose upstream has no advisory today. A `#` that starts a line or follows a space
# starts a comment (a lock source carries one of its own).
#
# THE FORKS. FORKS below names every fork of an advisory-bearing crate we know of. Each one in the
# lock must have rows, so deleting a fork's rows is a failure rather than a quiet exit from the watch.
#
# IT FAILS when:
#   (a) an advisory filed against an upstream in the list has no row for the fork,
#   (b) a `pinned` row's fork resolves from any source but the recorded one (the patch was dropped
#       or moved without a look at whether the release it moved to carries the fix),
#   (c) a fork in the list is not in Cargo.lock (a stale row),
#   (d) a row is malformed, or the list has no rows,
#   (e) a row names an advisory the database does not file against its upstream (a misspelled
#       upstream or ID would otherwise read as "no advisories" forever),
#   (f) a `ported` row's version is not the version of the fork in the lock, or
#   (g) a fork in FORKS is in the lock with no row.
#
# THE DATABASE. A shallow clone of https://github.com/rustsec/advisory-db, or the clone named by
# $ADVISORY_DB (the fixture uses that, so it runs offline). Withdrawn advisories still count: a row
# costs one line, and a missed one can cost a node.
#
# Dependency-free: POSIX sh + git + awk + grep + sed. Run from a repo root (or pass a root path):
#   sh scripts/fork-watch.sh [ROOT]

set -eu

# Forks of crates that carry RustSec advisories: n0's QUIC stack (quinn-proto, quinn, quinn-udp) and
# its ACME client (rustls-acme). A fork added to a lock later belongs here too.
FORKS="noq-proto noq noq-udp tokio-rustls-acme"

ROOT="${1:-.}"
LIST="$ROOT/scripts/fork-watch.txt"
LOCK="$ROOT/Cargo.lock"

[ -f "$LIST" ] || { echo "fork-watch: no $LIST" >&2; exit 1; }
[ -f "$LOCK" ] || { echo "fork-watch: no $LOCK" >&2; exit 1; }

if [ -n "${ADVISORY_DB:-}" ]; then
  db="$ADVISORY_DB"
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  git clone --quiet --depth 1 https://github.com/rustsec/advisory-db "$tmp/advisory-db"
  db="$tmp/advisory-db"
fi
[ -d "$db/crates" ] || { echo "fork-watch: $db holds no crates/ directory" >&2; exit 1; }

# The rows, comments and blank lines dropped.
rows=$(sed -e 's/^#.*//' -e 's/[[:space:]]#.*//' -e '/^[[:space:]]*$/d' "$LIST")
if [ -z "$rows" ]; then
  echo "fork-watch: $LIST has no rows" >&2
  exit 1
fi

# One line per lock block for a package name: its version, then its source ("none" for a block
# without one, which is a path or workspace crate). Any `[` line ends a block, so a trailing
# `[[patch.unused]]` or `[metadata]` table is never read as part of the last package.
lock_entries() {
  awk -v want="$1" '
    function flush() { if (inpkg && name == want) print ver " " (src == "" ? "none" : src) }
    /^\[/ { flush(); inpkg = ($0 == "[[package]]"); name = ""; ver = ""; src = ""; next }
    inpkg && /^name = / { name = $3; gsub(/"/, "", name) }
    inpkg && /^version = / { ver = $3; gsub(/"/, "", ver) }
    inpkg && /^source = / { src = $3; gsub(/"/, "", src) }
    END { flush() }
  ' "$LOCK"
}

fail=0
bad() { echo "fork-watch: $*" >&2; fail=1; }

# (d) the shape of each row.
printf '%s\n' "$rows" | while read -r fork upstream id status value extra; do
  case "$id:$status" in
    -:) ;;
    RUSTSEC-*:ported | RUSTSEC-*:pinned) [ -n "$value" ] && [ -z "$extra" ] || exit 1 ;;
    *) exit 1 ;;
  esac
done || bad "a row of $LIST is malformed; see the header of scripts/fork-watch.sh for the shape"

forks=$(printf '%s\n' "$rows" | awk '{ print $1 " " $2 }' | sort -u)

# (c) and (a), per fork.
printf '%s\n' "$forks" | {
  fail=0
  while read -r fork upstream; do
    if [ -z "$(lock_entries "$fork")" ]; then
      echo "fork-watch: $fork is listed but not in Cargo.lock; drop its rows" >&2
      fail=1
    fi
    for file in "$db/crates/$upstream"/RUSTSEC-*.md; do
      [ -f "$file" ] || continue
      id=$(basename "$file" .md)
      if ! printf '%s\n' "$rows" | awk -v f="$fork" -v u="$upstream" -v i="$id" \
        '$1 == f && $2 == u && $3 == i { found = 1 } END { exit !found }'; then
        echo "fork-watch: $id is filed against $upstream and $fork has no row for it; read the fix" \
          "against $fork's locked code and add a row (ported at that version, or pinned to the" \
          "source carrying it)" >&2
        fail=1
      fi
    done
  done
  exit "$fail"
} || fail=1

# (e) each advisory a row names is filed against that row's upstream.
printf '%s\n' "$rows" | awk '$3 ~ /^RUSTSEC-/ { print $1 " " $2 " " $3 }' | {
  fail=0
  while read -r fork upstream id; do
    if [ ! -f "$db/crates/$upstream/$id.md" ]; then
      echo "fork-watch: $fork's row names $id against $upstream, which the database does not file" \
        "there; check the spelling of both" >&2
      fail=1
    fi
  done
  exit "$fail"
} || fail=1

# (b) each pin still holds, and (f) each reading still matches the locked version.
printf '%s\n' "$rows" | awk '$4 == "pinned" || $4 == "ported" { print $1 " " $3 " " $4 " " $5 }' | {
  fail=0
  while read -r fork id status value; do
    entries=$(lock_entries "$fork")
    [ -n "$entries" ] || continue
    printf '%s\n' "$entries" | {
      fail=0
      while read -r version source; do
        if [ "$status" = pinned ] && [ "$source" != "$value" ]; then
          echo "fork-watch: $fork resolves from $source, but $id is pinned to $value; read the" \
            "fork at the version it moved to against $id, and record that version in a ported" \
            "row only if the fix is there, else restore the pin" >&2
          fail=1
        elif [ "$status" = ported ] && [ "$version" != "$value" ]; then
          echo "fork-watch: $fork is $version in the lock, but $id was read against $value; read" \
            "$version against $id and record it" >&2
          fail=1
        fi
      done
      exit "$fail"
    } || fail=1
  done
  exit "$fail"
} || fail=1

# (g) every known fork in the lock has rows.
for fork in $FORKS; do
  if [ -n "$(lock_entries "$fork")" ] &&
    ! printf '%s\n' "$rows" | awk -v f="$fork" '$1 == f { found = 1 } END { exit !found }'; then
    bad "$fork is in Cargo.lock but has no row in $LIST; list every advisory against what it forks"
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "fork-watch: OK -- every upstream advisory has a row for its fork, every pin holds, and every reading matches the locked version."
