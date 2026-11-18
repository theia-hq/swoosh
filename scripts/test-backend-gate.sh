#!/bin/sh
# test-backend-gate.sh -- a test-only bifrost backend is a dev-dependency, never more.
#
# THE RULE. A test-only backend has no handshake and proves nothing about a peer (bifrost-mem: every
# identity's secret is computable), yet its `Session::peer` reports a key like a shipping transport's
# does, and no type tells the two apart. So shipping code must never be able to name one. This gate
# fails any manifest under ROOT that takes a listed test-only backend as anything but a dev-dependency.
#
# The manifest half of bifrost's scripts/sealed-gate.sh, its awk copied verbatim so the two rule alike:
# bifrost owns the list and the reason. The impl half is not copied: a consumer wraps sessions (a
# `ServiceSession` is an `impl Session`), so an impl scan here would fail on a legitimate wrapper.
# The same file runs unchanged in every repo that depends on bifrost.
#
# WHAT IT CHECKS. Every manifest line that takes the crate (`bifrost-mem = ...`, `"bifrost-mem".x`,
# or a `[...dependencies.bifrost-mem]` header) must sit in a dev-dependency table (a target-specific
# one included) or in `[workspace.dependencies]`, which only declares it.
#
# OUT OF REACH (stated, not implied): a dependency renamed with `package = "..."`, and every manifest
# in another repo (this gate scans ROOT only).
#
# Dependency-free: POSIX sh + find + awk. Run from a repo root (or pass a root path):
#   sh scripts/test-backend-gate.sh [ROOT]

set -eu

ROOT="${1:-.}"

# The test-only backends, as bifrost's scripts/sealed-gate.sh marks them `:test`.
TEST_BACKENDS="bifrost-mem"

manifests=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/.target/*' -not -path '*/_archived/*' | sort)

fail=0
for crate in $TEST_BACKENDS; do
  # Every manifest line that takes it must sit in a dev-dependency table (or the workspace table that
  # only declares it). A `[...dependencies.<crate>]` header counts too.
  bad=$(for manifest in $manifests; do
    [ -n "$manifest" ] || continue
    awk -v t="$crate" '
      /^[[:space:]]*\[/ {
        sec = $0; gsub(/[[:space:]]/, "", sec)
        if (index(sec, "." t "]") && sec !~ /dev-dependencies\./ && sec !~ /^\[workspace\.dependencies\./)
          print FILENAME ":" NR ": " $0
        next
      }
      $0 ~ ("^[[:space:]]*\"?" t "\"?[[:space:]]*[=.]") {
        if (sec !~ /dev-dependencies\]$/ && sec != "[workspace.dependencies]")
          print FILENAME ":" NR ": " $0
      }' "$manifest"
  done)
  if [ -n "$bad" ]; then
    printf 'NOT-DEV     test-only backend %s is taken as more than a dev-dependency:\n' "$crate"
    printf '%s\n' "$bad" | sed 's/^/        /'
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  printf '\ntest-backend-gate: FAIL -- a test-only backend reaches shipping code.\n' >&2
  exit 1
fi
printf 'test-backend-gate: OK -- %s taken as a dev-dependency only.\n' "$TEST_BACKENDS"
