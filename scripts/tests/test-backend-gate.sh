#!/bin/sh
# test-backend-gate fixture: exercise the PASS and FAIL paths of scripts/test-backend-gate.sh on
# throwaway trees, so a regression in the section parse fails HERE instead of passing silently in CI.
# Each case writes one manifest, runs the gate against its tree, and asserts the exit code plus a
# substring of the output. Dependency-free: POSIX sh.

set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
gate="$here/../test-backend-gate.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# write_manifest <case> <manifest text>: one crate whose manifest is given whole.
write_manifest() {
  mkdir -p "$tmp/$1/app/src"
  printf '%s\n' "$2" > "$tmp/$1/app/Cargo.toml"
}

# expect_ok <label> <case>: the gate exits 0.
expect_ok() {
  if out=$(sh "$gate" "$tmp/$2" 2>&1); then
    pass=$((pass + 1))
    printf 'ok   %s\n' "$1"
    return
  fi
  fail=$((fail + 1))
  printf 'FAIL %s\n%s\n' "$1" "$out"
}

# expect_fail <label> <case>: the gate exits non-zero and names the refusal.
expect_fail() {
  if out=$(sh "$gate" "$tmp/$2" 2>&1); then
    :
  elif printf '%s\n' "$out" | grep -q -- 'NOT-DEV'; then
    pass=$((pass + 1))
    printf 'ok   %s\n' "$1"
    return
  fi
  fail=$((fail + 1))
  printf 'FAIL %s\n%s\n' "$1" "$out"
}

# The pass paths: a dev-dependency, a target-specific dev-dependency, and the workspace declaration.
write_manifest dev '[package]
name = "app"

[dev-dependencies]
bifrost-mem = { path = "../bifrost-mem" }'
expect_ok 'a dev-dependency passes' dev

write_manifest target-dev "[package]
name = \"app\"

[target.'cfg(unix)'.dev-dependencies]
bifrost-mem = { path = \"../bifrost-mem\" }"
expect_ok 'a target-specific dev-dependency passes' target-dev

write_manifest workspace '[workspace.dependencies]
bifrost-mem = { path = "../bifrost-mem" }'
expect_ok 'a workspace declaration passes' workspace

# The fail paths: a normal dependency, in either TOML form, and a build dependency.
write_manifest normal '[package]
name = "app"

[dependencies]
bifrost-mem = { path = "../bifrost-mem" }'
expect_fail 'a test-only backend as a dependency fails' normal

write_manifest table '[package]
name = "app"

[dependencies.bifrost-mem]
path = "../bifrost-mem"'
expect_fail 'a test-only backend as a dependency table fails' table

write_manifest build '[package]
name = "app"

[build-dependencies]
bifrost-mem = { path = "../bifrost-mem" }'
expect_fail 'a test-only backend as a build dependency fails' build

# An empty tree (no manifests) passes.
mkdir -p "$tmp/empty"
expect_ok 'an empty tree passes' empty

printf '\ntest-backend-gate fixture: %s passed, %s failed.\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
