#!/bin/sh
# lock-guard.sh -- fail if a repo's COMMITTED/STAGED Cargo.lock drifted from shipping-form.
#
# THE RULE (notes/design/release-robustness-spec.md; decision (A) in notes/02-DECISIONS.md). A
# committed Cargo.lock must record the SHIPPING form of every theia sibling: each sibling
# resolved from its `github.com/theia-hq/<repo>` git source at the exact rev its Cargo.toml
# pins, and every in-repo crate's lock version matching its own manifest. Five drifts break
# that, and this gate FAILS on any of them:
#
#   (a) PATH-DRIFT   -- a sibling's lock block has NO git `source =` line, a `path+` one, or any
#       source that is not the exact `git+https://github.com/theia-hq/<repo>?rev=<40hex>#<40hex>`
#       form. A local patched `cargo build` (the umbrella .cargo/config.toml [patch]es siblings to
#       local paths) rewrites the lock to path sources by design; committing that leaks the dev
#       machine's layout into the shipping lock. THIS IS THE EXACT v0.7.0 SAGA the gate stops.
#   (b) REV DISAGREEMENT -- ANY lock block named for a sibling carries a rev != the rev its
#       Cargo.toml git dep pins. Catches a manifest rev bump that never regenerated the lock, and
#       a stale nested pin that resolved a second copy at a different rev, statically (no build).
#   (c) OWN-VERSION SKEW -- an in-repo crate's lock `version` != its manifest `[package] version`.
#       The `cargo bump the version, forget to sync the lock` footgun, made mechanical.
#   (d) PATCH ARTIFACT -- the committed lock carries a `[[patch.unused]]` block. A shipping lock
#       is resolved patch-free and never carries patch artifacts; their presence means it was
#       written under the umbrella root [patch] (F12, red mains 2026-09-08..11), not a clean
#       resolve.
#   (e) DUPLICATE SIBLING -- more than one `[[package]]` block for the same sibling package name.
#       A lagging nested pin (a sibling at rev R whose OWN manifest depends on sibling S at an
#       older rev, while this repo pins S at the new rev) makes cargo resolve TWO copies of S from
#       different git sources; the umbrella [patch] hides it locally (every copy maps to one path),
#       and CI then fails at build (`package S is specified twice`, or a cross-rev type mismatch).
#       Checked against every name derived from the manifest git deps UNION every theia-hq git
#       source in the lock, so transitive-only crates (bifrost-core, tightbeam-handler, ...) are
#       covered without hardcoding a name list.
#
# WHY IT READS THE COMMITTED/STAGED LOCK, NOT THE WORKING-TREE FILE. Under the containment model
# a patched local build ALWAYS re-dirties the working-tree Cargo.lock to path sources (and an
# in-flight release may have bumped a manifest version that the committed lock hasn't caught up
# to yet). That ambient working-tree drift is EXPECTED local state, never a failure. The gate's
# job is only to stop that dirt from being COMMITTED, so it reads what a commit would record:
# the git INDEX (`git show :PATH`), which equals HEAD for an unstaged file and the staged blob
# for a `git add`ed one. Both the lock AND the manifests are read from the index so the check is
# coherent (a working-tree-only version bump does not trip check (c) against the committed lock).
# Outside a git repo it falls back to the on-disk files, so it still works on a plain checkout.
#
# NOTHING IS HARDCODED about WHICH siblings exist: the sibling set is DERIVED from the git deps
# in the manifests (same derive-from-manifest spirit as scripts/layering-gate.sh). Co-located
# path members (beam/fetch/measure/sshh) are NOT siblings and are never required to carry a git
# source, which is what distinguishes a legit sourceless workspace member from a path-drifted
# sibling.
#
# Dependency-free: POSIX sh + git + grep/sed/awk. Run from a repo root (or pass a root path):
#   sh scripts/lock-guard.sh [ROOT]

set -eu

ROOT="${1:-.}"
LOCK="$ROOT/Cargo.lock"

# Are we inside a git work tree? Governs whether we read the index (shipping intent) or disk.
in_git=0
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then in_git=1; fi

# read_indexed PATH -- emit a repo-relative PATH's committed/staged content (git index) in a git
# repo, else its on-disk content. `git show :PATH` reads the index, which is HEAD for an unstaged
# file and the staged blob after `git add`, i.e. exactly what a commit would record.
read_indexed() {
  if [ "$in_git" -eq 1 ]; then
    git -C "$ROOT" show ":$1" 2>/dev/null
  else
    cat "$ROOT/$1" 2>/dev/null
  fi
}

# list_manifests -- emit repo-relative Cargo.toml paths. In a git repo, from the INDEX
# (`ls-files`), which excludes target/ (gitignored) and any uncommitted stray for free; else a
# find over the tree, pruning the usual build/archive dirs.
list_manifests() {
  if [ "$in_git" -eq 1 ]; then
    git -C "$ROOT" ls-files -- '*Cargo.toml' 'Cargo.toml' 2>/dev/null | grep -v '_archived/' || true
  else
    ( cd "$ROOT" && find . -name Cargo.toml \
        -not -path '*/target/*' -not -path '*/.target/*' -not -path '*/_archived/*' \
        | sed 's#^\./##' )
  fi
}

# Materialize the lock content ONCE so awk/sed can scan it repeatedly.
LOCK_TMP=$(mktemp)
trap 'rm -f "$LOCK_TMP"' EXIT
if [ "$in_git" -eq 1 ]; then
  git -C "$ROOT" show :Cargo.lock >"$LOCK_TMP" 2>/dev/null || cat "$LOCK" >"$LOCK_TMP" 2>/dev/null || true
else
  cat "$LOCK" >"$LOCK_TMP" 2>/dev/null || true
fi
[ -s "$LOCK_TMP" ] || { echo "lock-guard: no committed Cargo.lock at $ROOT (skip)"; exit 0; }

fail=0

# (d): reject patch artifacts. `[[patch.unused]]` is emitted only when a `[patch]` (the umbrella
# root's) was consulted during resolution; a shipping lock, resolved patch-free, never has one.
# Report every block's line + package and the fix. Here-doc loop so fail survives in POSIX sh.
patch_hits=$(awk '
  /^\[\[patch\.unused\]\]/ { ln = NR; want = 1; next }
  want && /^name = "/ { sub(/^name = "/, ""); sub(/"$/, ""); print ln " " $0; want = 0 }
' "$LOCK_TMP")
while read -r ln pkg; do
  [ -n "$ln" ] || continue
  echo "PATCH Cargo.lock:$ln carries unused patch block '$pkg' (lock resolved under the umbrella [patch]); resolve patch-free outside theia-hq, then copy the lock back"
  fail=1
done <<EOF
$patch_hits
EOF

# lock_blocks NAME -- emit EVERY [[package]] block named NAME (a lagging nested pin can leave
# more than one in the lock), with each block's source + version lines. `head -n1` recovers the
# old first-block-only read for the own-version check, which needs one version per in-repo crate.
lock_blocks() {
  awk -v n="$1" '
    /^\[\[package\]\]/ { inb = 0 }
    $0 == "name = \"" n "\"" { inb = 1 }
    inb { print }
  ' "$LOCK_TMP"
}

# Derive siblings as "name repo rev" (space-separated; names/revs never contain spaces) from
# every theia-hq git dep across the manifests. The `|| true` on the grep is necessary: under
# `set -e` a no-match (exit 1) in this pipeline kills the `list_manifests | while` subshell at
# the first manifest that declares no theia dep, so a git dep declared outside the ROOT manifest
# was never enumerated (bifrost/quirk/nauthy reported 0 siblings and their drift went unchecked).
# sed with a real space avoids the BSD-sed `\t` gotcha (BSD sed emits a literal `t` for `\t`).
siblings=$(list_manifests | while IFS= read -r m; do
  [ -n "$m" ] || continue
  read_indexed "$m" | grep -oE \
    '^[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*=.*github\.com/theia-hq/[A-Za-z0-9_-]+.*rev[[:space:]]*=[[:space:]]*"[0-9a-f]{40}"' || true
done | sed -E 's/^[[:space:]]*([A-Za-z0-9_-]+).*theia-hq\/([A-Za-z0-9_-]+).*rev[[:space:]]*=[[:space:]]*"([0-9a-f]{40})".*/\1 \2 \3/' \
  | sort -u)

# (a) + (b): EVERY lock block named for a sibling must resolve from its theia-hq git source at the
# rev the manifest pins. Checking all blocks, not just the first, is what makes (b) catch the stale
# half of a duplicated pair when the matching copy happens to sort first. A here-doc feeds the loop
# so it runs in THIS shell (a `... | while` runs in a subshell whose fail=1 is lost in POSIX sh);
# the same reason scripts/layering-gate.sh avoids the pipe-into-while.
while read -r name repo rev; do
  [ -n "$name" ] || continue
  srcs=$(lock_blocks "$name" | sed -n 's/^source = "\(.*\)"/\1/p')
  if [ -z "$srcs" ]; then
    echo "DRIFT $name has NO git source in Cargo.lock (path-patched build leaked in); resolve patch-free outside theia-hq, then copy the lock back"
    fail=1
    continue
  fi
  while IFS= read -r src; do
    case "$src" in
      path+* )  echo "DRIFT $name lock source is a PATH source '$src' (path-patched build leaked in); resolve patch-free outside theia-hq, then copy the lock back"; fail=1; continue ;;
      git+https://github.com/theia-hq/"$repo"?rev=*#*) : ;;                        # shipping form
      * )       echo "DRIFT $name lock source is '$src' (expected the git+https://github.com/theia-hq/$repo?rev=<sha>#<sha> form in Cargo.lock); resolve patch-free outside theia-hq, then copy the lock back"; fail=1; continue ;;
    esac
    locrev=$(printf '%s' "$src" | sed -E 's/.*rev=([0-9a-f]{40}).*/\1/')
    [ "$locrev" = "$rev" ] || { echo "REV   $name lock rev $locrev != Cargo.toml rev $rev (Cargo.lock)"; fail=1; }
    locfrag=$(printf '%s' "$src" | sed -nE 's/^.*#([0-9a-f]{40})$/\1/p')
    [ "$locfrag" = "$rev" ] || { echo "SRC   $name lock source '$src' lacks the #<sha> git fragment (expected git+https://github.com/theia-hq/$repo?rev=$rev#$rev in Cargo.lock); resolve patch-free outside theia-hq, then copy the lock back"; fail=1; }
  done <<EOF2
$srcs
EOF2
done <<EOF
$siblings
EOF

# (e): no sibling package may carry more than one [[package]] block. A lagging nested pin (a
# sibling at rev R whose OWN manifest depends on sibling S at an older rev, while this repo pins S
# at the new rev) makes cargo resolve TWO copies of S from different git sources; the umbrella
# [patch] hides it locally (every copy maps to one path) and CI fails at build. Names checked:
# every manifest git-dep key UNION every theia-hq git source in the lock, so transitive-only
# crates (bifrost-core, tightbeam-handler, ...) are covered without a hardcoded name list.
lock_siblings=$(awk '
  /^name = "/ { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name) }
  index($0, "source = \"git+https://github.com/theia-hq/") == 1 { if (name != "") { print name; name = "" } }
' "$LOCK_TMP" | sort -u)
dup_names=$( { printf '%s\n' "$siblings" | awk 'NF { print $1 }'; printf '%s\n' "$lock_siblings"; } | sort -u )
while IFS= read -r nm; do
  [ -n "$nm" ] || continue
  cnt=$(awk -v n="$nm" '$0 == "name = \"" n "\"" { c++ } END { print c + 0 }' "$LOCK_TMP")
  [ "$cnt" -le 1 ] || {
    echo "DUP   $nm has $cnt [[package]] blocks in Cargo.lock (a lagging nested sibling pin resolved more than one copy; the umbrella [patch] hides this locally):"
    awk -v n="$nm" '
      /^\[\[package\]\]/ { if (hit) { printf "        Cargo.lock:%d %s\n", ln, (src == "" ? "(no source)" : src); hit = 0 } src = "" }
      $0 == "name = \"" n "\"" { hit = 1; ln = NR }
      hit && /^source = / { src = $0; sub(/^source = "/, "", src); sub(/"$/, "", src) }
      END { if (hit) printf "        Cargo.lock:%d %s\n", ln, (src == "" ? "(no source)" : src) }
    ' "$LOCK_TMP"
    fail=1
  }
done <<EOF
$dup_names
EOF

# (c): every in-repo [package] version must match its own lock block version. Here-doc again so
# fail survives; manifests read from the index so an in-flight working-tree bump is not a skew.
manifests=$(list_manifests)
while IFS= read -r m; do
  [ -n "$m" ] || continue
  content=$(read_indexed "$m")
  printf '%s\n' "$content" | grep -q '^\[package\]' || continue
  nm=$(printf '%s\n' "$content" | sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  mv=$(printf '%s\n' "$content" | sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$nm" ] && [ -n "$mv" ] || continue
  lv=$(lock_blocks "$nm" | sed -n 's/^version = "\(.*\)"/\1/p' | head -n1)
  [ -n "$lv" ] || continue
  [ "$lv" = "$mv" ] || { echo "VER   $nm lock version $lv != Cargo.toml version $mv"; fail=1; }
done <<EOF
$manifests
EOF

# (f): a lock block with NO `source` is a WORKSPACE member. Any other sourceless block is a path-patched
# build's leak, and the checks above cannot see it: (a)/(b) iterate the git deps this repo's manifests
# DECLARE, and a transitive-only sibling (tightbeam-handler, reached through tightbeam) is declared
# nowhere here; (e) unions in the lock's git-sourced names, and a leaked block has no source to union on.
# So a sibling that arrives only through another sibling could leak in as a path entry and pass both.
# Enumerating the repo's own [package] names and calling every OTHER sourceless block a leak needs no
# name list and cannot go stale.
own=$(printf '%s\n' "$manifests" | while IFS= read -r m; do
  [ -n "$m" ] || continue
  read_indexed "$m" | grep -q '^\[package\]' || continue
  read_indexed "$m" | sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
done | sort -u)
sourceless=$(awk '
  /^\[\[package\]\]/ { if (name != "" && !seen) print name; name = ""; seen = 0 }
  /^name = "/ { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name) }
  /^source = / { seen = 1 }
  END { if (name != "" && !seen) print name }
' "$LOCK_TMP" | sort -u)
while IFS= read -r nm; do
  [ -n "$nm" ] || continue
  printf '%s\n' "$own" | grep -qx "$nm" && continue
  echo "DRIFT $nm has a [[package]] block with NO source and is not a crate of this repo (a path-patched build leaked in); resolve patch-free outside theia-hq, then copy the lock back"
  fail=1
done <<EOF
$sourceless
EOF

# BELT (spec §6): a theia [patch] belongs ONLY in the local umbrella .cargo/config.toml, never
# committed inside a repo (a committed patch would re-introduce the ancestor-walk footgun in CI,
# where the single-repo checkout must resolve git sources like an outsider). Check the committed
# config, not the working tree.
if [ "$in_git" -eq 1 ]; then
  if git -C "$ROOT" ls-files --error-unmatch .cargo/config.toml >/dev/null 2>&1; then
    if read_indexed .cargo/config.toml | grep -q '^\[patch\."https://github.com/theia-hq/'; then
      echo "PATCH committed .cargo/config.toml carries a theia [patch] (must live only in the umbrella root)"
      fail=1
    fi
  fi
fi

if [ "$fail" -ne 0 ]; then
  printf '\nlock-guard: FAIL -- the committed Cargo.lock is not in shipping-form (see lines above).\n' >&2
  printf 'A local patched build re-dirties the working-tree lock by design; never `git add Cargo.lock`\n' >&2
  printf 'from a patched build. Regenerate in a patch-free checkout (`just relock <repo>`) instead.\n' >&2
  exit 1
fi
printf 'lock-guard: OK -- committed Cargo.lock is shipping-form (%s sibling(s) checked).\n' \
  "$(printf '%s\n' "$siblings" | grep -c .)"
