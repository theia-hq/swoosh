#!/bin/sh
# layering-gate.sh -- mechanical guard against layering leaks.
#
# THE RULE (STYLE.md "A library speaks only its OWN vocabulary"; audit at
# notes/reviews/layering-leak-audit.md). A layer speaks only its OWN vocabulary and never
# reaches UP to name a CONSUMER's crate or a consumer's CLI flag, in docs/comments/strings.
#
# WHY DOCS, NOT CODE. The compiler already forbids a code-level cross-crate reference: a
# crate that writes `swoosh::Foo` or `use tightbeam` in real code without declaring that
# dependency fails to build. So this gate does NOT re-police code -- cargo does. The leaks
# that compile CLEANLY, and so survive, live in DOC COMMENTS and STRINGS ("/// like swoosh's
# status", `"... a handler like sshd:"`). That is exactly this gate's job: a crate whose
# docs/comments/strings NAME a sibling or consumer crate it does not depend on.
#
# WHAT IT CHECKS, per crate found under ROOT:
#
#   1. CRATE-NAME check -- the crate's files reference, AS A CRATE, a theia crate that is
#      NOT its foundation. A crate's foundation is: a declared DEPENDENCY (a downward
#      reference, always legal -- swoosh names tightbeam and depends on it), or a co-located
#      sibling LIBRARY in its own tree (the substrate crates in a workspace document each
#      other). A leak is naming EITHER an EXTERNAL crate you do not depend on (`measure`
#      naming the byte-tunnel `tightbeam`) OR an APPLICATION crate (`measure`/`fetch`/`beam`
#      naming the consumer `swoosh`). See the classification block below.
#
#   2. FLAG check -- a prime LIBRARY (not a `src/bin/` CLI) alludes to a consumer long-flag
#      (`--for`/`--public`/`--peer`/`--authkey`/`--to`). A library owns a concept, never the
#      flag a CLI paints over it.
#
# NOTHING IS HARDCODED about WHICH crates exist. The crate SET is DERIVED (see below) from
# the Cargo.toml manifests in the tree, so a new crate is covered the day it lands. Each
# crate's own declared dependencies are derived from its own manifest.
#
# To exempt a legitimately-frozen constant or a deliberate reference, put the marker
# `layering-gate:allow` in a comment on the SAME line.
#
# Dependency-free: POSIX sh + grep + sed. Run from a repo root (or pass a root path):
#   sh layering-gate.sh [ROOT]

set -eu

ROOT="${1:-.}"
ALLOW_MARK="layering-gate:allow"

# A prime library must not allude to these consumer CLI long-flags. This SHORT list stays
# explicit ON PURPOSE: the flags cannot be reliably derived. clap paints almost all of them
# from the Args STRUCT-FIELD name via a bare `#[arg(long)]` (`pub r#for` -> `--for`,
# `pub public` -> `--public`), so the flag string `--for` never appears verbatim in the bin
# source -- deriving it would mean parsing every clap-derive struct's fields, kebab-casing
# them, and unwinding raw idents / `rename_all`, precisely the fragile parse we avoid. The
# check MATCHES a literal `--flag`, which is distinctive and cannot collide with prose.
FLAG_TOKENS="--for --public --peer --authkey --to"

# ---------------------------------------------------------------------------------------
# DERIVE the crate SET (the "universe" of theia crate names) from the manifests under ROOT.
#
# A theia crate name enters the universe two ways:
#   (a) it is a package DEFINED in this tree     -- `name = "..."` under `[package]`.
#   (b) it is a theia crate this tree DEPENDS ON  -- a dependency whose source is a theia
#       one: `git = "...github.com/theia-hq/..."` or a local `path = "..."`. The dependency
#       KEY is the crate name. (A `.workspace = true` dep resolves to such a line in the
#       workspace root's [workspace.dependencies], which IS scanned, so it is covered.)
# Third-party deps (`tokio = "1"`, a non-theia git) never match (a) or (b), so they never
# enter the universe and never trip the check.
#
# Scanning is over EVERY Cargo.toml under ROOT. This gate is meant to run PER REPO (as CI and
# the umbrella `just gate` both do): the universe is that repo's own crates plus the theia
# crates it depends on. A dependency crate from another repo (e.g. `tightbeam` in the swoosh
# repo) enters the universe as an EXTERNAL name, which is what makes `measure` naming it a
# detectable leak.
#
# RESIDUAL LIMITATION (stated honestly; it cannot be derived away under per-repo isolation).
# A lower repo naming a crate that lives ABOVE it in a DIFFERENT repo it does not depend on
# -- the classic being `tightbeam` (or `nauthy`, `bifrost`, `quirk`) naming the top app
# `swoosh` -- is NOT caught, because nothing in the lower repo's manifests references that
# consumer, so its name is not derivable there. The swoosh repo DOES depend on tightbeam and
# owns swoosh, so every leak AMONG swoosh-repo crates (`measure`/`fetch`/`beam`/`sshh` naming
# `tightbeam` or `swoosh`) IS caught. Recovering the lower->higher cross-repo case would
# require either hardcoding the consumer names (the brittleness this rework removes) or giving
# the check the sibling repos, which per-repo CI deliberately does not have.
# ---------------------------------------------------------------------------------------

manifests=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/_archived/*' | sort)

# (a) package names.
universe_pkgs=$(printf '%s\n' "$manifests" | while read -r m; do
  [ -n "$m" ] || continue
  grep -q '^\[package\]' "$m" || continue
  sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$m" | head -n1
done)

# (b) theia dependency keys: a dep line pointing at a theia git or a local path. The key is
# the leading token before `=`/`.`/whitespace. `[workspace.dependencies]` lines are included.
universe_deps=$(printf '%s\n' "$manifests" | while read -r m; do
  [ -n "$m" ] || continue
  grep -E '(github\.com/theia-hq/|[[:space:]]path[[:space:]]*=)' "$m" \
    | sed -n 's/^[[:space:]]*\([A-Za-z0-9_-]\{1,\}\)[[:space:]]*[.=].*/\1/p'
done)

UNIVERSE=$(printf '%s\n%s\n' "$universe_pkgs" "$universe_deps" | grep -v '^$' | sort -u)

# Classify each name so the check flags only genuine layering leaks, never a legitimate
# reference to the shared foundation:
#   * LOCAL   -- a package DEFINED in this tree (a co-located sibling), vs an EXTERNAL crate
#     known only as a git dependency. A crate may freely name a co-located sibling LIBRARY
#     (the substrate crates in a workspace document each other: bifrost-core points at where
#     the `Transport` seam lives, quirk describes its bifrost adapter). Naming an EXTERNAL
#     crate you do not depend on is the cross-layer leak (`measure` naming `tightbeam`).
#   * APP     -- a package whose primary product is a binary (a `src/main.rs`, Cargo's
#     application convention: `swoosh`). The application IS the consumer; NO other crate may
#     name it, even a co-located sibling (`measure`/`fetch`/`beam` must not name `swoosh`).
LOCAL_PKGS=" "
APP_PKGS=" "
for m in $manifests; do
  [ -n "$m" ] || continue
  grep -q '^\[package\]' "$m" || continue
  d=$(dirname "$m")
  nm=$(sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$m" | head -n1)
  [ -n "$nm" ] || continue
  LOCAL_PKGS="${LOCAL_PKGS}${nm} "
  [ -f "$d/src/main.rs" ] && APP_PKGS="${APP_PKGS}${nm} "
done

# ---------------------------------------------------------------------------------------
# Match a crate name only in a CRATE-REFERENCE context, never as a bare English word.
# Package names include ordinary words (`fetch`, `beam`, `measure`), which collide with
# prose ("a public download (`fetch`)", "a single measure ping"), so a bare-word or even a
# plain-backtick grep re-introduces the false positives the first version hardcoded around.
# We match ONLY forms that cannot be innocent prose:
#   * `N::`                 a module path -- only ever a reference to the crate/module N.
#   * possessive `N's`      "swoosh's registry" -- naming the crate as an actor.
#   * intra-doc link `[N]`  a rustdoc/markdown link to the crate.
#   * "N crate"             literally calling N a crate.
# Names carrying a hyphen/underscore/digit (`bifrost-core`, `bifrost-mem`, ...) are not
# English words, so for THOSE a bare identifier-boundary mention is matched too. Left/right
# identifier boundaries treat `-`/`_` as name chars, so `beam` never matches inside
# `tightbeam` and `bifrost` never inside `bifrost-core`.
# ---------------------------------------------------------------------------------------
BL='(^|[^A-Za-z0-9_-])'    # left identifier boundary
BR='([^A-Za-z0-9_-]|$)'    # right identifier boundary

fail=0
crates=0

for manifest in $manifests; do
  [ -n "$manifest" ] || continue
  grep -q '^\[package\]' "$manifest" || continue   # skip virtual workspace roots
  dir=$(dirname "$manifest")
  [ -d "$dir/src" ] || continue                     # a real crate has source
  crates=$((crates + 1))

  own=$(sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n1)

  # Files this crate owns: its manifest + every .rs under src/, tests/, examples/.
  set -- "$manifest"
  set -- "$@" $(find "$dir/src" -name '*.rs' 2>/dev/null)
  [ -d "$dir/tests" ] && set -- "$@" $(find "$dir/tests" -name '*.rs' 2>/dev/null)
  [ -d "$dir/examples" ] && set -- "$@" $(find "$dir/examples" -name '*.rs' 2>/dev/null)

  # 1. CRATE-NAME check.
  for n in $UNIVERSE; do
    [ "$n" = "$own" ] && continue
    # declared as a dependency of THIS crate? matches `n = ...`, `n.workspace = ...`.
    if grep -Eq "^[[:space:]]*${n}[[:space:]=.]" "$manifest"; then continue; fi
    # a co-located sibling LIBRARY (local, non-application) is shared foundation, nameable.
    case "$APP_PKGS" in *" $n "*) : ;; *)
      case "$LOCAL_PKGS" in *" $n "*) continue ;; esac ;;
    esac

    # Crate-reference forms (unambiguous for any name); every form carries a left
    # identifier boundary so `beam` never matches inside `tightbeam::` nor `quirk` inside
    # `bifrost_quirk::`.
    re="${BL}${n}::|${BL}${n}'s|\[${n}\]|${BL}${n} crate"
    # Hyphen/underscore/digit names are non-words: also catch a bare mention.
    case "$n" in
      *[-_0-9]*) re="${re}|${BL}${n}${BR}" ;;
    esac

    hits=$(grep -HEn "$re" "$@" 2>/dev/null | grep -v "$ALLOW_MARK" || true)
    if [ -n "$hits" ]; then
      printf 'LEAK  crate %-16s references non-dependency crate %s:\n' "$own" "$n"
      printf '%s\n' "$hits" | sed 's/^/        /'
      fail=1
    fi
  done

  # 2. FLAG check: a prime LIBRARY must not allude to a consumer CLI flag. Two surfaces name
  # flags legitimately and are derived, not listed:
  #   * An APPLICATION crate (its primary product IS the CLI) -- signalled by a `src/main.rs`
  #     (Cargo's primary-binary convention). swoosh IS the consumer; its flags are its own.
  #     Such a crate is skipped ENTIRELY.
  #   * A library that also ships an auxiliary demo binary under `src/bin/` (tightbeam) -- the
  #     library is the product and IS policed, but its `src/bin/` files are the CLI surface
  #     ("the bin's OWN flags are fine") and are excluded from THIS check only.
  if [ ! -f "$dir/src/main.rs" ]; then
    libfiles=""
    for f in "$@"; do
      case "$f" in */src/bin/*) continue ;; esac
      libfiles="$libfiles $f"
    done
    for flag in $FLAG_TOKENS; do
      # -e so the leading `--` of a flag is not read as a grep option.
      hits=$(grep -HEn -e "${flag}${BR}" $libfiles 2>/dev/null | grep -v "$ALLOW_MARK" || true)
      if [ -n "$hits" ]; then
        printf 'LEAK  crate %-16s alludes to consumer flag %s:\n' "$own" "$flag"
        printf '%s\n' "$hits" | sed 's/^/        /'
        fail=1
      fi
    done
  fi
done

if [ "$fail" -ne 0 ]; then
  printf '\nlayering-gate: FAIL -- a crate reached outside its layer (see LEAK lines above).\n' >&2
  exit 1
fi
printf 'layering-gate: OK -- %s crate(s) clean; %s crate name(s) in scope.\n' \
  "$crates" "$(printf '%s\n' "$UNIVERSE" | grep -c .)"
