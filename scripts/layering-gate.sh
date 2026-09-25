#!/bin/sh
# layering-gate.sh -- mechanical guard against layering leaks.
#
# THE RULE (STYLE.md "A library speaks only its OWN vocabulary"; audit at
# notes/reviews/layering-leak-audit.md). A layer speaks only its OWN vocabulary and never
# reaches UP to name a CONSUMER's crate or a consumer's CLI flag, in docs/comments/strings.
#
# WHY DOCS, NOT CODE. The compiler already forbids a code-level cross-crate reference: a
# crate that writes `other::Foo` or `use other` in real code without declaring that
# dependency fails to build. So checks 1-3 do NOT re-police code -- cargo does. The leaks
# that compile CLEANLY, and so survive, live in DOC COMMENTS and STRINGS ("/// like the app's
# status", `"... a handler like echo:"`). That is exactly this gate's job: a crate whose
# docs/comments/strings NAME a sibling or consumer crate it does not depend on.
#
# WHAT IT CHECKS, per crate found under ROOT:
#
#   1. CRATE-NAME check -- the crate's files reference, AS A CRATE, a sibling crate that is
#      NOT its foundation. A crate's foundation is: a declared DEPENDENCY (a downward
#      reference, always legal -- an app names the library it depends on), or a co-located
#      sibling LIBRARY in its own tree (the substrate crates in a workspace document each
#      other). A leak is naming EITHER an EXTERNAL crate you do not depend on (a service
#      crate naming a transport it does not use) OR an APPLICATION crate (a sibling library
#      naming the app that consumes it). See the classification block below.
#
#   2. FLAG check -- a prime LIBRARY (not a `src/bin/` CLI) alludes to a consumer long-flag
#      (`--for`/`--public`/`--peer`/`--authkey`/`--to`). A library owns a concept, never the
#      flag a CLI paints over it.
#
#   3. DOC COMMAND check -- a crate's docs spell a consumer's COMMAND (`<consumer> <verb>`).
#
#   4. CONSUMER-WORD check -- any tracked file but a CHANGELOG names a layer that depends on
#      this repo. The layers and their order are the one table in check 4.
#
#   5. OWN-WORDS check -- any tracked file but a CHANGELOG, in a library, uses the org's name
#      as its own word. Only the org's address may carry it.
#
#   6. HOUSE-WORD check -- any tracked file but a CHANGELOG, in a library, uses a word an app
#      coined for its own things. The words and the ordinary-English phrases that may carry one
#      are the two lines in check 6.
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
# DERIVE the crate SET (the "universe" of sibling crate names) from the manifests under ROOT.
#
# A sibling crate name enters the universe two ways:
#   (a) it is a package DEFINED in this tree      -- `name = "..."` under `[package]`.
#   (b) it is a sibling crate this tree DEPENDS ON -- a dependency whose source is a sibling
#       one: `git = "...github.com/theia-hq/..."` or a local `path = "..."`. The dependency
#       KEY is the crate name. (A `.workspace = true` dep resolves to such a line in the
#       workspace root's [workspace.dependencies], which IS scanned, so it is covered.)
# Third-party deps (`tokio = "1"`, a non-sibling git) never match (a) or (b), so they never
# enter the universe and never trip the check.
#
# Scanning is over EVERY Cargo.toml under ROOT. This gate is meant to run PER REPO (as CI and
# the umbrella `just gate` both do): the universe is that repo's own crates plus the sibling
# crates it depends on. A dependency crate from another repo enters the universe as an
# EXTERNAL name, which is what makes a sibling that does not depend on it naming it a
# detectable leak.
#
# RESIDUAL LIMITATION. A lower repo naming a consumer that lives ABOVE it, in a repo it does
# not depend on, is not derivable from its manifests; check 4 closes it with the LAYERS table.
# ---------------------------------------------------------------------------------------

manifests=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/_archived/*' | sort)

# (a) package names.
universe_pkgs=$(printf '%s\n' "$manifests" | while read -r m; do
  [ -n "$m" ] || continue
  grep -q '^\[package\]' "$m" || continue
  sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$m" | head -n1
done)

# (b) sibling dependency keys: a dep line pointing at a sibling git or a local path. The key is
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
#     (the substrate crates in a workspace document each other: a core crate points at where
#     a trait lives, an adapter crate describes what it adapts). Naming an EXTERNAL crate you
#     do not depend on is the cross-layer leak (a service crate naming a transport it skips).
#   * APP     -- a package whose primary product is a binary (a `src/main.rs`, Cargo's
#     application convention). The application IS the consumer; NO other crate may name it,
#     even a co-located sibling library.
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
# Package names can be ordinary English words, which collide with prose ("a crate called
# `ping`" next to "a single ping"), so a bare-word or even a
# plain-backtick grep re-introduces the false positives the first version hardcoded around.
# We match ONLY forms that cannot be innocent prose:
#   * `N::`                 a module path -- only ever a reference to the crate/module N.
#   * possessive `N's`      "the app's registry" -- naming the crate as an actor.
#   * intra-doc link `[N]`  a rustdoc/markdown link to the crate.
#   * "N crate"             literally calling N a crate.
# Names carrying a hyphen/underscore/digit (`name-core`, `name-mem`, ...) are not English
# words, so for THOSE a bare identifier-boundary mention is matched too. Left/right
# identifier boundaries treat `-`/`_` as name chars, so `core` never matches inside
# `name-core` and `name` never inside `name_core`.
# ---------------------------------------------------------------------------------------
BL='(^|[^A-Za-z0-9_-])'    # left identifier boundary
BR='([^A-Za-z0-9_-]|$)'    # right identifier boundary

# extract_code_contexts DOC -- emit only the parts of a Markdown doc where a COMMAND can
# live, so the doc command-pattern check (3 below) never fires on prose. A `<consumer>
# <verb>` inside a code fence or an inline `backtick` span is unambiguously a command; the
# same words in a sentence ("the app is a tool") are a description and must pass. Each emitted
# line is `<orig-lineno><TAB><code-text>`, so the caller recovers the true file:line. The
# lineno is always BEFORE the first tab, and the tab that separates it doubles as a left word
# boundary, so a name at the very start of a span still binds. Pure awk, no dependencies.
extract_code_contexts() {
  awk '
    # A fence line (```, ```sh, ~~~, ...) toggles block state and is itself never scanned.
    /^[[:space:]]*(```|~~~)/ { in_fence = !in_fence; next }
    in_fence { print NR "\t" $0; next }
    {
      # Outside a fence, only the contents of inline `...` spans are command contexts.
      rest = $0
      while (match(rest, /`[^`]*`/)) {
        print NR "\t" substr(rest, RSTART + 1, RLENGTH - 2)
        rest = substr(rest, RSTART + RLENGTH)
      }
    }
  ' "$1"
}

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
    # identifier boundary so `core` never matches inside `name-core::` nor inside
    # `name_core::`.
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
  #     (Cargo's primary-binary convention), or in this repo's copy by a bin tree named for the
  #     package, `src/bin/<package>/main.rs`, the app's own layout. The app IS the consumer; its
  #     flags are its own. Such a crate is skipped ENTIRELY.
  #   * A library that also ships an auxiliary demo binary under `src/bin/` -- the
  #     library is the product and IS policed, but its `src/bin/` files are the CLI surface
  #     ("the bin's OWN flags are fine") and are excluded from THIS check only.
  if [ ! -f "$dir/src/main.rs" ] && [ ! -f "$dir/src/bin/$own/main.rs" ]; then
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

  # 3. DOC COMMAND-PATTERN check: a library's README/docs may POINT at a real consumer (a
  # link, or the crate name in prose) but must never SPELL its COMMANDS. The distinction is
  # deliberate: a NAME/LINK is a signpost; a NAME followed by a SUBCOMMAND (`app serve`,
  # `... | app serve cam=stdin`, `app ssh`) adopts the consumer's command grammar and
  # rots when a verb is renamed or another consumer arrives. Code (checks 1/2 + the compiler)
  # is already policed; DOCS were the blind spot that let an `app serve` example sit in a
  # README behind a green gate.
  #
  # Scope, per crate (mirroring how checks 1/2 scope to a crate's own files): the crate's own
  # `*.md` directly under its dir, plus a `docs/` tree if present. A repo/workspace root that
  # is not itself a crate (no `[package]`) is skipped by the outer loop, so its README is out
  # of scope here, same as today.
  docs=$(find "$dir" -maxdepth 1 -name '*.md' \
    -not -path '*/target/*' -not -path '*/_archived/*' 2>/dev/null)
  if [ -d "$dir/docs" ]; then
    docs="$docs
$(find "$dir/docs" -name '*.md' -not -path '*/target/*' -not -path '*/_archived/*' 2>/dev/null)"
  fi

  for doc in $docs; do
    [ -f "$doc" ] || continue

    # 3b. Derive the consumer names to police FROM THE DOC ITSELF: any sibling crate the doc
    # LINKS to (`github.com/theia-hq/N`). Nothing is hardcoded, so a doc that links no
    # consumer polices none, and a bare name that shares a word with prose never trips. From
    # that link set, drop this crate's OWN foundation: its own name, a co-located sibling
    # LIBRARY (`LOCAL_PKGS`, shared substrate), and any DECLARED DEPENDENCY (a downward link,
    # always legal -- a library's README links the crates it depends on). What survives is a
    # genuine CONSUMER the doc points UP at, the only thing a library must not
    # overfit its docs to.
    linknames=$(grep -oE 'github\.com/theia-hq/[A-Za-z0-9_-]+' "$doc" 2>/dev/null \
      | sed 's#.*/theia-hq/##' | sort -u)

    for n in $linknames; do
      [ -n "$n" ] || continue
      [ "$n" = "$own" ] && continue
      case "$LOCAL_PKGS" in *" $n "*) continue ;; esac
      if grep -Eq "^[[:space:]]*${n}[[:space:]=.]" "$manifest"; then continue; fi

      # 3c/3d. Flag `<consumer> <verb>` (a name then one-or-more spaces then a lowercase verb
      # token) ONLY inside a code context (fence or inline span), where it is unambiguously a
      # command. `extract_code_contexts` already stripped prose, so the pointer carve-out
      # falls out for free -- no stopword list. `ffmpeg | app serve ...` still matches on
      # its `app serve` tail; the pipeline prefix is irrelevant.
      hits=$(extract_code_contexts "$doc" \
        | grep -E "${BL}${n}[[:space:]]+[a-z][a-z0-9-]*" 2>/dev/null || true)
      [ -n "$hits" ] || continue

      # Report per surviving original line, honoring a same-line `layering-gate:allow` marker
      # on the ORIGINAL doc line (the extracted context may not carry it, so re-read the
      # source line). The header names the first offending `<consumer> <verb>`.
      reported=""
      first=""
      for L in $(printf '%s\n' "$hits" | sed 's/	.*//' | grep -E '^[0-9]+$' | sort -un); do
        orig=$(sed -n "${L}p" "$doc")
        case "$orig" in *"$ALLOW_MARK"*) continue ;; esac
        if [ -z "$first" ]; then
          first=$(printf '%s' "$orig" | grep -oE "${n}[[:space:]]+[a-z][a-z0-9-]*" | head -n1)
        fi
        reported="${reported}${doc}:${L}: ${orig}
"
      done
      if [ -n "$reported" ]; then
        printf 'LEAK  crate %-16s spells consumer command pattern "%s" in docs:\n' \
          "$own" "${first:-$n <verb>}"
        printf '%s' "$reported" | sed 's/^/        /'
        fail=1
      fi
    done
  done
done

# 4. CONSUMER-WORD check: a repo names no layer that depends on it, anywhere but a CHANGELOG
# (LAYERS.md placement test 3). Downstream may name upstream, never the reverse.
#
# LAYERS is the family's one table, lowest first. Each row is a kind (`lib` for a library, `app`
# for a program built on the libraries), a layer, the DISTINCTIVE words that name it (never a
# common English word that prose would trip on), and the layers it depends on directly, as its
# Cargo.toml declares them (a layer with no manifest lists what it runs). This repo finds its own row by the package its root Cargo.toml defines, or for a
# virtual workspace a package among its members, and forbids the words of every layer that
# depends on it, directly or through another layer. A layer it depends on is never forbidden.
#
# Every tracked file is scanned but a CHANGELOG, its lines and its path. A word matches in any
# case with any non-alphanumeric character (`-` and `_` included) as a boundary, and also as
# one hump of an identifier: for a word `word`, `WordLink`, `myWord`, `wordX` and `WORD2`. A
# git failure fails the gate, since the scan would be incomplete. The rows below are the only
# lines exempt, and only in this file: every other line here, comments included, is checked
# like any file. The same-line allow marker is NOT honored. A new layer is one row in every copy.
LAYERS='
lib nauthy    | nauthy       |
lib quirk     | quirk        |
lib bifrost   | bifrost      | quirk
lib tightbeam | tightbeam    | bifrost nauthy
lib services  | sshh         | bifrost nauthy tightbeam
app swoosh    | swoosh sheer | bifrost nauthy services tightbeam
app qat       | qat          | swoosh
'
LAYER_ROW='^(lib|app) [a-z]+ +\| [a-z ]+\|[a-z ]*$'

# layer_field NAME COL -- column COL (1 kind, 2 words, 3 deps) of layer NAME's row.
layer_field() {
  printf '%s\n' "$LAYERS" | awk -F'|' -v n="$1" -v c="$2" '{
    split($1, a, " ")
    if ((a[1] == "lib" || a[1] == "app") && a[2] == n) print (c == 1 ? a[1] : $c)
  }'
}
layer_names=$(printf '%s\n' "$LAYERS" | awk '$1 == "lib" || $1 == "app" { print $2 }')

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
# git_ok WHAT STATUS MAX_OK -- a git read that exited above MAX_OK or wrote to stderr fails the
# gate.
git_ok() {
  if [ "$2" -gt "$3" ] || [ -s "$scratch/err" ]; then
    printf 'LEAK  %s failed (exit %s), so the scan is incomplete:\n' "$1" "$2"
    sed 's/^/        /' "$scratch/err"
    fail=1
  fi
}

# The packages the root manifest defines: its own `[package]`, or its workspace members'.
root_pkgs=""
if [ -f "$ROOT/Cargo.toml" ]; then
  root_entries=$(awk '
    /^\[/ { sec = $0; inm = 0 }
    sec == "[package]" && /^name[[:space:]]*=/ {
      s = $0; sub(/^[^"]*"/, "", s); sub(/".*/, "", s); print "pkg " s }
    sec == "[workspace]" && /^members[[:space:]]*=/ { inm = 1 }
    inm {
      s = $0
      while (match(s, /"[^"]*"/)) { print "dir " substr(s, RSTART + 1, RLENGTH - 2); s = substr(s, RSTART + RLENGTH) }
      if ($0 ~ /\]/) inm = 0
    }
  ' "$ROOT/Cargo.toml")
  for e in $(printf '%s\n' "$root_entries" | tr ' ' '='); do
    case "$e" in
      pkg=*) root_pkgs="$root_pkgs ${e#pkg=}" ;;
      dir=*)
        for d in "$ROOT"/${e#dir=}; do
          [ -f "$d/Cargo.toml" ] || continue
          root_pkgs="$root_pkgs $(sed -n '/^\[package\]/,/^\[/s/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$d/Cargo.toml" | head -n1)"
        done ;;
    esac
  done
fi

own_layer=""
for l in $layer_names; do
  for w in $(layer_field "$l" 2); do
    case " $root_pkgs " in *" $w "*)
      if [ -n "$own_layer" ] && [ "$own_layer" != "$l" ]; then
        printf 'LEAK  check 4: the root manifest matches two layers (%s, %s)\n' "$own_layer" "$l"
        fail=1
      fi
      own_layer=$l ;;
    esac
  done
done

if [ -z "$own_layer" ]; then
  printf 'LEAK  check 4: no LAYERS row names a package of %s/Cargo.toml (%s)\n' "$ROOT" "${root_pkgs# }"
  fail=1
else
  # Every layer that depends on this one, directly or through another: grow the set to a fixpoint.
  above=" $own_layer "
  while :; do
    before=$above
    for l in $layer_names; do
      case "$above" in *" $l "*) continue ;; esac
      for d in $(layer_field "$l" 3); do
        case "$above" in *" $d "*) above="$above$l "; break ;; esac
      done
    done
    [ "$above" = "$before" ] && break
  done
  forbidden=""
  for l in $above; do
    [ "$l" = "$own_layer" ] && continue
    forbidden="$forbidden $(layer_field "$l" 2)"
  done
  forbidden=$(printf '%s\n' $forbidden | sort -u | tr '\n' ' ' | sed 's/ $//')
  printf 'layering-gate: check 4: layer %s forbids: %s\n' "$own_layer" "${forbidden:-(nothing)}"

  if [ -n "$forbidden" ]; then
    if ! git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
      printf 'LEAK  check 4: %s is not a git checkout, so its tracked files cannot be read\n' "$ROOT"
      fail=1
    else
      # A word on its own, in any case: `word`, `Word-x`, `WORD_HOME`.
      bounded="(^|[^A-Za-z0-9])($(printf '%s' "$forbidden" | tr ' ' '|'))([^A-Za-z0-9]|\$)"
      # A word as one hump of an identifier, case-sensitive: `WordLink`, `myWord`, `wordX`,
      # `WORD2`.
      humped=""
      for w in $forbidden; do
        cap=$(printf '%s' "$w" | cut -c1 | tr '[:lower:]' '[:upper:]')$(printf '%s' "$w" | cut -c2-)
        up=$(printf '%s' "$w" | tr '[:lower:]' '[:upper:]')
        humped="$humped|${cap}[A-Z0-9]|[a-z0-9]${cap}|${w}[A-Z0-9]|${up}[A-Z0-9]"
      done
      humped=${humped#|}

      # Lines. git grep reads tracked paths itself, so a name with a space or a newline is never
      # split. It exits 0 on a match, 1 on none, and above 1 on an error. --text reads every file
      # as text, so a path marked binary in .gitattributes is scanned too.
      # grep_lines CASE PATTERN -- add the tracked lines, CHANGELOGs aside, that match to hits.
      hits=""
      grep_lines() {
        st=0
        out=$(git -C "$ROOT" grep --text -n "$1" -E -e "$2" \
          -- . ':(exclude,glob)**/CHANGELOG.md' 2>"$scratch/err") || st=$?
        git_ok "check 4: git grep" "$st" 1
        hits="$hits
$out"
      }
      grep_lines --ignore-case "$bounded"
      grep_lines --no-ignore-case "$humped"
      hits=$(printf '%s\n' "$hits" | grep . \
        | grep -v -E "^scripts/layering-gate\.sh:[0-9]+:${LAYER_ROW#^}" \
        | sort -t: -k1,1 -k2,2n -u || true)
      if [ -n "$hits" ]; then
        printf 'LEAK  this repo names a layer that depends on it (%s):\n' "$forbidden"
        printf '%s\n' "$hits" | sed 's/^/        /'
        fail=1
      fi

      # Paths. NUL-separated, so a newline in a name splits it into pieces that are each checked.
      st=0
      git -C "$ROOT" ls-files -z -- . ':(exclude,glob)**/CHANGELOG.md' \
        >"$scratch/paths" 2>"$scratch/err" || st=$?
      git_ok "check 4: git ls-files" "$st" 0
      tr '\0' '\n' <"$scratch/paths" >"$scratch/lines"
      paths=$( { grep -i -E -e "$bounded" "$scratch/lines"; grep -E -e "$humped" "$scratch/lines"; } \
        | sort -u || true)
      if [ -n "$paths" ]; then
        printf 'LEAK  a tracked path names a layer that depends on this repo (%s):\n' "$forbidden"
        printf '%s\n' "$paths" | sed 's/^/        /'
        fail=1
      fi
    fi
  fi
fi

# 5. OWN-WORDS check: a library speaks its own words (LAYERS.md placement test 3). The org's
# name, ORG below, is the org's word, never a library's: a library's wire, key, file and env
# names and its prose use its own crate's name. It matches as a substring in any case, so
# `_org`, `ORGKEY` and `ORG_HOME` are all caught, after the org's address (ORG then `-hq`) is
# removed from each line. Every tracked file is scanned but a CHANGELOG, its lines and its path.
# The ORG line is the only line exempt, and only in this file. An `app` row is skipped: a program
# built on the libraries may use any word. A repo no row names is scanned.
ORG='theia'
ORG_LINE="^ORG='[a-z]+'\$"

# own_org_hits -- read lines on stdin, print each whose text (after any `path:line:` prefix)
# still holds ORG once every ORG-hq is removed.
own_org_hits() {
  awk -v w="$ORG" -v p="$1" '{
    l = tolower($0)
    if (p) sub(/^[^:]*:[0-9]+:/, "", l)
    gsub(w "-hq", "", l)
    if (index(l, w)) print
  }'
}

if [ -n "$own_layer" ] && [ "$(layer_field "$own_layer" 1)" = app ]; then
  printf 'layering-gate: check 5: layer %s is an app, skipped\n' "$own_layer"
elif ! git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  printf 'LEAK  check 5: %s is not a git checkout, so its tracked files cannot be read\n' "$ROOT"
  fail=1
else
  st=0
  out=$(git -C "$ROOT" grep --text -n --ignore-case -F -e "$ORG" \
    -- . ':(exclude,glob)**/CHANGELOG.md' 2>"$scratch/err") || st=$?
  git_ok "check 5: git grep" "$st" 1
  hits=$(printf '%s\n' "$out" | grep . \
    | grep -v -E "^scripts/layering-gate\.sh:[0-9]+:${ORG_LINE#^}" \
    | own_org_hits 1 || true)
  if [ -n "$hits" ]; then
    printf 'LEAK  this repo uses the org name as its own word (only %s-hq is allowed):\n' "$ORG"
    printf '%s\n' "$hits" | sed 's/^/        /'
    fail=1
  fi

  st=0
  git -C "$ROOT" ls-files -z -- . ':(exclude,glob)**/CHANGELOG.md' \
    >"$scratch/paths" 2>"$scratch/err" || st=$?
  git_ok "check 5: git ls-files" "$st" 0
  paths=$(tr '\0' '\n' <"$scratch/paths" | own_org_hits "" || true)
  if [ -n "$paths" ]; then
    printf 'LEAK  a tracked path uses the org name (only %s-hq is allowed):\n' "$ORG"
    printf '%s\n' "$paths" | sed 's/^/        /'
    fail=1
  fi
fi

# 6. HOUSE-WORD check: a library speaks its own words, never an app's coinage for the things it
# builds from them (design/crate-independence-enforcement.md). HOUSE below lists those words. A
# word matches in any case with any non-alphanumeric character (`-` and `_` included) as a
# boundary, with or without a plural `s`, and also as one hump of an identifier: for a word
# `word`, `WordLink`, `myWord`, `wordX` and `WORD2`. A word run into lowercase letters is other
# English and passes. HOUSE_OK lists, comma-separated, the ordinary-English phrases that carry a
# word in its everyday sense; each is removed from a line, in any case, before the line is matched.
# Every tracked file is scanned but a CHANGELOG, its lines and its path. The two lines below are
# the only lines exempt, and only in this file. An `app` row is skipped: the app is where the
# words are coined. A repo no row names is scanned.
HOUSE='signet fleet'
HOUSE_OK="relay fleet,n0's fleet"
HOUSE_LINE="^HOUSE(_OK)?=['\"][a-z0-9' ,]+['\"]\$"

# house_hits PREFIXED -- read lines on stdin, print each whose text (after any `path:line:`
# prefix, when PREFIXED is set) holds a HOUSE word once every HOUSE_OK phrase is removed.
house_hits() {
  awk -v words="$HOUSE" -v ok="$HOUSE_OK" -v p="$1" '
  BEGIN {
    nw = split(words, w, " ")
    no = split(ok, phrase, ",")
    alt = ""
    hump = ""
    for (i = 1; i <= nw; i++) {
      cap = toupper(substr(w[i], 1, 1)) substr(w[i], 2)
      alt = alt (i > 1 ? "|" : "") w[i]
      hump = hump (i > 1 ? "|" : "") cap "[A-Z0-9]|[a-z0-9]" cap "|" w[i] "[A-Z0-9]|" toupper(w[i]) "[A-Z0-9]"
    }
    bounded = "(^|[^a-z0-9])(" alt ")s?([^a-z0-9]|$)"
  }
  {
    t = $0
    if (p) sub(/^[^:]*:[0-9]+:/, "", t)
    low = tolower(t)
    for (i = 1; i <= no; i++) {
      n = length(phrase[i])
      while ((at = index(low, phrase[i])) > 0) {
        blank = sprintf("%" n "s", "")
        t = substr(t, 1, at - 1) blank substr(t, at + n)
        low = substr(low, 1, at - 1) blank substr(low, at + n)
      }
    }
    if (low ~ bounded || t ~ hump) print
  }'
}

if [ -n "$own_layer" ] && [ "$(layer_field "$own_layer" 1)" = app ]; then
  printf 'layering-gate: check 6: layer %s is an app, skipped\n' "$own_layer"
elif ! git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  printf 'LEAK  check 6: %s is not a git checkout, so its tracked files cannot be read\n' "$ROOT"
  fail=1
else
  st=0
  out=$(git -C "$ROOT" grep --text -n --ignore-case -E -e "$(printf '%s' "$HOUSE" | tr ' ' '|')" \
    -- . ':(exclude,glob)**/CHANGELOG.md' 2>"$scratch/err") || st=$?
  git_ok "check 6: git grep" "$st" 1
  hits=$(printf '%s\n' "$out" | grep . \
    | grep -v -E "^scripts/layering-gate\.sh:[0-9]+:${HOUSE_LINE#^}" \
    | house_hits 1 || true)
  if [ -n "$hits" ]; then
    printf 'LEAK  this repo uses an app'"'"'s house word (%s):\n' "$HOUSE"
    printf '%s\n' "$hits" | sed 's/^/        /'
    fail=1
  fi

  st=0
  git -C "$ROOT" ls-files -z -- . ':(exclude,glob)**/CHANGELOG.md' \
    >"$scratch/paths" 2>"$scratch/err" || st=$?
  git_ok "check 6: git ls-files" "$st" 0
  paths=$(tr '\0' '\n' <"$scratch/paths" | house_hits "" || true)
  if [ -n "$paths" ]; then
    printf 'LEAK  a tracked path uses an app'"'"'s house word (%s):\n' "$HOUSE"
    printf '%s\n' "$paths" | sed 's/^/        /'
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  printf '\nlayering-gate: FAIL -- a crate reached outside its layer (see LEAK lines above).\n' >&2
  exit 1
fi
printf 'layering-gate: OK -- %s crate(s) clean; %s crate name(s) in scope.\n' \
  "$crates" "$(printf '%s\n' "$UNIVERSE" | grep -c .)"
