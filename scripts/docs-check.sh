#!/bin/sh
# docs-check.sh -- the docs freshness checker, slice 1: --lint and --self-test.
#
# THE RULE (notes/design/DOCS-MODEL.md sections 4-5; this script is its mechanical half). Every
# fenced block that shows a command or its output carries exactly ONE marker from five closed
# states, the marker binds to the fenced block that follows it, and the checker accounts for
# every marker: checked + listed + manual + pending == markers found, per page. A fenced block
# with a `$ ` prompt (or an `Error:` line) and no marker fails. The grammar is total: every
# marker lands on exactly one verdict, and a malformed marker fails the coverage equation
# instead of passing quietly.
#
# THE FIVE STATES (DOCS-MODEL section 4):
#   <!-- generated: <command-path> -->         parser-derived content; the renderer regenerates it
#   <!-- capture: [home=<label> ]<argv> -->    a shown transcript the runner re-runs and diffs
#   <!-- live-run: <what varies> -->           captured output that cannot be pinned; listed
#   <!-- pending live-run: <what is needed> --> not captured yet; release-fatal, lint-clean
#   <!-- manual: <reason> -->                  a shown command this harness cannot execute; counted
#
# THE COVERAGE INVARIANT (DOCS-MODEL section 4; the one check the design says not to cut):
#   found      = the loose five-state marker count, per file
#   classified = the structured parser's verdicts, per file
#   require classified == found, or COVERAGE <file>: found N markers, classified M
# A malformed marker of a known state is counted loosely and refused strictly, so the equation
# fails and the run exits 1 instead of passing quietly. The self-test pins that vector.
#
# WHAT --lint CHECKS (no toolchain, no build, no execution):
#   EMDASH   U+2014 anywhere in the tracked corpus (M1)
#   PROCESS  process language in product docs (M2; the STYLE.md contract itself is exempt)
#   PAYLOAD  marker payload grammar: executable argv, no prose, no placeholders (M3)
#   UNKNOWN / ORPHAN / DOUBLE / UNMARKED / COVERAGE   the marker binding rules (M3)
#   LINK / ANCHOR   every relative link resolves; every #anchor exists in its target (M5)
#   SECRET   a full-length invite:/swoosh: literal in expected text
#   plus the census and the coverage invariant above
#
# WHAT IT DOES NOT DO YET (the spec's later slices; those modes refuse instead of passing, so a
# mode typo cannot look green):
#   --generated  regenerate + byte-diff the generated blocks (slice 2, the renderer)
#   --tier1      re-run and diff every capture (slice 3, the runner)
#   --release    fail on pending live-run, print the tier-2 list (slice 4)
#   --examples   the examples runner where examples/ exists (slice 4)
#   --bless      rewrite a capture from an actual run (slice 3; local only, never CI)
# The spec's 21-row failure table maps here as: today's lanes are COVERAGE (vacuous pass), UNMARKED
# (unmarked output block, and a new block shrinking coverage), ORPHAN, DOUBLE, PAYLOAD, UNKNOWN,
# SECRET, SELF-TEST (harness rot), and the census line (version skew: commit + branch). Generated
# drift, capture drift, wrong status, blocked command, flake, platform drift, bless abuse,
# release-blocked, and the tier-2 list land with their modes; network creep and shell injection
# are by construction (CI never dials; only tracked files are ever read).
#
# CORPUS (spec 2.1 rule 8). `git ls-files '*.md'` at ROOT, minus target/, _archived/, .github/,
# scripts/fixtures/, and scripts/docs-check-fixtures/ (the self-test vectors are not product
# docs; the spec's exclusion list predates the vector home this script needs). Untracked files
# are outside the corpus; CI checks the PR checkout.
#
# Dependency-free: POSIX sh + git + awk + grep/sed. Run from a repo root:
#   sh scripts/docs-check.sh --lint .
#   sh scripts/docs-check.sh --self-test
#
# Exit: 0 clean; 1 findings or a stub mode; 2 usage.

set -eu

# The em dash is written as its three UTF-8 bytes so no em dash literal lives in this file.
EMDASH=$(printf '\342\200\224')
# M2's banned list (DOCS-MODEL section 5): process language in product docs.
PROCESS_RE='delib-[0-9]|deliberation|SYNTHESIS|DOC-VOICE|STYLE\.md|panel|sweep|PR #[0-9]'
# A full-length invite/swoosh token (32-byte seed, 52 base32 chars); truncated `invite:…` is not.
SECRET_RE='(invite|swoosh):[a-z2-7]{40,}'

usage() {
    printf 'usage: sh scripts/docs-check.sh --lint [ROOT] | --self-test\n' >&2
}

not_built() {
    printf 'NOT-BUILT: %s needs %s (slice %s); this slice is lint-only\n' "$1" "$2" "$3" >&2
    exit 1
}

# analyze_file LABEL PATH -- the structured parser, findings to stderr, one @@SUM line to stdout.
# LABEL is the file path as the writer sees it (corpus-relative); PATH is where to read it.
analyze_file() {
    awk -v file="$1" '
    function isblank(s) { return s ~ /^[ \t]*$/ }
    function ismarker(s) { return s ~ /^<!-- (generated|capture|live-run|pending live-run|manual):/ }
    function isstrict(s) { return s ~ /^<!-- (generated|capture|live-run|pending live-run|manual): .+ -->$/ }
    function isfence(s) { return s ~ /^```/ }
    function isclose(s) { return s ~ /^```[ \t]*$/ }
    function stateof(s, t) { t = s; sub(/^<!-- /, "", t); sub(/:.*/, "", t); return t }
    function payloadof(s, p) { p = substr(s, index(s, ": ") + 2); sub(/ -->$/, "", p); return p }
    function report(tok, line, msg) {
        printf "%s %s:%d: %s\n", tok, file, line, msg > "/dev/stderr"
    }
    # A capture payload is one executable argv: an optional home= binding, then a program and its
    # arguments, explicit. Prose, elisions, shell metacharacters, and angle placeholders all mean
    # the runner could not execute it as written, which is what the state promises.
    function checkpayload(st, pay, line,   p, prog) {
        if (pay ~ /^[ \t]*$/) { report("PAYLOAD", line, "empty payload"); return }
        if (index(pay, "-->") > 0) { report("PAYLOAD", line, "payload contains -->"); return }
        if (st != "capture") return
        p = pay
        if (p ~ /^home=/) {
            if (p ~ /^home=(server|member|stranger|fresh) /) { sub(/^home=[a-z]+ /, "", p) }
            else { report("PAYLOAD", line, "home= label must be server|member|stranger|fresh"); return }
        }
        if (p ~ /…/) { report("PAYLOAD", line, "ellipsis in an executable payload"); return }
        if (p ~ /[()]/) { report("PAYLOAD", line, "parenthetical prose in the payload"); return }
        if (p ~ /[;&|]/) { report("PAYLOAD", line, "shell metacharacter in the payload"); return }
        if (index(p, "`") > 0) { report("PAYLOAD", line, "backtick in the payload"); return }
        if (index(p, "$(") > 0) { report("PAYLOAD", line, "command substitution in the payload"); return }
        if (p ~ /<[^>]*>/) { report("PAYLOAD", line, "angle placeholder in the payload"); return }
        prog = p; sub(/ .*/, "", prog)
        if (prog != "swoosh" && prog != "scripts/demo.sh") {
            report("PAYLOAD", line, "program must be swoosh or scripts/demo.sh")
        }
    }

    { n++; L[n] = $0 }

    END {
        # Pass 1: the loose marker count. This is "markers found"; it deliberately accepts the
        # keyword-and-colon prefix so a malformed marker shows up as an equation mismatch.
        for (i = 1; i <= n; i++) {
            if (ismarker(L[i])) { found++ }
        }

        # Pair fences, and flag the output-bearing ones: a console/sh/bash block whose body shows
        # a `$ ` prompt or an `Error:` line. Only those carry the exactly-one-marker obligation.
        inf = 0; op = 0; consolen = 0
        for (i = 1; i <= n; i++) {
            if (inf) {
                if (isclose(L[i])) { inf = 0 }
                else if (L[i] ~ /^\$ / || L[i] ~ /^Error:/) { ob[op] = 1 }
            } else if (isfence(L[i])) {
                inf = 1; op = i; opened[i] = 1
                tag = substr(L[i], 4); sub(/[ \t]+$/, "", tag)
                if (tag == "console") { consolen++; shell[i] = 1 }
                else if (tag == "sh" || tag == "bash") { shell[i] = 1 }
            }
        }

        # Pass 2: classify every marker, and never skip one. A strict marker gets a verdict even
        # when its payload is bad. A known-state line that is not strict gets no verdict; the
        # coverage equation below is what catches it. An unknown keyword is always a failure.
        for (i = 1; i <= n; i++) {
            if (!ismarker(L[i])) {
                if (L[i] ~ /^<!-- [a-z][a-z0-9-]*( live-run)?: /) {
                    report("UNKNOWN", i, stateof(L[i]) " is not one of the five states")
                }
                continue
            }
            if (isstrict(L[i])) {
                st = stateof(L[i])
                classified++
                if (st == "generated") ng++
                else if (st == "capture") nc++
                else if (st == "live-run") nl++
                else if (st == "pending live-run") np++
                else if (st == "manual") nm++
                marker[i] = st
                checkpayload(st, payloadof(L[i]), i)
            }
        }

        # Bind markers to fences. A run of markers (only blanks between) binds as a unit to the
        # fence that follows it: the first claims the block, the rest are DOUBLE. A marker whose
        # run is not followed by a fence is an orphan for every state.
        i = 1
        while (i <= n) {
            if (marker[i] == "") { i++; continue }
            r = i; rn = 1; run[1] = i
            while (1) {
                k = r + 1
                while (k <= n && isblank(L[k])) k++
                if (k <= n && marker[k] != "") { r = k; rn++; run[rn] = k } else break
            }
            j = r + 1
            while (j <= n && isblank(L[j])) j++
            if (j <= n && opened[j]) {
                for (q = 1; q <= rn; q++) {
                    mq = marker[run[q]]
                    if (mq == "capture" && !shell[j]) { report("PAYLOAD", run[q], "capture: binds a console/sh/bash fence") }
                    if (mq == "generated" && shell[j]) { report("PAYLOAD", run[q], "generated: binds a plain usage fence") }
                }
                if (claimed[j] != "") {
                    for (q = 1; q <= rn; q++) { printf "DOUBLE %s:%d: block already claimed at %s:%d\n", file, run[q], file, claimed[j] > "/dev/stderr" }
                } else {
                    claimed[j] = i
                    for (q = 2; q <= rn; q++) { printf "DOUBLE %s:%d: block already claimed at %s:%d\n", file, run[q], file, i > "/dev/stderr" }
                }
            } else {
                for (q = 1; q <= rn; q++) { report("ORPHAN", run[q], marker[run[q]] " marker binds no fenced block") }
            }
            i = r + 1
        }

        # Coverage shrinkage: an output-bearing block no marker claims. This fires on every new
        # silent block, which is what makes the gate worth having.
        for (i = 1; i <= n; i++) {
            if (opened[i] && shell[i] && ob[i] && claimed[i] == "") {
                report("UNMARKED", i, "output-bearing block has no marker")
            }
        }

        # The invariant: the loose scan and the structured parser must agree, or some marker was
        # neither classified nor refused loudly. No silent pass.
        if (found != classified) {
            printf "COVERAGE %s: found %d markers, classified %d\n", file, found, classified > "/dev/stderr"
        }

        printf "@@SUM %s %d %d %d %d %d %d %d %d\n", file, found, classified, consolen, ng, nc, nl, np, nm
    }
    ' "$2"
}

# The corpus checks below append to $TMP/findings; $TMP is set by the mode before any of them run.

# M1: no em dash anywhere in the tracked corpus.
check_em_dash() {
    LC_ALL=C grep -n -F -e "$EMDASH" "$2" 2>/dev/null | while IFS=: read -r ln _; do
        printf 'EMDASH %s:%s: em dash is banned\n' "$1" "$ln" >> "$TMP/findings"
    done
    return 0
}

# M2: no process language in product docs. STYLE.md is the code contract, not a product surface;
# it names itself by construction, so it is exempt from its own ban list.
check_process() {
    case "$1" in
        STYLE.md) return 0 ;;
    esac
    LC_ALL=C grep -nE -e "$PROCESS_RE" "$2" 2>/dev/null | while IFS=: read -r ln rest; do
        printf 'PROCESS %s:%s: process language in a product doc:%s\n' "$1" "$ln" "$rest" >> "$TMP/findings"
    done
    return 0
}

# The anchor set of a tracked file: explicit <a id>/<a name> anchors plus GitHub-style heading
# slugs. Cached per file in $TMP because several link sites can point at the same target.
slugs_of() {
    cache="$TMP/slug.$(printf '%s' "$1" | tr / %)"
    if [ ! -f "$cache" ]; then
        awk '
        {
            s = $0
            while (match(s, /<a (id|name)="[^"]*"/)) {
                a = substr(s, RSTART, RLENGTH)
                sub(/^<a (id|name)="/, "", a); sub(/"$/, "", a)
                print a
                s = substr(s, RSTART + RLENGTH)
            }
            if ($0 ~ /^#{1,6}[ \t]/) {
                h = $0
                sub(/^#+[ \t]+/, "", h)
                gsub(/`/, "", h)
                gsub(/<[^>]*>/, "", h)
                gsub(/\]\([^)]*\)/, "", h)
                gsub(/\[/, "", h)
                h = tolower(h)
                gsub(/[^a-z0-9 _-]/, "", h)
                gsub(/ /, "-", h)
                print h
            }
        }
        ' "$ROOT/$1" > "$cache"
    fi
    cat "$cache"
}

# M5: every relative link resolves, and every #anchor exists in its target. Absolute URLs are out
# of reach on purpose (CI never dials); the lint checks the repo's own graph only.
check_links() {
    lf="$1"; lp="$2"
    awk '
    {
        line = $0; pos = 1
        while (match(substr(line, pos), /\]\([^)]*\)/)) {
            print NR "\t" substr(line, pos + RSTART + 1, RLENGTH - 3)
            pos = pos + RSTART + RLENGTH - 1
        }
    }
    ' "$lp" > "$TMP/links"
    while IFS="$(printf '\t')" read -r ln target; do
        case "$target" in
            '<'*'>') target=${target#<}; target=${target%>} ;;
        esac
        case "$target" in
            ''|http://*|https://*|mailto:*|ftp://*|//*) continue ;;
            *' '*) continue ;;
        esac
        anchor=""
        case "$target" in
            *'#'*) anchor=${target#*#}; pathpart=${target%%#*} ;;
            *) pathpart=$target ;;
        esac
        if [ -n "$pathpart" ]; then
            resolved="$(dirname "$lf")/$pathpart"
            if [ ! -e "$ROOT/$resolved" ]; then
                printf 'LINK %s:%s: %s does not resolve\n' "$lf" "$ln" "$target" >> "$TMP/findings"
                continue
            fi
            target_file="$resolved"
        else
            target_file="$lf"
        fi
        [ -n "$anchor" ] || continue
        case "$target_file" in
            *.md) ;;
            *) continue ;;
        esac
        [ -f "$ROOT/$target_file" ] || continue
        if ! slugs_of "$target_file" | grep -F -x -q -e "$anchor"; then
            printf 'ANCHOR %s:%s: %s#%s does not resolve\n' "$lf" "$ln" "$target_file" "$anchor" >> "$TMP/findings"
        fi
    done < "$TMP/links"
    return 0
}

# The full-length secret rule: a live invite or swoosh literal in expected text is a failure, not
# a nuance to mask. Truncated forms (`invite:…`) are the documented shape and do not match.
check_secret() {
    LC_ALL=C grep -nE -e "$SECRET_RE" "$2" 2>/dev/null | while IFS=: read -r ln _; do
        printf 'SECRET %s:%s: full-length invite/swoosh literal\n' "$1" "$ln" >> "$TMP/findings"
    done
    return 0
}

lint() {
    ROOT="$1"
    [ -d "$ROOT" ] || { printf 'docs-check: no such root: %s\n' "$ROOT" >&2; exit 2; }
    git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
        printf 'docs-check: %s is not a git work tree; the corpus is git ls-files\n' "$ROOT" >&2
        exit 2
    }
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT INT TERM
    : > "$TMP/findings"
    : > "$TMP/sums"
    git -C "$ROOT" ls-files '*.md' > "$TMP/list"
    while IFS= read -r f; do
        case "$f" in
            target/*|_archived/*|.github/*|scripts/fixtures/*|scripts/docs-check-fixtures/*) continue ;;
        esac
        analyze_file "$f" "$ROOT/$f" >> "$TMP/sums" 2>> "$TMP/findings"
        check_em_dash "$f" "$ROOT/$f"
        check_process "$f" "$ROOT/$f"
        check_secret "$f" "$ROOT/$f"
        check_links "$f" "$ROOT/$f"
    done < "$TMP/list"

    found=0; classified=0; fences=0; g=0; c=0; l=0; p=0; m=0
    while read -r tag sf sfound scls sfences sg sc sl sp sm; do
        [ "$tag" = "@@SUM" ] || continue
        found=$((found + sfound)); classified=$((classified + scls)); fences=$((fences + sfences))
        g=$((g + sg)); c=$((c + sc)); l=$((l + sl)); p=$((p + sp)); m=$((m + sm))
    done < "$TMP/sums"

    sha=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null) || sha=unknown
    branch=$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null) || branch=unknown
    if [ "$found" -eq 0 ]; then
        printf 'docs-check: run at %s on %s; 0 markers found; fences %d; classified %d\n' \
            "$sha" "$branch" "$fences" "$classified"
    else
        printf 'docs-check: run at %s on %s; markers %d (generated %d, capture %d, live-run %d, pending %d, manual %d); fences %d; classified %d\n' \
            "$sha" "$branch" "$found" "$g" "$c" "$l" "$p" "$m" "$fences" "$classified"
    fi

    if [ -s "$TMP/findings" ]; then
        cat "$TMP/findings" >&2
        exit 1
    fi
    exit 0
}

self_test() {
    [ -d "$FIXTURES" ] || { printf 'docs-check: fixture dir missing: %s\n' "$FIXTURES" >&2; exit 2; }
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT INT TERM
    fail=0; count=0
    for vec in "$FIXTURES"/*.md; do
        [ -f "$vec" ] || continue
        name=$(basename "$vec")
        expected="$FIXTURES/${name%.md}.expected"
        count=$((count + 1))
        if [ ! -f "$expected" ]; then
            printf 'SELF-TEST %s: expected file %s missing\n' "$name" "$expected" >&2
            fail=1
            continue
        fi
        analyze_file "$name" "$vec" > /dev/null 2> "$TMP/$name.actual"
        if ! diff -u "$expected" "$TMP/$name.actual" > "$TMP/$name.diff" 2>&1; then
            exp_n=$(wc -l < "$expected" | tr -d ' ')
            got_n=$(wc -l < "$TMP/$name.actual" | tr -d ' ')
            printf 'SELF-TEST %s: expected %s finding(s), got %s\n' "$name" "$exp_n" "$got_n" >&2
            cat "$TMP/$name.diff" >&2
            fail=1
        fi
    done
    if [ "$fail" -ne 0 ]; then
        exit 1
    fi
    if [ "$count" -eq 0 ]; then
        printf 'SELF-TEST: no vectors found in %s\n' "$FIXTURES" >&2
        exit 1
    fi
    printf 'docs-check: self-test green (%d vectors)\n' "$count"
    exit 0
}

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FIXTURES="$SCRIPT_DIR/docs-check-fixtures"

case "${1:-}" in
    --lint) lint "${2:-.}" ;;
    --self-test) self_test ;;
    --generated) not_built "--generated" "the renderer" 2 ;;
    --tier1) not_built "--tier1" "the capture runner" 3 ;;
    --release) not_built "--release" "the capture runner" 4 ;;
    --examples) not_built "--examples" "the examples runner" 4 ;;
    --bless) not_built "--bless" "the capture runner" 3 ;;
    ''|--help|-h) usage; exit 2 ;;
    *) printf 'docs-check: unknown mode: %s\n' "$1" >&2; usage; exit 2 ;;
esac
