#!/bin/sh
# prose-gate.sh -- our process does not ship.
#
# THE RULE. A reader of this repository gets the thing, never the story of how it was decided. A
# deliberation number, a review path, a round, a seat name, or a synthesis reference tells them nothing
# they can act on and everything about a corpus they cannot see. The style contract and the docs bar both
# ban it already; this gate is why the ban holds, because a rule with no check is a wish.
#
# WHAT IT CHECKS. Every tracked file except the ones named below, for:
#   delib-<n>, deliberation <n>       a decision's number
#   notes/reviews/, notes/deliberations/, SYNTHESIS
#                                     a path into the corpus
#   round-<n>                         a round of argument
#   FLAG(<Seat>)                      a seat addressed in a shipped file
#   DOCS-BAR, CLI-DESIGN, ...          a file in the corpus, named
#   (Adversary), (Craftsman), ...       a seat addressed parenthetically
#   ratified                            a process word with no meaning to a reader
#   a bare seat name in a comment     Adversary, Rust Reviewer, Style Warden, Founder's Advocate,
#                                     Cartographer, Convener, Librarian, Product Lead, Skeptic, Scribe,
#                                     Editor, Newcomer, Operator, Craftsman, Principal, Visionary,
#                                     Systems Architect, CLI Architect
#
# WHAT IT SCANS, and why that set. Only what reaches a USER: `src/` (rustdoc, help text, error
# messages), `docs/`, `README.md`, `CHANGELOG.md`, `action.yml`, and manifest descriptions. Contributor
# infrastructure is deliberately out of scope, because a citation there is an audit trail rather than a
# leak: the sealed gate's per-crate table cites the review that authorized each claim, and that citation
# IS the evidence the gate exists to carry. A gate that forbade it would break the thing it protects.
#
# THE FIX IS NEVER TO CITE DIFFERENTLY. It is to say the invariant. "Refused after admission so a
# disabled name and a gated one time the same" needs no number; "delib-67 F5" needs the corpus.
#
# ESCAPE HATCH. None. A frozen protocol constant that happens to contain a banned token is the only
# conceivable case, and none exists; if one ever does, the constant is renamed or this header gains its
# name and its reason.
#
# Dependency-free: POSIX sh + git + grep. Run from a repo root (or pass a root path):
#   sh scripts/prose-gate.sh [ROOT]

set -eu

ROOT="${1:-.}"
cd "$ROOT"

# A decision's number, a path into the corpus, a round, or a seat addressed in a shipped file.
PROCESS='delib-[0-9]|delib [0-9]|deliberation [0-9]|notes/reviews/|notes/deliberations/|SYNTHESIS|round-[0-9]|FLAG\([A-Za-z]|\bratified\b'

# The corpus by name. These files live in notes/ and a reader has no access to any of them, so citing one
# is the same leak as citing a number.
CORPUS='DOCS-BAR|DOC-VOICE|DOCS-MODEL|CLI-DESIGN|DESIGN-LEDGER|FOUNDER-PROFILE|FOUNDER-REQUESTS|FOUNDER-DOC-STYLE|LOOSE-ENDS|BUILD-SEQUENCE|DRIVE-PLAN|PROSE-ESTATE|craft-backlog|TEAM-NEEDS'

# A seat named in a comment or a doc. Bounded by word edges so `the editor of a file` and an `Operator`
# who is a person running a node do not trip it; the seat sense is always capitalised and standalone.
SEATS='(Rust Reviewer|Style Warden|Founder.s Advocate|Systems Architect|CLI Architect|Product Lead|the Adversary|the Cartographer|the Convener|the Librarian|the Skeptic|the Scribe|the Editor|the Newcomer|the Operator|the Craftsman|the Principal|the Visionary|the Builder|the Subtractor)'

# A seat addressed parenthetically, the shape a note to a colleague takes.
PARENS='\((Adversary|Craftsman|Editor|Scribe|Skeptic|Operator|Newcomer|Librarian|Cartographer|Convener|Principal|Visionary|Builder|Subtractor|Systems|Rust)\)'

files=$(git ls-files \
    | grep -E '(^|/)(src/|docs/)|(^|/)(README|CHANGELOG)\.md$|(^|/)action\.yml$|(^|/)Cargo\.toml$' \
    | grep -v '^notes/' \
    | grep -v '/notes/')

fail=0
hits=0

for f in $files; do
    [ -f "$f" ] || continue
    found=$(grep -nE "$PROCESS|$CORPUS|$SEATS|$PARENS" "$f" 2>/dev/null || true)
    [ -n "$found" ] || continue
    printf 'PROCESS    %s\n' "$f"
    printf '%s\n' "$found" | sed 's/^/        /'
    hits=$((hits + $(printf '%s\n' "$found" | grep -c .)))
    fail=1
done

if [ "$fail" -ne 0 ]; then
    printf '\nprose-gate: FAIL -- %s line(s) carry our process into a shipped file.\n' "$hits" >&2
    printf 'State the invariant instead of citing where it was decided. A reader has no corpus.\n' >&2
    exit 1
fi
printf 'prose-gate: OK -- no process reference in a shipped file.\n'
