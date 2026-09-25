#!/bin/sh
# layering-gate fixture: exercise checks 4 and 5 of scripts/layering-gate.sh on throwaway git trees,
# so a regression in the layer table, the dependent walk, the word boundary, the org-name match,
# the path handling or the self-exemption fails HERE instead of passing silently in CI. Each case
# builds a temp repo whose root manifest names one layer of the table, carries a copy of the gate,
# plants one file, and asserts the exit code plus a substring of the output. The layers are read
# from the gate's own table by row number and the org's name from its ORG line, so this file names
# none of them.
# Dependency-free: POSIX sh + git + awk + grep + sed.

set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
gate="$here/../layering-gate.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# Which rows depend on each row, directly or not, as the dependency graph stands. Row numbers
# follow the table's order, lowest layer first.
expected_above() {
  case "$1" in
    1) echo "4 5 6 7" ;;
    2) echo "3 4 5 6 7" ;;
    3) echo "4 5 6 7" ;;
    4) echo "5 6 7" ;;
    5) echo "6 7" ;;
    6) echo "7" ;;
    7) echo "" ;;
  esac
}

# The kind of each row: the libraries sit below the apps built on them.
expected_kind() {
  case "$1" in
    6 | 7) echo app ;;
    *) echo lib ;;
  esac
}

rows=$(grep -E '^(lib|app) [a-z]+ +\| [a-z ]+\|[a-z ]*$' "$gate" || true)
row_count=$(printf '%s\n' "$rows" | grep -c . || true)

# words_of ROW -- every word of that row; first_word_of ROW -- the one a manifest names.
words_of() { printf '%s\n' "$rows" | sed -n "${1}p" | awk -F'|' '{ print $2 }' | xargs; }
first_word_of() { words_of "$1" | awk '{ print $1 }'; }
kind_of() { printf '%s\n' "$rows" | sed -n "${1}p" | awk '{ print $1 }'; }
org=$(sed -n "s/^ORG='\([a-z]*\)'\$/\1/p" "$gate")

# mkrepo CASE ROW [ws] -- a git repo whose root manifest identifies as ROW: a root [package]
# named for it, or with `ws`, a virtual workspace whose member carries that name.
mkrepo() {
  repo="$tmp/$1"
  name=$(first_word_of "$2")
  mkdir -p "$repo/scripts" "$repo/src"
  if [ "${3:-}" = ws ]; then
    mkdir -p "$repo/crates/m/src"
    printf '[workspace]\nresolver = "3"\nmembers = [\n    "crates/m",\n]\n' > "$repo/Cargo.toml"
    printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2024"\n' "$name" > "$repo/crates/m/Cargo.toml"
    printf '//! fixture\n' > "$repo/crates/m/src/lib.rs"
  else
    printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2024"\n' "$name" > "$repo/Cargo.toml"
  fi
  printf '//! fixture\n' > "$repo/src/lib.rs"
  cp "$gate" "$repo/scripts/layering-gate.sh"
  git -C "$repo" init -q
}

# plant CASE PATH TEXT -- write TEXT to PATH in the case's repo and track it.
plant() {
  mkdir -p "$(dirname "$tmp/$1/$2")"
  printf '%s\n' "$3" >> "$tmp/$1/$2"
}

# expect CASE WANT_EXIT NEEDLE LABEL [untracked] -- track the case's files (unless told not to),
# run the gate on its repo and check it.
expect() {
  [ "${5:-}" = untracked ] || git -C "$tmp/$1" add -A
  set +e
  out=$(cd "$tmp/$1" && sh scripts/layering-gate.sh . 2>&1)
  code=$?
  set -e
  if [ "$code" -eq "$2" ] && printf '%s\n' "$out" | grep -qF -- "$3"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    printf 'FAIL  %s: want exit %s with "%s", got exit %s:\n%s\n\n' "$4" "$2" "$3" "$code" "$out"
  fi
}

if [ "$row_count" -ne 7 ]; then
  printf 'FAIL  the gate has %s layer rows; this fixture encodes 7. Update expected_above.\n' "$row_count"
  exit 1
fi
if [ -z "$org" ]; then
  printf 'FAIL  the gate has no ORG line\n'
  exit 1
fi

# Every layer computes the forbidden set its dependents give it, and a word from any other row
# fails exactly when that row depends on it.
r=1
while [ "$r" -le 7 ]; do
  kind=""
  [ "$r" -eq 5 ] && kind=ws
  want=""
  for a in $(expected_above "$r"); do want="$want $(words_of "$a")"; done
  want=$(printf '%s\n' $want | sort -u | tr '\n' ' ' | sed 's/ $//')
  mkrepo "set-$r" "$r" "$kind"
  expect "set-$r" 0 "forbids: ${want:-(nothing)}" "row $r computes its forbidden set"
  m=1
  while [ "$m" -le 7 ]; do
    if [ "$m" -ne "$r" ]; then
      mkrepo "word-$r-$m" "$r" "$kind"
      plant "word-$r-$m" src/lib.rs "//! see $(first_word_of "$m") here"
      case " $(expected_above "$r") " in
        *" $m "*) expect "word-$r-$m" 1 "src/lib.rs:2:" "row $r refuses a word of row $m, which depends on it" ;;
        *) expect "word-$r-$m" 0 "OK" "row $r allows a word of row $m, which does not depend on it" ;;
      esac
    fi
    m=$((m + 1))
  done
  r=$((r + 1))
done

top=$(first_word_of 6)
last=$(first_word_of 7)
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }
capital() { printf '%s%s' "$(upper "$(printf '%s' "$1" | cut -c1)")" "$(printf '%s' "$1" | cut -c2-)"; }

# A tracked path with a space is read, not split.
mkrepo space 1
plant space "a b/x.md" "made for $top"
expect space 1 "a b/x.md:1:" "a path with a space is scanned"

# An underscore or a hyphen is a boundary, so an env var or a suffixed crate name is caught.
mkrepo underscore 1
plant underscore src/lib.rs "const V: &str = \"$(printf '%s' "$top" | tr '[:lower:]' '[:upper:]')_HOME\";"
expect underscore 1 "src/lib.rs:2:" "an uppercase word before an underscore is caught"
mkrepo hyphen 1
plant hyphen src/lib.rs "//! a $(first_word_of 4)-handler crate"
expect hyphen 1 "src/lib.rs:2:" "a word before a hyphen is caught"

# A word is caught as one hump of an identifier, in every casing a name takes.
for ident in "$(capital "$top")Link" "my$(capital "$top")" "$(capital "$last")Client" "$(upper "$top")2" \
    "${top}Link"; do
  mkrepo "hump-$ident" 1
  plant "hump-$ident" src/lib.rs "struct $ident;"
  expect "hump-$ident" 1 "src/lib.rs:2:" "a word inside the identifier $ident is caught"
done
# A word run into lowercase letters is prose, not a name.
mkrepo prose 1
plant prose src/lib.rs "//! a ${top}ing sound"
expect prose 0 "OK" "a word run into lowercase letters is allowed"

# A tracked path is checked like a line: a file named for a dependent fails with no hit inside it.
mkrepo path 1
plant path "src/$top.rs" "//! fixture"
expect path 1 "src/$top.rs" "a file named for a dependent is caught"
mkrepo pathcap 1
plant pathcap "docs/$(capital "$last")-notes.md" "notes"
expect pathcap 1 "docs/$(capital "$last")-notes.md" "a capitalised word in a path is caught"

# A git read that fails fails the gate instead of reporting a clean scan.
mkrepo broken 1
git -C "$tmp/broken" add -A
printf 'junk' > "$tmp/broken/.git/index"
expect broken 1 "git grep failed" "a failed git grep fails the gate" untracked
# A path marked binary in .gitattributes is still read as text, so the mark cannot hide a hit.
for mark in -diff binary; do
  mkrepo "attr$mark" 1
  plant "attr$mark" src/lib.rs "//! made for $top"
  plant "attr$mark" .gitattributes "src/lib.rs $mark"
  expect "attr$mark" 1 "src/lib.rs:2:" "a path marked $mark in .gitattributes is still scanned"
done
mkrepo unreadable 1
plant unreadable notes.md "notes"
git -C "$tmp/unreadable" add -A
chmod 000 "$tmp/unreadable/notes.md"
if [ -r "$tmp/unreadable/notes.md" ]; then
  printf 'skip  an unreadable file cannot be made here (running as root)\n'
else
  expect unreadable 1 "git grep failed" "a file git grep cannot read fails the gate" untracked
fi
chmod 644 "$tmp/unreadable/notes.md"

# The gate checks its own comments: only a table row is exempt, and only in the gate.
mkrepo self 1
plant self scripts/layering-gate.sh "# as $top does it"
expect self 1 "scripts/layering-gate.sh:" "a comment in the gate itself is checked"
mkrepo rowcopy 1
printf '%s\n' "$rows" | sed -n 6p > "$tmp/rowcopy/notes.md"
expect rowcopy 1 "notes.md:1:" "a table row outside the gate is not exempt"

# A CHANGELOG at any depth may keep history.
mkrepo changelog 1
plant changelog CHANGELOG.md "- dropped the $top prefix"
plant changelog crates/x/CHANGELOG.md "- dropped the $top prefix"
expect changelog 0 "OK" "a CHANGELOG may name a dependent"

# A repo the table does not know fails loud instead of checking nothing.
mkrepo unknown 1
sed 's/^name = .*/name = "unlisted"/' "$tmp/unknown/Cargo.toml" > "$tmp/unknown/Cargo.toml.new"
mv "$tmp/unknown/Cargo.toml.new" "$tmp/unknown/Cargo.toml"
expect unknown 1 "no LAYERS row" "an unlisted root package fails"

# Check 5. Every library refuses the org's name as its own word, and every app is skipped.
r=1
while [ "$r" -le 7 ]; do
  kind=""
  [ "$r" -eq 5 ] && kind=ws
  if [ "$(kind_of "$r")" != "$(expected_kind "$r")" ]; then
    fail=$((fail + 1))
    printf 'FAIL  row %s is a %s, want a %s\n' "$r" "$(kind_of "$r")" "$(expected_kind "$r")"
  fi
  mkrepo "org-$r" "$r" "$kind"
  plant "org-$r" src/lib.rs "//! part of $org"
  if [ "$(expected_kind "$r")" = lib ]; then
    expect "org-$r" 1 "src/lib.rs:2:" "row $r, a library, refuses the org's name"
  else
    expect "org-$r" 0 "is an app, skipped" "row $r, an app, may use the org's name"
  fi
  r=$((r + 1))
done

# The org's name is a substring in any case: a word boundary would miss a run-together constant.
n=0
for text in "const SIG: [u8; 8] = *b\"$(upper "$org")KEY\";" "const S: &str = \"_${org}._udp\";" \
    "const V: &str = \"$(upper "$org")_HOME\";" "struct $(capital "$org")Link;" "//! the ${org}ish way"; do
  n=$((n + 1))
  mkrepo "org-sub-$n" 1
  plant "org-sub-$n" src/lib.rs "$text"
  expect "org-sub-$n" 1 "src/lib.rs:2:" "the org's name is caught in: $text"
done

# The org's address is allowed, in any case, and only the address: a bare name beside it is caught.
mkrepo org-addr 1
plant org-addr README.md "see https://github.com/${org}-hq/x and git+https://github.com/$(upper "$org")-HQ/y"
expect org-addr 0 "OK" "the org's address is allowed"
mkrepo org-addr-bare 1
plant org-addr-bare README.md "see https://github.com/${org}-hq/x, the $org way"
expect org-addr-bare 1 "README.md:1:" "a bare name beside the address is caught"

# A tracked path is checked like a line, with the same address exception.
mkrepo org-path 1
plant org-path "docs/$(capital "$org")-notes.md" "notes"
expect org-path 1 "docs/$(capital "$org")-notes.md" "a path with the org's name is caught"
mkrepo org-path-addr 1
plant org-path-addr "docs/${org}-hq.md" "notes"
expect org-path-addr 0 "OK" "a path with the org's address is allowed"

# A CHANGELOG at any depth may keep history.
mkrepo org-changelog 1
plant org-changelog CHANGELOG.md "- dropped the $org prefix"
plant org-changelog crates/x/CHANGELOG.md "- dropped the $org prefix"
expect org-changelog 0 "OK" "a CHANGELOG may use the org's name"

# A path marked binary in .gitattributes is still read as text for the org's name.
for mark in -diff binary; do
  mkrepo "org-attr$mark" 1
  plant "org-attr$mark" src/lib.rs "//! part of $org"
  plant "org-attr$mark" .gitattributes "src/lib.rs $mark"
  expect "org-attr$mark" 1 "src/lib.rs:2:" "a path marked $mark in .gitattributes is still scanned for the org's name"
done

# Only the ORG line is exempt, and only in the gate.
mkrepo org-self 1
plant org-self scripts/layering-gate.sh "# as $org does it"
expect org-self 1 "scripts/layering-gate.sh:" "a comment in the gate itself is checked for the org's name"
mkrepo org-linecopy 1
grep -E "^ORG='" "$gate" > "$tmp/org-linecopy/notes.md"
expect org-linecopy 1 "notes.md:1:" "the ORG line outside the gate is not exempt"

# A repo the table does not know is still scanned.
mkrepo org-unknown 1
sed 's/^name = .*/name = "unlisted"/' "$tmp/org-unknown/Cargo.toml" > "$tmp/org-unknown/Cargo.toml.new"
mv "$tmp/org-unknown/Cargo.toml.new" "$tmp/org-unknown/Cargo.toml"
plant org-unknown src/lib.rs "//! part of $org"
expect org-unknown 1 "uses the org name" "an unlisted repo is scanned for the org's name"

# A git read that fails fails check 5 too.
mkrepo org-broken 1
git -C "$tmp/org-broken" add -A
printf 'junk' > "$tmp/org-broken/.git/index"
expect org-broken 1 "check 5: git grep failed" "a failed git grep fails check 5" untracked

printf 'layering-gate fixture: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
