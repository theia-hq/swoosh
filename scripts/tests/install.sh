#!/bin/sh
# Exercise the installer with an isolated PATH: no fixture can reach a real downloader or installer.
set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
installer=${2:-"$here/../install.sh"}
shell=$(command -v "${TEST_SHELL:-sh}")
real_mktemp=$(command -v mktemp)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
mkdir -p "$tmp/bin" "$tmp/home" "$tmp/dest" "$tmp/scratch"
# These tools only manipulate fixture paths; everything network-facing is a stub.
for tool in sh tr rm chmod mkdir; do
  ln -s "$(command -v "$tool")" "$tmp/bin/$tool"
done
cat > "$tmp/stub" <<'STUB'
#!/bin/sh
set -eu
tool=${0##*/}
printf '%s\n' "$tool $*" >> "$CALLS"
case "$tool" in
  mktemp)
    [ "$#" -eq 1 ] && [ "$1" = -d ] || exit 97
    exec "$REAL_MKTEMP" -d "$TMPDIR/install.XXXXXXXX" ;;
  uname)
    case "$1" in -s) printf '%s\n' "$OS" ;; -m) printf '%s\n' "$ARCH" ;; *) exit 97 ;; esac ;;
  curl)
    [ "$CURL_FAIL" = 0 ] || exit 23
    [ "$#" -eq 4 ] && [ "$1" = -fsSL ] && [ "$3" = -o ] || exit 97
    printf '%s\n' 'fixture bytes, not a release binary' > "$4" ;;
  shasum | sha256sum) [ "$CHECKSUM_FAIL" = 0 ] ;;
  gh)
    case "$1 $2:$GH_MODE" in
      'attestation verify:verified' | 'auth status:authenticated') exit 0 ;;
      *) exit 1 ;;
    esac ;;
  install)
    [ "$#" -eq 4 ] && [ "$1" = -m ] && [ "$2" = 0755 ] || exit 97
    # The installer invokes --version after copying. This is a shell fixture, never the product.
    printf '#!/bin/sh\nprintf "fixture version\\n"\n' > "$4"
    chmod +x "$4" ;;
  sudo) exit 97 ;;
  *) exit 97 ;;
esac
STUB
chmod +x "$tmp/stub"
for tool in mktemp uname curl shasum sha256sum gh install sudo; do
  ln -s "$tmp/stub" "$tmp/bin/$tool"
done

fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
contains() {
  if ! grep -qF -- "$2" "$1"; then
    while IFS= read -r line; do printf '%s\n' "$line" >&2; done < "$1"
    fail "missing $2"
  fi
}
absent() { if grep -qF -- "$2" "$1"; then fail "unexpected $2"; fi; }
run() {
  : > "$tmp/calls"
  rm -f "$tmp/dest/swoosh"
  status=0
  PATH="$tmp/bin" HOME="$tmp/home" INSTALL_DIR="$tmp/dest" TMPDIR="$tmp/scratch" \
    CALLS="$tmp/calls" REAL_MKTEMP="$real_mktemp" OS="$1" ARCH="$2" CURL_FAIL="${3:-0}" \
    CHECKSUM_FAIL="${4:-0}" GH_MODE="${5:-verified}" \
    "$shell" "$installer" > "$tmp/output" 2>&1 || status=$?
}
refused() {
  contains "$tmp/output" "$1"
  [ "$status" -eq 1 ] || fail "refusal exit $status"
  for tool in curl shasum sha256sum gh install sudo; do
    absent "$tmp/calls" "$tool "
  done
  [ ! -e "$tmp/dest/swoosh" ] || fail 'refusal wrote destination'
}

# All existing aliases select exactly the three published asset names.
for os in Linux LiNuX Darwin DaRwIn; do
  for arch in x86_64 amd64 arm64 aarch64; do
    case "$os:$arch" in Darwin:x86_64 | Darwin:amd64 | DaRwIn:x86_64 | DaRwIn:amd64) continue ;; esac
    case "$os" in Linux | LiNuX) platform=linux ;; *) platform=macos ;; esac
    case "$arch" in x86_64 | amd64) cpu=x86_64 ;; *) cpu=aarch64 ;; esac
    run "$os" "$arch"
    [ "$status" -eq 0 ] || fail "supported $os $arch"
    asset="swoosh-$cpu-$platform"
    base=https://github.com/theia-hq/swoosh/releases/latest/download
    contains "$tmp/calls" "curl -fsSL $base/$asset -o $tmp/scratch/"
    contains "$tmp/calls" "curl -fsSL $base/$asset.sha256 -o $tmp/scratch/"
    contains "$tmp/calls" "shasum -a 256 -c $asset.sha256"
    contains "$tmp/calls" 'gh attestation verify '
    contains "$tmp/calls" "--repo theia-hq/swoosh"
    contains "$tmp/calls" 'install -m 0755 '
    absent "$tmp/calls" 'sudo '
    contains "$tmp/output" 'installed: fixture version'
  done
done
for arch in x86_64 amd64; do
  run Darwin "$arch"
  refused 'install: no prebuilt binary for Intel Macs; build from source or use an Apple Silicon Mac'
done
for os in MINGW64_NT-10.0 Windows FreeBSD; do
  run "$os" x86_64
  normalized=$(printf '%s' "$os" | tr '[:upper:]' '[:lower:]')
  refused "install: unsupported OS '$normalized'; prebuilt binaries are available for Linux and Apple Silicon macOS"
done
for os in Linux Darwin; do
  run "$os" riscv64
  refused "install: unsupported architecture 'riscv64'"
done

run Linux x86_64 1
[ "$status" -eq 1 ] || fail 'download failure exit'
contains "$tmp/output" 'could not download swoosh-x86_64-linux'
absent "$tmp/calls" 'shasum '
absent "$tmp/calls" 'install '
run Linux x86_64 0 1
[ "$status" -eq 1 ] || fail 'checksum failure exit'
contains "$tmp/output" 'checksum mismatch: refusing to install'
absent "$tmp/calls" 'gh '
absent "$tmp/calls" 'install '
for mode in verified authenticated unauthenticated; do
  run Linux x86_64 0 0 "$mode"
  [ "$status" -eq 0 ] || fail "provenance $mode"
  case "$mode" in
    verified) contains "$tmp/output" 'provenance verified:' ;;
    authenticated) contains "$tmp/output" 'verification failed; checksum still holds' ;;
    unauthenticated) contains "$tmp/output" 'gh not authenticated; checksum still holds' ;;
  esac
done
rm "$tmp/bin/gh" "$tmp/bin/shasum"
run Linux x86_64
[ "$status" -eq 0 ] || fail 'fallback checksum without gh'
contains "$tmp/calls" 'sha256sum -c swoosh-x86_64-linux.sha256'
contains "$tmp/output" 'gh not found; checksum still holds'

if [ "${1:-with-control}" = with-control ]; then
  # A private copy without the pair guard must fail this same suite at the Intel-Mac refusal.
  awk '
    /^case "\$os:\$arch" in$/ { skip=1; next }
    skip && /^esac$/ { skip=0; next }
    !skip { print }
  ' "$installer" > "$tmp/unguarded.sh"
  if "$shell" "$here/install.sh" without-control "$tmp/unguarded.sh" > "$tmp/control.out" 2>&1; then
    fail 'suite accepted the removed pair guard'
  fi
  contains "$tmp/control.out" 'FAIL missing install: no prebuilt binary for Intel Macs'
fi
printf '%s\n' 'installer fixtures passed'
