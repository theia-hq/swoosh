#!/bin/sh
# Install swoosh: download the latest release binary for your platform, verify it, and put it on PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/theia-hq/swoosh/main/scripts/install.sh | sh
#
# Always verifies a SHA-256 checksum. Also verifies the keyless build-provenance attestation when the
# GitHub CLI (`gh`) is present, so you can prove the binary was built by theia-hq's release workflow.
# Override the destination with INSTALL_DIR=/path (default: ~/.local/bin, or /usr/local/bin with sudo).
set -eu

REPO="theia-hq/swoosh"
BIN="swoosh"

say() { printf '%s\n' "$*" >&2; }
die() { say "install: $*"; exit 1; }

command -v curl >/dev/null 2>&1 || die "need 'curl' on PATH"
if command -v shasum >/dev/null 2>&1; then SHA="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"
else die "need 'shasum' or 'sha256sum' on PATH"; fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux) os=linux ;;
  darwin) os=macos ;;
  *) die "unsupported OS '$os' (linux and macos only; on windows, grab the binary from the releases page)" ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) die "unsupported architecture '$arch'" ;;
esac
asset="${BIN}-${arch}-${os}"
base="https://github.com/${REPO}/releases/latest/download"

tmp=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading ${asset} from the latest release..."
curl -fsSL "${base}/${asset}" -o "${tmp}/${BIN}" || die "could not download ${asset}"
curl -fsSL "${base}/${asset}.sha256" -o "${tmp}/${BIN}.sha256" || die "could not download the checksum"

say "verifying checksum..."
printf '%s  %s\n' "$(cat "${tmp}/${BIN}.sha256")" "${tmp}/${BIN}" | $SHA -c - >/dev/null 2>&1 \
  || die "checksum mismatch: refusing to install"

if command -v gh >/dev/null 2>&1; then
  say "verifying build provenance (gh attestation)..."
  if gh attestation verify "${tmp}/${BIN}" --repo "${REPO}" >/dev/null 2>&1; then
    say "provenance verified: built by ${REPO}'s release workflow."
  else
    say "provenance not verified (checksum still holds); install continues."
  fi
fi

chmod +x "${tmp}/${BIN}"

dir="${INSTALL_DIR:-${HOME}/.local/bin}"
mkdir -p "$dir" 2>/dev/null || true
if [ -w "$dir" ]; then
  install -m 0755 "${tmp}/${BIN}" "${dir}/${BIN}"
else
  say "elevated permissions needed to write ${dir}"
  sudo install -m 0755 "${tmp}/${BIN}" "${dir}/${BIN}"
fi

say "installed: $("${dir}/${BIN}" --version) -> ${dir}/${BIN}"
case ":${PATH}:" in
  *":${dir}:"*) ;;
  *) say "note: ${dir} is not on your PATH. add it, e.g.  export PATH=\"${dir}:\$PATH\"" ;;
esac
