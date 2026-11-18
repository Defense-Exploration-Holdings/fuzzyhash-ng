#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Defense Exploration Holdings, LLC
#
# Install the Zig version pinned in .zig-version, verifying what is downloaded.
#
# Strategy: install the official `ziglang` PyPI wheel (it bundles the real Zig
# toolchain) with `pip install --require-hashes -r scripts/zig-requirements.txt`.
# The requirements file pins the version and lists the SHA-256 of the wheels; its
# version must equal .zig-version. This works in sandboxes where ziglang.org is
# blocked but PyPI is reachable.
#
# If pip cannot be used (not installed, or PyPI unreachable), the official tarball
# is downloaded to a file and extracted only if its SHA-256 equals ZIG_TARBALL_SHA256,
# which the caller must set (the value is listed for each tarball at
# https://ziglang.org/download/index.json). Without it the fallback refuses to run.
# A hash mismatch is never retried or skipped.
#
# Usage: scripts/install-zig.sh [prefix]     (default prefix: $HOME/.local)
# Result: <prefix>/bin/zig  (add <prefix>/bin to PATH)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
want="$(tr -d '[:space:]' < "$root/.zig-version")"
req="$root/scripts/zig-requirements.txt"
prefix="${1:-$HOME/.local}"
bin="$prefix/bin"

die() { echo "install-zig: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

[ -n "$want" ] || die ".zig-version is empty"
[ -f "$req" ] || die "missing $req"

# The pinned requirement must name the version in .zig-version.
req_version="$(sed -nE 's/^ziglang==([^[:space:]\\;]+).*/\1/p' "$req" | head -n 1)"
[ -n "$req_version" ] || die "$req has no 'ziglang==<version>' line"
if [ "$req_version" != "$want" ]; then
  die "scripts/zig-requirements.txt pins ziglang==$req_version but .zig-version is $want; update the requirements and their hashes"
fi
grep -q -- '--hash=sha256:' "$req" || die "$req lists no hashes"

if command -v zig >/dev/null 2>&1 && [ "$(zig version)" = "$want" ]; then
  echo "zig $want already installed at $(command -v zig)"
  exit 0
fi

mkdir -p "$bin"
venv="$prefix/share/zig-venv-$want"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

install_wheel() {
  rm -rf "$venv"
  python3 -m venv "$venv" || return 1
  "$venv/bin/pip" install --disable-pip-version-check --quiet \
    --require-hashes --only-binary=:all: --no-deps -r "$req" >"$work/pip.log" 2>&1 || {
    if grep -q "DO NOT MATCH THE HASHES" "$work/pip.log"; then
      cat "$work/pip.log" >&2
      die "the downloaded ziglang wheel does not match the hashes in scripts/zig-requirements.txt; refusing to continue"
    fi
    cat "$work/pip.log" >&2
    return 1
  }
}

if install_wheel; then
  zigbin="$("$venv/bin/python" -c 'import ziglang, pathlib; print(pathlib.Path(ziglang.__file__).parent / "zig")')"
  ln -sf "$zigbin" "$bin/zig"
else
  echo "pip install failed; falling back to the ziglang.org tarball (needs ZIG_TARBALL_SHA256)" >&2
  [ -n "${ZIG_TARBALL_SHA256:-}" ] || die "ZIG_TARBALL_SHA256 is not set; refusing to install an unverified tarball"
  expected="$(printf '%s' "$ZIG_TARBALL_SHA256" | tr 'A-F' 'a-f')"
  case "$expected" in
    *[!0-9a-f]*) die "ZIG_TARBALL_SHA256 is not a hex digest" ;;
  esac
  [ "${#expected}" -eq 64 ] || die "ZIG_TARBALL_SHA256 must be 64 hex characters"

  arch="$(uname -m)"; os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$arch" in arm64) arch=aarch64 ;; amd64) arch=x86_64 ;; esac
  case "$os" in darwin) os=macos ;; esac
  tarball="$work/zig-$arch-$os-$want.tar.xz"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tarball" "https://ziglang.org/download/$want/zig-$arch-$os-$want.tar.xz"
  actual="$(sha256_of "$tarball")"
  if [ "$actual" != "$expected" ]; then
    die "tarball sha256 is $actual, expected $expected; refusing to extract"
  fi

  dest="$prefix/share/zig-$want"
  rm -rf "$dest"
  mkdir -p "$dest"
  tar -xJf "$tarball" -C "$dest" --strip-components=1
  ln -sf "$dest/zig" "$bin/zig"
fi

echo "installed: $("$bin/zig" version) -> $bin/zig"
case ":$PATH:" in *":$bin:"*) ;; *) echo "note: add $bin to PATH" ;; esac
