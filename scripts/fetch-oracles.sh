#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Defense Exploration Holdings, LLC
#
# Build the reference implementations that the differential tests compare against.
#
#   ssdeep 2.14.1   release tarball, verified by SHA-256, built with ./configure && make
#   TLSH 5.0.2      trendmicro/tlsh at a pinned commit, built with CMake once per variant
#                   (128 or 256 buckets, 1 or 3 checksum bytes)
#
# The oracles are run as programs only. Nothing from them is linked into or copied into
# fuzzyhash-ng. See CONTRIBUTING.md for the clean-room rule that applies to ssdeep.
#
# Usage: scripts/fetch-oracles.sh [dir]     (default: .oracles)
# Result:
#   <dir>/ssdeep/bin/ssdeep
#   <dir>/tlsh-<buckets>-<checksum>/bin/tlsh_unittest   for 128-1, 128-3, 256-1, 256-3
#
# Needs: curl, git, a C and C++ compiler, make, cmake.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="${1:-$root/.oracles}"
mkdir -p "$dest"
dest="$(cd "$dest" && pwd)"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

ssdeep_version=2.14.1
ssdeep_url="https://github.com/ssdeep-project/ssdeep/releases/download/release-$ssdeep_version/ssdeep-$ssdeep_version.tar.gz"
ssdeep_sha256=ff2eabc78106f009b4fb2def2d76fb0ca9e12acf624cbbfad9b3eb390d931313

tlsh_repo=https://github.com/trendmicro/tlsh.git
tlsh_commit=ebdec8fde93a4ac359437f4f3796c78d3ae433bf

die() { echo "fetch-oracles: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

for tool in curl git make cmake; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

build_ssdeep() {
  local out="$dest/ssdeep"
  if [ -x "$out/bin/ssdeep" ] && "$out/bin/ssdeep" -V 2>/dev/null | grep -qx "$ssdeep_version"; then
    echo "ssdeep $ssdeep_version already built in $out"
    return
  fi
  local work="$dest/src"
  mkdir -p "$work"
  local tarball="$work/ssdeep-$ssdeep_version.tar.gz"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tarball" "$ssdeep_url"
  local actual
  actual="$(sha256_of "$tarball")"
  [ "$actual" = "$ssdeep_sha256" ] || die "ssdeep tarball sha256 is $actual, expected $ssdeep_sha256"
  rm -rf "$work/ssdeep-$ssdeep_version"
  tar -xzf "$tarball" -C "$work"
  (
    cd "$work/ssdeep-$ssdeep_version"
    ./configure --quiet --prefix="$out" --disable-shared
    make --quiet -j"$jobs"
    make --quiet install
  )
  "$out/bin/ssdeep" -V | grep -qx "$ssdeep_version" || die "built ssdeep does not report version $ssdeep_version"
  echo "ssdeep $ssdeep_version -> $out/bin/ssdeep"
}

build_tlsh() {
  local src="$dest/src/tlsh"
  if [ "$(git -C "$src" rev-parse HEAD 2>/dev/null || true)" != "$tlsh_commit" ]; then
    rm -rf "$src"
    git init --quiet "$src"
    git -C "$src" fetch --quiet --depth 1 "$tlsh_repo" "$tlsh_commit"
    git -C "$src" checkout --quiet FETCH_HEAD
  fi
  [ "$(git -C "$src" rev-parse HEAD)" = "$tlsh_commit" ] || die "TLSH checkout is not at $tlsh_commit"

  local variant buckets checksum out
  for variant in 128-1 128-3 256-1 256-3; do
    buckets="${variant%-*}"
    checksum="${variant#*-}"
    out="$dest/tlsh-$variant"
    if [ -x "$out/bin/tlsh_unittest" ]; then
      echo "TLSH $variant already built in $out"
      continue
    fi
    # The TLSH build writes its programs to <source>/bin, so build one variant at a time.
    rm -rf "$src/build" "$src/bin"
    cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Release \
      "-DTLSH_BUCKETS_$buckets=1" "-DTLSH_CHECKSUM_${checksum}B=1" >/dev/null
    cmake --build "$src/build" --parallel "$jobs" >/dev/null
    mkdir -p "$out/bin"
    cp "$src/bin/tlsh_unittest" "$out/bin/"
    echo "TLSH $variant -> $out/bin/tlsh_unittest"
  done
  rm -rf "$src/build" "$src/bin"
}

build_ssdeep
build_tlsh
