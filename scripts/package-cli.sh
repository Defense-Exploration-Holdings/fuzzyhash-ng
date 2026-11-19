#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Defense Exploration Holdings, LLC
#
# Package the CLI binaries built by `zig build dist` for a GitHub Release.
#
#   scripts/package-cli.sh VERSION OUT_DIR
#
# For each zig-out/dist/<target>/ this writes OUT_DIR/fuzzyhash-VERSION-<target>.tar.gz
# (OUT_DIR/fuzzyhash-VERSION-<target>.zip for Windows) holding the binary, README.md,
# LICENSE and LICENSES/, then OUT_DIR/SHA256SUMS. The binaries include code under
# Apache-2.0 (telfhash), BSD-3-Clause and NCSA (capstone), so every archive carries the
# licence and notice files. File times are set to SOURCE_DATE_EPOCH (default: the time
# of the last commit) so that the same tree gives the same archives.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 VERSION OUT_DIR" >&2
  exit 2
fi
version="$1"
out="$2"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "bad version: $version" >&2; exit 2; }

root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/zig-out/dist"
[ -d "$dist" ] || { echo "no $dist: run zig build dist first" >&2; exit 1; }

epoch="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

count=0
for dir in "$dist"/*/; do
  target="$(basename "$dir")"
  name="fuzzyhash-$version-$target"
  stage="$work/$name"
  mkdir -p "$stage"
  if [ -f "$dir/fuzzyhash.exe" ]; then bin=fuzzyhash.exe; else bin=fuzzyhash; fi
  [ -f "$dir/$bin" ] || { echo "no binary in $dir" >&2; exit 1; }
  cp "$dir/$bin" "$stage/$bin"
  chmod 0755 "$stage/$bin"
  cp "$root/README.md" "$root/LICENSE" "$stage/"
  cp -R "$root/LICENSES" "$stage/LICENSES"
  find "$stage" -exec touch -h -d "@$epoch" {} +
  case "$target" in
    *windows*)
      (cd "$work" && find "$name" -print | LC_ALL=C sort | zip -q -X -@ "$out/$name.zip")
      ;;
    *)
      tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
        -cf - "$name" | gzip -n -9 > "$out/$name.tar.gz"
      ;;
  esac
  count=$((count + 1))
done

[ "$count" -gt 0 ] || { echo "no targets in $dist" >&2; exit 1; }

(cd "$out" && find . -maxdepth 1 -type f -name "fuzzyhash-$version-*" -printf '%f\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
cat "$out/SHA256SUMS"
