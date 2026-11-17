# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/). Any change to a digest, score or distance for any input is a major change.

## Unreleased

## 0.1.0 - 2026-11-17

### Added

- ssdeep in the Zig module: `fuzzyhash.Ssdeep` (streaming hasher, `hash`, `Digest` with `toString` and `parse`, `compare`, `compareStrings`), with the `eliminate_sequences` and `no_truncate` options. Digests and scores match ssdeep 2.14.1, including 64-bit block sizes when comparing digest strings.
- ssdeep in the npm package (`fuzzyhash-ng` and `fuzzyhash-ng/ssdeep`): `ssdeep`, `SsdeepHasher`, `ssdeepStream`, `ssdeepCompare` and `parseSsdeep`, backed by new `ssdeep_*` WebAssembly exports.
- Build for the Zig module `fuzzyhash`, three WebAssembly modules (`ssdeep`, `tlsh`, `fuzzy`) with fixed memory, and the `fuzzyhash` CLI (`--help`, `--version`).
- npm package skeleton `fuzzyhash-ng` with entry points `.`, `./ssdeep` and `./tlsh`, `ready()` and `FuzzyHashError`.
- `scripts/fetch-oracles.sh` to build ssdeep 2.14.1 and TLSH 5.0.2 as test references.
- `scripts/check-licenses.mjs` for SPDX headers and the GPL check.
