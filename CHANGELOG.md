# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/). Any change to a digest, score or distance for any input is a breaking change: a major version from 1.0, a minor version before it.

## Unreleased

## 0.4.0 - 2026-11-19

### Added

- The `fuzzyhash` command-line tool, built with `zig build cli`: `ssdeep` (hash mode and the `-m`, `-k` and `-x` matching modes, with standard output byte-identical to the `ssdeep` 2.14.1 program for the same options), `tlsh` (all four builds), `imphash`, `telfhash`, `lzjd`, `nilsimsa` and `compare`, which detects the kind of two digests and prints their score or distance. Every command takes `-r` for directories, reads standard input, and prints JSON lines with `--json`. See `docs/cli.md`.
- `zig build dist` builds the tool with ReleaseSafe for Linux (x86_64, aarch64), macOS (x86_64, aarch64) and Windows (x86_64). Each GitHub Release has these binaries attached, packed with the licence files, and a `SHA256SUMS` file.
- `test/reference/`: ssdeep and TLSH (all four builds) are checked against digests, scores and distances saved from ssdeep 2.14.1 and TLSH 5.0.2 for a generated corpus of 171 inputs and 72 pairs, in one-shot and streaming use. `scripts/reference-vectors.mjs` regenerates them from the programs `scripts/fetch-oracles.sh` builds.

### Changed

- Ported image hash code keeps its upstream licence and copyright lines: Pillow's resampler moved to `src/imagehash/resample.zig` (MIT-CMU), `src/imagehash.zig` is BSD-2-Clause (ImageHash) and `src/imagehash/dct.zig` is BSD-3-Clause (ducc0). They were marked MIT. SimHash's Unicode tables are marked `MIT AND Unicode-3.0`. No code or output changed.
- The npm licence field is the full SPDX expression, `MIT AND Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT-CMU AND NCSA AND Unicode-3.0`. JSR takes one identifier, so `jsr.json` keeps `MIT`.
- The package needs Node 20 or newer (`engines`), and CI runs the Node tests on Node 20 as well as 22. Node 18 is end of life and was not tested.
- The examples in the TypeScript declarations import the npm name (`fuzzyhash-ng`); the JSR build rewrites them to `@defense-exploration/fuzzyhash-ng`. Before, pasting one into a Node project failed.
- The README imports each family from its own entry point, and states the pHash platform dependency and the unsupported pHash sizes.

## 0.3.3 - 2026-11-18

### Changed

- TLSH (`src/tlsh.zig`) is now a clean-room implementation under MIT, written from the published description and checked against TLSH 5.0.2 as a black box. It replaces the port of the TLSH source, and `LICENSES/TLSH-LICENSE` and `LICENSES/TLSH-NOTICE.txt` are gone. Digests, distances and the API are unchanged: the new code gives the same results as TLSH 5.0.2 for all four builds. telfhash is still a port under Apache-2.0.

## 0.3.2 - 2026-11-17

### Changed

- Module documentation on every entry point, with an example, and documentation on the remaining exported types, fields and methods, for JSR and editors. No code changed.
- `package.json` has a top-level `types` field pointing at `src/index.d.mts`, for tools that do not read the `exports` map.

## 0.3.1 - 2026-11-17

### Changed

- The package licence field is now `MIT`, so that JSR accepts it (JSR takes one SPDX identifier, not an expression). Nothing else changed: ported code keeps its Apache-2.0, BSD and NCSA headers, and their licences and notices still ship in `LICENSES/`. 0.3.0 was published to npm but not to JSR.

## 0.3.0 - 2026-11-17

### Added

- Every family in the npm package, each with its own entry point and TypeScript declarations: `fuzzyhash-ng/tlsh` (`tlsh`, `tlshDiff`, `TlshHasher`, `tlshStream`, all four builds), `fuzzyhash-ng/imphash`, `fuzzyhash-ng/telfhash` (`telfhash`, `telfhashDiff`), `fuzzyhash-ng/imagehash` (`averageHash`, `dhash`, `phash`, `imageHashDistance`), `fuzzyhash-ng/minhash` (`MinHash`), `fuzzyhash-ng/simhash` (`simhash`, `simhashFeatures`, `simhashDistance`), `fuzzyhash-ng/lzjd` (`lzjd`, `lzjdSimilarity`) and `fuzzyhash-ng/nilsimsa` (`nilsimsa`, `nilsimsaCompare`, `NilsimsaHasher`, `nilsimsaStream`). The main entry point exports all of them. Results match the same references as the Zig module.
- The package on JSR as `@defense-exploration/fuzzyhash-ng`, for Deno, published from the same release tag as npm.
- `FuzzyHashError` codes `INVALID_INPUT`, `UNSUPPORTED_INPUT` and `OUT_OF_MEMORY`, and the matching `Status` codes 8 to 10.

### Changed

- The WebAssembly modules for imphash, telfhash, the image hashes, MinHash, SimHash and LZJD, and the main module, export `fuzzy_alloc` and `fuzzy_free`, and their memory can grow up to 2 GiB. The ssdeep, TLSH and Nilsimsa modules keep a fixed 128 KiB memory. See `docs/abi.md`.

### Fixed

- pHash failed to compile for 32-bit targets (a shift amount typed for 64-bit `usize`).

## 0.2.0 - 2026-11-17

### Added

- TLSH in the Zig module: `fuzzyhash.Tlsh.T1` (the standard digest) and `fuzzyhash.Tlsh.Tlsh(variant)` for the 128/3, 256/1 and 256/3 builds, each with a streaming hasher, `hash`, `Digest.toString` and `Digest.parse`, `diff` (with or without the length term) and `diffStrings`. Digests and distances match TLSH 5.0.2. Ported from TLSH under its Apache-2.0 option; the npm package licence is now `MIT AND Apache-2.0` and the package includes `LICENSES/`.
- imphash in the Zig module: `fuzzyhash.Imphash.hash` returns the import hash of a PE file. Results match pefile 2024.8.26 `get_imphash()`, including its handling of damaged import tables. pefile's ordinal tables for oleaut32.dll, ws2_32.dll and wsock32.dll are included (MIT, `LICENSES/pefile-LICENSE`).
- telfhash in the Zig module: `fuzzyhash.Telfhash.hash` returns the symbol hash of an ELF file, with `Result.toString` and `diffStrings`. Results match telfhash 0.9.8 (pyelftools 0.33, py-tlsh 5.0.0) for files with a symbol table, including the `tnull` and `-` results. Files without a symbol table (stripped static executables) are hashed from the call targets in their code, as telfhash does with capstone 5.0.9, for x86, x86-64, ARM and MIPS; this includes ports of capstone's x86 decoder (NCSA, `LICENSES/capstone-LICENSE-LLVM`) and tables of the ARM and MIPS instruction words capstone accepts (BSD-3-Clause, `LICENSES/capstone-LICENSE`). `scratchLength` gives a scratch size that is always enough. Ported from telfhash under Apache-2.0 (`LICENSES/telfhash-LICENSE`, `LICENSES/telfhash-NOTICE.txt`).
- Image hashes in the Zig module: `fuzzyhash.ImageHash.Hash` (64 bits) and `fuzzyhash.ImageHash.ImageHash(n)` with `average` (aHash), `difference` (dHash) and `perceptual` (pHash), `toHex`, `parseHex` and `distance`. They take decoded 8-bit gray, gray+alpha, RGB or RGBA pixels and caller-provided scratch memory. Results match ImageHash 4.3.2 with Pillow 13.0.0 and scipy 1.18.1 on x86-64 Linux, including pHash on flat images, where the result depends on the DCT's rounding. pHash sizes (`hash_size * highfreq_factor`) up to 1000 with prime factors below 135 are supported. Pillow's resampling (MIT-CMU) and the ducc0 FFT (BSD-3-Clause) are ported; their licences and ImageHash's (BSD-2-Clause) are in `LICENSES/`.
- MinHash in the Zig module: `fuzzyhash.MinHash.MinHash(scheme, num_perm)` with `init(seed)`, `update`, `updateHash`, `jaccard`, `merge`, `isEmpty` and `clear`, for the `affine32` (default), `affine64` and `legacy` schemes. Hash values match datasketch 2.0.0 with its default SHA-1 hash functions, including the permutations it draws from numpy's legacy `RandomState`.
- SimHash in the Zig module: `fuzzyhash.Simhash.Simhash(f)` with `fromText`, a weighted-feature `Builder` and `distance`. Values match the `simhash` 2.1.2 package with its default MD5 feature hash, including its text tokenizer (Python 3.13 `str.lower()` with the final sigma rule, the `[\w\u4e00-\u9fcc]` character class, 4-character windows) and its `OverflowError` for weights above 255. The Unicode tables are derived from the Unicode Character Database (`LICENSES/Unicode-LICENSE`).
- LZJD in the Zig module: `fuzzyhash.Lzjd.digest` (default mode, sorted int32 values), `digestSuper` (SuperHash mode, float32 values), `similarity`, `similaritySuper` and `scratchLen`, including the stochastic `false_seen_prob` variant. Digests, set sizes and similarity values match pyLZJD at commit e2c24bd for inputs up to 256 MiB; inputs up to 1 GiB are accepted.
- Nilsimsa in the Zig module: `fuzzyhash.Nilsimsa.hash`, a streaming `Hasher`, `Digest.toHex` and `Digest.parse`, `compare` and `compareStrings`. Digests and scores match the `nilsimsa` 0.3.8 package. `Digest.parse` accepts exactly 64 hex characters, where the package also scores some malformed strings.

## 0.1.1 - 2026-11-17

### Changed

- No code changes. This is the first version published by the release workflow, with npm provenance; 0.1.0 was published by hand.

## 0.1.0 - 2026-11-17

### Added

- ssdeep in the Zig module: `fuzzyhash.Ssdeep` (streaming hasher, `hash`, `Digest` with `toString` and `parse`, `compare`, `compareStrings`), with the `eliminate_sequences` and `no_truncate` options. Digests and scores match ssdeep 2.14.1, including 64-bit block sizes when comparing digest strings.
- ssdeep in the npm package (`fuzzyhash-ng` and `fuzzyhash-ng/ssdeep`): `ssdeep`, `SsdeepHasher`, `ssdeepStream`, `ssdeepCompare` and `parseSsdeep`, backed by new `ssdeep_*` WebAssembly exports.
- Build for the Zig module `fuzzyhash`, three WebAssembly modules (`ssdeep`, `tlsh`, `fuzzy`) with fixed memory, and the `fuzzyhash` CLI (`--help`, `--version`).
- npm package skeleton `fuzzyhash-ng` with entry points `.`, `./ssdeep` and `./tlsh`, `ready()` and `FuzzyHashError`.
- `scripts/fetch-oracles.sh` to build ssdeep 2.14.1 and TLSH 5.0.2 as test references.
- `scripts/check-licenses.mjs` for SPDX headers and the GPL check.
