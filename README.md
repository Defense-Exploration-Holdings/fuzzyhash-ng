# fuzzyhash-ng

[![npm](https://img.shields.io/npm/v/fuzzyhash-ng)](https://www.npmjs.com/package/fuzzyhash-ng)
[![license](https://img.shields.io/npm/l/fuzzyhash-ng)](LICENSE)
[![types](https://img.shields.io/npm/types/fuzzyhash-ng)](packages/fuzzyhash-ng/README.md)
[![JSR](https://jsr.io/badges/@defense-exploration/fuzzyhash-ng)](https://jsr.io/@defense-exploration/fuzzyhash-ng)

Fuzzy and similarity hashes in Zig, with results that match the reference implementations exactly.

## About

Fuzzy hashes tell you how alike two files are, not only whether they are identical. They help with malware triage, clustering and near-duplicate detection. fuzzyhash-ng puts the common ones in one dependency-free Zig codebase and ships it three ways: as a Zig module, as an npm package that runs the same code compiled to WebAssembly (Node, Bun, Deno and browsers), and as a small command-line tool.

The goal is exact compatibility: for every input, each hash should give the same digest, score or distance as its reference implementation. The tests check this on saved results from the reference programs. For ssdeep and TLSH these come from a generated corpus run through ssdeep 2.14.1 and TLSH 5.0.2 (`test/reference/`); for the other families they are smaller sets of recorded vectors. A change to any result for any input is treated as a breaking change.

| Family | Hashes | Matches |
|---|---|---|
| Context-triggered piecewise | ssdeep | ssdeep 2.14.1 |
| Locality-sensitive | TLSH (all four builds) | TLSH 5.0.2 |
| Executables | imphash (PE), telfhash (ELF, including stripped binaries) | pefile 2024.8.26, telfhash 0.9.8 |
| Images | aHash, dHash, pHash | ImageHash 4.3.2 (pHash as on x86-64 Linux) |
| Sets and text | MinHash, SimHash, Nilsimsa, LZJD | datasketch 2.0.0, simhash 2.1.2, nilsimsa 0.3.8, pyLZJD |

Known limits:

- pHash compares DCT values against their median, so on flat or symmetric images the last bit of rounding in `sin` and `cos` decides some hash bits. Results follow ImageHash on x86-64 Linux (glibc); ImageHash on other platforms can differ on those images. pHash sizes (`hash_size * highfreq_factor`) above 1000 or with a prime factor of 135 or more are not supported.
- LZJD matches pyLZJD at a pinned commit, since pyLZJD has no release.

> **Status: in development.** Every family above is in the Zig module and in the npm and JSR packages. The CLI has ssdeep, TLSH, imphash, telfhash, LZJD and Nilsimsa, and prebuilt binaries are attached to each GitHub Release. The API may still change before 1.0.

## What it does

| | ssdeep | TLSH |
|---|---|---|
| Hashing | streaming `init` / `update` / `final`, constant memory | streaming, all four build variants (128 or 256 buckets, 1 or 3 checksum bytes) |
| Output | `blocksize:part1:part2`, as ssdeep prints it | `T1` + 70 hex digits, or the legacy form without the prefix |
| Comparison | score from 0 to 100 | distance (0 means identical), with or without the length term |
| Compatible with | ssdeep 2.14.1 | TLSH 5.0.2 |

Fuzzy hashes help with triage, clustering and near-duplicate detection. They are not a security boundary: an attacker can change a file so that its digest moves away from (or toward) another one. Do not use them as an allow-list.

## Install

```sh
npm install fuzzyhash-ng
```

On Deno, from [JSR](https://jsr.io/@defense-exploration/fuzzyhash-ng):

```sh
deno add jsr:@defense-exploration/fuzzyhash-ng
```

## Usage

JavaScript and TypeScript (Node 20 or newer, Bun, Deno and browsers). TypeScript declarations are included. See the [package README](packages/fuzzyhash-ng/README.md) for every function.

Import each family from its own entry point (`fuzzyhash-ng/ssdeep`, `fuzzyhash-ng/tlsh`, ...). Each one loads only its own WebAssembly module: about 12 KB for ssdeep. The main entry point `fuzzyhash-ng` has every family in one module of about 700 KB, most of it the telfhash disassembler.

```js
import { ssdeep, ssdeepCompare } from 'fuzzyhash-ng/ssdeep';
import { tlsh, tlshDiff } from 'fuzzyhash-ng/tlsh';
import { imphash } from 'fuzzyhash-ng/imphash';
import { telfhash } from 'fuzzyhash-ng/telfhash';
import { phash } from 'fuzzyhash-ng/imagehash';
import { MinHash } from 'fuzzyhash-ng/minhash';
import { simhash } from 'fuzzyhash-ng/simhash';
import { lzjd } from 'fuzzyhash-ng/lzjd';
import { nilsimsa } from 'fuzzyhash-ng/nilsimsa';

const a = ssdeep(bytesA);          // '96:...:...'
ssdeepCompare(a, ssdeep(bytesB));  // integer from 0 to 100

tlsh(bytesA);                      // 'T1...' or null when the input is too short or too uniform
tlshDiff(tlsh(bytesA), tlsh(bytesB));

imphash(peBytes);                  // 32 hex characters, or null for a file without imports
telfhash(elfBytes);                // 't1...', 'tnull' or '-'
phash({ width, height, data });    // decoded pixels, for example a canvas ImageData
new MinHash().updateBatch(words).jaccard(other);
simhash('some text');              // bigint
lzjd(bytesA).digest;               // Int32Array
nilsimsa(bytesA);                  // 64 hex characters
```

Zig (`zig fetch --save git+https://github.com/Defense-Exploration-Holdings/fuzzyhash-ng`):

```zig
const fuzzyhash = @import("fuzzyhash");

var h = fuzzyhash.Ssdeep.init(.{});
h.update(chunk1);
h.update(chunk2);
const digest = try h.final();
```

Command line (`zig build cli`, then `zig-out/bin/fuzzyhash`; see [docs/cli.md](docs/cli.md)):

```sh
fuzzyhash ssdeep -r evidence/                # same output as `ssdeep -r`
fuzzyhash ssdeep -m known.txt -r samples/    # same matches as `ssdeep -m`
fuzzyhash tlsh -r samples/                   # digest<TAB>path
fuzzyhash telfhash /usr/bin/ls
fuzzyhash compare DIGEST_A DIGEST_B          # ssdeep score, TLSH distance, ...
```

## Building from source

You need Zig 0.17.1 (pinned in `.zig-version`) and Node.js 22 or newer.

```sh
scripts/install-zig.sh             # installs the pinned Zig into ~/.local/bin, verified by SHA-256
zig build check                    # Zig tests, then the Node tests against the built WebAssembly
zig build --release=small          # zig-out/wasm/*.wasm and zig-out/bin/fuzzyhash
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full list of commands.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | the Zig module (`src/root.zig`), WebAssembly exports (`src/wasm/`) and the CLI (`src/cli/`) |
| `packages/fuzzyhash-ng/` | the npm package: loader, entry points and TypeScript declarations |
| `test/` | Node tests that run against the built modules, and ssdeep and TLSH checks against saved reference results |
| `scripts/` | toolchain install, WebAssembly embedding, reference builds, licence check |
| `docs/` | the WebAssembly ABI and other reference notes |
| `examples/zig/` | a project that depends on the Zig package |

## Sponsors

<a href="https://appliku.com/"><img src="assets/sponsors/appliku.png" alt="Appliku" height="64"></a>
&nbsp;&nbsp;
<a href="https://github.com/speedpy/speedpy"><img src="assets/sponsors/speedpy.png" alt="SpeedPy" height="64"></a>

[Appliku](https://appliku.com/) and [SpeedPy](https://github.com/speedpy/speedpy) support this project.

## License

MIT, see [LICENSE](LICENSE). telfhash is ported from telfhash under Apache-2.0 and keeps its own SPDX header ([LICENSES/telfhash-LICENSE](LICENSES/telfhash-LICENSE), [LICENSES/telfhash-NOTICE.txt](LICENSES/telfhash-NOTICE.txt)); its disassembler ports capstone's x86 decoder (NCSA, [LICENSES/capstone-LICENSE-LLVM](LICENSES/capstone-LICENSE-LLVM)) and tables derived from capstone's ARM and MIPS decoders (BSD-3-Clause, [LICENSES/capstone-LICENSE](LICENSES/capstone-LICENSE)). The imphash ordinal tables come from pefile (MIT, [LICENSES/pefile-LICENSE](LICENSES/pefile-LICENSE)). The image hashes port Pillow's resampler (`src/imagehash/resample.zig`, MIT-CMU), ImageHash (`src/imagehash.zig`, BSD-2-Clause) and the ducc0 FFT used by scipy (`src/imagehash/dct.zig`, BSD-3-Clause); those files keep their upstream licence and copyright lines, and the licences are in [LICENSES/](LICENSES/). SimHash's Unicode tables are derived from the Unicode Character Database (Unicode-3.0, [LICENSES/Unicode-LICENSE](LICENSES/Unicode-LICENSE)). The npm package's licence field lists all of these as one SPDX expression; JSR accepts only one identifier, so it shows MIT.
