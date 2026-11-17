# fuzzyhash-ng

Fuzzy and similarity hashes in Zig, with results that match the reference implementations exactly.

## About

Fuzzy hashes tell you how alike two files are, not only whether they are identical. They help with malware triage, clustering and near-duplicate detection. fuzzyhash-ng puts the common ones in one dependency-free Zig codebase and ships it three ways: as a Zig module, as an npm package that runs the same code compiled to WebAssembly (Node, Bun, Deno and browsers), and as a small command-line tool.

The goal is exact compatibility. For every input, each hash gives the same digest, score or distance as its reference implementation, and every release is checked against those references on the same test files. A change to any result for any input is treated as a breaking change.

| Family | Hashes | Matches |
|---|---|---|
| Context-triggered piecewise | ssdeep | ssdeep 2.14.1 |
| Locality-sensitive | TLSH (all four builds) | TLSH 5.0.2 |
| Executables | imphash (PE), telfhash (ELF, including stripped binaries) | pefile 2024.8.26, telfhash 0.9.8 |
| Images | aHash, dHash, pHash | ImageHash 4.3.2 |
| Sets and text | MinHash, SimHash, Nilsimsa, LZJD | datasketch 2.0.0, simhash 2.1.2, nilsimsa 0.3.8, pyLZJD |

> **Status: in development.** Every family above is in the Zig module. The npm package has ssdeep so far, and TLSH and the other families follow. The CLI commands are planned. The API below is the planned v1.0 API.

## What it does

| | ssdeep | TLSH |
|---|---|---|
| Hashing | streaming `init` / `update` / `final`, constant memory | streaming, all four build variants (128 or 256 buckets, 1 or 3 checksum bytes) |
| Output | `blocksize:part1:part2`, as ssdeep prints it | `T1` + 70 hex digits, or the legacy form without the prefix |
| Comparison | score from 0 to 100 | distance (0 means identical), with or without the length term |
| Compatible with | ssdeep 2.14.1 | TLSH 5.0.2 |

Fuzzy hashes help with triage, clustering and near-duplicate detection. They are not a security boundary: an attacker can change a file so that its digest moves away from (or toward) another one. Do not use them as an allow-list.

## Planned API

JavaScript and TypeScript (`npm install fuzzyhash-ng`, Node 18 or newer, Bun, Deno and browsers):

```js
import { ssdeep, ssdeepCompare, tlsh, tlshDiff } from 'fuzzyhash-ng';

const a = ssdeep(bytesA);          // '96:...:...'
const b = ssdeep(bytesB);
ssdeepCompare(a, b);               // integer from 0 to 100

tlsh(bytesA);                      // 'T1...' or null when the input is too short or too uniform
tlshDiff(tlsh(bytesA), tlsh(bytesB));
```

Zig (`zig fetch --save git+https://github.com/Defense-Exploration-Holdings/fuzzyhash-ng`):

```zig
const fuzzyhash = @import("fuzzyhash");

var h = fuzzyhash.Ssdeep.init(.{});
h.update(chunk1);
h.update(chunk2);
const digest = try h.final();
```

Command line:

```sh
fuzzyhash ssdeep -r evidence/      # same output as `ssdeep -r`
fuzzyhash tlsh file.bin
fuzzyhash compare DIGEST_A DIGEST_B
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
| `test/` | Node tests that run against the built modules |
| `scripts/` | toolchain install, WebAssembly embedding, reference builds, licence check |
| `docs/` | the WebAssembly ABI and other reference notes |
| `examples/zig/` | a project that depends on the Zig package |

## Sponsors

<a href="https://appliku.com/"><img src="assets/sponsors/appliku.png" alt="Appliku" height="64"></a>
&nbsp;&nbsp;
<a href="https://github.com/speedpy/speedpy"><img src="assets/sponsors/speedpy.png" alt="SpeedPy" height="64"></a>

[Appliku](https://appliku.com/) and [SpeedPy](https://github.com/speedpy/speedpy) support this project.

## License

MIT, see [LICENSE](LICENSE). Code ported from TLSH is used under TLSH's Apache-2.0 option and keeps its own SPDX header; the TLSH licence and notice are in [LICENSES/](LICENSES/). telfhash is ported from telfhash under Apache-2.0 the same way ([LICENSES/telfhash-LICENSE](LICENSES/telfhash-LICENSE)); its disassembler ports capstone's x86 decoder (NCSA, [LICENSES/capstone-LICENSE-LLVM](LICENSES/capstone-LICENSE-LLVM)) and tables derived from capstone's ARM and MIPS decoders (BSD-3-Clause, [LICENSES/capstone-LICENSE](LICENSES/capstone-LICENSE)). The imphash ordinal tables come from pefile (MIT, [LICENSES/pefile-LICENSE](LICENSES/pefile-LICENSE)). The image hashes port code from Pillow (MIT-CMU), ImageHash (BSD-2-Clause) and the ducc0 FFT used by scipy (BSD-3-Clause); their licences are in [LICENSES/](LICENSES/). SimHash's Unicode tables are derived from the Unicode Character Database ([LICENSES/Unicode-LICENSE](LICENSES/Unicode-LICENSE)).
