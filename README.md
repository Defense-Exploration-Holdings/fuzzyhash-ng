# fuzzyhash-ng

ssdeep and TLSH similarity digests, written in Zig. One codebase ships as a Zig module, as an npm package that runs the same code compiled to WebAssembly, and as a small command-line tool.

The goal is exact compatibility: for every input, digests, ssdeep scores and TLSH distances are the same as those of **ssdeep 2.14.1** and **TLSH 5.0.2**. Every release is checked against those reference implementations.

> **Status: in development.** 0.1.0 is an early release. The API below is the planned v1.0 API. ssdeep is available in the Zig module and the npm package. TLSH and the CLI commands below land next.

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

## License

MIT, see [LICENSE](LICENSE). Code ported from TLSH is used under TLSH's Apache-2.0 option and keeps its own SPDX header; the TLSH licence and notice are in [LICENSES/](LICENSES/).
