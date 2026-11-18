# Contributing

## Setup

You need Zig 0.17.1 and Node.js 22 or newer. Zig is pinned in `.zig-version`; `scripts/install-zig.sh` installs it from the `ziglang` wheel whose hashes are listed in `scripts/zig-requirements.txt` (update both files together). Node is pinned in `.nvmrc`.

Zig 0.17 differs from most tutorials: the optimize modes are `debug`, `safe`, `fast` and `small`, and `std.Io` and `std.process.Init` replace the older I/O APIs. When in doubt, read the toolchain's own `lib/std`.

```sh
scripts/install-zig.sh
zig build check                    # Zig tests, then Node tests against the built WebAssembly
zig build check --release=small    # the same in the shipped mode
```

Other commands:

```sh
zig build wasm --release=small     # zig-out/wasm/<module>.wasm
zig build js                       # embed the modules for the npm package (check does this)
zig build cli                      # zig-out/bin/fuzzyhash
zig build run -- --help            # run the CLI
node scripts/check-licenses.mjs    # SPDX headers and the GPL check on the shipped tree
scripts/fetch-oracles.sh           # build ssdeep 2.14.1 and TLSH 5.0.2 into .oracles/
```

Run `zig build check` in debug and with `--release=small` before sending a change. Do not commit `zig-out/`, `.zig-cache/`, `.oracles/` or the generated `packages/fuzzyhash-ng/wasm/`.

## Ground rules

**Compatibility is the product.** Digests, ssdeep scores and TLSH distances must match ssdeep 2.14.1 and TLSH 5.0.2 for every input. Do not change scoring, rounding or edge cases, even where the reference looks wrong. A change in output for any input is a breaking change.

**ssdeep is a clean-room implementation.** ssdeep, SpamSum, ffuzzy and ppdeep are under licences this project cannot take code from. If you work on `src/ssdeep*.zig`, do not read their source. Work from the published description of the algorithm (Kornblum, "Identifying almost identical files using context triggered piecewise hashing", Digital Investigation 3S, 2006), from `docs/`, and from black-box comparison with the ssdeep program. The reference programs are only ever run as test oracles, never linked or copied.

**TLSH is ported from `trendmicro/tlsh`** under its Apache-2.0 option. Ported files start with `// SPDX-License-Identifier: Apache-2.0` and keep Trend Micro's copyright line. `LICENSES/TLSH-LICENSE` and `LICENSES/TLSH-NOTICE.txt` are verbatim copies and must stay that way.

**No dependencies, no allocation.** The Zig module allocates nothing and has no `std.Io` or file access; file handling lives in the CLI. The only allocator is in `src/wasm/heap.zig`, for the WebAssembly modules that take whole files or images. The npm package has no runtime dependencies.

## Code layout

- `src/root.zig`: the `fuzzyhash` module. Target-agnostic Zig with `test` blocks.
- `src/abi.zig`: the ABI version, `Status` codes and the scratch layout shared by all WebAssembly exports.
- `src/wasm/<module>.zig`: WebAssembly exports, the only files with `export fn`. Each module root imports `common.zig`, and `heap.zig` when it needs memory beyond the scratch region. Add a module to `wasm_modules` in `build.zig`.
- `src/cli/main.zig`: the command-line tool.
- `packages/fuzzyhash-ng/src/`: the npm entry points, the loader and hand-written `.d.mts` declarations. Keep the declarations in step with the exports. `jsr.json` follows `package.json`: after changing the version or the entry points, run `node scripts/build-jsr.mjs --sync`.
- [docs/abi.md](docs/abi.md): the calling convention between JavaScript and WebAssembly.

Every source file under `src/` and `packages/fuzzyhash-ng/src/` starts with an `SPDX-License-Identifier` line. CI runs `scripts/check-licenses.mjs`, which also fails if a GPL identifier or licence text appears anywhere in the shipped tree.

## Tests

Tests exercise behaviour: they call the code and check what it returns or does. Do not add tests that read repository files and check their text.

- Zig unit tests sit next to the code in `test` blocks and run with `zig build test`.
- Node tests in `test/js/` run against the built WebAssembly modules with `zig build test-js`.
- Expected digests and scores come from the reference programs built by `scripts/fetch-oracles.sh`, never from fuzzyhash-ng itself.
- Test inputs are generated (seeded PRNG) or taken from benign public corpora. Never add malware, samples from the wild or the EICAR string.

## Writing

Comments, docs and commit messages are plain technical English: short sentences, concrete statements, no filler. Do not use em dashes. Use a comma, a colon, parentheses or a new sentence instead.

## Conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Pull requests

Pull requests are welcome. Keep each one to a single change, describe what it changes and why, and say how you tested it. The maintainers may apply an accepted change on their side and credit you, in which case the pull request is closed with a note pointing to the commit or release that contains it.

## Licensing

By contributing you agree that your contribution is licensed under the MIT license of the project (see [LICENSE](LICENSE)), or under Apache-2.0 for changes to files ported from TLSH.
