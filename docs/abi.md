# WebAssembly ABI

Target: `wasm32-freestanding`, single-threaded, no imports. The module never calls out to the host: everything it needs is passed in as bytes. Enabled features are `bulk_memory`, `sign_ext` and `nontrapping_fptoint`, which Node LTS and evergreen browsers all support.

## Modules

There is one module per npm entry point, so an import only loads the code it uses:

| Module | Entry point | Contents |
|---|---|---|
| `ssdeep` | `fuzzyhash-ng/ssdeep` | ssdeep hashing and comparison |
| `tlsh` | `fuzzyhash-ng/tlsh` | TLSH hashing and distance, all variants |
| `fuzzy` | `fuzzyhash-ng` | both |

Roots are `src/wasm/<module>.zig`; the list is `wasm_modules` in `build.zig`. `zig build js` embeds each module as base64 in `packages/fuzzyhash-ng/wasm/<module>.mjs` (generated, not committed), and the loader in `packages/fuzzyhash-ng/src/loader.mjs` instantiates it synchronously on first use, or asynchronously through `ready()`.

## Memory

Each module is linked with a fixed memory of 2 pages (128 KiB): `initial_memory == max_memory`, with a 16 KiB stack. Memory never grows, so the host may keep one `Uint8Array` view over it. There is no `alloc` or `free`.

All calls go through one scratch region. Its address is `scratch_ptr()` and its size `scratch_len()`. Offsets from `scratch_ptr()` (constants in `src/abi.zig`):

| Offset | Size | Use |
|---|---|---|
| 0 | 4096 | hasher state, copied in before a call and out after |
| 4096 | 256 | output (digest strings) |
| 4352 | 65536 | input chunk |

Hasher state lives on the JavaScript side between calls. Each call copies it into the scratch region, runs, and copies it back, so any number of hashers can be in progress at once without the module holding them. Input longer than the input slot is passed in several calls.

## Common exports

Every module has these:

```
fuzzy_abi_version() -> u32     // ABI version; the loader refuses a module whose version differs from its own
version_ptr() -> u32           // the package version string (as in build.zig.zon)
version_len() -> u32
scratch_ptr() -> u32
scratch_len() -> u32
```

## Errors

Exports that can fail return an `i32` status: `0` is success, anything else is a `Status` code from `src/abi.zig`. Codes are append-only once released.

| Code | Name |
|---|---|
| 0 | `ok` |
| 1 | `invalid_argument` |
| 2 | `invalid_state` |
| 3 | `input_too_large` |
| 4 | `too_short` |
| 5 | `insufficient_variation` |
| 6 | `invalid_digest` |
| 7 | `invalid_variant` |

The `small` build has no runtime safety checks, so code validates its inputs and returns a status instead of relying on a trap. Every value read from a state copied in from the host is checked before it is used as an index.

## Versioning

`fuzzy_abi_version()` returns `abi.version` from `src/abi.zig`, and `ABI_VERSION` in the loader must equal it. Bump both on any incompatible change to the exports or these conventions.

Version 1 is the current version.

## ssdeep exports

In the `ssdeep` and `fuzzy` modules. Every pointer argument must point into the scratch region, with its whole length inside it; otherwise the call returns `invalid_argument` and touches nothing.

```
ssdeep_state_size() -> u32                                  // bytes of hasher state, at most 4096
ssdeep_init(state, flags) -> Status                         // flags: 1 eliminate_sequences, 2 no_truncate
ssdeep_update(state, data, len) -> Status
ssdeep_final(state, out, out_len_ptr) -> Status             // out holds up to 150 bytes; the length is a little-endian u32
ssdeep_compare(a, a_len, b, b_len) -> i32                   // 0..100, or -Status
ssdeep_parse(text, len, mode, out, out_len_ptr) -> Status   // mode 0 lenient, 1 strict; writes blocksize:part1:part2
```

`ssdeep_update` and `ssdeep_final` check the state before using it and return `invalid_state` for one the module could not have written. `ssdeep_final` zeroes the state. `ssdeep_compare` and `ssdeep_parse` return `invalid_digest` for a malformed digest. Digest strings can be longer than the input slot (a long file name after the comma, for example); the package shortens them first to a string that parses and compares the same way.

## Planned TLSH exports (v1.0)

```
tlsh_state_size(variant) -> u32
tlsh_init(state, variant, options)
tlsh_update(state, data, len) -> Status
tlsh_final(state, out, out_len_ptr, prefix) -> Status  // out holds up to 140 bytes
tlsh_diff(a, a_len, b, b_len, include_length) -> i32   // >= 0, or -Status
```
