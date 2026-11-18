# WebAssembly ABI

Target: `wasm32-freestanding`, single-threaded, no imports. The module never calls out to the host: everything it needs is passed in as bytes. Enabled features are `bulk_memory`, `sign_ext` and `nontrapping_fptoint`, which Node LTS and evergreen browsers all support.

## Modules

There is one module per npm entry point, so an import only loads the code it uses:

| Module | Entry point | Contents | Memory |
|---|---|---|---|
| `ssdeep` | `fuzzyhash-ng/ssdeep` | ssdeep | fixed |
| `tlsh` | `fuzzyhash-ng/tlsh` | TLSH, all variants | fixed |
| `nilsimsa` | `fuzzyhash-ng/nilsimsa` | Nilsimsa | fixed |
| `imphash` | `fuzzyhash-ng/imphash` | imphash | heap |
| `telfhash` | `fuzzyhash-ng/telfhash` | telfhash | heap |
| `imagehash` | `fuzzyhash-ng/imagehash` | aHash, dHash, pHash | heap |
| `minhash` | `fuzzyhash-ng/minhash` | MinHash | heap |
| `simhash` | `fuzzyhash-ng/simhash` | SimHash | heap |
| `lzjd` | `fuzzyhash-ng/lzjd` | LZJD | heap |
| `fuzzy` | `fuzzyhash-ng` | all of the above | heap |

Roots are `src/wasm/<module>.zig`; the list is `wasm_modules` in `build.zig`. `zig build js` embeds each module as base64 in `packages/fuzzyhash-ng/wasm/<module>.mjs` (generated, not committed), and the loader in `packages/fuzzyhash-ng/src/loader.mjs` instantiates it synchronously on first use, or asynchronously through `ready()`.

## Memory

Modules marked fixed are linked with a fixed memory of 2 pages (128 KiB): `initial_memory == max_memory`, with a 16 KiB stack. Their memory never grows, so the host may keep one `Uint8Array` view over it. They have no `alloc` or `free`.

Modules marked heap also export `fuzzy_alloc` and `fuzzy_free` (see below), have a 1 MiB stack, and their memory can grow up to 2 GiB, so every address is below 2^31. The host must take a new view of memory after any call that can allocate.

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
| 8 | `invalid_input` |
| 9 | `unsupported_input` |
| 10 | `out_of_memory` |

`invalid_input` means the reference cannot read the file or image (pefile refuses it, pyelftools fails, the image size does not match its pixels). `unsupported_input` means the reference gives no result for the input, or it needs something this port does not have.

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

## Heap exports

In the heap modules. Pointer arguments documented as heap blocks must lie inside memory; the call returns `invalid_argument` otherwise.

```
fuzzy_alloc(len) -> u32        // a block of at least max(len, 1) bytes, aligned to 16; 0 when memory cannot grow
fuzzy_free(ptr, len)           // free a block, with the length it was allocated with
```

## TLSH exports

In the `tlsh` and `fuzzy` modules. `variant` is bit 0 for a 3-byte checksum and bit 1 for 256 buckets; 0 is the standard digest. All pointers are in the scratch region. The state is copied in and out as for ssdeep.

```
tlsh_state_size(variant) -> u32                                     // 0 for an unknown variant
tlsh_init(state, variant, flags) -> Status                          // flags: 1 conservative
tlsh_update(state, variant, data, len) -> Status
tlsh_final(state, variant, prefix, out, out_len_ptr) -> Status      // prefix 1 writes "T1"; too_short, insufficient_variation
tlsh_diff(variant, a, a_len, b, b_len, include_length) -> i32       // >= 0, or -Status
```

## Nilsimsa exports

In the `nilsimsa` and `fuzzy` modules. All pointers are in the scratch region.

```
nilsimsa_state_size() -> u32
nilsimsa_init(state) -> Status
nilsimsa_update(state, data, len) -> Status
nilsimsa_final(state, out) -> Status                                // 64 hex characters; the state is reset
nilsimsa_compare(a, a_len, b, b_len, out) -> Status                 // score as a little-endian i32 at out
```

## imphash and telfhash exports

The file is a heap block; `out` and `out_len_ptr` are in the scratch region.

```
imphash_hash(data, len, out, out_len_ptr) -> Status                 // 32 hex characters, or length 0 for no imports
telfhash_hash(data, len, out, out_len_ptr) -> Status                // "t1..." (lower case), "tnull" or "-"
telfhash_diff(a, a_len, b, b_len) -> i32                            // scratch strings; >= 0, or -Status
```

## Image hash exports

Pixels are a heap block; `out` and `out_len_ptr` are in the scratch region.

```
imagehash_supported_size(hash_size) -> u32                          // 1 when the module is built for this size
imagehash_hash(kind, hash_size, highfreq_factor, width, height, format, pixels, len, out, out_len_ptr) -> Status
                                                                    // kind 0 aHash, 1 dHash, 2 pHash; format 0 L, 1 LA, 2 RGB, 3 RGBA
```

## MinHash exports

`scheme` is 0 affine32, 1 affine64, 2 legacy; `num_perm` is 16, 32, 64, 128, 256 or 512. The state, the items and the offsets are heap blocks. Every bit pattern is a valid state.

```
minhash_state_size(scheme, num_perm) -> u32                         // 0 when unsupported
minhash_values_offset(scheme, num_perm) -> u32                      // hashvalues: u32 for affine32, u64 otherwise, little-endian
minhash_init(scheme, num_perm, seed, state) -> Status
minhash_update(scheme, num_perm, state, data, len, offsets, count) -> Status   // item i is data[offsets[i] .. offsets[i + 1]]
```

## SimHash exports

`f` is the width in bits, a multiple of 8 from 8 to 128. Text, items, offsets and weights are heap blocks; `out` (f / 8 big-endian bytes) is in the scratch region.

```
simhash_text(f, text, len, out) -> Status                           // UTF-8 text
simhash_features(f, data, len, offsets, weights, count, out) -> Status        // weights are i32
```

## LZJD exports

Input and digests are heap blocks; `count_ptr` and `set_size_ptr` are in the scratch region.

```
lzjd_digest(mode, hash_size, false_seen_prob, seed, data, len, out, count_ptr, set_size_ptr) -> Status
                                                                    // mode 0: i32 values (sorted); mode 1 SuperHash: f32 values
lzjd_similarity(a, a_len, b, b_len) -> f64                          // i32 digests; NaN when both are empty
lzjd_similarity_super(a, a_len, b, b_len) -> f64                    // f32 digests; NaN when the lengths differ or both are empty
```
