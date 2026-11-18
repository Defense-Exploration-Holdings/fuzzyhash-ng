# fuzzyhash-ng

[![npm](https://img.shields.io/npm/v/fuzzyhash-ng)](https://www.npmjs.com/package/fuzzyhash-ng)
[![license](https://img.shields.io/npm/l/fuzzyhash-ng)](https://github.com/Defense-Exploration-Holdings/fuzzyhash-ng/blob/main/LICENSE)
[![types](https://img.shields.io/npm/types/fuzzyhash-ng)](#entry-points)
[![JSR](https://jsr.io/badges/@defense-exploration/fuzzyhash-ng)](https://jsr.io/@defense-exploration/fuzzyhash-ng)

Fuzzy and similarity hashes for JavaScript and TypeScript, compiled from Zig to WebAssembly: ssdeep, TLSH, imphash, telfhash, aHash, dHash, pHash, MinHash, SimHash, LZJD and Nilsimsa. Every digest, score and distance matches the reference implementation.

| Hash | Matches |
|---|---|
| ssdeep | ssdeep 2.14.1 |
| TLSH | TLSH 5.0.2 (all four builds) |
| imphash | pefile 2024.8.26 `get_imphash()` |
| telfhash | telfhash 0.9.8 (pyelftools 0.33, capstone 5.0.9) |
| aHash, dHash, pHash | ImageHash 4.3.2 (Pillow 13.0, scipy 1.18 on x86-64 Linux) |
| MinHash | datasketch 2.0.0 |
| SimHash | simhash 2.1.2 |
| LZJD | pyLZJD (commit e2c24bd) |
| Nilsimsa | nilsimsa 0.3.8 |

> **Status: in development.** The API may still change before 1.0.

Runs on Node.js 18 or newer, Bun, Deno and evergreen browsers. No runtime dependencies.

```sh
npm install fuzzyhash-ng
deno add jsr:@defense-exploration/fuzzyhash-ng
```

## Entry points

| Import | Contents |
|---|---|
| `fuzzyhash-ng` | every family |
| `fuzzyhash-ng/ssdeep` | ssdeep |
| `fuzzyhash-ng/tlsh` | TLSH |
| `fuzzyhash-ng/imphash` | imphash |
| `fuzzyhash-ng/telfhash` | telfhash |
| `fuzzyhash-ng/imagehash` | aHash, dHash and pHash |
| `fuzzyhash-ng/minhash` | MinHash |
| `fuzzyhash-ng/simhash` | SimHash |
| `fuzzyhash-ng/lzjd` | LZJD |
| `fuzzyhash-ng/nilsimsa` | Nilsimsa |

Each entry point carries its own WebAssembly module and compiles it synchronously on first use. The main entry point carries all of them (about 700 KB, most of it the x86 decoder tables telfhash needs); import a single family to load less. Where synchronous compilation is refused, call `await ready()` first. Pages with a strict Content-Security-Policy need `'wasm-unsafe-eval'` in `script-src`.

Inputs are a `Uint8Array`, an `ArrayBuffer`, any other `ArrayBufferView`, or a string, which is hashed as UTF-8. Errors are thrown as `FuzzyHashError` with a `code`: `INVALID_OPTION`, `INVALID_DIGEST`, `INVALID_INPUT` (a file or image the reference cannot read), `UNSUPPORTED_INPUT` (the reference gives no result), `INPUT_TOO_LARGE`, `OUT_OF_MEMORY` or `WASM_UNAVAILABLE`.

## ssdeep

```js
import { ssdeep, ssdeepCompare, SsdeepHasher, ssdeepStream, parseSsdeep } from 'fuzzyhash-ng/ssdeep';

const a = ssdeep(bytes);                         // '96:...:...'
ssdeep(bytes, { eliminateSequences: true, noTruncate: true });
ssdeepCompare(a, ssdeep(otherBytes));            // integer from 0 to 100

const h = new SsdeepHasher();
h.update(chunk1).update(chunk2);
h.digest();                                      // the hasher cannot be used after this

await ssdeepStream(fs.createReadStream(path));   // Node streams, web streams, async iterables
parseSsdeep('3:iKn:p,"a.txt"');                  // { blockSize: 3, part1: 'iKn', part2: 'p', filename: 'a.txt' }
```

`ssdeepCompare` accepts what ssdeep's compare accepts, including a file name after a comma, and scores digests with block sizes that cannot be compared as 0. It throws `INVALID_DIGEST` where ssdeep reports an error. Leading whitespace and a leading sign are rejected. `parseSsdeep` in the default lenient mode skips any text between the block size and the first colon, as ssdeep does; use `'strict'` to reject it.

## TLSH

```js
import { tlsh, tlshDiff, TlshHasher, tlshStream } from 'fuzzyhash-ng/tlsh';

tlsh(bytes);                                     // 'T1' + 70 hex digits, or null
tlsh(bytes, { buckets: 256, checksum: 3 });      // the other reference builds
tlsh(bytes, { conservative: true, prefix: false });
tlshDiff(a, b);                                  // 0 for identical digests
tlshDiff(a, b, { includeLength: false });        // py-tlsh diffxlen
new TlshHasher().update(chunk1).update(chunk2).digest();
await tlshStream(stream);
```

`tlsh` returns null where TLSH gives no digest: fewer than 50 bytes (256 with `conservative`) or too little variation. To compare digests of another build, pass the same `buckets` and `checksum` to `tlshDiff`. As in TLSH, only the standard digest can be read back with its `T1` prefix.

## imphash and telfhash

```js
import { imphash } from 'fuzzyhash-ng/imphash';
import { telfhash, telfhashDiff } from 'fuzzyhash-ng/telfhash';

imphash(peBytes);            // 32 lowercase hex characters, or null where pefile returns ''
telfhash(elfBytes);          // 't1' + 70 hex digits, 'tnull' or '-'
telfhashDiff(a, b);          // TLSH distance, as telfhash's grouping computes it
```

Both take the whole file. `imphash` throws `INVALID_INPUT` where pefile refuses the file. `telfhash` throws `INVALID_INPUT` where pyelftools cannot read the file (telfhash prints `-` there) and `UNSUPPORTED_INPUT` where telfhash gives no result (a symbol name that is not ASCII, a compressed code section, or headers telfhash never finishes reading).

## Image hashes

```js
import { averageHash, dhash, phash, imageHashDistance } from 'fuzzyhash-ng/imagehash';

const image = { width, height, data };           // decoded 8-bit pixels, for example a canvas ImageData
averageHash(image);                              // '00030f1f3c3b377e', as str(imagehash.average_hash(img))
dhash(image, { hashSize: 16 });
phash(image, { hashSize: 8, highfreqFactor: 4 });
imageHashDistance(a, b);                         // differing bits
```

`data` holds `height` rows of `width` pixels without padding, in Pillow's `L`, `LA`, `RGB` or `RGBA` layout. `format` can be given; otherwise it follows from the data length. Alpha is ignored, as in Pillow's `convert("L")`. `hashSize` is one of 4, 6, 8 (default), 10, 12, 14, 16, 20, 24, 28 or 32. The package does not decode image files: use the platform's decoder (a canvas, `createImageBitmap`, or an image library) first. pHash results on flat or symmetric images follow the reference on x86-64 Linux.

## MinHash

```js
import { MinHash } from 'fuzzyhash-ng/minhash';

const a = new MinHash({ numPerm: 128, seed: 1, scheme: 'affine32' });  // datasketch's defaults
a.update('word').updateBatch(['other', 'words']);
a.jaccard(b);
a.merge(b);
a.digest();                                      // Uint32Array (affine32) or BigUint64Array
a.copy(); a.clear(); a.isEmpty();
```

`numPerm` is one of 16, 32, 64, 128, 256 or 512. `scheme` is `affine32`, `affine64` or `legacy`, as in datasketch 2.0.0. Items are hashed with SHA-1, datasketch's default.

## SimHash

```js
import { simhash, simhashFeatures, simhashDistance } from 'fuzzyhash-ng/simhash';

simhash('some text');                            // bigint, Simhash(text).value
simhash('some text', { f: 128 });
simhashFeatures(['a', 'b', ['c', 3]]);           // Simhash(features).value
simhashDistance(x, y);
```

`f` is a multiple of 8 from 8 to 128 (default 64). As in simhash 2.1.2, a bare feature after a `[feature, weight]` pair takes that pair's weight. A weight above 255, or a text where one 4-character window occurs more than 255 times, throws `UNSUPPORTED_INPUT` where the package raises OverflowError.

## LZJD

```js
import { lzjd, lzjdSimilarity } from 'fuzzyhash-ng/lzjd';

const a = lzjd(bytes);                           // { digest: Int32Array, setSize }
const s = lzjd(bytes, { mode: 'SuperHash', hashSize: 1024 });  // digest is a Float32Array
lzjdSimilarity(a, lzjd(otherBytes));             // 0 to 1
```

Options follow pyLZJD's `digest`: `hashSize` (default 1024), `mode`, `falseSeenProb` and `seed`. `lzjdSimilarity` returns null for two empty default-mode digests, where pyLZJD raises.

## Nilsimsa

```js
import { nilsimsa, nilsimsaCompare, NilsimsaHasher, nilsimsaStream } from 'fuzzyhash-ng/nilsimsa';

nilsimsa(bytes);                                 // 64 lowercase hex characters
nilsimsaCompare(a, b);                           // -128 to 128
```

## License

MIT. Code ported from TLSH and telfhash is used under Apache-2.0 and keeps its own SPDX header. The licences and notices of all ported code ship in `LICENSES/`. See the [repository](https://github.com/Defense-Exploration-Holdings/fuzzyhash-ng) for source and documentation.
