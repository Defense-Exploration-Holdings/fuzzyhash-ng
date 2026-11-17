# fuzzyhash-ng

ssdeep and TLSH similarity digests for JavaScript and TypeScript, compiled from Zig to WebAssembly. Digests, ssdeep scores and TLSH distances match ssdeep 2.14.1 and TLSH 5.0.2.

> **Status: in development.** ssdeep is in; TLSH arrives before 1.0. The `tlsh` entry point exports only `ready()` until then.

Runs on Node.js 18 or newer, Bun, Deno and evergreen browsers. No runtime dependencies.

## Entry points

| Import | Contents |
|---|---|
| `fuzzyhash-ng` | ssdeep and TLSH |
| `fuzzyhash-ng/ssdeep` | ssdeep only |
| `fuzzyhash-ng/tlsh` | TLSH only |

Each entry point carries its own WebAssembly module and compiles it synchronously on first use. Where synchronous compilation is refused, call `await ready()` first. Pages with a strict Content-Security-Policy need `'wasm-unsafe-eval'` in `script-src`.

If WebAssembly is unavailable, calls throw `FuzzyHashError` with code `WASM_UNAVAILABLE`.

## ssdeep

```js
import { ssdeep, ssdeepCompare, SsdeepHasher, ssdeepStream, parseSsdeep } from 'fuzzyhash-ng/ssdeep';

const a = ssdeep(bytes);                         // '96:...:...'; strings are hashed as UTF-8
ssdeep(bytes, { eliminateSequences: true, noTruncate: true });
ssdeepCompare(a, ssdeep(otherBytes));            // integer from 0 to 100

const h = new SsdeepHasher();
h.update(chunk1).update(chunk2);
h.digest();                                      // the hasher cannot be used after this

await ssdeepStream(fs.createReadStream(path));   // Node streams, web streams, async iterables
parseSsdeep('3:iKn:p,"a.txt"');                  // { blockSize: 3, part1: 'iKn', part2: 'p', filename: 'a.txt' }
```

`ssdeepCompare` accepts what ssdeep's compare accepts, including a file name after a comma, and scores digests with block sizes that cannot be compared as 0. It throws `FuzzyHashError` with code `INVALID_DIGEST` where ssdeep reports an error. Leading whitespace and a leading sign are rejected. `parseSsdeep` in the default lenient mode skips any text between the block size and the first colon, as ssdeep does; use `'strict'` to reject it.

## License

MIT. See the [repository](https://github.com/Defense-Exploration-Holdings/fuzzyhash-ng) for source, documentation and the TLSH licence notice.
