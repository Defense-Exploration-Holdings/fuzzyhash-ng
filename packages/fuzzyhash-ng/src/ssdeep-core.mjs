// SPDX-License-Identifier: MIT
// ssdeep functions over a loaded WebAssembly module. Used by the `ssdeep` and
// main entry points, each with its own module. See docs/abi.md.

import { FuzzyHashError } from './errors.mjs';

// Scratch layout, as in src/abi.zig.
const STATE_OFFSET = 0;
const OUTPUT_OFFSET = 4096;
const OUTPUT_LENGTH_OFFSET = OUTPUT_OFFSET + 252;
const INPUT_OFFSET = 4096 + 256;
const INPUT_CAPACITY = 64 * 1024;

// Status codes from src/abi.zig.
const STATUS_INPUT_TOO_LARGE = 3;
const STATUS_INVALID_DIGEST = 6;

// Digest strings longer than this are shortened before they are passed in.
const SHORTEN_ABOVE = 4096;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Bytes of any accepted input. Strings are UTF-8. */
export function toBytes(input) {
  if (typeof input === 'string') return encoder.encode(input);
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  throw new FuzzyHashError('INVALID_OPTION', 'input must be a string, an ArrayBuffer or an ArrayBufferView');
}

function flagsOf(opts) {
  if (opts === undefined || opts === null) return 0;
  if (typeof opts !== 'object') throw new FuzzyHashError('INVALID_OPTION', 'options must be an object');
  return (opts.eliminateSequences ? 1 : 0) | (opts.noTruncate ? 2 : 0);
}

function fail(code, what) {
  if (code === STATUS_INPUT_TOO_LARGE) {
    throw new FuzzyHashError('INPUT_TOO_LARGE', 'input is longer than ssdeep supports (206,158,430,208 bytes)');
  }
  if (code === STATUS_INVALID_DIGEST) throw new FuzzyHashError('INVALID_DIGEST', `${what}: not a valid ssdeep digest`);
  throw new FuzzyHashError('INVALID_OPTION', `${what} failed with status ${code}`);
}

const MAX_BLOCK_SIZE = encoder.encode('18446744073709551615');

/**
 * A short string that parses and compares exactly like `b`. Parsing reads the
 * leading digits (saturating at 2^64 - 1), then part 1 up to ':', then part 2
 * up to ','. Text between the digits and the first ':' is cut to one
 * character. Runs of more than three equal characters count as three, and a
 * part that keeps more than 64 characters is an error. So it is enough to keep
 * the value of the digits, 65 kept characters per part, and nothing after
 * the comma.
 */
export function shortenDigest(b) {
  if (b.length <= SHORTEN_ABOVE) return b;
  const out = [];
  let i = 0;
  while (i < b.length && b[i] >= 0x30 && b[i] <= 0x39) i++;
  const digitsEnd = i;
  let z = 0;
  while (z < digitsEnd - 1 && b[z] === 0x30) z++;
  const digits = b.subarray(z, digitsEnd);
  for (const c of digits.length > 20 ? MAX_BLOCK_SIZE : digits) out.push(c);
  // Keep one character of anything between the digits and the first ':',
  // so a parser that rejects it still sees it, then skip the rest of it.
  if (i < b.length && b[i] !== 0x3a) {
    out.push(b[i]);
    while (i < b.length && b[i] !== 0x3a) i++;
  }
  if (i >= b.length) return Uint8Array.from(out);
  out.push(0x3a);
  i++;
  for (const delimiter of [0x3a, 0x2c]) {
    let kept = 0;
    let run = 0;
    let prev = -1;
    while (i < b.length && b[i] !== delimiter) {
      const c = b[i++];
      if (kept !== 0 && c === prev) {
        if (run >= 3) continue;
        run++;
      } else {
        prev = c;
        run = 1;
      }
      if (kept <= 64) out.push(c);
      kept++;
    }
    if (i >= b.length || delimiter === 0x2c) break;
    out.push(0x3a);
    i++;
  }
  return Uint8Array.from(out);
}

export function createSsdeep(loader) {
  let wasm = null;
  function api() {
    if (wasm) return wasm;
    const e = loader.get().exports;
    const base = e.scratch_ptr();
    wasm = {
      e,
      base,
      view: () => new Uint8Array(e.memory.buffer),
      stateSize: e.ssdeep_state_size(),
    };
    return wasm;
  }

  function readOutput(w) {
    const mem = w.view();
    const p = w.base + OUTPUT_LENGTH_OFFSET;
    const n = mem[p] | (mem[p + 1] << 8) | (mem[p + 2] << 16) | (mem[p + 3] << 24);
    return decoder.decode(mem.subarray(w.base + OUTPUT_OFFSET, w.base + OUTPUT_OFFSET + n));
  }

  class SsdeepHasher {
    #state;
    #done = false;

    constructor(opts) {
      const w = api();
      const code = w.e.ssdeep_init(w.base + STATE_OFFSET, flagsOf(opts));
      if (code !== 0) fail(code, 'init');
      this.#state = w.view().slice(w.base + STATE_OFFSET, w.base + STATE_OFFSET + w.stateSize);
    }

    update(input) {
      if (this.#done) throw new FuzzyHashError('INVALID_OPTION', 'update after digest');
      const bytes = toBytes(input);
      const w = api();
      const mem = w.view();
      mem.set(this.#state, w.base + STATE_OFFSET);
      for (let off = 0; off < bytes.length || off === 0; off += INPUT_CAPACITY) {
        const chunk = bytes.subarray(off, off + INPUT_CAPACITY);
        mem.set(chunk, w.base + INPUT_OFFSET);
        const code = w.e.ssdeep_update(w.base + STATE_OFFSET, w.base + INPUT_OFFSET, chunk.length);
        if (code !== 0) fail(code, 'update');
        if (bytes.length === 0) break;
      }
      this.#state.set(mem.subarray(w.base + STATE_OFFSET, w.base + STATE_OFFSET + w.stateSize));
      return this;
    }

    digest() {
      if (this.#done) throw new FuzzyHashError('INVALID_OPTION', 'digest called twice');
      this.#done = true;
      const w = api();
      w.view().set(this.#state, w.base + STATE_OFFSET);
      this.#state.fill(0);
      const code = w.e.ssdeep_final(w.base + STATE_OFFSET, w.base + OUTPUT_OFFSET, w.base + OUTPUT_LENGTH_OFFSET);
      if (code !== 0) fail(code, 'digest');
      return readOutput(w);
    }
  }

  function ssdeep(input, opts) {
    return new SsdeepHasher(opts).update(input).digest();
  }

  function ssdeepCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
      throw new FuzzyHashError('INVALID_OPTION', 'ssdeepCompare takes two strings');
    }
    const ba = shortenDigest(encoder.encode(a));
    const bb = shortenDigest(encoder.encode(b));
    const w = api();
    const mem = w.view();
    const pa = w.base + INPUT_OFFSET;
    const pb = pa + ba.length;
    mem.set(ba, pa);
    mem.set(bb, pb);
    const r = w.e.ssdeep_compare(pa, ba.length, pb, bb.length);
    if (r < 0) fail(-r, 'ssdeepCompare');
    return r;
  }

  function parseSsdeep(s, mode = 'lenient') {
    if (typeof s !== 'string') throw new FuzzyHashError('INVALID_OPTION', 'parseSsdeep takes a string');
    if (mode !== 'lenient' && mode !== 'strict') {
      throw new FuzzyHashError('INVALID_OPTION', "mode must be 'lenient' or 'strict'");
    }
    const all = encoder.encode(s);
    const short = shortenDigest(all);
    const w = api();
    w.view().set(short, w.base + INPUT_OFFSET);
    const code = w.e.ssdeep_parse(
      w.base + INPUT_OFFSET,
      short.length,
      mode === 'strict' ? 1 : 0,
      w.base + OUTPUT_OFFSET,
      w.base + OUTPUT_LENGTH_OFFSET,
    );
    if (code !== 0) fail(code, 'parseSsdeep');
    const [bs, part1, part2] = readOutput(w).split(':');
    const big = BigInt(bs);
    const result = {
      blockSize: big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big,
      part1,
      part2,
    };
    const filename = filenameOf(all);
    if (filename !== undefined) result.filename = filename;
    return result;
  }

  async function ssdeepStream(src, opts) {
    const h = new SsdeepHasher(opts);
    if (src && typeof src.getReader === 'function' && typeof src[Symbol.asyncIterator] !== 'function') {
      const reader = src.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          h.update(value);
        }
      } finally {
        reader.releaseLock();
      }
    } else {
      for await (const chunk of src) h.update(chunk);
    }
    return h.digest();
  }

  return { ssdeep, ssdeepCompare, parseSsdeep, ssdeepStream, SsdeepHasher };
}

/**
 * The file name after the digest, as the `ssdeep` program prints it
 * (`digest,"name"` with `\"` for a quote), or undefined when there is none.
 */
function filenameOf(b) {
  let i = 0;
  while (i < b.length && b[i] >= 0x30 && b[i] <= 0x39) i++;
  const first = b.indexOf(0x3a, i);
  if (first < 0) return undefined;
  const second = b.indexOf(0x3a, first + 1);
  if (second < 0) return undefined;
  const comma = b.indexOf(0x2c, second + 1);
  if (comma < 0) return undefined;
  let name = decoder.decode(b.subarray(comma + 1));
  if (name.length >= 2 && name.startsWith('"') && name.endsWith('"')) {
    name = name.slice(1, -1).replaceAll('\\"', '"');
  }
  return name;
}
