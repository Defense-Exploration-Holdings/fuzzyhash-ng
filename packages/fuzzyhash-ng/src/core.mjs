// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Helpers shared by the family modules: input conversion, the scratch layout,
// heap blocks and status codes. See docs/abi.md.

import { FuzzyHashError } from './errors.mjs';

// Scratch layout, as in src/abi.zig.
export const STATE_OFFSET = 0;
export const OUTPUT_OFFSET = 4096;
export const OUTPUT_CAPACITY = 256;
export const INPUT_OFFSET = 4096 + 256;
export const INPUT_CAPACITY = 64 * 1024;

// Status codes from src/abi.zig.
export const STATUS = Object.freeze({
  OK: 0,
  INVALID_ARGUMENT: 1,
  INVALID_STATE: 2,
  INPUT_TOO_LARGE: 3,
  TOO_SHORT: 4,
  INSUFFICIENT_VARIATION: 5,
  INVALID_DIGEST: 6,
  INVALID_VARIANT: 7,
  INVALID_INPUT: 8,
  UNSUPPORTED_INPUT: 9,
  OUT_OF_MEMORY: 10,
});

const encoder = new TextEncoder();
export const decoder = new TextDecoder();

/** UTF-8 bytes of a string. */
export function utf8(s) {
  return encoder.encode(s);
}

/** Bytes of any accepted input. Strings are UTF-8. */
export function toBytes(input) {
  if (typeof input === 'string') return encoder.encode(input);
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  throw new FuzzyHashError('INVALID_OPTION', 'input must be a string, an ArrayBuffer or an ArrayBufferView');
}

/** An options argument: undefined, null or a plain object. */
export function optionsOf(opts) {
  if (opts === undefined || opts === null) return {};
  if (typeof opts !== 'object') throw new FuzzyHashError('INVALID_OPTION', 'options must be an object');
  return opts;
}

/** Throws the FuzzyHashError for a non-zero status. */
export function fail(code, what) {
  switch (code) {
    case STATUS.INPUT_TOO_LARGE:
      throw new FuzzyHashError('INPUT_TOO_LARGE', `${what}: input is too large`);
    case STATUS.INVALID_DIGEST:
      throw new FuzzyHashError('INVALID_DIGEST', `${what}: not a valid digest`);
    case STATUS.INVALID_INPUT:
      throw new FuzzyHashError('INVALID_INPUT', `${what}: the input cannot be read`);
    case STATUS.UNSUPPORTED_INPUT:
      throw new FuzzyHashError('UNSUPPORTED_INPUT', `${what}: the reference gives no result for this input`);
    case STATUS.OUT_OF_MEMORY:
      throw new FuzzyHashError('OUT_OF_MEMORY', `${what}: out of WebAssembly memory`);
    default:
      throw new FuzzyHashError('INVALID_OPTION', `${what} failed with status ${code}`);
  }
}

/** Little-endian u32 at `p`. */
export function readU32(mem, p) {
  return (mem[p] | (mem[p + 1] << 8) | (mem[p + 2] << 16) | (mem[p + 3] << 24)) >>> 0;
}

/**
 * The exports of a loaded module and its scratch base, created on first use.
 * `view()` returns a fresh view of memory: heap modules can grow it.
 */
export function lazyApi(loader) {
  let api = null;
  return function get() {
    if (api) return api;
    const e = loader.get().exports;
    api = { e, base: e.scratch_ptr() >>> 0, view: () => new Uint8Array(e.memory.buffer) };
    return api;
  };
}

/**
 * Runs `fn(ptrs)` with heap blocks holding each of `parts` (Uint8Arrays) and
 * frees them afterwards. Blocks are aligned to 16.
 */
export function withBlocks(w, parts, fn) {
  const ptrs = [];
  try {
    for (const bytes of parts) {
      const p = w.e.fuzzy_alloc(bytes.length) >>> 0;
      if (p === 0) throw new FuzzyHashError('OUT_OF_MEMORY', 'out of WebAssembly memory');
      ptrs.push(p);
      w.view().set(bytes, p);
    }
    return fn(ptrs);
  } finally {
    for (let i = 0; i < ptrs.length; i++) w.e.fuzzy_free(ptrs[i], parts[i].length);
  }
}

/** Items (strings or bytes) as one byte array and `count + 1` u32 offsets. */
export function packItems(items, what) {
  if (items === null || typeof items !== 'object' || typeof items[Symbol.iterator] !== 'function') {
    throw new FuzzyHashError('INVALID_OPTION', `${what} takes an iterable of strings or byte arrays`);
  }
  const list = [];
  let total = 0;
  for (const item of items) {
    const b = toBytes(item);
    list.push(b);
    total += b.length;
  }
  const data = new Uint8Array(total);
  const offsets = new Uint32Array(list.length + 1);
  let off = 0;
  for (let i = 0; i < list.length; i++) {
    data.set(list[i], off);
    off += list[i].length;
    offsets[i + 1] = off;
  }
  return { data, offsets, count: list.length };
}

/** Bytes of a typed array, without copying. */
export function bytesOf(typed) {
  return new Uint8Array(typed.buffer, typed.byteOffset, typed.byteLength);
}

/** Feeds a web ReadableStream, a Node Readable or any async iterable of bytes into `h.update`. */
export async function feed(h, src) {
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
  return h;
}

/**
 * A streaming hasher class over state kept on the JavaScript side: each call
 * copies the state into the scratch region, runs, and copies it back.
 *
 * `spec.init(w, statePtr, args)` returns a status, `spec.update(w, statePtr,
 * dataPtr, len, args)` returns a status, and `spec.final(w, statePtr, args)`
 * returns the result. `spec.stateSize(w, args)` gives the state length.
 */
export function stateHasher(getApi, spec) {
  return class {
    #state;
    #args;
    #done = false;

    constructor(opts) {
      const w = getApi();
      this.#args = spec.args(opts);
      const size = spec.stateSize(w, this.#args);
      const code = spec.init(w, w.base + STATE_OFFSET, this.#args);
      if (code !== 0) fail(code, `${spec.name} init`);
      this.#state = w.view().slice(w.base + STATE_OFFSET, w.base + STATE_OFFSET + size);
    }

    update(input) {
      if (this.#done) throw new FuzzyHashError('INVALID_OPTION', 'update after digest');
      const bytes = toBytes(input);
      const w = getApi();
      const mem = w.view();
      mem.set(this.#state, w.base + STATE_OFFSET);
      for (let off = 0; off < bytes.length; off += INPUT_CAPACITY) {
        const chunk = bytes.subarray(off, off + INPUT_CAPACITY);
        mem.set(chunk, w.base + INPUT_OFFSET);
        const code = spec.update(w, w.base + STATE_OFFSET, w.base + INPUT_OFFSET, chunk.length, this.#args);
        if (code !== 0) fail(code, `${spec.name} update`);
      }
      this.#state.set(mem.subarray(w.base + STATE_OFFSET, w.base + STATE_OFFSET + this.#state.length));
      return this;
    }

    digest() {
      if (this.#done) throw new FuzzyHashError('INVALID_OPTION', 'digest called twice');
      this.#done = true;
      const w = getApi();
      w.view().set(this.#state, w.base + STATE_OFFSET);
      this.#state.fill(0);
      return spec.final(w, w.base + STATE_OFFSET, this.#args);
    }
  };
}

/**
 * Writes two strings into the input slot and returns [pa, la, pb, lb]. Each
 * is cut to its first `limit` bytes: the parsers never look further.
 */
export function placePair(w, a, b, what, limit) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    throw new FuzzyHashError('INVALID_OPTION', `${what} takes two strings`);
  }
  const ba = encoder.encode(a).subarray(0, limit);
  const bb = encoder.encode(b).subarray(0, limit);
  const mem = w.view();
  const pa = w.base + INPUT_OFFSET;
  const pb = pa + ba.length;
  mem.set(ba, pa);
  mem.set(bb, pb);
  return [pa, ba.length, pb, bb.length];
}

/** Text written to the output slot, `len` bytes. */
export function readOutput(w, len) {
  const mem = w.view();
  return decoder.decode(mem.subarray(w.base + OUTPUT_OFFSET, w.base + OUTPUT_OFFSET + len));
}
