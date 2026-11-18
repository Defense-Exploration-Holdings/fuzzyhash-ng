// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// LZJD (pyLZJD) over a loaded WebAssembly module. Used by the `lzjd` and main
// entry points. See docs/abi.md.

import { FuzzyHashError } from './errors.mjs';
import { INPUT_OFFSET, bytesOf, fail, lazyApi, optionsOf, readU32, toBytes, withBlocks } from './core.mjs';

const COUNT_OFFSET = INPUT_OFFSET;
const SET_SIZE_OFFSET = INPUT_OFFSET + 4;

function digestOf(x, what) {
  const d = x instanceof Int32Array || x instanceof Float32Array ? x : x?.digest;
  if (!(d instanceof Int32Array) && !(d instanceof Float32Array)) {
    throw new FuzzyHashError('INVALID_OPTION', `${what} takes lzjd() results or their digests`);
  }
  return d;
}

export function createLzjd(loader) {
  const api = lazyApi(loader);

  /** pyLZJD `digest(data, hash_size, mode, false_seen_prob, seed)`. */
  function lzjd(input, opts) {
    const o = optionsOf(opts);
    const hashSize = o.hashSize ?? 1024;
    const mode = o.mode ?? 'default';
    const falseSeenProb = o.falseSeenProb ?? 0;
    const seed = o.seed ?? 0;
    if (mode !== 'default' && mode !== 'SuperHash') throw new FuzzyHashError('INVALID_OPTION', "mode must be 'default' or 'SuperHash'");
    const superHash = mode === 'SuperHash';
    if (!Number.isInteger(hashSize) || hashSize < (superHash ? 1 : 0) || hashSize > 0x3fffffff) {
      throw new FuzzyHashError('INVALID_OPTION', 'hashSize must be a positive integer');
    }
    if (typeof falseSeenProb !== 'number' || Number.isNaN(falseSeenProb)) throw new FuzzyHashError('INVALID_OPTION', 'falseSeenProb must be a number');
    if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff) throw new FuzzyHashError('INVALID_OPTION', 'seed must be an integer from 0 to 2^32 - 1');
    const bytes = toBytes(input);
    const out = new Uint8Array(hashSize * 4);
    const w = api();
    return withBlocks(w, [bytes, out], ([pi, po]) => {
      const code = w.e.lzjd_digest(
        superHash ? 1 : 0, hashSize, falseSeenProb, seed, pi, bytes.length, po,
        w.base + COUNT_OFFSET, w.base + SET_SIZE_OFFSET,
      );
      if (code !== 0) fail(code, 'lzjd');
      const mem = w.view();
      const count = readU32(mem, w.base + COUNT_OFFSET);
      const setSize = readU32(mem, w.base + SET_SIZE_OFFSET);
      const values = mem.slice(po, po + count * 4);
      const digest = superHash ? new Float32Array(values.buffer) : new Int32Array(values.buffer);
      return { digest, setSize };
    });
  }

  /** pyLZJD `sim(A, B)`. null for two empty default-mode digests, where pyLZJD raises. */
  function lzjdSimilarity(a, b) {
    const da = digestOf(a, 'lzjdSimilarity');
    const db = digestOf(b, 'lzjdSimilarity');
    if (da.constructor !== db.constructor) throw new FuzzyHashError('INVALID_OPTION', 'lzjdSimilarity: both digests need the same mode');
    const superHash = da instanceof Float32Array;
    if (superHash && da.length !== db.length) throw new FuzzyHashError('INVALID_OPTION', 'lzjdSimilarity: SuperHash digests need the same length');
    if (!superHash && da.length === 0 && db.length === 0) return null;
    const w = api();
    return withBlocks(w, [bytesOf(da), bytesOf(db)], ([pa, pb]) =>
      superHash ? w.e.lzjd_similarity_super(pa, da.length, pb, db.length) : w.e.lzjd_similarity(pa, da.length, pb, db.length),
    );
  }

  return { lzjd, lzjdSimilarity };
}
