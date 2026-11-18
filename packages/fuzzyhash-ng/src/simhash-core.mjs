// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// SimHash (the `simhash` Python package) over a loaded WebAssembly module.
// Used by the `simhash` and main entry points. See docs/abi.md.

import { FuzzyHashError } from './errors.mjs';
import { OUTPUT_OFFSET, bytesOf, fail, lazyApi, optionsOf, packItems, toBytes, withBlocks } from './core.mjs';

function widthOf(opts) {
  const f = optionsOf(opts).f ?? 64;
  if (!Number.isInteger(f) || f < 8 || f > 128 || f % 8 !== 0) {
    throw new FuzzyHashError('INVALID_OPTION', 'f must be a multiple of 8 from 8 to 128');
  }
  return f;
}

function readValue(w, f) {
  const mem = w.view();
  let v = 0n;
  for (let i = 0; i < f / 8; i++) v = (v << 8n) | BigInt(mem[w.base + OUTPUT_OFFSET + i]);
  return v;
}

export function createSimhash(loader) {
  const api = lazyApi(loader);

  /** `Simhash(text, f=f).value`. */
  function simhash(text, opts) {
    const f = widthOf(opts);
    const bytes = toBytes(text);
    const w = api();
    return withBlocks(w, [bytes], ([p]) => {
      const code = w.e.simhash_text(f, p, bytes.length, w.base + OUTPUT_OFFSET);
      if (code !== 0) fail(code, 'simhash');
      return readValue(w, f);
    });
  }

  /**
   * `Simhash(features, f=f).value`: each feature is a [feature, weight] pair
   * or a bare string. As in simhash 2.1.2, a bare string takes the weight of
   * the last pair before it, or 1 when there is none.
   */
  function simhashFeatures(features, opts) {
    const f = widthOf(opts);
    if (features === null || typeof features !== 'object' || typeof features[Symbol.iterator] !== 'function') {
      throw new FuzzyHashError('INVALID_OPTION', 'simhashFeatures takes an iterable of features');
    }
    const names = [];
    const weights = [];
    let last = 1;
    for (const item of features) {
      if (Array.isArray(item)) {
        const [name, weight] = item;
        if (!Number.isInteger(weight) || weight < -0x80000000 || weight > 0x7fffffff) {
          throw new FuzzyHashError('INVALID_OPTION', 'a feature weight must be a 32-bit integer');
        }
        names.push(name);
        weights.push(weight);
        last = weight;
      } else {
        names.push(item);
        weights.push(last);
      }
    }
    const { data, offsets, count } = packItems(names, 'simhashFeatures');
    const ws = Int32Array.from(weights);
    const w = api();
    return withBlocks(w, [data, bytesOf(offsets), bytesOf(ws)], ([pd, po, pw]) => {
      const code = w.e.simhash_features(f, pd, data.length, po, pw, count, w.base + OUTPUT_OFFSET);
      if (code !== 0) fail(code, 'simhashFeatures');
      return readValue(w, f);
    });
  }

  return { simhash, simhashFeatures, simhashDistance };
}

/** `distance(other)`: the number of differing bits. */
export function simhashDistance(a, b) {
  if (typeof a !== 'bigint' || typeof b !== 'bigint' || a < 0n || b < 0n) {
    throw new FuzzyHashError('INVALID_OPTION', 'simhashDistance takes two non-negative bigints');
  }
  let x = a ^ b;
  let d = 0;
  while (x) {
    d += Number(x & 1n);
    x >>= 1n;
  }
  return d;
}
