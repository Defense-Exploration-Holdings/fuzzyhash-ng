// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// MinHash (datasketch) over a loaded WebAssembly module. Used by the
// `minhash` and main entry points. See docs/abi.md.

import { FuzzyHashError } from './errors.mjs';
import { bytesOf, fail, lazyApi, optionsOf, packItems, withBlocks } from './core.mjs';

const SCHEMES = { affine32: 0, affine64: 1, legacy: 2 };
export const PERM_COUNTS = Object.freeze([16, 32, 64, 128, 256, 512]);

/** Passed to the constructor by `copy()`; not reachable from outside this module. */
class CopyOf {
  constructor(src) {
    this.src = src;
  }
}

export function createMinHash(loader) {
  const api = lazyApi(loader);

  class MinHash {
    #scheme;
    #numPerm;
    #seed;
    #state;
    #values;

    constructor(opts) {
      if (opts instanceof CopyOf) {
        const src = opts.src;
        this.#scheme = src.#scheme;
        this.#numPerm = src.#numPerm;
        this.#seed = src.#seed;
        this.#state = src.#state.slice();
        this.#values = this.#viewValues(src.#values.byteOffset);
        return;
      }
      const o = optionsOf(opts);
      const scheme = o.scheme ?? 'affine32';
      const numPerm = o.numPerm ?? 128;
      const seed = o.seed ?? 1;
      if (!Object.hasOwn(SCHEMES, scheme)) throw new FuzzyHashError('INVALID_OPTION', "scheme must be 'affine32', 'affine64' or 'legacy'");
      if (!PERM_COUNTS.includes(numPerm)) throw new FuzzyHashError('INVALID_OPTION', `numPerm must be one of ${PERM_COUNTS.join(', ')}`);
      if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff) throw new FuzzyHashError('INVALID_OPTION', 'seed must be an integer from 0 to 2^32 - 1');
      this.#scheme = scheme;
      this.#numPerm = numPerm;
      this.#seed = seed;
      const w = api();
      const s = SCHEMES[scheme];
      const size = w.e.minhash_state_size(s, numPerm);
      const offset = w.e.minhash_values_offset(s, numPerm);
      this.#state = new Uint8Array(size);
      this.#values = this.#viewValues(offset);
      withBlocks(w, [this.#state], ([p]) => {
        const code = w.e.minhash_init(s, numPerm, seed, p);
        if (code !== 0) fail(code, 'MinHash');
        this.#state.set(w.view().subarray(p, p + size));
      });
    }

    #viewValues(offset) {
      const T = this.#scheme === 'affine32' ? Uint32Array : BigUint64Array;
      return new T(this.#state.buffer, offset, this.#numPerm);
    }

    get scheme() {
      return this.#scheme;
    }

    get numPerm() {
      return this.#numPerm;
    }

    get seed() {
      return this.#seed;
    }

    /** `update(b)`: add one item (bytes, or a string as UTF-8). */
    update(item) {
      return this.updateBatch([item]);
    }

    /** `update_batch(b)`: add each item of an iterable. */
    updateBatch(items) {
      const { data, offsets, count } = packItems(items, 'updateBatch');
      if (count === 0) return this;
      const w = api();
      const s = SCHEMES[this.#scheme];
      withBlocks(w, [this.#state, data, bytesOf(offsets)], ([ps, pd, po]) => {
        const code = w.e.minhash_update(s, this.#numPerm, ps, pd, data.length, po, count);
        if (code !== 0) fail(code, 'MinHash update');
        this.#state.set(w.view().subarray(ps, ps + this.#state.length));
      });
      return this;
    }

    #check(other, what) {
      if (!(other instanceof MinHash)) throw new FuzzyHashError('INVALID_OPTION', `${what} takes a MinHash`);
      if (other.#seed !== this.#seed || other.#numPerm !== this.#numPerm || other.#scheme !== this.#scheme) {
        throw new FuzzyHashError('INVALID_OPTION', `${what}: both MinHashes need the same seed, numPerm and scheme`);
      }
    }

    /** `jaccard(other)`: the share of equal hash values. */
    jaccard(other) {
      this.#check(other, 'jaccard');
      const a = this.#values;
      const b = other.#values;
      let n = 0;
      for (let i = 0; i < a.length; i++) if (a[i] === b[i]) n++;
      return n / a.length;
    }

    /** `merge(other)`: element-wise minimum, in place. */
    merge(other) {
      this.#check(other, 'merge');
      const a = this.#values;
      const b = other.#values;
      for (let i = 0; i < a.length; i++) if (b[i] < a[i]) a[i] = b[i];
      return this;
    }

    #max() {
      return this.#scheme === 'affine32' ? 0xffffffff : this.#scheme === 'affine64' ? 0xffffffffffffffffn : 0xffffffffn;
    }

    /** `is_empty()`. */
    isEmpty() {
      const m = this.#max();
      return this.#values.every((v) => v === m);
    }

    /** `clear()`. */
    clear() {
      this.#values.fill(this.#max());
      return this;
    }

    /** `digest()`: a copy of the hash values (Uint32Array for affine32, BigUint64Array otherwise). */
    digest() {
      return this.#values.slice();
    }

    /** `copy()`. */
    copy() {
      return new MinHash(new CopyOf(this));
    }
  }

  return { MinHash };
}
