// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/** One item of a set: bytes, or a string as UTF-8. */
export type MinHashItem = Uint8Array | ArrayBuffer | ArrayBufferView | string;

/** Options for the `MinHash` constructor. */
export interface MinHashOptions {
  /** Number of permutations: 16, 32, 64, 128 (default), 256 or 512. */
  numPerm?: number;
  /** numpy `RandomState` seed, 0 to 2^32 - 1 (default 1). */
  seed?: number;
  /** datasketch's `scheme`: `affine32` (default), `affine64` or `legacy`. */
  scheme?: 'affine32' | 'affine64' | 'legacy';
}

/** `datasketch.MinHash` with its default SHA-1 hash functions. */
export declare class MinHash {
  /** An empty MinHash, as `MinHash(num_perm, seed)`. */
  constructor(opts?: MinHashOptions);
  /** Number of permutations. */
  readonly numPerm: number;
  /** Seed of the permutations. */
  readonly seed: number;
  /** Hash scheme. */
  readonly scheme: 'affine32' | 'affine64' | 'legacy';
  /** `update(b)`. */
  update(item: MinHashItem): this;
  /** `update_batch(b)`. */
  updateBatch(items: Iterable<MinHashItem>): this;
  /** `jaccard(other)`. Both need the same seed, numPerm and scheme. */
  jaccard(other: MinHash): number;
  /** `merge(other)`, in place. */
  merge(other: MinHash): this;
  /** `is_empty()`. */
  isEmpty(): boolean;
  /** `clear()`. */
  clear(): this;
  /** `digest()`: Uint32Array for affine32, BigUint64Array otherwise. */
  digest(): Uint32Array | BigUint64Array;
  /** `copy()`. */
  copy(): MinHash;
}
