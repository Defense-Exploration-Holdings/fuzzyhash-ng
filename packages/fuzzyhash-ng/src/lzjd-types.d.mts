// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

import type { Input } from './ssdeep-types.mjs';

export interface LzjdOptions {
  /** Digest size (default 1024): at most this many values, or exactly this many in SuperHash mode. */
  hashSize?: number;
  /** pyLZJD's `mode`: `default` or `SuperHash`. */
  mode?: 'default' | 'SuperHash';
  /** pyLZJD's `false_seen_prob` (default 0). */
  falseSeenProb?: number;
  /** pyLZJD's `seed` (default 0). */
  seed?: number;
}

export interface LzjdDigest {
  /** Int32Array in default mode (sorted), Float32Array in SuperHash mode. */
  digest: Int32Array | Float32Array;
  /** Number of distinct phrase hashes. */
  setSize: number;
}

/** pyLZJD `digest(data, ...)`. */
export declare function lzjd(input: Input, opts?: LzjdOptions): LzjdDigest;

/**
 * pyLZJD `sim(A, B)`, from 0 to 1. null for two empty default-mode digests
 * (pyLZJD raises ZeroDivisionError), NaN for two empty SuperHash digests.
 */
export declare function lzjdSimilarity(a: LzjdDigest | Int32Array | Float32Array, b: LzjdDigest | Int32Array | Float32Array): number | null;
