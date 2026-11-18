// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/** Options for `simhash` and `simhashFeatures`. */
export interface SimhashOptions {
  /** Fingerprint width in bits, a multiple of 8 from 8 to 128 (default 64). */
  f?: number;
}

/**
 * A feature and its integer weight, or a bare feature. As in simhash 2.1.2, a
 * bare feature takes the weight of the last pair before it, or 1 when there
 * is none.
 */
export type SimhashFeature = string | Uint8Array | [string | Uint8Array, number];

/**
 * `Simhash(text, f=f).value`. Bytes must be UTF-8. Throws `FuzzyHashError`
 * with code `UNSUPPORTED_INPUT` when one 4-character window occurs more than
 * 255 times, where the package raises OverflowError.
 */
export declare function simhash(text: string | Uint8Array, opts?: SimhashOptions): bigint;

/** `Simhash(features, f=f).value`. Weights above 255 throw `UNSUPPORTED_INPUT`. */
export declare function simhashFeatures(features: Iterable<SimhashFeature>, opts?: SimhashOptions): bigint;

/** `distance(other)`: the number of differing bits. */
export declare function simhashDistance(a: bigint, b: bigint): number;
