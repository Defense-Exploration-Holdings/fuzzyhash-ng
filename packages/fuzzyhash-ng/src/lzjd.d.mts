// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * Lempel-Ziv Jaccard distance (LZJD) digests and similarity, with the same
 * values as pyLZJD.
 *
 * @example
 * ```ts
 * import { lzjd, lzjdSimilarity } from '@defense-exploration/fuzzyhash-ng/lzjd';
 *
 * const text = Array.from({ length: 400 }, (_, i) => `line ${(i * 7919) % 1009}`).join('\n');
 * const edited = text.replace('line 0', 'line zero');
 *
 * console.log(lzjdSimilarity(lzjd(text), lzjd(edited))); // 0 to 1
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './lzjd-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
