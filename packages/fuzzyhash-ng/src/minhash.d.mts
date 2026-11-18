// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * MinHash signatures and Jaccard estimates, with the same values as
 * datasketch's `MinHash`.
 *
 * @example
 * ```ts
 * import { MinHash } from '@defense-exploration/fuzzyhash-ng/minhash';
 *
 * const a = new MinHash().updateBatch(['a', 'b', 'c']);
 * const b = new MinHash().updateBatch(['a', 'b', 'd']);
 * console.log(a.jaccard(b));
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './minhash-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
