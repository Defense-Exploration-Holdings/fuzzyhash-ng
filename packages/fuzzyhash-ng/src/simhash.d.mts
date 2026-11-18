// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * Simhash fingerprints and distances, with the same values as the simhash
 * 2.1.2 Python package.
 *
 * @example
 * ```ts
 * import { simhash, simhashDistance } from '@defense-exploration/fuzzyhash-ng/simhash';
 *
 * const a = simhash('the quick brown fox');
 * const b = simhash('the quick brown dog');
 * console.log(simhashDistance(a, b));
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './simhash-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
