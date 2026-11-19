// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * Nilsimsa digests and scores, with the same values as the nilsimsa 0.3.8
 * Python package.
 *
 * @example
 * ```ts
 * import { nilsimsa, nilsimsaCompare } from 'fuzzyhash-ng/nilsimsa';
 *
 * const text = Array.from({ length: 400 }, (_, i) => `line ${(i * 7919) % 1009}`).join('\n');
 * const edited = text.replace('line 0', 'line zero');
 *
 * console.log(nilsimsaCompare(nilsimsa(text), nilsimsa(edited))); // -128 to 128
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './nilsimsa-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
