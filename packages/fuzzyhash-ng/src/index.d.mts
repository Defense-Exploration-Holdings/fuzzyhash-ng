// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * Every hash family in the package, from one WebAssembly module: ssdeep, TLSH,
 * imphash, telfhash, ImageHash, MinHash, Simhash, LZJD and Nilsimsa. Each
 * family is also its own entry point with a smaller module.
 *
 * @example
 * ```ts
 * import { ssdeep, ssdeepCompare, tlsh, tlshDiff } from 'fuzzyhash-ng';
 *
 * const text = Array.from({ length: 400 }, (_, i) => `line ${(i * 7919) % 1009}`).join('\n');
 * const edited = text.replace('line 0', 'line zero');
 *
 * console.log(ssdeepCompare(ssdeep(text), ssdeep(edited))); // 99
 * console.log(tlshDiff(tlsh(text)!, tlsh(edited)!)); // 4
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './ssdeep-types.mjs';
export * from './tlsh-types.mjs';
export * from './imphash-types.mjs';
export * from './telfhash-types.mjs';
export * from './imagehash-types.mjs';
export * from './minhash-types.mjs';
export * from './simhash-types.mjs';
export * from './lzjd-types.mjs';
export * from './nilsimsa-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
