// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * ssdeep context triggered piecewise hashes, with the same digests and
 * scores as ssdeep 2.14.1: one-shot and streaming hashing, digest
 * comparison and digest parsing.
 *
 * @example
 * ```ts
 * import { ssdeep, ssdeepCompare } from '@defense-exploration/fuzzyhash-ng/ssdeep';
 *
 * const text = Array.from({ length: 400 }, (_, i) => `line ${(i * 7919) % 1009}`).join('\n');
 * const edited = text.replace('line 0', 'line zero');
 *
 * console.log(ssdeepCompare(ssdeep(text), ssdeep(edited))); // 99
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './ssdeep-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
