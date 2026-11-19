// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * TLSH locality sensitive hashes, with the same digests and distances as
 * TLSH 5.0.2, for the 128 and 256 bucket and 1 and 3 byte checksum builds.
 *
 * @example
 * ```ts
 * import { tlsh, tlshDiff } from 'fuzzyhash-ng/tlsh';
 *
 * const text = Array.from({ length: 400 }, (_, i) => `line ${(i * 7919) % 1009}`).join('\n');
 * const edited = text.replace('line 0', 'line zero');
 *
 * // null when the input is too short or too uniform
 * const a = tlsh(text);
 * const b = tlsh(edited);
 * if (a && b) console.log(tlshDiff(a, b)); // 4
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './tlsh-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
