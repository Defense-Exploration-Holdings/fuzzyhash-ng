// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * telfhash of an ELF file and the distance between two telfhash digests, as
 * telfhash 0.9.8 computes them.
 *
 * @example
 * ```ts
 * import { telfhash, telfhashDiff } from 'fuzzyhash-ng/telfhash';
 *
 * const a = telfhash(await Deno.readFile('a.elf'));
 * const b = telfhash(await Deno.readFile('b.elf'));
 * console.log(telfhashDiff(a, b));
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './telfhash-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
