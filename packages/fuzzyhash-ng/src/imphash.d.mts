// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * Import hash (imphash) of a PE file, as pefile computes it.
 *
 * @example
 * ```ts
 * import { imphash } from 'fuzzyhash-ng/imphash';
 *
 * const bytes = await Deno.readFile('program.exe');
 * console.log(imphash(bytes)); // 32 hex characters, or null
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './imphash-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
