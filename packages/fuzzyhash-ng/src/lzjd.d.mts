// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './lzjd-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
