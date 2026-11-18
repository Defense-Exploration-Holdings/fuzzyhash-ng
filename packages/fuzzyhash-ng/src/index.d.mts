// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

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
