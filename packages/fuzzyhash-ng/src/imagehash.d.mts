// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/**
 * Perceptual image hashes as the ImageHash Python package computes them:
 * average hash, difference hash and pHash, from decoded pixels.
 *
 * @example
 * ```ts
 * import { averageHash, imageHashDistance } from '@defense-exploration/fuzzyhash-ng/imagehash';
 *
 * const image = { width: 2, height: 2, data: new Uint8Array([0, 255, 255, 0]), format: 'L' as const };
 * const h = averageHash(image);
 * console.log(imageHashDistance(h, h)); // 0
 * ```
 *
 * @module
 */

export { FuzzyHashError, type FuzzyHashErrorCode } from './errors.mjs';
export * from './imagehash-types.mjs';

/**
 * Compile the WebAssembly module ahead of the first call. Only needed where
 * synchronous compilation is refused, for example under some browser limits.
 */
export declare function ready(): Promise<void>;
