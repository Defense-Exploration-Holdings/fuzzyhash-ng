// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/** Pixel layout, as Pillow's modes. Alpha is ignored. */
export type ImageFormat = 'L' | 'LA' | 'RGB' | 'RGBA';

/**
 * A decoded image: `height` rows of `width` pixels, 8 bits per channel, no
 * padding. An `ImageData` from a canvas fits as it is. Without `format`, it
 * follows from the data length.
 */
export interface DecodedImage {
  /** Pixels per row. */
  width: number;
  /** Number of rows. */
  height: number;
  /** Pixel bytes, row by row. */
  data: ArrayBufferView;
  /** Pixel layout. Without it, it follows from the data length. */
  format?: ImageFormat;
}

/** Options for `averageHash`, `dhash` and `phash`. */
export interface ImageHashOptions {
  /** ImageHash's `hash_size`: 4, 6, 8 (default), 10, 12, 14, 16, 20, 24, 28 or 32. */
  hashSize?: number;
}

/** Options for `phash`. */
export interface PhashOptions extends ImageHashOptions {
  /** ImageHash's `highfreq_factor` (default 4). */
  highfreqFactor?: number;
}

/** `imagehash.average_hash(image, hash_size)`, as `str()` prints it. */
export declare function averageHash(image: DecodedImage, opts?: ImageHashOptions): string;

/** `imagehash.dhash(image, hash_size)`, as `str()` prints it. */
export declare function dhash(image: DecodedImage, opts?: ImageHashOptions): string;

/** `imagehash.phash(image, hash_size, highfreq_factor)`, as `str()` prints it. */
export declare function phash(image: DecodedImage, opts?: PhashOptions): string;

/** Differing bits between two hashes of the same size (`hash1 - hash2` in ImageHash). */
export declare function imageHashDistance(a: string, b: string): number;
