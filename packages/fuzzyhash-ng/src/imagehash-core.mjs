// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// aHash, dHash and pHash over a loaded WebAssembly module. Used by the
// `imagehash` and main entry points. See docs/abi.md.

import { FuzzyHashError } from './errors.mjs';
import { OUTPUT_OFFSET, INPUT_OFFSET, bytesOf, fail, lazyApi, optionsOf, readOutput, readU32, withBlocks } from './core.mjs';

const FORMATS = { L: 0, LA: 1, RGB: 2, RGBA: 3 };
const CHANNELS = ['L', 'LA', 'RGB', 'RGBA'];

/** Validated image fields: width, height, the format code and the pixel bytes. */
function imageOf(image) {
  if (image === null || typeof image !== 'object') {
    throw new FuzzyHashError('INVALID_OPTION', 'image must be an object with width, height and data');
  }
  const { width, height, data } = image;
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 0 || height < 0 || width > 0xffffffff || height > 0xffffffff) {
    throw new FuzzyHashError('INVALID_OPTION', 'image width and height must be non-negative integers');
  }
  if (!ArrayBuffer.isView(data)) throw new FuzzyHashError('INVALID_OPTION', 'image data must be a typed array of 8-bit pixels');
  const pixels = bytesOf(data);
  let format = image.format;
  if (format === undefined) {
    const n = width * height;
    const k = n === 0 ? 0 : pixels.length / n;
    format = Number.isInteger(k) && k >= 1 && k <= 4 ? CHANNELS[k - 1] : 'L';
  }
  if (!Object.hasOwn(FORMATS, format)) throw new FuzzyHashError('INVALID_OPTION', "image format must be 'L', 'LA', 'RGB' or 'RGBA'");
  return { width, height, format: FORMATS[format], pixels };
}

export function createImageHash(loader) {
  const api = lazyApi(loader);

  function run(kind, image, opts, what) {
    const o = optionsOf(opts);
    const hashSize = o.hashSize ?? 8;
    const highfreq = o.highfreqFactor ?? 4;
    const img = imageOf(image);
    const w = api();
    if (!Number.isInteger(hashSize) || w.e.imagehash_supported_size(hashSize) !== 1) {
      throw new FuzzyHashError('INVALID_OPTION', 'hashSize must be one of 4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32');
    }
    if (!Number.isInteger(highfreq) || highfreq < 1) throw new FuzzyHashError('INVALID_OPTION', 'highfreqFactor must be a positive integer');
    return withBlocks(w, [img.pixels], ([p]) => {
      const code = w.e.imagehash_hash(
        kind, hashSize, Math.min(highfreq, 0x10000), img.width, img.height, img.format,
        p, img.pixels.length, w.base + OUTPUT_OFFSET, w.base + INPUT_OFFSET,
      );
      if (code !== 0) fail(code, what);
      return readOutput(w, readU32(w.view(), w.base + INPUT_OFFSET));
    });
  }

  const averageHash = (image, opts) => run(0, image, opts, 'averageHash');
  const dhash = (image, opts) => run(1, image, opts, 'dhash');
  const phash = (image, opts) => run(2, image, opts, 'phash');

  return { averageHash, dhash, phash, imageHashDistance };
}

/** Differing bits between two hex hashes of the same size (`hash1 - hash2` in ImageHash). */
export function imageHashDistance(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') throw new FuzzyHashError('INVALID_OPTION', 'imageHashDistance takes two strings');
  if (a.length !== b.length || !/^[0-9a-fA-F]+$/.test(a) || !/^[0-9a-fA-F]+$/.test(b)) {
    throw new FuzzyHashError('INVALID_DIGEST', 'imageHashDistance: the hashes must be hex strings of the same length');
  }
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    let x = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    while (x) {
      d += x & 1;
      x >>= 1;
    }
  }
  return d;
}
