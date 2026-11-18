// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// aHash, dHash and pHash through the npm entry points. Expected values were
// recorded from ImageHash 4.3.2 with Pillow 13.0 and scipy 1.18.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as main from '../../packages/fuzzyhash-ng/src/index.mjs';
import * as only from '../../packages/fuzzyhash-ng/src/imagehash.mjs';

const width = 33;
const height = 21;
const rgb = new Uint8Array(width * height * 3);
const rgba = new Uint8Array(width * height * 4);
const gray = new Uint8Array(width * height);
for (let y = 0; y < height; y++) {
  for (let x = 0; x < width; x++) {
    const i = y * width + x;
    const px = [(x * 7 + y * 3) % 256, (x * y) % 256, (((255 - x * 5) % 256) + 256) % 256];
    rgb.set(px, i * 3);
    rgba.set([...px, (x * 11) % 256], i * 4);
    gray[i] = (Math.floor((x * 255) / (width - 1)) + y * 3) % 256;
  }
}

for (const [name, m] of [['main', main], ['imagehash', only]]) {
  test(`${name}: RGB and RGBA images match the reference`, () => {
    const img = { width, height, data: rgb };
    assert.equal(m.averageHash(img), '00030f1f3c3b377e');
    assert.equal(m.dhash(img), 'fffffffcf9f2e6ec');
    assert.equal(m.phash(img), '853b664952a52b5f');
    // Alpha is ignored, as in convert("L").
    assert.equal(m.averageHash({ width, height, data: rgba }), '00030f1f3c3b377e');
    assert.equal(m.averageHash({ width, height, data: new Uint8ClampedArray(rgba.buffer), format: 'RGBA' }), '00030f1f3c3b377e');
  });

  test(`${name}: grayscale images and other hash sizes match the reference`, () => {
    const img = { width, height, data: gray, format: 'L' };
    assert.equal(m.averageHash(img), '0f0f1e1e1e1e3c3c');
    assert.equal(m.dhash(img), 'fefefefefcfcfcf9');
    assert.equal(m.phash(img), '9425aaaaeaaeaaaa');
    assert.equal(m.averageHash(img, { hashSize: 16 }), '00ff00ff01fe01fe01fe01fe03fe03fc03fc03fc07f807f807f807f80ff00ff0');
    assert.equal(m.phash(img, { hashSize: 16 }), '9494255d2a55a2a52aaaaaaaaaeaaaaaaaabaadaad2a5abe56aab5aa4ab4aa55');
    assert.equal(m.phash(img, { highfreqFactor: 2 }), '9425aaaaeaaeaaaa');
  });

  test(`${name}: distance`, () => {
    assert.equal(m.imageHashDistance('853b664952a52b5f', '9425aaaaeaaeaaaa'), 30);
    assert.equal(m.imageHashDistance('ffff', '0000'), 16);
    assert.throws(() => m.imageHashDistance('ff', 'fff'), { code: 'INVALID_DIGEST' });
  });

  test(`${name}: bad images and options throw`, () => {
    assert.throws(() => m.averageHash({ width: 0, height: 0, data: new Uint8Array(0) }), { code: 'INVALID_INPUT' });
    assert.throws(() => m.averageHash({ width: 2, height: 2, data: new Uint8Array(5) }), { code: 'INVALID_INPUT' });
    assert.throws(() => m.averageHash({ width: 2, height: 2, data: new Uint8Array(4), format: 'RGB' }), { code: 'INVALID_INPUT' });
    assert.throws(() => m.averageHash({ width, height, data: gray }, { hashSize: 7 }), { code: 'INVALID_OPTION' });
    assert.throws(() => m.averageHash({ width, height, data: gray, format: 'CMYK' }), { code: 'INVALID_OPTION' });
    assert.throws(() => m.averageHash({ width, height, data: [1, 2, 3] }), { code: 'INVALID_OPTION' });
    // scipy's DCT length here is 32 * 37 = 1184, beyond what the port computes.
    assert.throws(() => m.phash({ width, height, data: gray }, { hashSize: 32, highfreqFactor: 37 }), { code: 'UNSUPPORTED_INPUT' });
  });
}
