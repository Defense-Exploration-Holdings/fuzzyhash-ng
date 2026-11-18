// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// LZJD through the npm entry points. Expected values were recorded from
// pyLZJD (commit e2c24bd).
import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as main from '../../packages/fuzzyhash-ng/src/index.mjs';
import * as only from '../../packages/fuzzyhash-ng/src/lzjd.mjs';

const fox = 'The quick brown fox jumps over the lazy dog';
const cat = fox.replace('dog', 'cat');
const mix5000 = Uint8Array.from({ length: 5000 }, (_, i) => (i * 7 + Math.floor(i / 13)) % 256);

const FOX = [
  -2128973781, -1737498726, -1261379688, -1248839937, -1112552363, -1040803305, -967714644, -809654831, -729632045,
  -629790692, -516762017, -284916816, -179652781, -12346081, -11875599, -8255000, 1009084850, 1050319643, 1199411734,
  1357062167, 1553167345, 1646279392, 1701593959, 1748272243, 1780883936, 1969489443, 2005904822, 2129959832,
];
const MIX8 = [-2147112860, -2144633847, -2140763568, -2137513236, -2136761733, -2134763116, -2130082181, -2125028529];
const SUPER = ['38040000', '3eb37f46', '3e5e8834', '3f82a0b8', '3e25b470', '3ea8da96', '3e5aa954', '40e0536b'];

const bits = (f32) => Array.from(new Uint32Array(f32.buffer, f32.byteOffset, f32.length), (v) => v.toString(16).padStart(8, '0'));

for (const [name, m] of [['main', main], ['lzjd', only]]) {
  test(`${name}: default-mode digests and similarity match the reference`, () => {
    const a = m.lzjd(fox);
    assert.ok(a.digest instanceof Int32Array);
    assert.deepEqual(Array.from(a.digest), FOX);
    assert.equal(a.setSize, 28);
    assert.equal(m.lzjdSimilarity(a, m.lzjd(cat)), 0.9);
    assert.deepEqual(Array.from(m.lzjd(mix5000, { hashSize: 8 }).digest), MIX8);
    assert.equal(m.lzjdSimilarity(m.lzjd(''), m.lzjd('')), null);
  });

  test(`${name}: SuperHash digests and similarity match the reference`, () => {
    const a = m.lzjd(fox, { mode: 'SuperHash', hashSize: 8 });
    assert.ok(a.digest instanceof Float32Array);
    assert.deepEqual(bits(a.digest), SUPER);
    const b = m.lzjd(cat, { mode: 'SuperHash', hashSize: 8 });
    assert.equal(m.lzjdSimilarity(a.digest, b.digest), 0.75);
  });

  test(`${name}: bad options and mixed digests throw`, () => {
    assert.throws(() => m.lzjd(fox, { mode: 'super' }), { code: 'INVALID_OPTION' });
    assert.throws(() => m.lzjd(fox, { mode: 'SuperHash', hashSize: 0 }), { code: 'INVALID_OPTION' });
    const d = m.lzjd(fox);
    const s = m.lzjd(fox, { mode: 'SuperHash', hashSize: 8 });
    assert.throws(() => m.lzjdSimilarity(d, s), { code: 'INVALID_OPTION' });
    assert.throws(() => m.lzjdSimilarity(s, m.lzjd(fox, { mode: 'SuperHash', hashSize: 4 })), { code: 'INVALID_OPTION' });
    assert.throws(() => m.lzjdSimilarity([1, 2], d), { code: 'INVALID_OPTION' });
  });
}
