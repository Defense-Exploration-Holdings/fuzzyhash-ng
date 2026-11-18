// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Nilsimsa through the npm entry points. Expected values were recorded from
// the nilsimsa 0.3.8 Python package.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';

import * as main from '../../packages/fuzzyhash-ng/src/index.mjs';
import * as only from '../../packages/fuzzyhash-ng/src/nilsimsa.mjs';

const fox = 'The quick brown fox jumps over the lazy dog';
const mix5000 = Uint8Array.from({ length: 5000 }, (_, i) => (i * 7 + Math.floor(i / 13)) % 256);
const FOX = '02b0b4ae03001086d100c660ab88503545c14ae760282108390a2928020120db';
const MIX = '7d53f0ec2444ad2dae606b5c2816757b56c07679c852953820c4e9defa003724';

for (const [name, m] of [['main', main], ['nilsimsa', only]]) {
  test(`${name}: digests match the reference`, () => {
    assert.equal(m.nilsimsa(fox), FOX);
    assert.equal(m.nilsimsa(''), '0'.repeat(64));
    assert.equal(m.nilsimsa(mix5000), MIX);
  });

  test(`${name}: compare matches the reference`, () => {
    assert.equal(m.nilsimsaCompare(FOX, FOX), 128);
    assert.equal(m.nilsimsaCompare(FOX, m.nilsimsa(fox.replace('dog', 'cat'))), 112);
    assert.equal(m.nilsimsaCompare(FOX, FOX.toUpperCase()), 128);
    const inverted = FOX.replace(/./g, (c) => (15 - parseInt(c, 16)).toString(16));
    assert.equal(m.nilsimsaCompare(FOX, inverted), -128);
  });

  test(`${name}: streaming and malformed digests`, async () => {
    const h = new m.NilsimsaHasher();
    for (let i = 0; i < mix5000.length; i += 7) h.update(mix5000.subarray(i, i + 7));
    assert.equal(h.digest(), MIX);
    assert.equal(await m.nilsimsaStream(Readable.from([mix5000])), MIX);
    assert.throws(() => m.nilsimsaCompare(FOX, FOX.slice(1)), { code: 'INVALID_DIGEST' });
    assert.throws(() => m.nilsimsaCompare(FOX, `${FOX}0`), { code: 'INVALID_DIGEST' });
    assert.throws(() => m.nilsimsaCompare(FOX, 'g'.repeat(64)), { code: 'INVALID_DIGEST' });
  });
}
