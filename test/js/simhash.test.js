// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// SimHash through the npm entry points. Expected values were recorded from
// the simhash 2.1.2 Python package.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as main from '../../packages/fuzzyhash-ng/src/index.mjs';
import * as only from '../../packages/fuzzyhash-ng/src/simhash.mjs';

const fox = 'The quick brown fox jumps over the lazy dog';

for (const [name, m] of [['main', main], ['simhash', only]]) {
  test(`${name}: text fingerprints match the reference`, () => {
    assert.equal(m.simhash(fox), 3182376498800265610n);
    assert.equal(m.simhash(fox, { f: 32 }), 2424998282n);
    assert.equal(m.simhash(fox, { f: 128 }), 55423179981541540515949847695011252618n);
    assert.equal(m.simhash('Straße ΣΑΣ İstanbul 一二'), 90569252482626049n);
    assert.equal(m.simhash('ab'), 3404963397999061920n);
    assert.equal(m.simhash(new TextEncoder().encode(fox)), 3182376498800265610n);
  });

  test(`${name}: feature fingerprints match the reference`, () => {
    assert.equal(m.simhashFeatures(['a', 'b', 'c']), 3587003245248337699n);
    assert.equal(m.simhashFeatures([['a', 3], ['b', 1], ['c', -1]]), 3585878926028121697n);
    // A bare feature after a pair takes that pair's weight, as in the package.
    assert.equal(m.simhashFeatures([['a', 3], 'b']), 3513678945095583233n);
  });

  test(`${name}: distance, overflow and bad input`, () => {
    assert.equal(m.simhashDistance(m.simhash(fox), m.simhash(fox)), 0);
    assert.equal(m.simhashDistance(0n, 0xffn), 8);
    // One 4-character window more than 255 times: the package raises OverflowError.
    assert.throws(() => m.simhash('abcd'.repeat(300)), { code: 'UNSUPPORTED_INPUT' });
    assert.throws(() => m.simhashFeatures([['a', 256]]), { code: 'UNSUPPORTED_INPUT' });
    assert.throws(() => m.simhash(Uint8Array.of(0xff, 0xfe)), { code: 'INVALID_INPUT' });
    assert.throws(() => m.simhash(fox, { f: 12 }), { code: 'INVALID_OPTION' });
    assert.throws(() => m.simhashDistance(1, 2), { code: 'INVALID_OPTION' });
  });
}
