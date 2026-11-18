// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// MinHash through the npm entry points. Expected values were recorded from
// datasketch 2.0.0.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as main from '../../packages/fuzzyhash-ng/src/index.mjs';
import * as only from '../../packages/fuzzyhash-ng/src/minhash.mjs';

const fox = 'The quick brown fox jumps over the lazy dog';
const words = fox.split(' ');
const cat = fox.replace('dog', 'cat').split(' ');

const expected = {
  affine32: {
    values: [491029986, 323847753, 144864103, 994941520, 154545740, 341636437, 18697152, 813498672, 697632968, 226888826, 9524871, 416116130, 919230927, 755724242, 132514254, 734461424],
    jaccard: 0.8125,
  },
  affine64: {
    values: [1318790761215602328n, 1400100987400493432n, 1649640729405310147n, 1470115668552436715n, 1267747415811816960n, 79938361649193423n, 21700944441176857n, 309945234208656657n, 7244547576790333509n, 1645917041408995541n, 1940782647471099053n, 1309043153439814690n, 1853312254964092426n, 3033673799956331639n, 167359289199774070n, 289272523103920669n],
    jaccard: 0.6875,
  },
  legacy: {
    values: [407326892n, 34383241n, 44059036n, 1119886979n, 136245013n, 1552394070n, 196634065n, 1105811553n, 945575762n, 96528969n, 677708402n, 604224000n, 467893433n, 791496607n, 429187043n, 269329519n],
    jaccard: 0.8125,
  },
};

for (const [name, m] of [['main', main], ['minhash', only]]) {
  for (const [scheme, want] of Object.entries(expected)) {
    test(`${name}: ${scheme} hash values and Jaccard estimate match the reference`, () => {
      const a = new m.MinHash({ numPerm: 16, seed: 1, scheme }).updateBatch(words);
      const b = new m.MinHash({ numPerm: 16, seed: 1, scheme });
      for (const w of cat) b.update(w);
      assert.deepEqual(Array.from(a.digest()), want.values);
      assert.equal(a.jaccard(b), want.jaccard);
    });
  }

  test(`${name}: defaults are num_perm 128, seed 1, affine32`, () => {
    const a = new m.MinHash().updateBatch(words);
    assert.equal(a.numPerm, 128);
    assert.equal(a.seed, 1);
    assert.equal(a.scheme, 'affine32');
    assert.deepEqual(Array.from(a.digest().subarray(0, 4)), [2103838, 659818257, 132321410, 1849789506]);
  });

  test(`${name}: merge, copy, clear and isEmpty`, () => {
    const a = new m.MinHash({ numPerm: 32 }).updateBatch(words.slice(0, 4));
    const b = new m.MinHash({ numPerm: 32 }).updateBatch(words.slice(4));
    const all = new m.MinHash({ numPerm: 32 }).updateBatch(words);
    const c = a.copy().merge(b);
    assert.deepEqual(c.digest(), all.digest());
    assert.notDeepEqual(a.digest(), all.digest());
    assert.equal(new m.MinHash().isEmpty(), true);
    assert.equal(c.isEmpty(), false);
    assert.equal(c.clear().isEmpty(), true);
    assert.equal(new m.MinHash({ scheme: 'legacy' }).isEmpty(), true);
  });

  test(`${name}: mismatched sketches and bad options throw`, () => {
    const a = new m.MinHash();
    assert.throws(() => a.jaccard(new m.MinHash({ seed: 2 })), { code: 'INVALID_OPTION' });
    assert.throws(() => a.merge(new m.MinHash({ numPerm: 64 })), { code: 'INVALID_OPTION' });
    assert.throws(() => new m.MinHash({ numPerm: 100 }), { code: 'INVALID_OPTION' });
    assert.throws(() => new m.MinHash({ scheme: 'other' }), { code: 'INVALID_OPTION' });
    assert.throws(() => new m.MinHash({ seed: -1 }), { code: 'INVALID_OPTION' });
  });
}
