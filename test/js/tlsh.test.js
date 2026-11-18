// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// TLSH through the npm entry points. Expected digests and distances were
// recorded from py-tlsh (TLSH 4.7.2 bindings, same T1 digests as TLSH 5.0.2).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';

import * as main from '../../packages/fuzzyhash-ng/src/index.mjs';
import * as only from '../../packages/fuzzyhash-ng/src/tlsh.mjs';

const fox = 'The quick brown fox jumps over the lazy dog';
const para = fox.repeat(8);
const mix5000 = Uint8Array.from({ length: 5000 }, (_, i) => (i * 7 + Math.floor(i / 13)) % 256);
const mod251 = Uint8Array.from({ length: 1000 }, (_, i) => i % 251);

const PARA = 'T157E0024A21181298658A1884438D95B2C2CCC5147121141164306002180C1219CD8451';
const PARA_CAT = 'T15DE00246211822A4A08A2CC4418D94B2C2C8C6106521144978346002181C1219C98451';
const MIX = 'T1C7A11E7E00E73DF3E084A28CA3E266B5FB705D46EFAC67D11297847D8C84D9A042E127';
const MOD = 'T175119524E6514E7D1F1759CC908E54DE654FCDE301C9002517F146C1C510194440ED1D';

for (const [name, m] of [['main', main], ['tlsh', only]]) {
  test(`${name}: digests match the reference`, () => {
    assert.equal(m.tlsh(para), PARA);
    assert.equal(m.tlsh(para.replaceAll('dog', 'cat')), PARA_CAT);
    assert.equal(m.tlsh(mix5000), MIX);
    assert.equal(m.tlsh(mod251), MOD);
    assert.equal(m.tlsh(mix5000, { conservative: true }), MIX);
  });

  test(`${name}: short or uniform input gives null`, () => {
    assert.equal(m.tlsh(fox), null);
    assert.equal(m.tlsh(''), null);
    assert.equal(m.tlsh(new Uint8Array(1000)), null);
    assert.equal(m.tlsh(fox.repeat(5), { conservative: true }), null);
  });

  test(`${name}: distances match the reference`, () => {
    assert.equal(m.tlshDiff(PARA, PARA), 0);
    assert.equal(m.tlshDiff(PARA, PARA_CAT), 28);
    assert.equal(m.tlshDiff(PARA, MIX), 402);
    assert.equal(m.tlshDiff(PARA, MIX, { includeLength: false }), 258);
    assert.equal(m.tlshDiff(PARA.slice(2), MIX.toLowerCase().replace('t1', '')), 402);
  });

  test(`${name}: prefix option and the other variants`, () => {
    assert.equal(m.tlsh(para, { prefix: false }), PARA.slice(2));
    const long = m.tlsh(mix5000, { buckets: 256, checksum: 3 });
    assert.match(long, /^T1[0-9A-F]{138}$/);
    assert.equal(m.tlsh(mix5000, { buckets: 128, checksum: 3 }).length, 2 + 74);
    assert.equal(m.tlsh(mix5000, { buckets: 256 }).length, 2 + 134);
    const variant = { buckets: 256, checksum: 3 };
    assert.equal(m.tlshDiff(long.slice(2), long.slice(2), variant), 0);
    // Like the reference, only the standard digest can be read back with its prefix.
    assert.throws(() => m.tlshDiff(long, long, variant), { code: 'INVALID_DIGEST' });
  });

  test(`${name}: streaming gives the same digest however the input is split`, async () => {
    for (const size of [1, 3, 64, 4999]) {
      const h = new m.TlshHasher();
      for (let i = 0; i < mix5000.length; i += size) h.update(mix5000.subarray(i, i + size));
      assert.equal(h.digest(), MIX);
    }
    assert.equal(await m.tlshStream(Readable.from([mix5000.subarray(0, 100), mix5000.subarray(100)])), MIX);
    const big = new Uint8Array(200000).map((_, i) => (i * 31 + (i >> 9)) & 255);
    assert.equal(m.tlsh(big), new m.TlshHasher().update(big.subarray(0, 70000)).update(big.subarray(70000)).digest());
  });

  test(`${name}: bad digests and options throw`, () => {
    assert.throws(() => m.tlshDiff('T1', PARA), { code: 'INVALID_DIGEST' });
    assert.throws(() => m.tlshDiff(PARA, 'xyz'), { code: 'INVALID_DIGEST' });
    assert.throws(() => m.tlshDiff(PARA, 7), { code: 'INVALID_OPTION' });
    assert.throws(() => m.tlsh(para, { buckets: 64 }), { code: 'INVALID_OPTION' });
    assert.throws(() => m.tlsh(para, { checksum: 2 }), { code: 'INVALID_OPTION' });
    const h = new m.TlshHasher();
    h.digest();
    assert.throws(() => h.digest(), { code: 'INVALID_OPTION' });
    assert.throws(() => h.update('x'), { code: 'INVALID_OPTION' });
  });
}
