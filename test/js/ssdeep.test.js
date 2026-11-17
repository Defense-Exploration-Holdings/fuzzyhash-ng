// SPDX-License-Identifier: MIT
// ssdeep through the npm entry points. Expected digests and scores were
// recorded from ssdeep 2.14.1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';

import * as main from '../../packages/fuzzyhash-ng/src/index.mjs';
import * as only from '../../packages/fuzzyhash-ng/src/ssdeep.mjs';
import { wasmBytes } from '../../packages/fuzzyhash-ng/wasm/ssdeep.mjs';
import { createLoader } from '../../packages/fuzzyhash-ng/src/loader.mjs';

const P = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef';
const Q = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdeQ';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const seq256 = Uint8Array.from({ length: 256 }, (_, i) => i);
const mod251 = (n) => Uint8Array.from({ length: n }, (_, i) => i % 251);
const mix5000 = Uint8Array.from({ length: 5000 }, (_, i) => (i * 7 + Math.floor(i / 13)) % 256);

const digests = [
  ['', {}, '3::'],
  ['a', {}, '3:E:E'],
  ['hello', {}, '3:iKn:p'],
  ['The quick brown fox jumps over the lazy dog', {}, '3:FJKKIUKact:FHIGi'],
  ['b'.repeat(500), {}, '3:HHHH:n'],
  ['b'.repeat(500), { eliminateSequences: true }, '3:HHH:n'],
  [new Uint8Array(16), {}, '3::'],
  [
    seq256,
    {},
    '6:Iq103+54vmkCNMvWRQzaLhMvmNKzuxBJB16LO5SfG9YmorO0+7ymBADOMeLsGYba:Iq103+54vmkCNMvWRQzaLhMvmNKzuxB9',
  ],
  [
    seq256,
    { noTruncate: true },
    '6:Iq103+54vmkCNMvWRQzaLhMvmNKzuxBJB16LO5SfG9YmorO0+7ymBADOMeLsGYba:Iq103+54vmkCNMvWRQzaLhMvmNKzuxBJB16LO5SfG9YmorO0+7ymBADOMeLsGYba',
  ],
  [
    mod251(1000),
    { noTruncate: true, eliminateSequences: true },
    '24:X+OmvmLeO22LSeKufL6uS+iv+7ym2/eL+u2/m7muTL2fP+OmvmLeO22LSeKufL6N:XDfLTTLTDfLTTf7fTL377fTLMDfLTTLTDfLTTf7fTL377fTLMDfLTTLTDfLTTf7h',
  ],
  [mod251(20000), {}, '192:znnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknn0:n'],
  [
    mix5000,
    {},
    '96:wXDbvjnbTrXz3LvLb7bv//jHrPXXDbvjnbTrXz3LvLb7bv//jHrPXXDbvjnbTrXA:unnHX3n3XHHnnHX3n3XHHnnHX3n3XHHM',
  ],
];

const scores = [
  ['48:ABCDEFGHIJ:x', '48:ABCDEFGHIX:y', 91],
  ['3:ABCDEFGHIJ:x', '3:ABCDEFGHIX:y', 10],
  ['3:AAAA:AAAA', '3:AAA:AAA', 100],
  ['6:ABCDEFGHIJ:x', '3:ABCDEFG:ABCDEFG', 14],
  ['3:E:E', '6:E:E', 0],
  ['3::', '3::', 100],
  ['4294967296:ABCDEFGHIJKL:xyz', '4294967296:ABCDEFGHIJKX:xyz', 93],
  [`18446744073709551616:${P}:x`, `18446744073709551615:${Q}:x`, 97],
  [`9223372036854775808:x:${P}`, `9223372036854775808:y:${Q}`, 0],
  [`9223372036854775807:x:${P}`, `9223372036854775807:y:${Q}`, 97],
  ['12:y', '1', 0],
  [`3:${P}:x,"${'f'.repeat(990)}"`, `3:${Q}:x`, 32],
  [`3:${P}:x,${'f'.repeat(100000)}`, `3:${Q}:x`, 32],
  [`3:${P}:x,${'f'.repeat(3000)}`, `3:${P}:x,${'g'.repeat(3000)}`, 100],
  [`3:${P}:x${'Z'.repeat(2000)}`, `3:${Q}:x`, 32],
  [`3:${P}${'X'.repeat(2000)}:x`, `3:${Q}:x`, 32],
  [`3:${P}:x:${'y'.repeat(2000)}`, `3:${Q}:x`, 32],
  [`6:${P}:x,"${'f'.repeat(3000)}"`, `3:x:${Q}`, 64],
  [`48:${P}:x,"${'f'.repeat(3000)}"`, `3:x:${Q}`, 0],
  [`000000000000000000000000000000000000000006:${P}:x${'Z'.repeat(5000)}`, `6:${Q}:x`, 64],
  [`99999999999999999999999:${P}:x${'Z'.repeat(5000)}`, `18446744073709551615:${Q}:x`, 97],
  ['6x:ABC:DEF', '6:ABC:DEF', 100],
  [`6,"f":${P}:x`, `6:${Q}:x`, 64],
  [`12x:${P}:x`, `6:x:${Q}`, 97],
  [`6${'z'.repeat(5000)}:${P}:x`, `6:${Q}:x`, 64],
];

const malformed = [
  ['12:y', '6'],
  ['', '3:E:E'],
  ['abc', '3:E:E'],
  [' 3:E:E', '3:E:E'],
  ['-3:E:E', '3:E:E'],
  ['6x', '6:ABC:DEF'],
  [`6x${P}:x`, `6:${Q}:x`],
  [`3:${P}${'Z'.repeat(2000)}`, `3:${Q}:x`],
  [`3:${B64.repeat(20)}:x`, `3:${Q}:x`],
  [`3:${P}:${B64.repeat(20)}`, `3:${Q}:x`],
];

for (const [entry, api] of [
  ['fuzzyhash-ng', main],
  ['fuzzyhash-ng/ssdeep', only],
]) {
  test(`${entry}: digests match ssdeep 2.14.1 for every option`, () => {
    for (const [input, opts, expected] of digests) assert.equal(api.ssdeep(input, opts), expected);
  });

  test(`${entry}: chunked hashing gives the same digest`, () => {
    for (const [input, opts, expected] of digests) {
      const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
      for (const size of [1, 3, 7, 64, 1000]) {
        const h = new api.SsdeepHasher(opts);
        for (let i = 0; i < bytes.length; i += size) h.update(bytes.subarray(i, i + size));
        assert.equal(h.digest(), expected, `chunk size ${size}`);
      }
    }
  });

  test(`${entry}: inputs above the 64 KiB input slot are split`, () => {
    const big = mod251(10_000_000);
    const expected = '192:znnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnE:n';
    assert.equal(api.ssdeep(big), expected);
    assert.equal(api.ssdeep(big.buffer), expected);
    assert.equal(api.ssdeep(new DataView(big.buffer)), expected);
  });

  test(`${entry}: strings are hashed as UTF-8`, () => {
    assert.equal(api.ssdeep('héllo'), api.ssdeep(new TextEncoder().encode('héllo')));
  });

  test(`${entry}: ssdeepCompare matches ssdeep 2.14.1 in both orders`, () => {
    for (const [a, b, score] of scores) {
      assert.equal(api.ssdeepCompare(a, b), score, `${a.slice(0, 40)} / ${b.slice(0, 40)}`);
      assert.equal(api.ssdeepCompare(b, a), score);
    }
  });

  test(`${entry}: ssdeepCompare throws INVALID_DIGEST where ssdeep reports an error`, () => {
    for (const [a, b] of malformed) {
      assert.throws(() => api.ssdeepCompare(a, b), { name: 'FuzzyHashError', code: 'INVALID_DIGEST' });
      assert.throws(() => api.ssdeepCompare(b, a), { name: 'FuzzyHashError', code: 'INVALID_DIGEST' });
    }
  });

  test(`${entry}: a digest compares 100 with itself`, () => {
    for (const [input, opts] of digests) {
      const d = api.ssdeep(input, opts);
      assert.equal(api.ssdeepCompare(d, d), 100);
    }
  });

  test(`${entry}: parseSsdeep returns the fields and the file name`, () => {
    assert.deepEqual(api.parseSsdeep('3:iKn:p,"dir/a \\"b\\".txt"'), {
      blockSize: 3,
      part1: 'iKn',
      part2: 'p',
      filename: 'dir/a "b".txt',
    });
    assert.deepEqual(api.parseSsdeep('03:AAAAAA:BB'), { blockSize: 3, part1: 'AAA', part2: 'BB' });
    assert.deepEqual(api.parseSsdeep(`3:${P}:x,"${'f'.repeat(70000)}"`, 'strict'), {
      blockSize: 3,
      part1: P,
      part2: 'x',
      filename: 'f'.repeat(70000),
    });
    assert.equal(api.parseSsdeep('99999999999999999999999:a:b').blockSize, 18446744073709551615n);
    assert.equal(api.parseSsdeep('5:a!:b').part1, 'a!');
  });

  test(`${entry}: parseSsdeep strict mode rejects what ssdeep would not produce`, () => {
    assert.deepEqual(api.parseSsdeep('6x:ABC:DEF'), { blockSize: 6, part1: 'ABC', part2: 'DEF' });
    for (const s of ['5:a:b', '3:a!:b', '6442450944:a:b', '+3:a:b', '3:a', '', '6x:ABC:DEF', `6${'z'.repeat(5000)}:ABC:DEF`]) {
      assert.throws(() => api.parseSsdeep(s, 'strict'), { code: 'INVALID_DIGEST' }, s);
    }
    assert.throws(() => api.parseSsdeep('3:a:b', 'loose'), { code: 'INVALID_OPTION' });
  });

  test(`${entry}: ssdeepStream reads Node streams, web streams and async iterables`, async () => {
    const data = mix5000;
    const expected = api.ssdeep(data);
    const chunks = () => [data.subarray(0, 1234), data.subarray(1234, 4000), data.subarray(4000)];
    assert.equal(await api.ssdeepStream(Readable.from(chunks())), expected);
    assert.equal(
      await api.ssdeepStream(
        new ReadableStream({
          start(c) {
            for (const x of chunks()) c.enqueue(x);
            c.close();
          },
        }),
      ),
      expected,
    );
    assert.equal(
      await api.ssdeepStream(
        (async function* () {
          yield* chunks();
        })(),
      ),
      expected,
    );
  });

  test(`${entry}: a hasher cannot be used after digest`, () => {
    const h = new api.SsdeepHasher();
    h.update('abc');
    assert.equal(h.digest(), '3:uG:uG');
    assert.throws(() => h.update('x'), { code: 'INVALID_OPTION' });
    assert.throws(() => h.digest(), { code: 'INVALID_OPTION' });
  });

  test(`${entry}: hashers in progress do not share state`, () => {
    const a = new api.SsdeepHasher();
    const b = new api.SsdeepHasher({ noTruncate: true });
    for (let i = 0; i < seq256.length; i += 16) {
      a.update(seq256.subarray(i, i + 16));
      b.update(seq256.subarray(i, i + 16));
    }
    assert.equal(a.digest(), digests[7][2]);
    assert.equal(b.digest(), digests[8][2]);
  });

  test(`${entry}: bad arguments throw INVALID_OPTION`, () => {
    assert.throws(() => api.ssdeep(42), { code: 'INVALID_OPTION' });
    assert.throws(() => api.ssdeep('a', 'fast'), { code: 'INVALID_OPTION' });
    assert.throws(() => api.ssdeepCompare('3:E:E'), { code: 'INVALID_OPTION' });
  });
}

test('wasm exports reject ranges outside the scratch region and states they did not write', () => {
  const e = createLoader('ssdeep', wasmBytes).get().exports;
  const base = e.scratch_ptr();
  const mem = () => new Uint8Array(e.memory.buffer);
  const size = e.ssdeep_state_size();
  assert.ok(size < 4096);

  assert.equal(e.ssdeep_init(base, 4), 1, 'unknown flag');
  assert.equal(e.ssdeep_init(0, 0), 1, 'state outside scratch');
  assert.equal(e.ssdeep_init(base + e.scratch_len() - 8, 0), 1, 'state past the end of scratch');

  assert.equal(e.ssdeep_init(base, 0), 0);
  assert.equal(e.ssdeep_update(base, 0, 16), 1, 'input outside scratch');
  assert.equal(e.ssdeep_update(base, base + 4352, 0xffffffff), 1, 'input length past the end');
  assert.equal(e.ssdeep_compare(0, 4, base, 4), -1);

  // Corrupt a saved state: every byte 0xff is not a state the module wrote.
  const saved = mem().slice(base, base + size);
  mem().fill(0xff, base, base + size);
  assert.equal(e.ssdeep_update(base, base + 4352, 1), 2);
  assert.equal(e.ssdeep_final(base, base + 4096, base + 4348), 2);

  // The saved copy still works.
  mem().set(saved, base);
  mem().set(new TextEncoder().encode('hello'), base + 4352);
  assert.equal(e.ssdeep_update(base, base + 4352, 5), 0);
  assert.equal(e.ssdeep_final(base, base + 4096, base + 4348), 0);
  const n = new DataView(e.memory.buffer).getUint32(base + 4348, true);
  assert.equal(new TextDecoder().decode(mem().subarray(base + 4096, base + 4096 + n)), '3:iKn:p');
});
