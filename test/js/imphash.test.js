// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// imphash and telfhash through the npm entry points, on small files built in
// memory. Expected values were recorded from pefile 2024.8.26 and telfhash
// 0.9.8.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as main from '../../packages/fuzzyhash-ng/src/index.mjs';
import * as imp from '../../packages/fuzzyhash-ng/src/imphash.mjs';
import * as telf from '../../packages/fuzzyhash-ng/src/telfhash.mjs';
import { buildElf, buildPe } from './fixtures.js';

const symbols = [
  'printf', 'Open', 'socket', 'connect', 'send', 'recv', 'close', 'fork', 'execve', 'getenv', '_init', 'main', 'strlen',
  'memcpy', 'lseek64', 'fopen', 'fread', 'fwrite', 'fclose', 'sleep', 'time', 'rand', 'srand', 'exit', 'pthread_create',
  'pthread_join', 'dlopen', 'dlsym', 'kill', 'signal', 'inet_addr', 'htons',
];
const TELF = 't123c01295e5790c8c46f66c71444459a665433125857409105f84d5d1803f913b24ca67';

for (const [name, m] of [['main', main], ['imphash', imp]]) {
  test(`${name}: imphash matches pefile`, () => {
    const named = buildPe(false, [['KERNEL32.dll', ['GetProcAddress', 'LoadLibraryA']], ['USER32.dll', ['MessageBoxW']]]);
    assert.equal(m.imphash(named), 'fcd11f719155dd55447a1f2dd8254800');
    const ordinals = buildPe(true, [['WS2_32.dll', ['#3', '#115', '#60000']], ['oleaut32.DLL', ['#2']], ['custom.ocx', ['#7']], ['drv.sys.bak', ['Init']]]);
    assert.equal(m.imphash(ordinals), '432a2f2631ac0d530ebd87983d595dfd');
    assert.equal(m.imphash(buildPe(false, [])), null);
  });

  test(`${name}: files pefile refuses throw INVALID_INPUT`, () => {
    assert.throws(() => m.imphash(new Uint8Array(0)), { code: 'INVALID_INPUT' });
    assert.throws(() => m.imphash(Uint8Array.of(0x4d, 0x5a, ...new Uint8Array(100))), { code: 'INVALID_INPUT' });
  });
}

for (const [name, m] of [['main', main], ['telfhash', telf]]) {
  test(`${name}: telfhash matches telfhash`, () => {
    assert.equal(m.telfhash(buildElf(symbols)), TELF);
    assert.equal(m.telfhash(buildElf(['printf', 'socket'])), 'tnull');
    assert.equal(m.telfhash(buildElf(['main', '_init'])), '-');
    assert.equal(m.telfhashDiff(TELF, TELF), 0);
    assert.equal(m.telfhashDiff(TELF, TELF.toUpperCase()), 0);
    assert.ok(m.telfhashDiff(TELF, m.telfhash(buildElf(symbols.slice(0, 28)))) > 0);
  });

  test(`${name}: files pyelftools cannot read throw INVALID_INPUT`, () => {
    assert.throws(() => m.telfhash('MZ'), { code: 'INVALID_INPUT' });
    assert.throws(() => m.telfhash(Uint8Array.of(0x7f, 0x45, 0x4c, 0x46, 2, 1)), { code: 'INVALID_INPUT' });
    assert.throws(() => m.telfhashDiff(TELF, 'tnull'), { code: 'INVALID_DIGEST' });
  });
}
