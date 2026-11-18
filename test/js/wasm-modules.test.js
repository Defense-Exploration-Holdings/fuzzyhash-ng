// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// The embedded WebAssembly modules, instantiated the way the package does it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { ABI_VERSION, createLoader, readVersion } from '../../packages/fuzzyhash-ng/src/loader.mjs';

const zon = readFileSync(new URL('../../build.zig.zon', import.meta.url), 'utf8');
const packageVersion = /\.version\s*=\s*"([^"]+)"/.exec(zon)[1];

const fixed = ['ssdeep', 'tlsh', 'nilsimsa'];
const growable = ['imphash', 'telfhash', 'imagehash', 'minhash', 'simhash', 'lzjd', 'fuzzy'];
const modules = [...fixed, ...growable];

for (const name of modules) {
  const { wasmBytes } = await import(`../../packages/fuzzyhash-ng/wasm/${name}.mjs`);

  test(`${name}: instantiates synchronously with no imports and the loader's ABI version`, () => {
    const inst = createLoader(name, wasmBytes).get();
    assert.equal(inst.exports.fuzzy_abi_version(), ABI_VERSION);
  });

  test(`${name}: reports the package version`, () => {
    const inst = createLoader(name, wasmBytes).get();
    assert.equal(readVersion(inst), packageVersion);
  });

  if (fixed.includes(name)) {
    test(`${name}: memory is fixed at 128 KiB and cannot grow`, () => {
      const { memory } = createLoader(name, wasmBytes).get().exports;
      assert.equal(memory.buffer.byteLength, 128 * 1024);
      assert.throws(() => memory.grow(1), RangeError);
    });
  } else {
    test(`${name}: fuzzy_alloc grows memory and blocks can be freed and reused`, () => {
      const { memory, fuzzy_alloc, fuzzy_free } = createLoader(name, wasmBytes).get().exports;
      const before = memory.buffer.byteLength;
      const len = before + 1024 * 1024;
      const p = fuzzy_alloc(len) >>> 0;
      assert.notEqual(p, 0);
      assert.equal(p % 16, 0);
      assert.ok(memory.buffer.byteLength >= p + len);
      new Uint8Array(memory.buffer, p, len).fill(1);
      fuzzy_free(p, len);
      assert.equal(fuzzy_alloc(len) >>> 0, p);
      fuzzy_free(p, len);
      // Beyond the 2 GiB limit: 0, not a trap.
      assert.equal(fuzzy_alloc(0xffffff00) >>> 0, 0);
    });
  }

  test(`${name}: the scratch region lies inside memory and is writable`, () => {
    const { memory, scratch_ptr, scratch_len } = createLoader(name, wasmBytes).get().exports;
    const ptr = scratch_ptr();
    const len = scratch_len();
    assert.ok(len >= 64 * 1024 + 4096 + 256, `scratch is ${len} bytes`);
    assert.ok(ptr + len <= memory.buffer.byteLength);
    const view = new Uint8Array(memory.buffer, ptr, len);
    view.fill(0xa5);
    assert.equal(new Uint8Array(memory.buffer, ptr, len).every((b) => b === 0xa5), true);
  });

  test(`${name}: ready() compiles asynchronously and get() reuses that instance`, async () => {
    const loader = createLoader(name, wasmBytes);
    await loader.ready();
    assert.equal(loader.get(), loader.get());
    await loader.ready();
  });
}
