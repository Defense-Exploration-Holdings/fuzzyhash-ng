// SPDX-License-Identifier: MIT
// The embedded WebAssembly modules, instantiated the way the package does it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { ABI_VERSION, createLoader, readVersion } from '../../packages/fuzzyhash-ng/src/loader.mjs';

const zon = readFileSync(new URL('../../build.zig.zon', import.meta.url), 'utf8');
const packageVersion = /\.version\s*=\s*"([^"]+)"/.exec(zon)[1];

const modules = ['ssdeep', 'tlsh', 'fuzzy'];

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

  test(`${name}: memory is fixed at 128 KiB and cannot grow`, () => {
    const { memory } = createLoader(name, wasmBytes).get().exports;
    assert.equal(memory.buffer.byteLength, 128 * 1024);
    assert.throws(() => memory.grow(1), RangeError);
  });

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
