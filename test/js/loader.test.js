// SPDX-License-Identifier: MIT
// Loader behaviour that does not depend on the real modules: ABI checks and
// hosts without WebAssembly.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { ABI_VERSION, createLoader } from '../../packages/fuzzyhash-ng/src/loader.mjs';
import { FuzzyHashError } from '../../packages/fuzzyhash-ng/src/errors.mjs';

// A minimal module: one export `name` of type () -> i32 that returns `value`.
function moduleReturning(name, value) {
  const enc = new TextEncoder().encode(name);
  const leb = (n) => {
    const out = [];
    do {
      let byte = n & 0x7f;
      n >>= 7;
      if ((n !== 0 && n !== -1) || (n === 0 && byte & 0x40) || (n === -1 && !(byte & 0x40))) byte |= 0x80;
      out.push(byte);
      if (!(byte & 0x80)) break;
    } while (true);
    return out;
  };
  const section = (id, body) => [id, body.length, ...body];
  const body = [0x00, 0x41, ...leb(value), 0x0b];
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, [1, 0x60, 0, 1, 0x7f]),
    ...section(3, [1, 0]),
    ...section(7, [1, enc.length, ...enc, 0x00, 0]),
    ...section(10, [1, body.length, ...body]),
  ]);
}

test('a module with the expected ABI version is accepted', async () => {
  const bytes = moduleReturning('fuzzy_abi_version', ABI_VERSION);
  assert.equal(createLoader('t', () => bytes).get().exports.fuzzy_abi_version(), ABI_VERSION);
  await createLoader('t', () => bytes).ready();
});

test('a module with another ABI version is refused, sync and async', async () => {
  const bytes = moduleReturning('fuzzy_abi_version', ABI_VERSION + 1);
  const check = (err) => err instanceof FuzzyHashError && err.code === 'WASM_UNAVAILABLE' && /ABI version/.test(err.message);
  assert.throws(() => createLoader('t', () => bytes).get(), check);
  await assert.rejects(createLoader('t', () => bytes).ready(), check);
});

test('a module without the ABI export is refused', () => {
  const bytes = moduleReturning('something_else', ABI_VERSION);
  assert.throws(
    () => createLoader('t', () => bytes).get(),
    (err) => err instanceof FuzzyHashError && err.code === 'WASM_UNAVAILABLE',
  );
});

test('a failed ready() can be retried', async () => {
  let bytes = moduleReturning('fuzzy_abi_version', ABI_VERSION + 1);
  const loader = createLoader('t', () => bytes);
  await assert.rejects(loader.ready(), FuzzyHashError);
  bytes = moduleReturning('fuzzy_abi_version', ABI_VERSION);
  await loader.ready();
});

test('without WebAssembly, the entry points throw WASM_UNAVAILABLE', () => {
  const entries = ['index', 'ssdeep', 'tlsh'].map((e) =>
    fileURLToPath(new URL(`../../packages/fuzzyhash-ng/src/${e}.mjs`, import.meta.url)),
  );
  const script = `
    delete globalThis.WebAssembly;
    const results = [];
    for (const path of ${JSON.stringify(entries)}) {
      const mod = await import(path);
      try { await mod.ready(); results.push('resolved'); }
      catch (err) { results.push(err instanceof mod.FuzzyHashError ? err.code : String(err)); }
    }
    console.log(JSON.stringify(results));
  `;
  const run = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), ['WASM_UNAVAILABLE', 'WASM_UNAVAILABLE', 'WASM_UNAVAILABLE']);
});
