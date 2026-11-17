// SPDX-License-Identifier: MIT
// Entry point `fuzzyhash-ng`: ssdeep and TLSH together.

import { wasmBytes } from '../wasm/fuzzy.mjs';
import { createLoader } from './loader.mjs';
import { createSsdeep } from './ssdeep-core.mjs';

const loader = createLoader('fuzzy', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { ssdeep, ssdeepCompare, parseSsdeep, ssdeepStream, SsdeepHasher } = createSsdeep(loader);

/** Compile the WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
