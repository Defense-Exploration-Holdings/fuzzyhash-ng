// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/simhash`.

import { wasmBytes } from '../wasm/simhash.mjs';
import { createLoader } from './loader.mjs';
import { createSimhash } from './simhash-core.mjs';

const loader = createLoader('simhash', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { simhash, simhashFeatures, simhashDistance } = createSimhash(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
