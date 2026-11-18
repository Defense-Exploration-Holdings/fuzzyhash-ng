// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/ssdeep`.

import { wasmBytes } from '../wasm/ssdeep.mjs';
import { createLoader } from './loader.mjs';
import { createSsdeep } from './ssdeep-core.mjs';

const loader = createLoader('ssdeep', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { ssdeep, ssdeepCompare, parseSsdeep, ssdeepStream, SsdeepHasher } = createSsdeep(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
