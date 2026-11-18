// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/nilsimsa`.

import { wasmBytes } from '../wasm/nilsimsa.mjs';
import { createLoader } from './loader.mjs';
import { createNilsimsa } from './nilsimsa-core.mjs';

const loader = createLoader('nilsimsa', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { nilsimsa, nilsimsaCompare, nilsimsaStream, NilsimsaHasher } = createNilsimsa(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
