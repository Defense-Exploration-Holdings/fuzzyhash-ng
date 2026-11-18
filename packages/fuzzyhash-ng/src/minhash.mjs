// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/minhash`.

import { wasmBytes } from '../wasm/minhash.mjs';
import { createLoader } from './loader.mjs';
import { createMinHash } from './minhash-core.mjs';

const loader = createLoader('minhash', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { MinHash } = createMinHash(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
