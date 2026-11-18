// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/telfhash`.

import { wasmBytes } from '../wasm/telfhash.mjs';
import { createLoader } from './loader.mjs';
import { createTelfhash } from './telfhash-core.mjs';

const loader = createLoader('telfhash', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { telfhash, telfhashDiff } = createTelfhash(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
