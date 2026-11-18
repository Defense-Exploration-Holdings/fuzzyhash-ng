// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/lzjd`.

import { wasmBytes } from '../wasm/lzjd.mjs';
import { createLoader } from './loader.mjs';
import { createLzjd } from './lzjd-core.mjs';

const loader = createLoader('lzjd', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { lzjd, lzjdSimilarity } = createLzjd(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
