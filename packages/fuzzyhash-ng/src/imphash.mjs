// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/imphash`.

import { wasmBytes } from '../wasm/imphash.mjs';
import { createLoader } from './loader.mjs';
import { createImphash } from './imphash-core.mjs';

const loader = createLoader('imphash', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { imphash } = createImphash(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
