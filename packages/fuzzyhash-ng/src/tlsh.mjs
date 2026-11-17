// SPDX-License-Identifier: MIT
// Entry point `fuzzyhash-ng/tlsh`.

import { wasmBytes } from '../wasm/tlsh.mjs';
import { createLoader } from './loader.mjs';

const loader = createLoader('tlsh', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
