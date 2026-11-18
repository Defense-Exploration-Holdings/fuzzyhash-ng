// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/tlsh`.

import { wasmBytes } from '../wasm/tlsh.mjs';
import { createLoader } from './loader.mjs';
import { createTlsh } from './tlsh-core.mjs';

const loader = createLoader('tlsh', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { tlsh, tlshDiff, tlshStream, TlshHasher } = createTlsh(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
