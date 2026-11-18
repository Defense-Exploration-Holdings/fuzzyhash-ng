// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng/imagehash`.

import { wasmBytes } from '../wasm/imagehash.mjs';
import { createLoader } from './loader.mjs';
import { createImageHash } from './imagehash-core.mjs';

const loader = createLoader('imagehash', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { averageHash, dhash, phash, imageHashDistance } = createImageHash(loader);

/** Compile this entry point's WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
