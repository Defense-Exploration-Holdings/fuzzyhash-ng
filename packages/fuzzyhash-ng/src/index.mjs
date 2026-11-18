// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Entry point `fuzzyhash-ng`: every family, from one WebAssembly module.

import { wasmBytes } from '../wasm/fuzzy.mjs';
import { createLoader } from './loader.mjs';
import { createSsdeep } from './ssdeep-core.mjs';
import { createTlsh } from './tlsh-core.mjs';
import { createImphash } from './imphash-core.mjs';
import { createTelfhash } from './telfhash-core.mjs';
import { createImageHash } from './imagehash-core.mjs';
import { createMinHash } from './minhash-core.mjs';
import { createSimhash } from './simhash-core.mjs';
import { createLzjd } from './lzjd-core.mjs';
import { createNilsimsa } from './nilsimsa-core.mjs';

const loader = createLoader('fuzzy', wasmBytes);

export { FuzzyHashError } from './errors.mjs';

export const { ssdeep, ssdeepCompare, parseSsdeep, ssdeepStream, SsdeepHasher } = createSsdeep(loader);
export const { tlsh, tlshDiff, tlshStream, TlshHasher } = createTlsh(loader);
export const { imphash } = createImphash(loader);
export const { telfhash, telfhashDiff } = createTelfhash(loader);
export const { averageHash, dhash, phash, imageHashDistance } = createImageHash(loader);
export const { MinHash } = createMinHash(loader);
export const { simhash, simhashFeatures, simhashDistance } = createSimhash(loader);
export const { lzjd, lzjdSimilarity } = createLzjd(loader);
export const { nilsimsa, nilsimsaCompare, nilsimsaStream, NilsimsaHasher } = createNilsimsa(loader);

/** Compile the WebAssembly module ahead of the first call. */
export function ready() {
  return loader.ready();
}
