// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Nilsimsa functions over a loaded WebAssembly module. Used by the
// `nilsimsa` and main entry points. See docs/abi.md.

import { OUTPUT_OFFSET, fail, feed, lazyApi, placePair, readOutput, readU32, stateHasher } from './core.mjs';

// A digest is exactly 64 hex digits; one more byte is enough to reject a longer string.
const DIGEST_LIMIT = 65;

export function createNilsimsa(loader) {
  const api = lazyApi(loader);

  const NilsimsaHasher = stateHasher(api, {
    name: 'nilsimsa',
    args: () => ({}),
    stateSize: (w) => w.e.nilsimsa_state_size(),
    init: (w, state) => w.e.nilsimsa_init(state),
    update: (w, state, data, len) => w.e.nilsimsa_update(state, data, len),
    final(w, state) {
      const code = w.e.nilsimsa_final(state, w.base + OUTPUT_OFFSET);
      if (code !== 0) fail(code, 'nilsimsa');
      return readOutput(w, 64);
    },
  });

  function nilsimsa(input) {
    return new NilsimsaHasher().update(input).digest();
  }

  async function nilsimsaStream(src) {
    return (await feed(new NilsimsaHasher(), src)).digest();
  }

  function nilsimsaCompare(a, b) {
    const w = api();
    const [pa, la, pb, lb] = placePair(w, a, b, 'nilsimsaCompare', DIGEST_LIMIT);
    const out = w.base + OUTPUT_OFFSET;
    const code = w.e.nilsimsa_compare(pa, la, pb, lb, out);
    if (code !== 0) fail(code, 'nilsimsaCompare');
    return readU32(w.view(), out) | 0;
  }

  return { nilsimsa, nilsimsaCompare, nilsimsaStream, NilsimsaHasher };
}
