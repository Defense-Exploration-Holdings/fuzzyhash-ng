// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// TLSH functions over a loaded WebAssembly module. Used by the `tlsh` and
// main entry points. See docs/abi.md.

import { FuzzyHashError } from './errors.mjs';
import { STATUS, OUTPUT_OFFSET, INPUT_OFFSET, fail, feed, lazyApi, optionsOf, placePair, readOutput, readU32, stateHasher } from './core.mjs';

// The output length goes to the input slot, which final() does not use.
const LENGTH_OFFSET = INPUT_OFFSET;
// Longest digest ("T1" + 138 hex digits) plus the one character the parser checks after it.
const DIGEST_LIMIT = 141;

/** Variant code: bit 0 for a 3-byte checksum, bit 1 for 256 buckets. */
function variantOf(opts) {
  const o = optionsOf(opts);
  const buckets = o.buckets ?? 128;
  const checksum = o.checksum ?? 1;
  if (buckets !== 128 && buckets !== 256) throw new FuzzyHashError('INVALID_OPTION', 'buckets must be 128 or 256');
  if (checksum !== 1 && checksum !== 3) throw new FuzzyHashError('INVALID_OPTION', 'checksum must be 1 or 3');
  return (checksum === 3 ? 1 : 0) | (buckets === 256 ? 2 : 0);
}

export function createTlsh(loader) {
  const api = lazyApi(loader);

  const TlshHasher = stateHasher(api, {
    name: 'tlsh',
    args(opts) {
      const o = optionsOf(opts);
      return { variant: variantOf(o), conservative: o.conservative ? 1 : 0, prefix: o.prefix === false ? 0 : 1 };
    },
    stateSize: (w, a) => w.e.tlsh_state_size(a.variant),
    init: (w, state, a) => w.e.tlsh_init(state, a.variant, a.conservative),
    update: (w, state, data, len, a) => w.e.tlsh_update(state, a.variant, data, len),
    final(w, state, a) {
      const code = w.e.tlsh_final(state, a.variant, a.prefix, w.base + OUTPUT_OFFSET, w.base + LENGTH_OFFSET);
      if (code === STATUS.TOO_SHORT || code === STATUS.INSUFFICIENT_VARIATION) return null;
      if (code !== 0) fail(code, 'tlsh');
      return readOutput(w, readU32(w.view(), w.base + LENGTH_OFFSET));
    },
  });

  function tlsh(input, opts) {
    return new TlshHasher(opts).update(input).digest();
  }

  async function tlshStream(src, opts) {
    return (await feed(new TlshHasher(opts), src)).digest();
  }

  function tlshDiff(a, b, opts) {
    const o = optionsOf(opts);
    const variant = variantOf(o);
    const w = api();
    const [pa, la, pb, lb] = placePair(w, a, b, 'tlshDiff', DIGEST_LIMIT);
    const r = w.e.tlsh_diff(variant, pa, la, pb, lb, o.includeLength === false ? 0 : 1);
    if (r < 0) fail(-r, 'tlshDiff');
    return r;
  }

  return { tlsh, tlshDiff, tlshStream, TlshHasher };
}
