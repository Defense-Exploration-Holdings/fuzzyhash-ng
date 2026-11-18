// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// telfhash over a loaded WebAssembly module. Used by the `telfhash` and main
// entry points. See docs/abi.md.

import { OUTPUT_OFFSET, INPUT_OFFSET, fail, lazyApi, placePair, readOutput, readU32, toBytes, withBlocks } from './core.mjs';

// "t1" + 70 hex digits, and the one character the parser checks after it.
const DIGEST_LIMIT = 73;

export function createTelfhash(loader) {
  const api = lazyApi(loader);

  function telfhash(input) {
    const bytes = toBytes(input);
    const w = api();
    return withBlocks(w, [bytes], ([p]) => {
      const code = w.e.telfhash_hash(p, bytes.length, w.base + OUTPUT_OFFSET, w.base + INPUT_OFFSET);
      if (code !== 0) fail(code, 'telfhash');
      return readOutput(w, readU32(w.view(), w.base + INPUT_OFFSET));
    });
  }

  function telfhashDiff(a, b) {
    const w = api();
    const [pa, la, pb, lb] = placePair(w, a, b, 'telfhashDiff', DIGEST_LIMIT);
    const r = w.e.telfhash_diff(pa, la, pb, lb);
    if (r < 0) fail(-r, 'telfhashDiff');
    return r;
  }

  return { telfhash, telfhashDiff };
}
