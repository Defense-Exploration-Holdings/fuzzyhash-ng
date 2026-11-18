// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// imphash over a loaded WebAssembly module. Used by the `imphash` and main
// entry points. See docs/abi.md.

import { OUTPUT_OFFSET, INPUT_OFFSET, fail, lazyApi, readOutput, readU32, toBytes, withBlocks } from './core.mjs';

export function createImphash(loader) {
  const api = lazyApi(loader);

  function imphash(input) {
    const bytes = toBytes(input);
    const w = api();
    return withBlocks(w, [bytes], ([p]) => {
      const code = w.e.imphash_hash(p, bytes.length, w.base + OUTPUT_OFFSET, w.base + INPUT_OFFSET);
      if (code !== 0) fail(code, 'imphash');
      const n = readU32(w.view(), w.base + INPUT_OFFSET);
      return n === 0 ? null : readOutput(w, n);
    });
  }

  return { imphash };
}
