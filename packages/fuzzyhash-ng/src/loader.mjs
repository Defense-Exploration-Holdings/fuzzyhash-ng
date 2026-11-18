// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Instantiates one embedded WebAssembly module, synchronously on first use or
// asynchronously through ready(). See docs/abi.md.

import { FuzzyHashError } from './errors.mjs';

/** ABI version this loader speaks. Must equal `abi.version` in src/abi.zig. */
export const ABI_VERSION = 1;

/**
 * Wraps a function that returns the module bytes. The returned object compiles
 * the module once and hands out the same instance afterwards.
 */
export function createLoader(name, getBytes) {
  let instance = null;
  let pending = null;

  function wasmApi() {
    const wasm = globalThis.WebAssembly;
    if (typeof wasm !== 'object' || wasm === null || typeof wasm.Module !== 'function') {
      throw new FuzzyHashError('WASM_UNAVAILABLE', 'WebAssembly is not available in this environment');
    }
    return wasm;
  }

  function accept(inst) {
    const exports = inst.exports;
    if (typeof exports.fuzzy_abi_version !== 'function') {
      throw new FuzzyHashError('WASM_UNAVAILABLE', `the ${name} module has no fuzzy_abi_version export`);
    }
    const got = exports.fuzzy_abi_version() >>> 0;
    if (got !== ABI_VERSION) {
      throw new FuzzyHashError(
        'WASM_UNAVAILABLE',
        `the ${name} module has ABI version ${got}, this loader needs ${ABI_VERSION}`,
      );
    }
    instance = inst;
    return inst;
  }

  return {
    /** The instance, compiling the module synchronously if needed. */
    get() {
      if (instance) return instance;
      const wasm = wasmApi();
      return accept(new wasm.Instance(new wasm.Module(getBytes()), {}));
    },

    /** Compile asynchronously, for hosts that refuse synchronous compilation. */
    ready() {
      if (instance) return Promise.resolve();
      if (!pending) {
        pending = Promise.resolve()
          .then(() => wasmApi().instantiate(getBytes(), {}))
          .then((result) => {
            accept(result.instance);
          })
          .catch((err) => {
            pending = null;
            throw err;
          });
      }
      return pending;
    },
  };
}

/** The version string the module carries, as in build.zig.zon. */
export function readVersion(inst) {
  const { memory, version_ptr, version_len } = inst.exports;
  const bytes = new Uint8Array(memory.buffer, version_ptr(), version_len());
  return new TextDecoder().decode(bytes);
}
