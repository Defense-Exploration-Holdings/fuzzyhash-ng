// SPDX-License-Identifier: MIT

export type FuzzyHashErrorCode = 'INPUT_TOO_LARGE' | 'INVALID_DIGEST' | 'INVALID_OPTION' | 'WASM_UNAVAILABLE';

/** Error thrown by every fuzzyhash-ng function. `code` says what went wrong. */
export declare class FuzzyHashError extends Error {
  constructor(code: FuzzyHashErrorCode, message: string);
  readonly name: 'FuzzyHashError';
  readonly code: FuzzyHashErrorCode;
}
