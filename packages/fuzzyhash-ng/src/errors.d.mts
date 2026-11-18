// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/** What went wrong, on `FuzzyHashError.code`. */
export type FuzzyHashErrorCode =
  | 'INPUT_TOO_LARGE'
  | 'INVALID_DIGEST'
  | 'INVALID_INPUT'
  | 'INVALID_OPTION'
  | 'OUT_OF_MEMORY'
  | 'UNSUPPORTED_INPUT'
  | 'WASM_UNAVAILABLE';

/** Error thrown by every fuzzyhash-ng function. `code` says what went wrong. */
export declare class FuzzyHashError extends Error {
  /** An error with the given code and message. */
  constructor(code: FuzzyHashErrorCode, message: string);
  /** Always `FuzzyHashError`. */
  readonly name: 'FuzzyHashError';
  /** What went wrong. */
  readonly code: FuzzyHashErrorCode;
}
