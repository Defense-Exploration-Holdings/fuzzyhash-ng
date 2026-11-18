// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

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
  constructor(code: FuzzyHashErrorCode, message: string);
  readonly name: 'FuzzyHashError';
  readonly code: FuzzyHashErrorCode;
}
