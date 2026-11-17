// SPDX-License-Identifier: MIT

/** Error thrown by every fuzzyhash-ng function. `code` says what went wrong. */
export class FuzzyHashError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'FuzzyHashError';
    this.code = code;
  }
}
