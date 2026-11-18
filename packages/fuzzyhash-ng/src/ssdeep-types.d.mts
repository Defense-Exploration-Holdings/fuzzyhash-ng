// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

/** Bytes to hash. Strings are encoded as UTF-8. */
export type Input = Uint8Array | ArrayBuffer | ArrayBufferView | string;

/** Options for ssdeep hashing. Both are off by default. */
export interface SsdeepOptions {
  /** Keep at most three of any run of equal characters in the digest. */
  eliminateSequences?: boolean;
  /** Keep the whole second part instead of cutting it to 32 characters. */
  noTruncate?: boolean;
}

/** ssdeep digest of `input`, as `blocksize:part1:part2`. */
export declare function ssdeep(input: Input, opts?: SsdeepOptions): string;

/**
 * Similarity of two ssdeep digests, an integer from 0 to 100. A file name
 * after a comma is ignored. Throws `FuzzyHashError` with code
 * `INVALID_DIGEST` for a malformed digest, except that two digests whose
 * block sizes cannot be compared score 0.
 */
export declare function ssdeepCompare(a: string, b: string): number;

/** Streaming hasher. `digest()` ends it; call it once. */
export declare class SsdeepHasher {
  /** A new hasher with no input. */
  constructor(opts?: SsdeepOptions);
  /** Add bytes to the input. Returns the hasher. */
  update(input: Input): this;
  /** The digest of everything passed to `update`. */
  digest(): string;
}

/** A digest split into its fields, as `parseSsdeep` returns it. */
export interface ParsedSsdeep {
  /** A number, or a bigint when the value is above `Number.MAX_SAFE_INTEGER` (lenient mode only). */
  blockSize: number | bigint;
  /** Hash part for the block size. */
  part1: string;
  /** Hash part for twice the block size. */
  part2: string;
  /** Text after the comma, without the surrounding quotes, when present. */
  filename?: string;
}

/**
 * Read a digest string. `lenient` (the default) accepts what ssdeep's compare
 * accepts; `strict` also requires a block size of 3 * 2^k and base64 parts.
 * Runs longer than three characters are shortened to three.
 */
export declare function parseSsdeep(s: string, mode?: 'lenient' | 'strict'): ParsedSsdeep;

/** Hash a stream: a web `ReadableStream`, a Node `Readable`, or any async iterable of bytes. */
export declare function ssdeepStream(
  src: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>,
  opts?: SsdeepOptions,
): Promise<string>;
