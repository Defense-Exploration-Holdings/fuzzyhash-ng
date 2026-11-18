// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

import type { Input } from './ssdeep-types.mjs';

/** Which TLSH build to reproduce. The defaults give the standard `T1` digest. */
export interface TlshVariant {
  /** 128 (default) or 256 buckets. */
  buckets?: 128 | 256;
  /** Checksum length in bytes: 1 (default) or 3. */
  checksum?: 1 | 3;
}

/** Options for TLSH hashing. */
export interface TlshOptions extends TlshVariant {
  /** Require 256 bytes of input instead of 50. */
  conservative?: boolean;
  /** Write the `T1` prefix (default true), as the reference does for every variant. */
  prefix?: boolean;
}

/** Options for `tlshDiff`. */
export interface TlshDiffOptions extends TlshVariant {
  /** Count the length term (default true, py-tlsh `diff`); false is py-tlsh `diffxlen`. */
  includeLength?: boolean;
}

/**
 * TLSH digest of `input` in upper-case hex, or null when the input is too
 * short (under 50 bytes, or 256 with `conservative`) or too uniform.
 */
export declare function tlsh(input: Input, opts?: TlshOptions): string | null;

/**
 * TLSH distance between two digests: 0 for identical ones, larger for more
 * different ones. Only the 128-bucket, 1-byte checksum digest may carry the
 * `T1` prefix, as in the reference. Throws `FuzzyHashError` with code
 * `INVALID_DIGEST` for a malformed digest.
 */
export declare function tlshDiff(a: string, b: string, opts?: TlshDiffOptions): number;

/** Streaming hasher. `digest()` ends it; call it once. */
export declare class TlshHasher {
  /** A new hasher with no input. */
  constructor(opts?: TlshOptions);
  /** Add bytes to the input. Returns the hasher. */
  update(input: Input): this;
  /** The digest of everything passed to `update`. */
  digest(): string | null;
}

/** Hash a stream: a web `ReadableStream`, a Node `Readable`, or any async iterable of bytes. */
export declare function tlshStream(
  src: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>,
  opts?: TlshOptions,
): Promise<string | null>;
