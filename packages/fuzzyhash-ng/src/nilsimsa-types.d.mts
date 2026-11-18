// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

import type { Input } from './ssdeep-types.mjs';

/** Nilsimsa digest of `input`: 64 lowercase hex characters, as `nilsimsa` 0.3.8's `hexdigest()`. */
export declare function nilsimsa(input: Input): string;

/** Score from -128 (every bit differs) to 128 (identical), as `compare_digests`. */
export declare function nilsimsaCompare(a: string, b: string): number;

/** Streaming hasher. `digest()` ends it; call it once. */
export declare class NilsimsaHasher {
  constructor();
  update(input: Input): this;
  digest(): string;
}

/** Hash a stream: a web `ReadableStream`, a Node `Readable`, or any async iterable of bytes. */
export declare function nilsimsaStream(src: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>): Promise<string>;
