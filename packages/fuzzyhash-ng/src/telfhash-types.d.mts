// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

import type { Input } from './ssdeep-types.mjs';

/**
 * telfhash of an ELF file, as telfhash 0.9.8 prints it: `t1` and 70
 * lowercase hex digits, `tnull` when the symbol list is too short or too
 * uniform for TLSH, or `-` when no symbols are left. Throws
 * `FuzzyHashError` with code `INVALID_INPUT` where pyelftools cannot read
 * the file (telfhash prints `-`), and `UNSUPPORTED_INPUT` where telfhash
 * gives no result.
 */
export declare function telfhash(input: Input): string;

/** Distance between two telfhash digests, as telfhash's grouping computes it. */
export declare function telfhashDiff(a: string, b: string): number;
