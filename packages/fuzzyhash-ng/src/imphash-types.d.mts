// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

import type { Input } from './ssdeep-types.mjs';

/**
 * Import hash of a PE file, as pefile's `get_imphash()`: 32 lowercase hex
 * characters, or null where pefile returns an empty string (no import
 * directory, or none of its entries can be read). Throws `FuzzyHashError`
 * with code `INVALID_INPUT` where pefile refuses the file.
 */
export declare function imphash(input: Input): string | null;
