// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Conventions shared by every WebAssembly export. See docs/abi.md.

/// Bumped on any incompatible change to the exports or their conventions. The
/// JavaScript loader refuses a module whose ABI version differs from its own.
pub const version: u32 = 1;

/// Result of an export that can fail. Zero is success. Codes are append-only
/// once released.
pub const Status = enum(i32) {
    ok = 0,
    invalid_argument = 1,
    invalid_state = 2,
    input_too_large = 3,
    too_short = 4,
    insufficient_variation = 5,
    invalid_digest = 6,
    invalid_variant = 7,
    /// The file or image is not one the reference can read.
    invalid_input = 8,
    /// The reference gives no result for this input, or the input needs a
    /// feature this port does not have.
    unsupported_input = 9,
    /// Memory could not grow far enough.
    out_of_memory = 10,
    _,

    pub fn code(s: Status) i32 {
        return @intFromEnum(s);
    }
};

/// Fixed scratch region the JavaScript side fills and drains. Offsets from
/// `scratch_ptr()`:
///
///     [0, 4096)             hasher state, copied in before a call and out after
///     [4096, 4352)          output (digest strings, up to 256 bytes)
///     [4352, 4352 + cap)    input chunk
pub const state_offset = 0;
pub const state_capacity = 4096;
pub const output_offset = state_offset + state_capacity;
pub const output_capacity = 256;
pub const input_offset = output_offset + output_capacity;
pub const input_capacity = 64 * 1024;
pub const scratch_size = input_offset + input_capacity;
