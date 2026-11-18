// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Exports that every WebAssembly module carries: ABI and version metadata and
//! the scratch region used for allocation-free calls.
//!
//! A module root (`src/wasm/<name>.zig`) starts with
//!
//!     comptime { _ = @import("common.zig"); }
//!
//! so that these exports are linked in.

const fuzzyhash = @import("fuzzyhash");
const abi = fuzzyhash.abi;

pub var scratch: [abi.scratch_size]u8 align(16) = undefined;

/// The bytes `ptr .. ptr + len` when they lie inside the scratch region, null
/// otherwise. Exports only read and write host-supplied ranges through this.
pub fn scratchSlice(ptr: u32, len: u32) ?[]u8 {
    const start: usize = @intFromPtr(&scratch);
    const p: usize = ptr;
    const n: usize = len;
    if (p < start) return null;
    const offset = p - start;
    if (offset > scratch.len or n > scratch.len - offset) return null;
    return scratch[offset..][0..n];
}

export fn fuzzy_abi_version() u32 {
    return abi.version;
}

export fn version_ptr() [*]const u8 {
    return fuzzyhash.version_string.ptr;
}

export fn version_len() u32 {
    return fuzzyhash.version_string.len;
}

export fn scratch_ptr() u32 {
    return @intFromPtr(&scratch);
}

export fn scratch_len() u32 {
    return scratch.len;
}
