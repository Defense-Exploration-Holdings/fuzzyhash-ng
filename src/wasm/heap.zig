// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Heap exports for modules whose hashes need the whole input at once
//! (imphash, telfhash, image hashes, LZJD) or state larger than the scratch
//! slot (MinHash). See docs/abi.md.
//!
//! A module root that imports this file links `fuzzy_alloc` and
//! `fuzzy_free`, and its memory can grow. The host must take a new view of
//! memory after any call that may allocate.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");

pub const allocator = std.heap.wasm_allocator;

const block_align: std.mem.Alignment = .@"16";

/// Allocate `len` bytes (at least 1), aligned to 16. Returns 0 when memory
/// cannot grow far enough.
export fn fuzzy_alloc(len: u32) u32 {
    const mem = allocator.alignedAlloc(u8, block_align, @max(len, 1)) catch return 0;
    return @intFromPtr(mem.ptr);
}

/// Free a block from `fuzzy_alloc`, with the length it was allocated with.
export fn fuzzy_free(ptr: u32, len: u32) void {
    if (ptr == 0 or ptr % 16 != 0) return;
    const p: [*]align(16) u8 = @ptrFromInt(ptr);
    allocator.free(p[0..@max(len, 1)]);
}

/// The bytes `ptr .. ptr + len` when they lie inside memory, null otherwise.
/// A zero length is always accepted.
pub fn slice(ptr: u32, len: u32) ?[]u8 {
    if (len == 0) return &.{};
    if (ptr == 0) return null;
    const size: usize = @wasmMemorySize(0) * 65536;
    const p: usize = ptr;
    const n: usize = len;
    if (p > size or n > size - p) return null;
    return @as([*]u8, @ptrFromInt(p))[0..n];
}

/// `count` values of type T at `ptr`, which must be aligned for T.
pub fn typed(comptime T: type, ptr: u32, count: u32) ?[]T {
    if (count == 0) return &.{};
    if (ptr % @alignOf(T) != 0) return null;
    const bytes_len = std.math.mul(u32, count, @sizeOf(T)) catch return null;
    const bytes = slice(ptr, bytes_len) orelse return null;
    const p: [*]T = @ptrCast(@alignCast(bytes.ptr));
    return p[0..count];
}

pub fn status(s: fuzzyhash.abi.Status) i32 {
    return s.code();
}
