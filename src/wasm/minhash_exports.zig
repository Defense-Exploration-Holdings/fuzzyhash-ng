// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! MinHash exports, linked into the `minhash` and `fuzzy` modules. See
//! docs/abi.md.
//!
//! `scheme`: 0 affine32 (datasketch's default), 1 affine64, 2 legacy.
//! `num_perm` must be one of `perm_counts`. The state is kept on the host
//! and passed in a block from `fuzzy_alloc`, aligned to 16. Every bit
//! pattern is a valid state, so nothing in it needs checking.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const heap = @import("heap.zig");

const M = fuzzyhash.MinHash;
const status = heap.status;

pub const perm_counts = [_]u32{ 16, 32, 64, 128, 256, 512 };
const schemes = [_]M.Scheme{ .affine32, .affine64, .legacy };

/// Calls `f(T, args...)` with the MinHash type for `scheme` and `num_perm`,
/// or returns `otherwise`.
fn dispatch(scheme: u32, num_perm: u32, comptime R: type, otherwise: R, comptime f: anytype, args: anytype) R {
    inline for (schemes, 0..) |s, si| {
        if (scheme == si) {
            inline for (perm_counts) |n| {
                if (num_perm == n) return @call(.auto, f, .{M.MinHash(s, n)} ++ args);
            }
        }
    }
    return otherwise;
}

fn stateOf(comptime T: type, ptr: u32) ?*T {
    const s = heap.typed(T, ptr, 1) orelse return null;
    return &s[0];
}

fn size(comptime T: type) u32 {
    return @sizeOf(T);
}

fn valuesOffset(comptime T: type) u32 {
    return @offsetOf(T, "hashvalues");
}

/// Bytes of state, or 0 for an unsupported scheme or `num_perm`.
export fn minhash_state_size(scheme: u32, num_perm: u32) u32 {
    return dispatch(scheme, num_perm, u32, 0, size, .{});
}

/// Offset of `hashvalues` in the state: `num_perm` little-endian values,
/// u32 for affine32 and u64 otherwise.
export fn minhash_values_offset(scheme: u32, num_perm: u32) u32 {
    return dispatch(scheme, num_perm, u32, 0, valuesOffset, .{});
}

/// `MinHash(num_perm, seed, scheme)` into the state at `state`.
export fn minhash_init(scheme: u32, num_perm: u32, seed: u32, state: u32) i32 {
    return dispatch(scheme, num_perm, i32, status(.invalid_variant), init, .{ seed, state });
}

fn init(comptime T: type, seed: u32, state: u32) i32 {
    const s = stateOf(T, state) orelse return status(.invalid_argument);
    s.* = T.init(seed);
    return status(.ok);
}

/// `update(b)` for each of `count` byte strings: item i is
/// `data[offsets[i] .. offsets[i + 1]]`, with `count + 1` u32 offsets.
export fn minhash_update(scheme: u32, num_perm: u32, state: u32, data: u32, len: u32, offsets: u32, count: u32) i32 {
    return dispatch(scheme, num_perm, i32, status(.invalid_variant), update, .{ state, data, len, offsets, count });
}

fn update(comptime T: type, state: u32, data: u32, len: u32, offsets: u32, count: u32) i32 {
    const s = stateOf(T, state) orelse return status(.invalid_argument);
    const bytes = heap.slice(data, len) orelse return status(.invalid_argument);
    if (count == std.math.maxInt(u32)) return status(.invalid_argument);
    const offs = heap.typed(u32, offsets, count + 1) orelse return status(.invalid_argument);
    for (0..count) |i| {
        if (offs[i] > offs[i + 1] or offs[i + 1] > bytes.len) return status(.invalid_argument);
    }
    for (0..count) |i| s.update(bytes[offs[i]..offs[i + 1]]);
    return status(.ok);
}
