// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! LZJD exports, linked into the `lzjd` and `fuzzy` modules. See
//! docs/abi.md. Input and digests are passed in blocks from `fuzzy_alloc`.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const common = @import("common.zig");
const heap = @import("heap.zig");

const Lzjd = fuzzyhash.Lzjd;
const status = heap.status;

/// Digest of `data`. mode 0 is pyLZJD's default mode (`out` receives up to
/// `hash_size` i32 values, sorted), mode 1 is SuperHash (`out` receives
/// exactly `hash_size` f32 values). The number of values written and the set
/// size go to the little-endian u32s at `count_ptr` and `set_size_ptr`
/// (scratch region).
export fn lzjd_digest(
    mode: u32,
    hash_size: u32,
    false_seen_prob: f32,
    seed: u32,
    data: u32,
    len: u32,
    out: u32,
    count_ptr: u32,
    set_size_ptr: u32,
) i32 {
    if (mode > 1) return status(.invalid_variant);
    const input = heap.slice(data, len) orelse return status(.invalid_argument);
    const count_out = common.scratchSlice(count_ptr, 4) orelse return status(.invalid_argument);
    const set_out = common.scratchSlice(set_size_ptr, 4) orelse return status(.invalid_argument);
    if (input.len > Lzjd.max_input_len) return status(.input_too_large);
    const opts: Lzjd.Options = .{ .hash_size = hash_size, .false_seen_prob = false_seen_prob, .seed = seed };
    const scratch = heap.allocator.alloc(u8, Lzjd.scratchLen(input.len, hash_size)) catch return status(.out_of_memory);
    defer heap.allocator.free(scratch);
    var count: usize = 0;
    var set_size: u32 = 0;
    if (mode == 0) {
        const o = heap.typed(i32, out, hash_size) orelse return status(.invalid_argument);
        const d = Lzjd.digest(input, opts, scratch, o) catch |err| return mapError(err);
        count = d.values.len;
        set_size = d.set_size;
    } else {
        if (hash_size == 0) return status(.invalid_argument);
        const o = heap.typed(f32, out, hash_size) orelse return status(.invalid_argument);
        const d = Lzjd.digestSuper(input, opts, scratch, o) catch |err| return mapError(err);
        count = d.values.len;
        set_size = d.set_size;
    }
    std.mem.writeInt(u32, count_out[0..4], @intCast(count), .little);
    std.mem.writeInt(u32, set_out[0..4], set_size, .little);
    return status(.ok);
}

fn mapError(err: Lzjd.Error) i32 {
    return switch (err) {
        error.InvalidHashSize => status(.invalid_argument),
        error.InputTooLarge => status(.input_too_large),
        error.ScratchTooSmall, error.OutputTooSmall => status(.out_of_memory),
    };
}

/// Similarity of two default-mode digests (i32 arrays of `a_len` and
/// `b_len` values). NaN when both are empty, where pyLZJD raises.
export fn lzjd_similarity(a: u32, a_len: u32, b: u32, b_len: u32) f64 {
    const sa = heap.typed(i32, a, a_len) orelse return std.math.nan(f64);
    const sb = heap.typed(i32, b, b_len) orelse return std.math.nan(f64);
    return Lzjd.similarity(sa, sb) orelse std.math.nan(f64);
}

/// Similarity of two SuperHash digests (f32 arrays). NaN when the lengths
/// differ or both are empty.
export fn lzjd_similarity_super(a: u32, a_len: u32, b: u32, b_len: u32) f64 {
    const sa = heap.typed(f32, a, a_len) orelse return std.math.nan(f64);
    const sb = heap.typed(f32, b, b_len) orelse return std.math.nan(f64);
    return Lzjd.similaritySuper(sa, sb);
}
