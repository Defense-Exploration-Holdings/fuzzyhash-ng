// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! SimHash exports, linked into the `simhash` and `fuzzy` modules. See
//! docs/abi.md. `f` is the fingerprint width in bits, a multiple of 8 from 8
//! to 128. The fingerprint is written to `out` as f / 8 big-endian bytes.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const common = @import("common.zig");
const heap = @import("heap.zig");

const S = fuzzyhash.Simhash;
const status = heap.status;

fn mapError(err: S.Error) i32 {
    return switch (err) {
        error.InvalidUtf8 => status(.invalid_input),
        error.WeightTooLarge => status(.unsupported_input),
        error.ScratchTooSmall => status(.out_of_memory),
    };
}

fn writeValue(comptime H: type, h: H, out: []u8) void {
    std.mem.writeInt(H.Value, out[0..H.hash_bytes], h.value, .big);
}

/// `Simhash(text, f=f)` of the UTF-8 text at `text` (a `fuzzy_alloc` block).
export fn simhash_text(f: u32, text: u32, len: u32, out: u32) i32 {
    const input = heap.slice(text, len) orelse return status(.invalid_argument);
    inline for (1..17) |i| {
        if (f == i * 8) {
            const H = S.Simhash(i * 8);
            const o = common.scratchSlice(out, H.hash_bytes) orelse return status(.invalid_argument);
            const scratch = heap.allocator.alloc(u128, S.scratchLen(input.len)) catch return status(.out_of_memory);
            defer heap.allocator.free(scratch);
            const h = H.fromText(input, scratch) catch |err| return mapError(err);
            writeValue(H, h, o);
            return status(.ok);
        }
    }
    return status(.invalid_variant);
}

/// `Simhash(features, f=f)` for `count` features with integer weights:
/// feature i is `data[offsets[i] .. offsets[i + 1]]` (`count + 1` u32
/// offsets) with weight `weights[i]` (i32).
export fn simhash_features(f: u32, data: u32, len: u32, offsets: u32, weights: u32, count: u32, out: u32) i32 {
    const bytes = heap.slice(data, len) orelse return status(.invalid_argument);
    if (count == std.math.maxInt(u32)) return status(.invalid_argument);
    const offs = heap.typed(u32, offsets, count + 1) orelse return status(.invalid_argument);
    const ws = heap.typed(i32, weights, count) orelse return status(.invalid_argument);
    for (0..count) |i| {
        if (offs[i] > offs[i + 1] or offs[i + 1] > bytes.len) return status(.invalid_argument);
    }
    inline for (1..17) |i| {
        if (f == i * 8) {
            const H = S.Simhash(i * 8);
            const o = common.scratchSlice(out, H.hash_bytes) orelse return status(.invalid_argument);
            var b: H.Builder = .{};
            for (0..count) |k| b.add(bytes[offs[k]..offs[k + 1]], ws[k]) catch |err| return mapError(err);
            writeValue(H, b.final(), o);
            return status(.ok);
        }
    }
    return status(.invalid_variant);
}
