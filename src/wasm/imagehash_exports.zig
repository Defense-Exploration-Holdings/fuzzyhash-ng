// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Image hash exports (aHash, dHash, pHash), linked into the `imagehash` and
//! `fuzzy` modules. See docs/abi.md. Pixels are passed in a block from
//! `fuzzy_alloc`.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const common = @import("common.zig");
const heap = @import("heap.zig");

const ImageHash = fuzzyhash.ImageHash;
const status = heap.status;

/// Hash sizes the module is built for (`hash_size` in ImageHash).
pub const hash_sizes = [_]u16{ 4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32 };

comptime {
    for (hash_sizes) |n| {
        if (ImageHash.ImageHash(n).hex_length > fuzzyhash.abi.output_capacity) @compileError("image hash does not fit the output slot");
    }
}

export fn imagehash_supported_size(hash_size: u32) u32 {
    inline for (hash_sizes) |n| {
        if (hash_size == n) return 1;
    }
    return 0;
}

/// kind: 0 average, 1 difference, 2 perceptual. format: 0 L, 1 LA, 2 RGB,
/// 3 RGBA. `highfreq_factor` is used by pHash only. Writes the lowercase hex
/// digest to `out` and its length to the little-endian u32 at `out_len_ptr`.
export fn imagehash_hash(
    kind: u32,
    hash_size: u32,
    highfreq_factor: u32,
    width: u32,
    height: u32,
    format: u32,
    pixels: u32,
    len: u32,
    out: u32,
    out_len_ptr: u32,
) i32 {
    const k: ImageHash.Kind = switch (kind) {
        0 => .average,
        1 => .difference,
        2 => .perceptual,
        else => return status(.invalid_argument),
    };
    const f: ImageHash.Format = switch (format) {
        0 => .gray,
        1 => .gray_alpha,
        2 => .rgb,
        3 => .rgba,
        else => return status(.invalid_argument),
    };
    if (k == .perceptual and (highfreq_factor == 0 or highfreq_factor > std.math.maxInt(u16))) return status(.unsupported_input);
    const hf: u16 = if (k == .perceptual) @intCast(highfreq_factor) else 4;
    const px = heap.slice(pixels, len) orelse return status(.invalid_argument);
    const out_len = common.scratchSlice(out_len_ptr, 4) orelse return status(.invalid_argument);
    const image: ImageHash.Image = .{ .width = width, .height = height, .format = f, .pixels = px };
    inline for (hash_sizes) |n| {
        if (hash_size == n) {
            const H = ImageHash.ImageHash(n);
            const out_bytes = common.scratchSlice(out, H.hex_length) orelse return status(.invalid_argument);
            const h = run(H, k, image, hf) catch |err| return switch (err) {
                error.EmptyImage, error.InvalidImage => status(.invalid_input),
                error.ImageTooLarge, error.UnsupportedSize => status(.unsupported_input),
                error.ScratchTooSmall, error.OutOfMemory => status(.out_of_memory),
            };
            _ = h.toHex(out_bytes[0..H.hex_length]);
            std.mem.writeInt(u32, out_len[0..4], H.hex_length, .little);
            return status(.ok);
        }
    }
    return status(.invalid_argument);
}

fn run(comptime H: type, kind: ImageHash.Kind, image: ImageHash.Image, hf: u16) (ImageHash.Error || error{OutOfMemory})!H {
    // Errors about the image itself come first, without allocating.
    switch (kind) {
        .average => if (H.average(image, &.{})) |_| {} else |e| if (e != error.ScratchTooSmall) return e,
        .difference => if (H.difference(image, &.{})) |_| {} else |e| if (e != error.ScratchTooSmall) return e,
        .perceptual => if (H.perceptual(image, hf, &.{})) |_| {} else |e| if (e != error.ScratchTooSmall) return e,
    }
    const scratch = try heap.allocator.alloc(u8, H.scratchSize(kind, image.width, image.height, hf));
    defer heap.allocator.free(scratch);
    return switch (kind) {
        .average => H.average(image, scratch),
        .difference => H.difference(image, scratch),
        .perceptual => H.perceptual(image, hf, scratch),
    };
}
