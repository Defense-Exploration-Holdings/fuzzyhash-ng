// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! TLSH exports, linked into the `tlsh` and `fuzzy` modules. See docs/abi.md.
//!
//! `variant` selects the reference build: bit 0 set for a 3-byte checksum,
//! bit 1 set for 256 buckets. 0 is the standard `T1` digest. The hasher
//! state lives on the host between calls, as for ssdeep.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const common = @import("common.zig");

const Tlsh = fuzzyhash.Tlsh;
const Status = fuzzyhash.abi.Status;

const flag_conservative: u32 = 1;

fn Hasher(comptime v: u2) type {
    return Tlsh.Tlsh(.{
        .checksum = if (v & 1 != 0) .three else .one,
        .buckets = if (v & 2 != 0) .b256 else .b128,
    });
}

comptime {
    for (0..4) |v| {
        const H = Hasher(v);
        if (@sizeOf(H) > fuzzyhash.abi.state_capacity) @compileError("TLSH state does not fit the state slot");
        if (H.max_string_length > fuzzyhash.abi.output_capacity - 4) @compileError("TLSH digest does not fit the output slot");
    }
}

fn status(s: Status) i32 {
    return s.code();
}

fn stateBytes(comptime H: type, ptr: u32) ?*[@sizeOf(H)]u8 {
    const bytes = common.scratchSlice(ptr, @sizeOf(H)) orelse return null;
    return bytes[0..@sizeOf(H)];
}

/// Copy a state out of `bytes`, or null when it is not one this module could
/// have written. The bucket indexes are bytes and the buckets array has 256
/// entries, so only the option flag needs checking.
fn loadState(comptime H: type, bytes: *const [@sizeOf(H)]u8) ?H {
    if (bytes[@offsetOf(H, "options") + @offsetOf(Tlsh.Options, "conservative")] > 1) return null;
    var h: H = undefined;
    @memcpy(std.mem.asBytes(&h), bytes);
    return h;
}

fn writeLength(ptr: u32, len: usize) void {
    const out = common.scratchSlice(ptr, 4) orelse return;
    std.mem.writeInt(u32, out[0..4], @intCast(len), .little);
}

export fn tlsh_state_size(variant: u32) u32 {
    return switch (variant) {
        inline 0...3 => |v| @sizeOf(Hasher(v)),
        else => 0,
    };
}

/// Start a hasher. Flags: 1 conservative (require 256 bytes of input).
export fn tlsh_init(state: u32, variant: u32, flags: u32) i32 {
    if (flags & ~flag_conservative != 0) return status(.invalid_argument);
    return switch (variant) {
        inline 0...3 => |v| init(Hasher(v), state, flags),
        else => status(.invalid_variant),
    };
}

fn init(comptime H: type, state: u32, flags: u32) i32 {
    const bytes = stateBytes(H, state) orelse return status(.invalid_argument);
    const h = H.init(.{ .conservative = flags & flag_conservative != 0 });
    @memcpy(bytes, std.mem.asBytes(&h));
    return status(.ok);
}

export fn tlsh_update(state: u32, variant: u32, data: u32, len: u32) i32 {
    return switch (variant) {
        inline 0...3 => |v| update(Hasher(v), state, data, len),
        else => status(.invalid_variant),
    };
}

fn update(comptime H: type, state: u32, data: u32, len: u32) i32 {
    const bytes = stateBytes(H, state) orelse return status(.invalid_argument);
    const input = common.scratchSlice(data, len) orelse return status(.invalid_argument);
    var h = loadState(H, bytes) orelse return status(.invalid_state);
    h.update(input);
    @memcpy(bytes, std.mem.asBytes(&h));
    return status(.ok);
}

/// Finish the digest into `out` and its length into the little-endian u32
/// at `out_len_ptr`. `prefix` 1 writes the `T1` prefix. The state is zeroed
/// except for its options, as the reference does.
export fn tlsh_final(state: u32, variant: u32, prefix: u32, out: u32, out_len_ptr: u32) i32 {
    if (prefix > 1) return status(.invalid_argument);
    return switch (variant) {
        inline 0...3 => |v| final(Hasher(v), state, prefix == 1, out, out_len_ptr),
        else => status(.invalid_variant),
    };
}

fn final(comptime H: type, state: u32, prefix: bool, out: u32, out_len_ptr: u32) i32 {
    const bytes = stateBytes(H, state) orelse return status(.invalid_argument);
    const out_bytes = common.scratchSlice(out, H.max_string_length) orelse return status(.invalid_argument);
    if (common.scratchSlice(out_len_ptr, 4) == null) return status(.invalid_argument);
    var h = loadState(H, bytes) orelse return status(.invalid_state);
    const result = h.final();
    @memcpy(bytes, std.mem.asBytes(&h));
    const digest = result catch |err| return switch (err) {
        error.TooShort => status(.too_short),
        error.InsufficientVariation => status(.insufficient_variation),
        error.InputTooLarge => status(.input_too_large),
    };
    var text: [H.max_string_length]u8 = undefined;
    const str = digest.toString(&text, .{ .prefix = prefix });
    @memcpy(out_bytes[0..str.len], str);
    writeLength(out_len_ptr, str.len);
    return status(.ok);
}

/// TLSH distance of two digest strings, or minus a Status code.
/// `include_length` 1 counts the length term (py-tlsh `diff`), 0 leaves it
/// out (`diffxlen`).
export fn tlsh_diff(variant: u32, a: u32, a_len: u32, b: u32, b_len: u32, include_length: u32) i32 {
    if (include_length > 1) return -status(.invalid_argument);
    const sa = common.scratchSlice(a, a_len) orelse return -status(.invalid_argument);
    const sb = common.scratchSlice(b, b_len) orelse return -status(.invalid_argument);
    return switch (variant) {
        inline 0...3 => |v| blk: {
            const d = Hasher(v).diffStrings(sa, sb, .{ .include_length = include_length == 1 }) catch
                break :blk -status(.invalid_digest);
            break :blk @intCast(d);
        },
        else => -status(.invalid_variant),
    };
}
