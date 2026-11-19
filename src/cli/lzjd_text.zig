// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Text form of LZJD digests for the CLI: "lzjd:" followed by the standard
//! base64 (with padding) of the digest values as little-endian 32-bit
//! integers, in the sorted order that `Lzjd.digest` returns.

const std = @import("std");
const Lzjd = @import("fuzzyhash").Lzjd;
const Allocator = std.mem.Allocator;

pub const prefix = "lzjd:";
/// Largest `--hash-size` the CLI accepts.
pub const max_values: u32 = 1 << 20;

const b64 = std.base64.standard;

/// The digest values of `data`. The caller frees the result.
pub fn digestFile(gpa: Allocator, data: []const u8, hash_size: u32) ![]i32 {
    if (data.len > Lzjd.max_input_len) return error.InputTooLarge;
    const scratch = try gpa.alloc(u8, Lzjd.scratchLen(data.len, hash_size));
    defer gpa.free(scratch);
    const out = try gpa.alloc(i32, hash_size);
    errdefer gpa.free(out);
    const d = try Lzjd.digest(data, .{ .hash_size = hash_size }, scratch, out);
    return gpa.realloc(out, d.values.len);
}

pub fn encode(gpa: Allocator, values: []const i32) ![]u8 {
    const raw = try gpa.alloc(u8, values.len * 4);
    defer gpa.free(raw);
    for (values, 0..) |v, i| std.mem.writeInt(i32, raw[4 * i ..][0..4], v, .little);
    const text = try gpa.alloc(u8, prefix.len + b64.Encoder.calcSize(raw.len));
    @memcpy(text[0..prefix.len], prefix);
    _ = b64.Encoder.encode(text[prefix.len..], raw);
    return text;
}

pub const DecodeError = error{InvalidFormat} || Allocator.Error;

/// Reads text written by `encode`. The caller frees the result.
pub fn decode(gpa: Allocator, text: []const u8) DecodeError![]i32 {
    if (!std.mem.startsWith(u8, text, prefix)) return error.InvalidFormat;
    const body = text[prefix.len..];
    const n = b64.Decoder.calcSizeForSlice(body) catch return error.InvalidFormat;
    if (n % 4 != 0 or n / 4 > max_values) return error.InvalidFormat;
    const raw = try gpa.alloc(u8, n);
    defer gpa.free(raw);
    b64.Decoder.decode(raw, body) catch return error.InvalidFormat;
    const values = try gpa.alloc(i32, n / 4);
    for (values, 0..) |*v, i| v.* = std.mem.readInt(i32, raw[4 * i ..][0..4], .little);
    return values;
}

const testing = std.testing;

test "encode and decode round trip" {
    const vals = [_]i32{ -5, 0, 7, 2147483647 };
    const text = try encode(testing.allocator, &vals);
    defer testing.allocator.free(text);
    try testing.expect(std.mem.startsWith(u8, text, prefix));
    const back = try decode(testing.allocator, text);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(i32, &vals, back);
}

test "decode rejects other text" {
    try testing.expectError(error.InvalidFormat, decode(testing.allocator, "3:ab:cd"));
    try testing.expectError(error.InvalidFormat, decode(testing.allocator, "lzjd:AAA"));
    try testing.expectError(error.InvalidFormat, decode(testing.allocator, "lzjd:!!!!"));
}

test "a file digest compares equal to itself" {
    const data = "the quick brown fox jumps over the lazy dog, again and again and again";
    const v = try digestFile(testing.allocator, data, 64);
    defer testing.allocator.free(v);
    try testing.expect(v.len > 0);
    try testing.expectEqual(@as(?f64, 1.0), Lzjd.similarity(v, v));
}
