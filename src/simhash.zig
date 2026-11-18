// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! SimHash compatible with the `simhash` 2.1.2 Python package
//! (`simhash.Simhash`) and its default MD5 feature hash.
//!
//! `Simhash(f).fromText` follows `Simhash(text)`: Python's `str.lower()`,
//! keep the characters matched by `[\w一-鿌]`, take every window
//! of 4 characters (or the whole string when it is shorter), weight each
//! distinct window by its count. The Unicode tables come from Python 3.13
//! (Unicode 15.1). `Builder` follows `Simhash(features)` for features with
//! integer weights.

const std = @import("std");
const Md5 = std.crypto.hash.Md5;
const uni = @import("simhash/unicode.zig");

fn inRanges(table: []const [2]u21, c: u21) bool {
    var lo: usize = 0;
    var hi: usize = table.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (c < table[mid][0]) {
            hi = mid;
        } else if (c > table[mid][1]) {
            lo = mid + 1;
        } else return true;
    }
    return false;
}

fn isWord(c: u21) bool {
    return inRanges(&uni.word, c);
}

fn isCaseIgnorable(c: u21) bool {
    return inRanges(&uni.case_ignorable, c);
}

/// Cased and not case-ignorable.
fn isCased(c: u21) bool {
    return inRanges(&uni.cased, c);
}

/// `chr(c).lower()` for c != U+03A3. Writes up to 3 code points.
fn lower(c: u21, out: *[3]u21) []const u21 {
    for (uni.lower_multi) |m| if (m.cp == c) {
        @memcpy(out[0..m.to.len], m.to);
        return out[0..m.to.len];
    };
    for (uni.lower_runs) |r| {
        if (c >= r.start and c <= r.end and (c - r.start) % r.stride == 0) {
            out[0] = @intCast(@as(i32, c) + r.delta);
            return out[0..1];
        }
    }
    out[0] = c;
    return out[0..1];
}

pub const Error = error{
    /// The text is not valid UTF-8.
    InvalidUtf8,
    /// A feature weight is above 255. The package raises OverflowError:
    /// it multiplies a uint8 bit array by the weight. In text mode this
    /// happens when one 4-character window occurs more than 255 times.
    WeightTooLarge,
    /// `scratch` is shorter than `scratchLen` asks for.
    ScratchTooSmall,
};

/// Entries of `scratch` that `fromText` needs for a text of this many
/// bytes. Texts under 259 bytes cannot repeat a window more than 255 times
/// and need none.
pub fn scratchLen(text_len: usize) usize {
    return if (text_len < 259) 0 else text_len;
}

/// `Simhash(value, f=f)`: an f-bit fingerprint, f a multiple of 8 up to 128.
pub fn Simhash(comptime f: u16) type {
    if (f == 0 or f % 8 != 0 or f > 128) @compileError("f must be a multiple of 8 from 8 to 128");
    return struct {
        const Self = @This();
        pub const Value = @Int(.unsigned, f);
        pub const hash_bytes = f / 8;

        /// `Simhash.value`.
        value: Value,

        /// `Simhash(features)` for integer weights. Add each feature (a
        /// token and its weight) once; `final` gives the fingerprint.
        pub const Builder = struct {
            sums: [f]i64 = @splat(0),
            count: i64 = 0,

            /// One feature, hashed with MD5 as the package's default
            /// `hashfunc` does.
            pub fn add(self: *Builder, feature: []const u8, weight: i64) Error!void {
                var d: [Md5.digest_length]u8 = undefined;
                Md5.hash(feature, &d, .{});
                try self.addHash(d[Md5.digest_length - hash_bytes ..][0..hash_bytes], weight);
            }

            /// One feature by its hash bytes (a custom `hashfunc`'s last
            /// f/8 bytes).
            pub fn addHash(self: *Builder, h: *const [hash_bytes]u8, weight: i64) Error!void {
                if (weight > 255) return error.WeightTooLarge;
                self.count += weight;
                // Weights of 50 or less go through `bytes * weight`, which is
                // empty for negative weights: they still count, but add no
                // bits.
                const w = @max(weight, 0);
                if (w == 0) return;
                for (0..f) |j| {
                    if (h[j / 8] & (@as(u8, 0x80) >> @intCast(j % 8)) != 0) self.sums[j] += w;
                }
            }

            pub fn final(self: *const Builder) Self {
                var v: Value = 0;
                for (0..f) |j| {
                    // combined_sums > count / 2
                    if (@as(i128, self.sums[j]) * 2 > self.count) v |= @as(Value, 1) << @intCast(f - 1 - j);
                }
                return .{ .value = v };
            }
        };

        /// `Simhash(text, f=f)` for UTF-8 text. `scratch` needs
        /// `scratchLen(text.len)` entries.
        pub fn fromText(text: []const u8, scratch: []u128) Error!Self {
            if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
            const need = scratchLen(text.len);
            if (scratch.len < need) return error.ScratchTooSmall;
            var b: Builder = .{};
            var keys: usize = 0;
            var win: [4]u21 = undefined;
            var n: usize = 0; // characters kept so far
            // Final sigma context: was the last non-case-ignorable character
            // cased? null before the first one.
            var last_cased: ?bool = null;
            var it = std.unicode.Utf8View.initUnchecked(text).iterator();
            while (it.nextCodepoint()) |c| {
                var buf: [3]u21 = undefined;
                const lowered: []const u21 = if (c == 0x3a3) blk: {
                    buf[0] = if (finalSigma(last_cased, text[it.i..])) 0x3c2 else 0x3c3;
                    break :blk buf[0..1];
                } else lower(c, &buf);
                if (!isCaseIgnorable(c)) last_cased = isCased(c);
                for (lowered) |l| {
                    if (!isWord(l)) continue;
                    if (n >= 4) {
                        std.mem.copyForwards(u21, win[0..3], win[1..4]);
                        win[3] = l;
                    } else win[n] = l;
                    n += 1;
                    if (n >= 4) {
                        if (need == 0) {
                            addWindow(&b, &win) catch unreachable;
                        } else {
                            scratch[keys] = key(&win);
                            keys += 1;
                        }
                    }
                }
            }
            if (n < 4) {
                addWindow(&b, win[0..n]) catch unreachable;
                return b.final();
            }
            if (need != 0) {
                // Each distinct window is one feature weighted by its count.
                const ks = scratch[0..keys];
                std.mem.sort(u128, ks, {}, std.sort.asc(u128));
                var i: usize = 0;
                while (i < ks.len) {
                    var j = i + 1;
                    while (j < ks.len and ks[j] == ks[i]) j += 1;
                    if (j - i > 255) return error.WeightTooLarge;
                    var cps: [4]u21 = undefined;
                    for (0..4) |q| cps[q] = @truncate(ks[i] >> @intCast(21 * (3 - q)));
                    try addWindowWeighted(&b, &cps, @intCast(j - i));
                    i = j;
                }
            }
            return b.final();
        }

        fn key(cps: *const [4]u21) u128 {
            var k: u128 = 0;
            for (cps) |c| k = (k << 21) | c;
            return k;
        }

        fn addWindowWeighted(b: *Builder, cps: []const u21, weight: i64) Error!void {
            var buf: [16]u8 = undefined;
            var len: usize = 0;
            for (cps) |c| len += std.unicode.utf8Encode(c, buf[len..]) catch unreachable;
            try b.add(buf[0..len], weight);
        }

        fn addWindow(b: *Builder, cps: []const u21) Error!void {
            return addWindowWeighted(b, cps, 1);
        }

        /// CPython's handle_capital_sigma: final when preceded (skipping
        /// case-ignorable characters) by a cased one and not followed
        /// (skipping case-ignorable characters) by a cased one.
        fn finalSigma(last_cased: ?bool, rest: []const u8) bool {
            if (last_cased != true) return false;
            var it = std.unicode.Utf8View.initUnchecked(rest).iterator();
            while (it.nextCodepoint()) |c| {
                if (!isCaseIgnorable(c)) return !isCased(c);
            }
            return true;
        }

        /// `distance(other)`: differing bits.
        pub fn distance(a: Self, b: Self) u32 {
            return @popCount(a.value ^ b.value);
        }
    };
}

test "lower and word tables" {
    var buf: [3]u21 = undefined;
    try std.testing.expectEqualSlices(u21, &.{'a'}, lower('A', &buf));
    try std.testing.expectEqualSlices(u21, &.{ 'i', 0x307 }, lower(0x130, &buf));
    try std.testing.expectEqualSlices(u21, &.{0x101}, lower(0x100, &buf));
    try std.testing.expect(isWord('_') and isWord('7') and isWord(0x4e00) and !isWord(' ') and !isWord(0x307));
}

test "values match simhash 2.1.2" {
    const cases = [_]struct { text: []const u8, v64: u64, v32: u32 }{
        .{ .text = "How are you? I am fine. Thanks.", .v64 = 3419227768443824139, .v32 = 540993547 },
        .{ .text = "", .v64 = 16825458760271544958, .v32 = 3975692926 },
        .{ .text = "ab", .v64 = 3404963397999061920, .v32 = 2465262496 },
        .{ .text = "\u{3a3}\u{391}\u{3a3} \u{39f}\u{394}\u{39f}\u{3a3}", .v64 = 437429861251416391, .v32 = 638189895 },
        .{ .text = "\u{130}stanbul", .v64 = 10618295023664214097, .v32 = 3721244753 },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.v64, (try Simhash(64).fromText(c.text, &.{})).value);
        try std.testing.expectEqual(c.v32, (try Simhash(32).fromText(c.text, &.{})).value);
    }
    // Punctuation and case do not matter.
    const a = try Simhash(64).fromText("How are you i am fine. thanks.", &.{});
    try std.testing.expectEqual(@as(u32, 0), Simhash(64).distance(a, try Simhash(64).fromText(cases[0].text, &.{})));
}

test "features with weights" {
    var b: Simhash(64).Builder = .{};
    try std.testing.expectEqual(@as(u64, 0), b.final().value);
    try b.add("a", 3);
    try b.add("b", -2);
    try b.add("c", 60);
    try std.testing.expectEqual(@as(u64, 10764887580597772083), b.final().value);
    try std.testing.expectError(error.WeightTooLarge, b.add("d", 256));
}

test "a window repeated more than 255 times is an error, as in the package" {
    var scratch: [300]u128 = undefined;
    const t258: [258]u8 = @splat('a');
    try std.testing.expectEqual(@as(u64, 15222026846552835557), (try Simhash(64).fromText(&t258, &scratch)).value);
    const t259: [259]u8 = @splat('a');
    try std.testing.expectError(error.WeightTooLarge, Simhash(64).fromText(&t259, &scratch));
    try std.testing.expectError(error.ScratchTooSmall, Simhash(64).fromText(&t259, scratch[0..10]));
    try std.testing.expectError(error.InvalidUtf8, Simhash(64).fromText("\xff", &.{}));
}
