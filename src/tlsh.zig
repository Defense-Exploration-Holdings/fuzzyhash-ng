// SPDX-License-Identifier: Apache-2.0
// Copyright 2013 Trend Micro Incorporated
//
// Ported from TLSH 5.0.2 (trendmicro/tlsh, src/tlsh_impl.cpp and
// src/tlsh_util.cpp), used under TLSH's Apache-2.0 option. See
// LICENSES/TLSH-LICENSE and LICENSES/TLSH-NOTICE.txt.

//! TLSH (Trend Micro Locality Sensitive Hash), compatible with TLSH 5.0.2.
//!
//! `Tlsh(variant)` is generic over the reference build options: 128 or 256
//! buckets, 1- or 3-byte checksum. `T1` is the standard digest (128 buckets,
//! 1-byte checksum) that `tlsh` and py-tlsh print by default.
//!
//! Differences from the reference that change no digest: `update` gives the
//! same result however the input is split (the reference's fast path loses
//! window bytes when the first call is shorter than 4 bytes), and input
//! longer than 4,224,281,216 bytes is rejected instead of reading past the
//! length table.

const std = @import("std");

pub const Variant = struct {
    buckets: Buckets = .b128,
    checksum: ChecksumLength = .one,

    pub const Buckets = enum { b128, b256 };
    pub const ChecksumLength = enum { one, three };
};

/// Largest input with a defined length code.
pub const max_input_length: u64 = 4_224_281_216;

pub const FinalError = error{ TooShort, InsufficientVariation, InputTooLarge };
pub const ParseError = error{ InvalidLength, InvalidCharacter, PrefixNotAllowed };

pub const Options = struct {
    /// Require 256 bytes of input instead of 50.
    conservative: bool = false,
};

pub const StringOptions = struct {
    /// Write the `T1` prefix, as the reference does for every variant. Only
    /// the 128-bucket, 1-byte checksum digest can be parsed back with it.
    prefix: bool = true,
};

pub const DiffOptions = struct {
    /// Include the length term (py-tlsh `diff`); false is py-tlsh `diffxlen`.
    include_length: bool = true,
};

const min_data_length: u64 = 50;
const min_conservative_data_length: u64 = 256;
const window_size = 5;
const length_mult: u32 = 12;
const qratio_mult: u32 = 12;

pub fn Tlsh(comptime variant: Variant) type {
    return struct {
        const Self = @This();

        pub const effective_buckets: usize = switch (variant.buckets) {
            .b128 => 128,
            .b256 => 256,
        };
        pub const checksum_length: usize = switch (variant.checksum) {
            .one => 1,
            .three => 3,
        };
        pub const code_size: usize = effective_buckets / 4;
        /// Hex characters without prefix: checksum, length, ratios, body.
        pub const hex_length: usize = 2 * (checksum_length + 2 + code_size);
        /// The reference prints `T1` before every variant's digest but only
        /// parses it back for 128 buckets with a 1-byte checksum.
        pub const parses_prefix = variant.buckets == .b128 and variant.checksum == .one;
        pub const max_string_length: usize = hex_length + 2;

        buckets: [256]u32 = @splat(0),
        window: [window_size]u8 = @splat(0),
        checksum: [checksum_length]u8 = @splat(0),
        len: u64 = 0,
        options: Options,

        pub const Digest = struct {
            checksum: [checksum_length]u8,
            /// Log-scale length code.
            lvalue: u8,
            q1ratio: u4,
            q2ratio: u4,
            /// Quartile codes, 2 bits per bucket; byte i holds buckets 4i to 4i+3,
            /// bucket 4i in the low bits. The string shows this array reversed.
            body: [code_size]u8,

            /// Writes the digest in upper-case hex and returns the written slice.
            pub fn toString(self: Digest, out: *[max_string_length]u8, opts: StringOptions) []const u8 {
                var i: usize = 0;
                if (opts.prefix) {
                    out[0] = 'T';
                    out[1] = '1';
                    i = 2;
                }
                const start = i;
                for (self.checksum) |c| {
                    putHex(out, &i, swapNibbles(c));
                }
                putHex(out, &i, swapNibbles(self.lvalue));
                putHex(out, &i, (@as(u8, self.q1ratio) << 4) | self.q2ratio);
                var k: usize = code_size;
                while (k > 0) {
                    k -= 1;
                    putHex(out, &i, self.body[k]);
                }
                std.debug.assert(i - start == hex_length);
                return out[0..i];
            }

            /// Parses a digest string as TLSH does: an optional `T1` prefix (only
            /// for 128/1), exactly `hex_length` hex digits in either case, and
            /// then the end of the string or a character that is not a hex digit.
            pub fn parse(text: []const u8) ParseError!Digest {
                var start: usize = 0;
                if (text.len >= 2 and text[0] == 'T' and text[1] == '1') {
                    if (!parses_prefix) return error.PrefixNotAllowed;
                    start = 2;
                }
                if (text.len < start + hex_length) {
                    for (text[start..]) |c| if (hexValue(c) == null) return error.InvalidCharacter;
                    return error.InvalidLength;
                }
                for (text[start..][0..hex_length]) |c| if (hexValue(c) == null) return error.InvalidCharacter;
                if (text.len > start + hex_length and hexValue(text[start + hex_length]) != null) return error.InvalidLength;

                const h = text[start..];
                var d: Digest = undefined;
                var pos: usize = 0;
                for (&d.checksum) |*c| {
                    c.* = swapNibbles(hexByte(h, pos));
                    pos += 2;
                }
                d.lvalue = swapNibbles(hexByte(h, pos));
                pos += 2;
                const q = hexByte(h, pos);
                pos += 2;
                d.q1ratio = @intCast(q >> 4);
                d.q2ratio = @intCast(q & 15);
                for (0..code_size) |k| {
                    d.body[code_size - 1 - k] = hexByte(h, pos);
                    pos += 2;
                }
                return d;
            }
        };

        pub fn init(options: Options) Self {
            return .{ .options = options };
        }

        pub fn update(self: *Self, bytes: []const u8) void {
            var w = self.window;
            var len = self.len;
            var checksum = self.checksum;
            for (bytes) |b| {
                // w[0] is the newest byte.
                // Shift through a copy: an array literal that reads `w` while
                // writing it would alias.
                const prev = w;
                w = .{ b, prev[0], prev[1], prev[2], prev[3] };
                len +%= 1;
                if (len < window_size) continue;
                checksum[0] = fastMapping(1, w[0], w[1], checksum[0]);
                if (checksum_length > 1) {
                    inline for (1..checksum_length) |k| {
                        checksum[k] = fullMapping(checksum[k - 1], w[0], w[1], checksum[k]);
                    }
                }
                self.buckets[fastMapping(49, w[0], w[1], w[2])] +%= 1;
                self.buckets[fastMapping(12, w[0], w[1], w[3])] +%= 1;
                self.buckets[fastMapping(178, w[0], w[2], w[3])] +%= 1;
                self.buckets[fastMapping(166, w[0], w[2], w[4])] +%= 1;
                self.buckets[fastMapping(84, w[0], w[1], w[4])] +%= 1;
                self.buckets[fastMapping(230, w[0], w[3], w[4])] +%= 1;
            }
            self.window = w;
            self.len = len;
            self.checksum = checksum;
        }

        /// Finishes the digest and zeroes the hasher.
        pub fn final(self: *Self) FinalError!Digest {
            defer self.* = .{ .options = self.options };
            if (self.len > max_input_length) return error.InputTooLarge;
            const min = if (self.options.conservative) min_conservative_data_length else min_data_length;
            if (self.len < min) return error.TooShort;

            var sorted: [effective_buckets]u32 = self.buckets[0..effective_buckets].*;
            std.mem.sort(u32, &sorted, {}, std.sort.asc(u32));
            const q1 = sorted[effective_buckets / 4 - 1];
            const q2 = sorted[effective_buckets / 2 - 1];
            const q3 = sorted[effective_buckets - effective_buckets / 4 - 1];
            if (q3 == 0) return error.InsufficientVariation;

            var nonzero: usize = 0;
            for (self.buckets[0..effective_buckets]) |c| {
                if (c > 0) nonzero += 1;
            }
            if (nonzero <= effective_buckets / 2) return error.InsufficientVariation;

            var d: Digest = .{
                .checksum = self.checksum,
                .lvalue = lengthCode(@intCast(self.len)),
                .q1ratio = @intCast((@as(u64, q1) * 100 / q3) % 16),
                .q2ratio = @intCast((@as(u64, q2) * 100 / q3) % 16),
                .body = undefined,
            };
            for (0..code_size) |i| {
                var h: u8 = 0;
                for (0..4) |j| {
                    const k = self.buckets[4 * i + j];
                    const shift: u3 = @intCast(j * 2);
                    if (q3 < k) {
                        h += @as(u8, 3) << shift;
                    } else if (q2 < k) {
                        h += @as(u8, 2) << shift;
                    } else if (q1 < k) {
                        h += @as(u8, 1) << shift;
                    }
                }
                d.body[i] = h;
            }
            return d;
        }

        pub fn hash(bytes: []const u8, options: Options) FinalError!Digest {
            var h = init(options);
            h.update(bytes);
            return h.final();
        }

        /// TLSH distance: 0 for identical digests, larger for more different ones.
        pub fn diff(a: Digest, b: Digest, opts: DiffOptions) u32 {
            var d: u32 = 0;
            if (opts.include_length) {
                const ldiff = modDiff(a.lvalue, b.lvalue, 256);
                d = if (ldiff <= 1) ldiff else ldiff * length_mult;
            }
            const q1diff = modDiff(a.q1ratio, b.q1ratio, 16);
            d += if (q1diff <= 1) q1diff else (q1diff - 1) * qratio_mult;
            const q2diff = modDiff(a.q2ratio, b.q2ratio, 16);
            d += if (q2diff <= 1) q2diff else (q2diff - 1) * qratio_mult;
            if (!std.mem.eql(u8, &a.checksum, &b.checksum)) d += 1;
            for (a.body, b.body) |x, y| d += byteDistance(x, y);
            return d;
        }

        pub fn diffStrings(a: []const u8, b: []const u8, opts: DiffOptions) ParseError!u32 {
            return diff(try Digest.parse(a), try Digest.parse(b), opts);
        }
    };
}

/// The standard digest: 128 buckets, 1-byte checksum.
pub const T1 = Tlsh(.{});

// ---- tables and helpers ----------------------------------------------------

/// Pearson's sample random table.
const v_table = [256]u8{
    1,   87,  49,  12,  176, 178, 102, 166, 121, 193, 6,   84,  249, 230, 44,  163,
    14,  197, 213, 181, 161, 85,  218, 80,  64,  239, 24,  226, 236, 142, 38,  200,
    110, 177, 104, 103, 141, 253, 255, 50,  77,  101, 81,  18,  45,  96,  31,  222,
    25,  107, 190, 70,  86,  237, 240, 34,  72,  242, 20,  214, 244, 227, 149, 235,
    97,  234, 57,  22,  60,  250, 82,  175, 208, 5,   127, 199, 111, 62,  135, 248,
    174, 169, 211, 58,  66,  154, 106, 195, 245, 171, 17,  187, 182, 179, 0,   243,
    132, 56,  148, 75,  128, 133, 158, 100, 130, 126, 91,  13,  153, 246, 216, 219,
    119, 68,  223, 78,  83,  88,  201, 99,  122, 11,  92,  32,  136, 114, 52,  10,
    138, 30,  48,  183, 156, 35,  61,  26,  143, 74,  251, 94,  129, 162, 63,  152,
    170, 7,   115, 167, 241, 206, 3,   150, 55,  59,  151, 220, 90,  53,  23,  131,
    125, 173, 15,  238, 79,  95,  89,  16,  105, 137, 225, 224, 217, 160, 37,  123,
    118, 73,  2,   157, 46,  116, 9,   145, 134, 228, 207, 212, 202, 215, 69,  229,
    27,  188, 67,  124, 168, 252, 42,  4,   29,  108, 21,  247, 19,  205, 39,  203,
    233, 40,  186, 147, 198, 192, 155, 33,  164, 191, 98,  204, 165, 180, 117, 76,
    140, 36,  210, 172, 41,  54,  159, 8,   185, 232, 113, 196, 231, 47,  146, 120,
    51,  65,  28,  144, 254, 221, 93,  189, 194, 139, 112, 43,  71,  109, 184, 209,
};

/// Pearson hash of (salt, i, j, k).
fn fullMapping(salt: u8, i: u8, j: u8, k: u8) u8 {
    var h: u8 = v_table[salt];
    h = v_table[h ^ i];
    h = v_table[h ^ j];
    return v_table[h ^ k];
}

/// `fullMapping` with the first step done: `ms` is v_table[salt].
fn fastMapping(ms: u8, i: u8, j: u8, k: u8) u8 {
    return v_table[v_table[v_table[ms ^ i] ^ j] ^ k];
}

/// Upper bound of each length code (`topval` in the reference).
const top_value = [170]u32{
    1,          2,          3,          5,          7,          11,         17,         25,         38,         57,
    86,         129,        194,        291,        437,        656,        854,        1110,       1443,       1876,
    2439,       3171,       3475,       3823,       4205,       4626,       5088,       5597,       6157,       6772,
    7450,       8195,       9014,       9916,       10907,      11998,      13198,      14518,      15970,      17567,
    19323,      21256,      23382,      25720,      28292,      31121,      34233,      37656,      41422,      45564,
    50121,      55133,      60646,      66711,      73382,      80721,      88793,      97672,      107439,     118183,
    130002,     143002,     157302,     173032,     190335,     209369,     230306,     253337,     278670,     306538,
    337191,     370911,     408002,     448802,     493682,     543050,     597356,     657091,     722800,     795081,
    874589,     962048,     1058252,    1164078,    1280486,    1408534,    1549388,    1704327,    1874759,    2062236,
    2268459,    2495305,    2744836,    3019320,    3321252,    3653374,    4018711,    4420582,    4862641,    5348905,
    5883796,    6472176,    7119394,    7831333,    8614467,    9475909,    10423501,   11465851,   12612437,   13873681,
    15261050,   16787154,   18465870,   20312458,   22343706,   24578077,   27035886,   29739474,   32713425,   35984770,
    39583245,   43541573,   47895730,   52685306,   57953837,   63749221,   70124148,   77136564,   84850228,   93335252,
    102668779,  112935659,  124229227,  136652151,  150317384,  165349128,  181884040,  200072456,  220079703,  242087671,
    266296456,  292926096,  322218735,  354440623,  389884688,  428873168,  471760495,  518936559,  570830240,  627913311,
    690704607,  759775136,  835752671,  919327967,  1011260767, 1112386880, 1223623232, 1345985727, 1480584256, 1628642751,
    1791507135, 1970657856, 2167723648, 2384496256, 2622945920, 2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
};

/// Length code: the binary search of the reference `l_capturing`, which
/// returns the smallest index whose upper bound is at least `len`.
fn lengthCode(len: u32) u8 {
    var bottom: i32 = 0;
    var top: i32 = 170;
    var idx: i32 = 85;
    // At most about 8 steps for len <= max_input_length; the bound only guards the loop.
    var steps: u32 = 0;
    while (steps < 64) : (steps += 1) {
        if (idx <= 0) return 0;
        if (idx >= top_value.len) return top_value.len - 1;
        const i: usize = @intCast(idx);
        if (len <= top_value[i] and len > top_value[i - 1]) return @intCast(i);
        if (len < top_value[i]) top = idx - 1 else bottom = idx + 1;
        idx = @divTrunc(bottom + top, 2);
    }
    return 0;
}

fn modDiff(x: u32, y: u32, r: u32) u32 {
    const dl = if (y > x) y - x else x - y;
    const dr = if (y > x) x + r - y else y + r - x;
    return @min(dl, dr);
}

/// Sum over the four 2-bit cells of the differences, weighted 1, 2, 6.
fn byteDistance(x: u8, y: u8) u32 {
    var d: u32 = 0;
    inline for (0..4) |c| {
        const a: i32 = (x >> (2 * c)) & 3;
        const b: i32 = (y >> (2 * c)) & 3;
        d += switch (@abs(a - b)) {
            0 => 0,
            1 => 1,
            2 => 2,
            else => 6,
        };
    }
    return d;
}

fn swapNibbles(b: u8) u8 {
    return (b >> 4) | (b << 4);
}

fn putHex(out: []u8, i: *usize, b: u8) void {
    const chars = "0123456789ABCDEF";
    out[i.*] = chars[b >> 4];
    out[i.* + 1] = chars[b & 15];
    i.* += 2;
}

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn hexByte(h: []const u8, pos: usize) u8 {
    return (hexValue(h[pos]).? << 4) | hexValue(h[pos + 1]).?;
}

// ---- tests ------------------------------------------------------------------

const testing = std.testing;

fn vectorInput(edited: bool) [1000]u8 {
    var a: [1000]u8 = undefined;
    for (&a, 0..) |*b, i| b.* = @truncate(i * i * 7 + (i >> 3) + ((i * 13) >> 5));
    if (edited) {
        @memcpy(a[100..110], "0123456789");
        a[700] ^= 0x55;
    }
    return a;
}

test "digests and distances match TLSH 5.0.2 for all variants" {
    const a = vectorInput(false);
    const b = vectorInput(true);
    const cases = .{
        .{ Tlsh(.{}), "T19D11C81A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06", "T11811A52A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06", 53 },
        .{ Tlsh(.{ .checksum = .three }), "T19DC04411C81A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06", "T1183E7211A52A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06", 53 },
        .{ Tlsh(.{ .buckets = .b256 }), "T19D11C8C5835CF04297DB84BFADFC29D20E3CC2D4331C9567537DC4695055235C95C01A1A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06", "T11811A5C9435CF04197DA84BFAEBC29D20A3C8694331895775379C0695051234C95D01A2A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06", 70 },
        .{ Tlsh(.{ .buckets = .b256, .checksum = .three }), "T19DC04411C8C5835CF04297DB84BFADFC29D20E3CC2D4331C9567537DC4695055235C95C01A1A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06", "T1183E7211A5C9435CF04197DA84BFAEBC29D20A3C8694331895775379C0695051234C95D01A2A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06", 70 },
    };
    inline for (cases) |c| {
        const T = c[0];
        var out: [T.max_string_length]u8 = undefined;
        const da = try T.hash(&a, .{});
        const db = try T.hash(&b, .{});
        try testing.expectEqualStrings(c[1], da.toString(&out, .{}));
        try testing.expectEqualStrings(c[2], db.toString(&out, .{}));
        try testing.expectEqual(@as(u32, c[3]), T.diff(da, db, .{}));
        try testing.expectEqual(@as(u32, c[3]), T.diff(da, db, .{ .include_length = false }));
        try testing.expectEqualStrings(c[1][2..], da.toString(&out, .{ .prefix = false }));
    }
}

test "length code matches the table search" {
    try testing.expectEqual(@as(u8, 0), lengthCode(0));
    try testing.expectEqual(@as(u8, 0), lengthCode(1));
    try testing.expectEqual(@as(u8, 1), lengthCode(2));
    try testing.expectEqual(@as(u8, 3), lengthCode(4));
    try testing.expectEqual(@as(u8, 169), lengthCode(4_224_281_216));
    var len: u64 = 1;
    while (len < 4_000_000_000) : (len = len * 3 / 2 + 1) {
        var want: u8 = 0;
        while (top_value[want] < len) want += 1;
        try testing.expectEqual(want, lengthCode(@intCast(len)));
    }
}

test "byte distance weights" {
    try testing.expectEqual(@as(u32, 0), byteDistance(0xAB, 0xAB));
    try testing.expectEqual(@as(u32, 6 * 4), byteDistance(0x00, 0xFF));
    try testing.expectEqual(@as(u32, 1 + 2), byteDistance(0b00_00_00_00, 0b00_00_10_01));
}

test "short and flat inputs give no digest" {
    try testing.expectError(error.TooShort, T1.hash(&@as([49]u8, @splat(120)), .{}));
    try testing.expectError(error.InsufficientVariation, T1.hash(&@as([1000]u8, @splat(0)), .{}));
    var buf: [200]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    try testing.expectError(error.TooShort, T1.hash(&buf, .{ .conservative = true }));
}

test "streaming gives the same digest for any split" {
    var buf: [3000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    r.bytes(&buf);
    const whole = try T1.hash(&buf, .{});
    for (0..50) |_| {
        var h = T1.init(.{});
        var rest: []const u8 = &buf;
        while (rest.len > 0) {
            const n = @min(rest.len, r.uintLessThan(usize, 8));
            h.update(rest[0..n]);
            rest = rest[n..];
        }
        const d = try h.final();
        try testing.expectEqualDeep(whole, d);
    }
}

test "toString and parse round trip, diff of a digest with itself is 0" {
    var buf: [3000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(9);
    prng.random().bytes(&buf);
    inline for (.{ Tlsh(.{}), Tlsh(.{ .checksum = .three }), Tlsh(.{ .buckets = .b256 }), Tlsh(.{ .buckets = .b256, .checksum = .three }) }) |T| {
        const d = try T.hash(&buf, .{});
        var out: [T.max_string_length]u8 = undefined;
        const s = d.toString(&out, .{});
        try testing.expectEqual(T.max_string_length, s.len);
        const p = try T.Digest.parse(if (T.parses_prefix) s else s[2..]);
        try testing.expectEqualDeep(d, p);
        try testing.expectEqual(@as(u32, 0), T.diff(d, p, .{}));
    }
}

test "parse rejects bad strings" {
    const good = "T1B5B002EDE6E7CEEC0A97A99180008DD89BEBF5D40264F4D9F0CD551116AD138B460392";
    _ = try T1.Digest.parse(good);
    _ = try T1.Digest.parse(good[2..]);
    _ = try T1.Digest.parse(good ++ " trailing");
    try testing.expectError(error.InvalidLength, T1.Digest.parse(good ++ "0"));
    try testing.expectError(error.InvalidLength, T1.Digest.parse(good[0 .. good.len - 1]));
    try testing.expectError(error.InvalidCharacter, T1.Digest.parse("t1" ++ good[2..]));
    try testing.expectError(error.PrefixNotAllowed, Tlsh(.{ .buckets = .b256 }).Digest.parse(good));
}
