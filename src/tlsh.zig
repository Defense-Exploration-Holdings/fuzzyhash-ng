// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC

//! TLSH (Trend Micro Locality Sensitive Hash) similarity digests.
//!
//! Output is compatible with TLSH 5.0.2: the same digest strings and the same
//! distances, for the four build variants of TLSH (128 or 256 buckets, each
//! with a 1-byte or a 3-byte checksum).
//!
//! The code does not allocate, does not recurse and touches no OS facility.
//! Every array index is in range by construction, so the results do not
//! depend on runtime safety checks.

const std = @import("std");

/// Selects one of the four TLSH build variants.
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
    /// Write the `T1` prefix.
    prefix: bool = true,
};
pub const DiffOptions = struct {
    /// Include the length term (py-tlsh `diff`); false is py-tlsh `diffxlen`.
    include_length: bool = true,
};

/// The sample permutation table from Pearson's 1990 paper.
const pearson_table = [256]u8{
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

comptime {
    // The table must be a permutation of 0..255.
    var seen: [256]bool = @splat(false);
    for (pearson_table) |v| {
        if (seen[v]) @compileError("pearson_table is not a permutation");
        seen[v] = true;
    }
}

/// Upper bounds of the input length for each length code. The code of a
/// length `n` is the smallest index `i` with `length_bounds[i] >= n`.
const length_bounds = [170]u32{
    1,          2,          3,          5,          7,
    11,         17,         25,         38,         57,
    86,         129,        194,        291,        437,
    656,        854,        1110,       1443,       1876,
    2439,       3171,       3475,       3823,       4205,
    4626,       5088,       5597,       6157,       6772,
    7450,       8195,       9014,       9916,       10907,
    11998,      13198,      14518,      15970,      17567,
    19323,      21256,      23382,      25720,      28292,
    31121,      34233,      37656,      41422,      45564,
    50121,      55133,      60646,      66711,      73382,
    80721,      88793,      97672,      107439,     118183,
    130002,     143002,     157302,     173032,     190335,
    209369,     230306,     253337,     278670,     306538,
    337191,     370911,     408002,     448802,     493682,
    543050,     597356,     657091,     722800,     795081,
    874589,     962048,     1058252,    1164078,    1280486,
    1408534,    1549388,    1704327,    1874759,    2062236,
    2268459,    2495305,    2744836,    3019320,    3321252,
    3653374,    4018711,    4420582,    4862641,    5348905,
    5883796,    6472176,    7119394,    7831333,    8614467,
    9475909,    10423501,   11465851,   12612437,   13873681,
    15261050,   16787154,   18465870,   20312458,   22343706,
    24578077,   27035886,   29739474,   32713425,   35984770,
    39583245,   43541573,   47895730,   52685306,   57953837,
    63749221,   70124148,   77136564,   84850228,   93335252,
    102668779,  112935659,  124229227,  136652151,  150317384,
    165349128,  181884040,  200072456,  220079703,  242087671,
    266296456,  292926096,  322218735,  354440623,  389884688,
    428873168,  471760495,  518936559,  570830240,  627913311,
    690704607,  759775136,  835752671,  919327967,  1011260767,
    1112386880, 1223623232, 1345985727, 1480584256, 1628642751,
    1791507135, 1970657856, 2167723648, 2384496256, 2622945920,
    2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
};

comptime {
    for (length_bounds[1..], length_bounds[0 .. length_bounds.len - 1]) |hi, lo| {
        if (hi <= lo) @compileError("length_bounds is not strictly increasing");
    }
    if (length_bounds[length_bounds.len - 1] != max_input_length) {
        @compileError("max_input_length does not match length_bounds");
    }
}

/// Length code of an input of `n` bytes. Inputs above `max_input_length`
/// have no code; they get the last one so that the function is total.
fn lengthCode(n: u64) u8 {
    var lo: usize = 0;
    var hi: usize = length_bounds.len - 1;
    // Invariant: the answer is in lo..hi (inclusive) when n is in range.
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (length_bounds[mid] >= n) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    return @truncate(lo);
}

/// Pearson mapping of three bytes. `seed` is the table entry of the salt,
/// so that `pearson3(pearson_table[s], a, b, c)` is `H(s, a, b, c)`.
inline fn pearson3(seed: u8, a: u8, b: u8, c: u8) u8 {
    return pearson_table[pearson_table[pearson_table[seed ^ a] ^ b] ^ c];
}

const upper_hex = "0123456789ABCDEF";

/// Value of a hex digit, or null for any other byte.
fn hexValue(ch: u8) ?u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'f' => ch - 'a' + 10,
        'A'...'F' => ch - 'A' + 10,
        else => null,
    };
}

/// Distance on a circle of `range` values. Requires x, y < range.
fn modDiff(x: u32, y: u32, range: u32) u32 {
    const d = if (x > y) x - y else y - x;
    return @min(d, range - d);
}

/// Distance of two body nibbles (two 2-bit cells each), indexed by
/// `x << 4 | y`. A cell difference of 0, 1, 2 or 3 costs 0, 1, 2 or 6.
const nibble_distance: [256]u8 = blk: {
    @setEvalBranchQuota(4000);
    const cost = [4]u8{ 0, 1, 2, 6 };
    var table: [256]u8 = undefined;
    for (&table, 0..) |*entry, index| {
        const x = index >> 4;
        const y = index & 15;
        const lo_x = x & 3;
        const lo_y = y & 3;
        const hi_x = x >> 2;
        const hi_y = y >> 2;
        const lo_d = if (lo_x > lo_y) lo_x - lo_y else lo_y - lo_x;
        const hi_d = if (hi_x > hi_y) hi_x - hi_y else hi_y - hi_x;
        entry.* = cost[lo_d] + cost[hi_d];
    }
    break :blk table;
};

pub fn Tlsh(comptime variant: Variant) type {
    return struct {
        const Self = @This();

        /// Number of buckets that take part in the digest.
        pub const effective_buckets: usize = switch (variant.buckets) {
            .b128 => 128,
            .b256 => 256,
        };
        /// Number of checksum bytes.
        pub const checksum_length: usize = switch (variant.checksum) {
            .one => 1,
            .three => 3,
        };
        /// Number of body bytes; each holds four 2-bit bucket codes.
        pub const code_size: usize = effective_buckets / 4;
        /// Length of the digest string without the `T1` prefix.
        pub const hex_length: usize = 2 * (checksum_length + 2 + code_size);
        /// Whether `Digest.parse` accepts a leading `T1`.
        pub const parses_prefix: bool = effective_buckets == 128 and checksum_length == 1;
        /// Buffer size for `Digest.toString`.
        pub const max_string_length: usize = hex_length + 2;

        // Hasher state. It holds integers and arrays of integers only, and
        // `update` and `final` accept every bit pattern of the fields other
        // than `options`: bucket indices are bytes into a 256-entry array,
        // the counters use wrapping or saturating arithmetic and nothing
        // here is used as a position or a length.

        /// Hit counts of all 256 buckets. Counts wrap modulo 2^32.
        buckets: [256]u32,
        /// Number of input bytes seen so far. Saturates instead of wrapping.
        count: u64,
        /// The last four input bytes, newest first.
        window: [4]u8,
        /// Running checksum bytes.
        checksum: [checksum_length]u8,
        options: Options,

        pub const Digest = struct {
            checksum: [checksum_length]u8,
            /// Length code.
            lvalue: u8,
            q1ratio: u4,
            q2ratio: u4,
            /// Byte i holds buckets 4i..4i+3, bucket 4i in the low 2 bits.
            body: [code_size]u8,

            /// Writes the digest as upper-case hex into `out` and returns
            /// the written part.
            pub fn toString(self: Digest, out: *[max_string_length]u8, opts: StringOptions) []const u8 {
                var n: usize = 0;
                if (opts.prefix) {
                    out[0] = 'T';
                    out[1] = '1';
                    n = 2;
                }
                // Checksum and length code are written low nibble first.
                for (self.checksum) |c| {
                    out[n] = upper_hex[c & 15];
                    out[n + 1] = upper_hex[c >> 4];
                    n += 2;
                }
                out[n] = upper_hex[self.lvalue & 15];
                out[n + 1] = upper_hex[self.lvalue >> 4];
                out[n + 2] = upper_hex[self.q1ratio];
                out[n + 3] = upper_hex[self.q2ratio];
                n += 4;
                // The body is written from its last byte to its first.
                var i: usize = code_size;
                while (i > 0) {
                    i -= 1;
                    const b = self.body[i];
                    out[n] = upper_hex[b >> 4];
                    out[n + 1] = upper_hex[b & 15];
                    n += 2;
                }
                return out[0..n];
            }

            /// Reads a digest string as written by `toString`. A leading
            /// `T1` is accepted only by the 128-bucket, 1-byte variant.
            /// Text after the digest is ignored unless it starts with a
            /// hex digit.
            pub fn parse(text: []const u8) ParseError!Digest {
                var rest = text;
                if (rest.len >= 2 and rest[0] == 'T' and rest[1] == '1') {
                    if (!parses_prefix) return error.PrefixNotAllowed;
                    rest = rest[2..];
                }
                if (rest.len < hex_length) {
                    for (rest) |ch| {
                        if (hexValue(ch) == null) return error.InvalidCharacter;
                    }
                    return error.InvalidLength;
                }
                var nibbles: [hex_length]u8 = undefined;
                for (&nibbles, rest[0..hex_length]) |*nibble, ch| {
                    nibble.* = hexValue(ch) orelse return error.InvalidCharacter;
                }
                if (rest.len > hex_length and hexValue(rest[hex_length]) != null) {
                    return error.InvalidLength;
                }

                var digest: Digest = undefined;
                var n: usize = 0;
                for (&digest.checksum) |*c| {
                    c.* = nibbles[n] | nibbles[n + 1] << 4;
                    n += 2;
                }
                digest.lvalue = nibbles[n] | nibbles[n + 1] << 4;
                digest.q1ratio = @truncate(nibbles[n + 2]);
                digest.q2ratio = @truncate(nibbles[n + 3]);
                n += 4;
                var i: usize = code_size;
                while (i > 0) {
                    i -= 1;
                    digest.body[i] = nibbles[n] << 4 | nibbles[n + 1];
                    n += 2;
                }
                return digest;
            }
        };

        pub fn init(options: Options) Self {
            return .{
                .buckets = @splat(0),
                .count = 0,
                .window = @splat(0),
                .checksum = @splat(0),
                .options = options,
            };
        }

        /// Processes one input byte `w0` whose four predecessors are
        /// `w1` (newest) to `w4` (oldest).
        inline fn step(
            buckets: *[256]u32,
            checksum: *[checksum_length]u8,
            w0: u8,
            w1: u8,
            w2: u8,
            w3: u8,
            w4: u8,
        ) void {
            checksum[0] = pearson3(pearson_table[0], w0, w1, checksum[0]);
            if (checksum_length == 3) {
                checksum[1] = pearson3(pearson_table[checksum[0]], w0, w1, checksum[1]);
                checksum[2] = pearson3(pearson_table[checksum[1]], w0, w1, checksum[2]);
            }
            buckets[pearson3(pearson_table[2], w0, w1, w2)] +%= 1;
            buckets[pearson3(pearson_table[3], w0, w1, w3)] +%= 1;
            buckets[pearson3(pearson_table[5], w0, w2, w3)] +%= 1;
            buckets[pearson3(pearson_table[7], w0, w2, w4)] +%= 1;
            buckets[pearson3(pearson_table[11], w0, w1, w4)] +%= 1;
            buckets[pearson3(pearson_table[13], w0, w3, w4)] +%= 1;
        }

        /// Adds input. The final digest depends only on the concatenated
        /// input, not on how it is split across calls.
        pub fn update(self: *Self, bytes: []const u8) void {
            var checksum = self.checksum;
            var window = self.window;
            var seen = self.count;

            // The first four bytes of a call take part of their window
            // from the bytes kept from earlier calls.
            const head = @min(bytes.len, 4);
            for (bytes[0..head]) |b| {
                if (seen >= 4) {
                    step(&self.buckets, &checksum, b, window[0], window[1], window[2], window[3]);
                }
                // Shift through a copy: the literal below is built in place.
                const older = window;
                window = .{ b, older[0], older[1], older[2] };
                seen +|= 1;
            }

            // From the fifth byte on the whole window is inside `bytes`.
            var i: usize = head;
            while (i < bytes.len) : (i += 1) {
                step(
                    &self.buckets,
                    &checksum,
                    bytes[i],
                    bytes[i - 1],
                    bytes[i - 2],
                    bytes[i - 3],
                    bytes[i - 4],
                );
            }
            if (bytes.len > 4) {
                const n = bytes.len;
                window = .{ bytes[n - 1], bytes[n - 2], bytes[n - 3], bytes[n - 4] };
                seen +|= n - 4;
            }

            self.checksum = checksum;
            self.window = window;
            self.count = seen;
        }

        /// Sorts ascending. Shell sort: in place, no recursion.
        fn sortCounts(values: *[effective_buckets]u32) void {
            const gaps = [_]usize{ 57, 23, 10, 4, 1 };
            for (gaps) |gap| {
                var i: usize = gap;
                while (i < values.len) : (i += 1) {
                    const v = values[i];
                    var j = i;
                    while (j >= gap and values[j - gap] > v) : (j -= gap) {
                        values[j] = values[j - gap];
                    }
                    values[j] = v;
                }
            }
        }

        /// Finishes the digest and resets the hasher to `init(self.options)`, also on error.
        pub fn final(self: *Self) FinalError!Digest {
            const options = self.options;
            const n = self.count;
            const checksum = self.checksum;
            const counts: [effective_buckets]u32 = self.buckets[0..effective_buckets].*;
            self.* = init(options);

            if (n > max_input_length) return error.InputTooLarge;
            const min_length: u64 = if (options.conservative) 256 else 50;
            if (n < min_length) return error.TooShort;

            var sorted = counts;
            sortCounts(&sorted);
            const q1 = sorted[effective_buckets / 4 - 1];
            const q2 = sorted[effective_buckets / 2 - 1];
            const q3 = sorted[3 * effective_buckets / 4 - 1];
            if (q3 == 0) return error.InsufficientVariation;

            var nonzero: usize = 0;
            for (counts) |c| {
                if (c != 0) nonzero += 1;
            }
            if (nonzero <= effective_buckets / 2) return error.InsufficientVariation;

            var digest: Digest = undefined;
            digest.checksum = checksum;
            digest.lvalue = lengthCode(n);
            // q3 is not zero here, see above.
            digest.q1ratio = @truncate(@as(u64, q1) * 100 / q3);
            digest.q2ratio = @truncate(@as(u64, q2) * 100 / q3);
            for (&digest.body, 0..) |*out, i| {
                var packed_codes: u8 = 0;
                for (counts[4 * i ..][0..4], 0..) |c, cell| {
                    const code: u8 = if (c > q3) 3 else if (c > q2) 2 else if (c > q1) 1 else 0;
                    packed_codes |= code << @as(u3, @truncate(2 * cell));
                }
                out.* = packed_codes;
            }
            return digest;
        }

        /// Digest of `bytes` hashed in one go.
        pub fn hash(bytes: []const u8, options: Options) FinalError!Digest {
            var hasher = init(options);
            hasher.update(bytes);
            return hasher.final();
        }

        /// Distance of two digests. 0 means the digests are equal.
        pub fn diff(a: Digest, b: Digest, opts: DiffOptions) u32 {
            var total: u32 = 0;
            if (opts.include_length) {
                const d = modDiff(a.lvalue, b.lvalue, 256);
                total += if (d <= 1) d else 12 * d;
            }
            const ratios = [2][2]u32{
                .{ a.q1ratio, b.q1ratio },
                .{ a.q2ratio, b.q2ratio },
            };
            for (ratios) |pair| {
                const d = modDiff(pair[0], pair[1], 16);
                total += if (d <= 1) d else 12 * (d - 1);
            }
            var checksum_differs = false;
            for (a.checksum, b.checksum) |x, y| {
                if (x != y) checksum_differs = true;
            }
            if (checksum_differs) total += 1;
            for (a.body, b.body) |x, y| {
                total += nibble_distance[(x & 0xF0) | (y >> 4)];
                total += nibble_distance[(x & 0x0F) << 4 | (y & 0x0F)];
            }
            return total;
        }

        /// Distance of two digest strings. The first parse error wins.
        pub fn diffStrings(a: []const u8, b: []const u8, opts: DiffOptions) ParseError!u32 {
            const digest_a = try Digest.parse(a);
            const digest_b = try Digest.parse(b);
            return diff(digest_a, digest_b, opts);
        }
    };
}

/// The standard digest: 128 buckets, 1-byte checksum.
pub const T1 = Tlsh(.{});

// Tests.
//
// Every expected digest and distance below was produced by the TLSH 5.0.2
// reference programs (the four `tlsh_unittest` builds and py-tlsh 5.0.0).
// None comes from this implementation.

const testing = std.testing;

const all_variants = .{
    Tlsh(.{}),
    Tlsh(.{ .checksum = .three }),
    Tlsh(.{ .buckets = .b256 }),
    Tlsh(.{ .buckets = .b256, .checksum = .three }),
};

const Vector = struct {
    kind: enum { random, alphabet, periodic, sparse, literal },
    seed: u32,
    len: u32,
    param: u32,
    /// Per variant: the digest, or the name of the error.
    digests: [4][]const u8,
    /// Result with `conservative` set: the same, or TooShort everywhere.
    conservative: enum { same, too_short },
};
const DistanceVector = struct { a: usize, b: usize, expected: [4][2]u32 };
const StringDistanceVector = struct { a: []const u8, b: []const u8, diff: u32, diffxlen: u32 };

/// Byte generator for the generated test inputs.
const Lcg = struct {
    x: u32,
    fn next(self: *Lcg) u8 {
        self.x = self.x *% 1664525 +% 1013904223;
        return @truncate(self.x >> 24);
    }
};

// The test runner runs tests one after another, so they can share this.
var test_buffer: [70000]u8 = undefined;

fn generate(v: Vector) []const u8 {
    const out = test_buffer[0..v.len];
    var lcg: Lcg = .{ .x = v.seed };
    const param: u8 = @truncate(v.param);
    switch (v.kind) {
        .random => for (out) |*b| {
            b.* = lcg.next();
        },
        .alphabet => for (out) |*b| {
            b.* = 'a' + lcg.next() % param;
        },
        .periodic => for (out, 0..) |*b, i| {
            b.* = if (i < v.param) lcg.next() else out[i - v.param];
        },
        .sparse => for (out) |*b| {
            const value = lcg.next();
            const gate = lcg.next();
            b.* = if (gate % param == 0) value else 0;
        },
        .literal => @memcpy(out, literal_inputs[v.param]),
    }
    return out;
}

/// Compares a result with an oracle result: a digest string with prefix,
/// or the name of the error.
fn expectResult(comptime T: type, expected: []const u8, actual: FinalError!T.Digest) !void {
    var buf: [T.max_string_length]u8 = undefined;
    const text: []const u8 = if (actual) |digest| digest.toString(&buf, .{}) else |err| @errorName(err);
    try testing.expectEqualStrings(expected, text);
}

/// Parses an oracle digest string. Only 128/1 reads the prefix back.
fn parseOracle(comptime T: type, text: []const u8) !T.Digest {
    try testing.expect(std.mem.startsWith(u8, text, "T1"));
    return T.Digest.parse(if (T.parses_prefix) text else text[2..]);
}

const fox = "The quick brown fox jumps over the lazy dog";
const lorem_sentence = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";

fn fillVa(out: *[1000]u8) void {
    for (out, 0..) |*b, i| {
        b.* = @truncate(i * i * 7 + (i >> 3) + ((i * 13) >> 5));
    }
}

fn fillVb(out: *[1000]u8) void {
    fillVa(out);
    @memcpy(out[100..110], "0123456789");
    out[700] ^= 0x55;
}

fn fillLorem(out: *[lorem_sentence.len * 20]u8) void {
    for (out, 0..) |*b, i| b.* = lorem_sentence[i % lorem_sentence.len];
}

fn fillRamp(out: *[1024]u8) void {
    for (out, 0..) |*b, i| b.* = @truncate(i);
}

test "variant constants" {
    const expected_hex = [4]usize{ 70, 74, 134, 138 };
    inline for (all_variants, expected_hex, 0..) |T, hex, vi| {
        try testing.expectEqual(hex, T.hex_length);
        try testing.expectEqual(hex + 2, T.max_string_length);
        try testing.expectEqual(T.effective_buckets / 4, T.code_size);
        try testing.expectEqual(2 * (T.checksum_length + 2 + T.code_size), T.hex_length);
        try testing.expectEqual(vi == 0, T.parses_prefix);
        try testing.expect(@sizeOf(T) <= 4096);
    }
    try testing.expectEqual(128, T1.effective_buckets);
    try testing.expectEqual(1, T1.checksum_length);
    try testing.expectEqual(3, all_variants[3].checksum_length);
    try testing.expectEqual(256, all_variants[3].effective_buckets);
    try testing.expectEqual(@as(u64, 4_224_281_216), max_input_length);
}

test "hasher state holds integers only" {
    inline for (all_variants) |T| {
        const info = @typeInfo(T).@"struct";
        var has_options = false;
        inline for (info.field_names, info.field_types) |name, Field| {
            if (comptime std.mem.eql(u8, name, "options")) {
                try testing.expect(Field == Options);
                has_options = true;
            } else switch (@typeInfo(Field)) {
                .int => {},
                .array => |array| try testing.expect(@typeInfo(array.child) == .int),
                else => return error.UnexpectedFieldType,
            }
        }
        try testing.expect(has_options);
    }
}

test "known digests, 128 buckets and 1-byte checksum" {
    const T = T1;
    var va: [1000]u8 = undefined;
    fillVa(&va);
    var vb: [1000]u8 = undefined;
    fillVb(&vb);
    var ramp: [1024]u8 = undefined;
    fillRamp(&ramp);
    var lorem: [lorem_sentence.len * 20]u8 = undefined;
    fillLorem(&lorem);
    const zeros: [1000]u8 = @splat(0);
    const fox2 = fox ++ fox;
    var ab: [300]u8 = undefined;
    for (&ab, 0..) |*b, i| b.* = if (i % 2 == 0) 'a' else 'b';

    const cases = [_]struct { input: []const u8, digest: []const u8, conservative: []const u8 }{
        .{
            .input = fox2,
            .digest = "T1CEA0024A21181298658A1884438D95B2C2CCC5147121141164306002180C1219CD8451",
            .conservative = "TooShort",
        },
        .{
            .input = fox2[0..50],
            .digest = "T1AC90024A21181298658A1884438D95B2C2CCC51471211411A4306002280C2219CD8451",
            .conservative = "TooShort",
        },
        .{ .input = fox2[0..49], .digest = "TooShort", .conservative = "TooShort" },
        .{
            .input = &va,
            .digest = "T19D11C81A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06",
            .conservative = "T19D11C81A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06",
        },
        .{
            .input = &vb,
            .digest = "T11811A52A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06",
            .conservative = "T11811A52A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06",
        },
        .{
            .input = &ramp,
            .digest = "T16D119524E6514D7D1F175ADCD04E44DF554FCDE302C5002517F186D1C510294440ED1D",
            .conservative = "T16D119524E6514D7D1F175ADCD04E44DF554FCDE302C5002517F186D1C510294440ED1D",
        },
        .{
            .input = &lorem,
            .digest = "T177210259415F0BD99A56903F3ADB842FE50825242B2590961CF690599152224C051556",
            .conservative = "T177210259415F0BD99A56903F3ADB842FE50825242B2590961CF690599152224C051556",
        },
        .{ .input = &zeros, .digest = "InsufficientVariation", .conservative = "InsufficientVariation" },
        .{ .input = &ab, .digest = "InsufficientVariation", .conservative = "InsufficientVariation" },
    };
    for (cases) |case| {
        try expectResult(T, case.digest, T.hash(case.input, .{}));
        try expectResult(T, case.conservative, T.hash(case.input, .{ .conservative = true }));
    }
}

test "known digests, other variants" {
    var va: [1000]u8 = undefined;
    fillVa(&va);
    var vb: [1000]u8 = undefined;
    fillVb(&vb);
    const fox2 = fox ++ fox;
    const expected = [3][3][]const u8{
        .{
            "T1CE3E76A0024A21181298658A1884438D95B2C2CCC5147121141164306002180C1219CD8451",
            "T19DC04411C81A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06",
            "T1183E7211A52A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06",
        },
        .{
            "T1CEA002344115305F44D0D50CDEF700C144D0D4545516D155D4404031C5E7D7D53430754F311C13D875CF1CC443CDD5F3C3CCC51471311411743070031C0C131DCDC451",
            "T19D11C8C5835CF04297DB84BFADFC29D20E3CC2D4331C9567537DC4695055235C95C01A1A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06",
            "T11811A5C9435CF04197DA84BFAEBC29D20A3C8694331895775379C0695051234C95D01A2A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06",
        },
        .{
            "T1CE3E76A002344115305F44D0D50CDEF700C144D0D4545516D155D4404031C5E7D7D53430754F311C13D875CF1CC443CDD5F3C3CCC51471311411743070031C0C131DCDC451",
            "T19DC04411C8C5835CF04297DB84BFADFC29D20E3CC2D4331C9567537DC4695055235C95C01A1A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06",
            "T1183E7211A5C9435CF04197DA84BFAEBC29D20A3C8694331895775379C0695051234C95D01A2A18C286D4564523B269B0BC334ACD765B2D807DA93D92996C2E893FC2316E06",
        },
    };
    inline for (.{ all_variants[1], all_variants[2], all_variants[3] }, expected) |T, row| {
        try expectResult(T, row[0], T.hash(fox2, .{}));
        try expectResult(T, row[1], T.hash(&va, .{}));
        try expectResult(T, row[2], T.hash(&vb, .{}));
        try expectResult(T, "TooShort", T.hash(fox2, .{ .conservative = true }));
        try expectResult(T, row[1], T.hash(&va, .{ .conservative = true }));
    }
}

test "known distances" {
    var va: [1000]u8 = undefined;
    fillVa(&va);
    var vb: [1000]u8 = undefined;
    fillVb(&vb);
    var ramp: [1024]u8 = undefined;
    fillRamp(&ramp);
    var lorem: [lorem_sentence.len * 20]u8 = undefined;
    fillLorem(&lorem);
    const fox2 = fox ++ fox;

    // Pairs of (first, second, with length, without length); one table for
    // both 128-bucket variants and one for both 256-bucket variants.
    const Pair = struct { a: []const u8, b: []const u8, d128: [2]u32, d256: [2]u32 };
    const pairs = [_]Pair{
        .{ .a = &va, .b = &vb, .d128 = .{ 53, 53 }, .d256 = .{ 70, 70 } },
        .{ .a = fox2, .b = fox2[0..50], .d128 = .{ 5, 4 }, .d256 = .{ 50, 49 } },
        .{ .a = &va, .b = &lorem, .d128 = .{ 287, 286 }, .d256 = .{ 465, 464 } },
        .{ .a = &ramp, .b = &va, .d128 = .{ 262, 262 }, .d256 = .{ 468, 468 } },
        .{ .a = fox2, .b = &lorem, .d128 = .{ 258, 162 }, .d256 = .{ 445, 349 } },
    };
    inline for (all_variants) |T| {
        for (pairs) |pair| {
            const expected = if (T.effective_buckets == 128) pair.d128 else pair.d256;
            const a = try T.hash(pair.a, .{});
            const b = try T.hash(pair.b, .{});
            try testing.expectEqual(expected[0], T.diff(a, b, .{}));
            try testing.expectEqual(expected[1], T.diff(a, b, .{ .include_length = false }));
            try testing.expectEqual(expected[0], T.diff(b, a, .{}));
            try testing.expectEqual(expected[1], T.diff(b, a, .{ .include_length = false }));
            try testing.expectEqual(0, T.diff(a, a, .{}));
        }
    }
}

test "digest fields" {
    // py-tlsh reports these parts for `va`.
    var va: [1000]u8 = undefined;
    fillVa(&va);
    const d = try T1.hash(&va, .{});
    try testing.expectEqual(217, d.checksum[0]);
    try testing.expectEqual(17, d.lvalue);
    try testing.expectEqual(12, d.q1ratio);
    try testing.expectEqual(8, d.q2ratio);
    // py-tlsh `bucket_value(i)` is the code of bucket 127 - i.
    const first_values = [8]u8{ 0, 1, 2, 2, 0, 1, 3, 1 };
    for (first_values, 0..) |value, i| {
        const bucket = 127 - i;
        try testing.expectEqual(value, (d.body[bucket / 4] >> @as(u3, @truncate(2 * (bucket % 4)))) & 3);
    }

    const v = oracle_vectors[12];
    const e = try T1.hash(generate(v), .{});
    try testing.expectEqual(oracle_fields.checksum, e.checksum[0]);
    try testing.expectEqual(oracle_fields.lvalue, e.lvalue);
    try testing.expectEqual(oracle_fields.q1ratio, e.q1ratio);
    try testing.expectEqual(oracle_fields.q2ratio, e.q2ratio);
    for (oracle_fields.bucket_values, 0..) |value, i| {
        const bucket = 127 - i;
        try testing.expectEqual(value, (e.body[bucket / 4] >> @as(u3, @truncate(2 * (bucket % 4)))) & 3);
    }
}

test "oracle vectors: digests, default and conservative" {
    for (oracle_vectors) |v| {
        const input = generate(v);
        inline for (all_variants, 0..) |T, vi| {
            try expectResult(T, v.digests[vi], T.hash(input, .{}));
            const conservative = switch (v.conservative) {
                .same => v.digests[vi],
                .too_short => "TooShort",
            };
            try expectResult(T, conservative, T.hash(input, .{ .conservative = true }));
        }
    }
}

test "oracle vectors: the digest does not depend on how the input is split" {
    var lcg: Lcg = .{ .x = 20261118 };
    for (oracle_vectors) |v| {
        const input = generate(v);
        inline for (all_variants, 0..) |T, vi| {
            const expected = v.digests[vi];
            var h = T.init(.{});

            // One byte at a time.
            for (input) |*b| h.update(b[0..1]);
            try expectResult(T, expected, h.final());

            // One cut, at every offset for short inputs and at the first
            // offsets otherwise, with empty pieces mixed in.
            const cut_limit = if (input.len <= 300) input.len else 12;
            var cut: usize = 0;
            while (cut <= cut_limit) : (cut += 1) {
                h.update(input[0..cut]);
                h.update(input[cut..cut]);
                h.update(input[cut..]);
                try expectResult(T, expected, h.final());
            }

            // Random pieces; the first ones are 0 to 4 bytes long.
            var round: usize = 0;
            while (round < 4) : (round += 1) {
                var pos: usize = 0;
                var piece: usize = 0;
                while (pos < input.len) : (piece += 1) {
                    const want: usize = if (piece < 6)
                        lcg.next() % 5
                    else if (round % 2 == 0)
                        lcg.next() % 9
                    else
                        @as(usize, lcg.next()) * 16 + lcg.next();
                    const len = @min(want, input.len - pos);
                    h.update(input[pos..][0..len]);
                    pos += len;
                }
                try expectResult(T, expected, h.final());
            }
        }
    }
}

test "oracle vectors: distances" {
    for (oracle_distances) |pair| {
        const va = oracle_vectors[pair.a];
        const vb = oracle_vectors[pair.b];
        inline for (all_variants, 0..) |T, vi| {
            const a = try parseOracle(T, va.digests[vi]);
            const b = try parseOracle(T, vb.digests[vi]);
            try testing.expectEqual(pair.expected[vi][0], T.diff(a, b, .{}));
            try testing.expectEqual(pair.expected[vi][1], T.diff(a, b, .{ .include_length = false }));
            try testing.expectEqual(pair.expected[vi][0], T.diff(b, a, .{}));
            try testing.expectEqual(pair.expected[vi][1], T.diff(b, a, .{ .include_length = false }));
            // The same through the string interface, without prefix.
            const sa = va.digests[vi][2..];
            const sb = vb.digests[vi][2..];
            try testing.expectEqual(pair.expected[vi][0], try T.diffStrings(sa, sb, .{}));
            try testing.expectEqual(pair.expected[vi][1], try T.diffStrings(sb, sa, .{ .include_length = false }));
        }
    }
}

test "string distances as py-tlsh computes them" {
    for (oracle_string_distances) |case| {
        try testing.expectEqual(case.diff, try T1.diffStrings(case.a, case.b, .{}));
        try testing.expectEqual(case.diffxlen, try T1.diffStrings(case.a, case.b, .{ .include_length = false }));
        try testing.expectEqual(case.diff, try T1.diffStrings(case.b, case.a, .{}));
        try testing.expectEqual(case.diffxlen, try T1.diffStrings(case.b, case.a, .{ .include_length = false }));
    }
}

test "strings py-tlsh refuses are refused" {
    const valid = oracle_vectors[12].digests[0];
    for (oracle_refused_strings) |text| {
        if (T1.Digest.parse(text)) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
        if (T1.diffStrings(text, valid, .{})) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
        if (T1.diffStrings(valid, text, .{})) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "toString and parse round trip" {
    for (oracle_vectors) |v| {
        inline for (all_variants, 0..) |T, vi| {
            const text = v.digests[vi];
            if (std.mem.startsWith(u8, text, "T1")) {
                const bare = text[2..];
                try testing.expectEqual(T.hex_length, bare.len);
                const digest = try T.Digest.parse(bare);
                var buf: [T.max_string_length]u8 = undefined;
                try testing.expectEqualStrings(text, digest.toString(&buf, .{}));
                try testing.expectEqualStrings(text, digest.toString(&buf, .{ .prefix = true }));
                try testing.expectEqualStrings(bare, digest.toString(&buf, .{ .prefix = false }));
                // Parsing what was hashed gives the same value back.
                const hashed = try T.hash(generate(v), .{});
                try testing.expectEqualDeep(hashed, digest);
                if (T.parses_prefix) {
                    try testing.expectEqualDeep(hashed, try T.Digest.parse(text));
                } else {
                    try testing.expectError(error.PrefixNotAllowed, T.Digest.parse(text));
                }
            }
        }
    }
}

test "parse rules" {
    const text = "T19D11C81A1DC246C45745237159B0BC334ACD766B2DC07C983D92996C2E857FC2316E06";
    const bare = text[2..];
    const D = T1.Digest;
    const digest = try D.parse(text);
    try testing.expectEqual(217, digest.checksum[0]);
    try testing.expectEqual(17, digest.lvalue);
    try testing.expectEqual(12, digest.q1ratio);
    try testing.expectEqual(8, digest.q2ratio);
    try testing.expectEqual(0x1A, digest.body[31]);
    try testing.expectEqual(0x06, digest.body[0]);
    try testing.expectEqualDeep(digest, try D.parse(bare));

    // Hex digits may be lower case; the prefix may not.
    var lower: [72]u8 = undefined;
    for (&lower, text) |*out, ch| out.* = std.ascii.toLower(ch);
    try testing.expectEqualDeep(digest, try D.parse(lower[2..]));
    try testing.expectError(error.InvalidCharacter, D.parse(&lower));
    var mixed: [72]u8 = undefined;
    @memcpy(&mixed, text);
    @memcpy(mixed[2..4], lower[2..4]);
    @memcpy(mixed[40..50], lower[40..50]);
    try testing.expectEqualDeep(digest, try D.parse(&mixed));

    // Too short: InvalidCharacter if a non-hex character is present.
    try testing.expectError(error.InvalidLength, D.parse(""));
    try testing.expectError(error.InvalidLength, D.parse("T1"));
    try testing.expectError(error.InvalidLength, D.parse(bare[0..69]));
    try testing.expectError(error.InvalidLength, D.parse(text[0..71]));
    try testing.expectError(error.InvalidCharacter, D.parse("TNULL"));
    try testing.expectError(error.InvalidCharacter, D.parse("T"));
    try testing.expectError(error.InvalidCharacter, D.parse("T1" ++ bare[0..10] ++ "?"));
    try testing.expectError(error.InvalidCharacter, D.parse("T1T1"));

    // A bad character inside the digest.
    var bad: [72]u8 = undefined;
    for ([_]usize{ 2, 30, 71 }) |at| {
        for ([_]u8{ 'G', 'g', ' ', '/', ':', '@', '`', 0, 0xFF }) |ch| {
            @memcpy(&bad, text);
            bad[at] = ch;
            try testing.expectError(error.InvalidCharacter, D.parse(&bad));
            try testing.expectError(error.InvalidCharacter, D.parse(bad[2..]));
        }
    }
    // A second prefix is not skipped.
    try testing.expectError(error.InvalidCharacter, D.parse("T1" ++ text));
    try testing.expectError(error.InvalidCharacter, D.parse(" " ++ text));

    // After the digest: a hex digit is an error, anything else is ignored.
    try testing.expectError(error.InvalidLength, D.parse(text ++ "0"));
    try testing.expectError(error.InvalidLength, D.parse(text ++ "f"));
    try testing.expectError(error.InvalidLength, D.parse(bare ++ "A"));
    try testing.expectError(error.InvalidLength, D.parse(bare ++ "00"));
    try testing.expectEqualDeep(digest, try D.parse(text ++ "G"));
    try testing.expectEqualDeep(digest, try D.parse(text ++ " 0123"));
    try testing.expectEqualDeep(digest, try D.parse(bare ++ "\n"));
    try testing.expectEqualDeep(digest, try D.parse(bare ++ "\x00"));
    try testing.expectEqualDeep(digest, try D.parse(text ++ "\tfile name"));

    // The other variants refuse the prefix and follow the same rules.
    inline for (.{ all_variants[1], all_variants[2], all_variants[3] }) |T| {
        const zeros: [T.hex_length + 3]u8 = @splat('0');
        const body = zeros[0..T.hex_length];
        const parsed = try T.Digest.parse(body);
        try testing.expectEqual(0, parsed.lvalue);
        var buf: [T.max_string_length]u8 = undefined;
        try testing.expectEqualStrings(body, parsed.toString(&buf, .{ .prefix = false }));
        try testing.expectEqualStrings("T1", parsed.toString(&buf, .{})[0..2]);
        try testing.expectError(error.PrefixNotAllowed, T.Digest.parse("T1"));
        try testing.expectError(error.PrefixNotAllowed, T.Digest.parse("T1" ++ body));
        try testing.expectError(error.PrefixNotAllowed, T.Digest.parse("T1?"));
        try testing.expectError(error.PrefixNotAllowed, T.diffStrings("T1" ++ body, body, .{}));
        try testing.expectError(error.PrefixNotAllowed, T.diffStrings(body, "T1" ++ body, .{}));
        try testing.expectError(error.InvalidLength, T.Digest.parse(body[0 .. T.hex_length - 1]));
        try testing.expectError(error.InvalidLength, T.Digest.parse(&zeros));
        try testing.expectError(error.InvalidCharacter, T.Digest.parse("t1" ++ body));
        try testing.expectError(error.InvalidCharacter, T.Digest.parse("x"));
        try testing.expectEqualDeep(parsed, try T.Digest.parse(body ++ "."));
        try testing.expectEqual(0, try T.diffStrings(body, body ++ " ", .{}));
    }

    // diffStrings reports the error of the first argument first.
    try testing.expectError(error.InvalidCharacter, T1.diffStrings("x", "", .{}));
    try testing.expectError(error.InvalidLength, T1.diffStrings("", "x", .{}));
    try testing.expectError(error.InvalidCharacter, T1.diffStrings(text, "x", .{}));
}

test "length codes at every table boundary" {
    // Real inputs for the short boundaries; the oracle runs behind these
    // are in the vector table (lengths 50, 57, 58, 86, 87, 129, 130, ...).
    const short = [_][2]u32{
        .{ 50, 9 },    .{ 57, 9 },    .{ 58, 10 },    .{ 86, 10 },  .{ 87, 11 },
        .{ 129, 11 },  .{ 130, 12 },  .{ 255, 13 },   .{ 256, 13 }, .{ 257, 13 },
        .{ 1000, 17 }, .{ 4097, 24 }, .{ 65536, 53 },
    };
    for (short) |entry| {
        for (oracle_vectors) |v| {
            if (v.kind == .random and v.len == entry[0]) {
                // The length code is the second byte of the 128/1 digest,
                // written low nibble first.
                const text = v.digests[0];
                const high = hexValue(text[5]) orelse return error.TestUnexpectedResult;
                const low = hexValue(text[4]) orelse return error.TestUnexpectedResult;
                const from_oracle = high * 16 + low;
                try testing.expectEqual(entry[1], from_oracle);
                const d = try T1.hash(generate(v), .{});
                try testing.expectEqual(entry[1], d.lvalue);
            }
        }
    }

    // Every boundary of the table, by setting the byte count of a hasher
    // that already holds a valid input.
    const input = generate(oracle_vectors[12]);
    inline for (all_variants) |T| {
        for (length_bounds, 0..) |bound, code| {
            if (bound < 50) continue;
            var h = T.init(.{});
            h.update(input);
            h.count = bound;
            try testing.expectEqual(code, (try h.final()).lvalue);

            h.update(input);
            h.count = @as(u64, bound) - 1;
            const below = try h.final();
            const previous_bound = length_bounds[code - 1];
            try testing.expectEqual(if (bound - 1 > previous_bound) code else code - 1, below.lvalue);

            h.update(input);
            h.count = @as(u64, bound) + 1;
            if (code + 1 < length_bounds.len) {
                try testing.expectEqual(code + 1, (try h.final()).lvalue);
            } else {
                try testing.expectError(error.InputTooLarge, h.final());
            }
        }
    }
}

test "long inputs" {
    const input = generate(oracle_vectors[12]);
    inline for (all_variants) |T| {
        var h = T.init(.{});

        // Exactly at the limit: the last length code.
        h.update(input);
        h.count = max_input_length - input.len;
        h.update(input);
        try testing.expectEqual(max_input_length, h.count);
        try testing.expectEqual(169, (try h.final()).lvalue);

        // One byte more.
        h.update(input);
        h.count = max_input_length;
        h.update("x");
        try testing.expectError(error.InputTooLarge, h.final());
        try testing.expectEqual(0, h.count);

        // The count is 64 bits wide: 2^32 + 1000 bytes is not 1000 bytes.
        h.update(input);
        h.count = (1 << 32) + 1000 - 1;
        h.update("x");
        try testing.expectError(error.InputTooLarge, h.final());

        // The count saturates and never wraps back into the valid range.
        h.update(input);
        h.count = std.math.maxInt(u64) - 3;
        h.update(input);
        try testing.expectEqual(std.math.maxInt(u64), h.count);
        h.update("x");
        h.update(input[0..4]);
        try testing.expectEqual(std.math.maxInt(u64), h.count);
        try testing.expectError(error.InputTooLarge, h.final());

        // InputTooLarge is reported before every other error.
        h.count = max_input_length + 1;
        try testing.expectError(error.InputTooLarge, h.final());
    }
}

test "errors come in the documented order" {
    const zeros: [1000]u8 = @splat(0);
    inline for (all_variants) |T| {
        // Too short wins over insufficient variation.
        try testing.expectError(error.TooShort, T.hash("", .{}));
        try testing.expectError(error.TooShort, T.hash(zeros[0..49], .{}));
        try testing.expectError(error.InsufficientVariation, T.hash(zeros[0..50], .{}));
        try testing.expectError(error.TooShort, T.hash(zeros[0..255], .{ .conservative = true }));
        try testing.expectError(error.InsufficientVariation, T.hash(zeros[0..256], .{ .conservative = true }));
    }
}

test "final resets the hasher" {
    const input = generate(oracle_vectors[12]);
    inline for (all_variants, 0..) |T, vi| {
        inline for (.{ false, true }) |conservative| {
            const options: Options = .{ .conservative = conservative };
            var h = T.init(options);
            try testing.expectEqualDeep(T.init(options), h);

            // After a digest.
            h.update(input);
            try expectResult(T, oracle_vectors[12].digests[vi], h.final());
            try testing.expectEqualDeep(T.init(options), h);

            // After each error.
            h.update(input[0..40]);
            try testing.expectError(error.TooShort, h.final());
            try testing.expectEqualDeep(T.init(options), h);
            const zeros: [300]u8 = @splat(0);
            h.update(&zeros);
            try testing.expectError(error.InsufficientVariation, h.final());
            try testing.expectEqualDeep(T.init(options), h);
            h.update(input);
            h.count = max_input_length + 1;
            try testing.expectError(error.InputTooLarge, h.final());
            try testing.expectEqualDeep(T.init(options), h);

            // The hasher is usable again and keeps its options.
            h.update(input);
            try expectResult(T, oracle_vectors[12].digests[vi], h.final());
            h.update(input[0..255]);
            if (conservative) {
                try testing.expectError(error.TooShort, h.final());
            } else {
                _ = try h.final();
            }
            try testing.expectEqual(conservative, h.options.conservative);
        }
    }
}

test "bucket counters wrap modulo 2^32" {
    const input = generate(oracle_vectors[12]);
    inline for (all_variants) |T| {
        var plain = T.init(.{});
        plain.update(input);
        var wrapped = T.init(.{});
        wrapped.buckets = @splat(std.math.maxInt(u32));
        wrapped.update(input);
        for (plain.buckets, wrapped.buckets) |p, w| {
            try testing.expectEqual(p -% 1, w);
        }
        _ = wrapped.final() catch {};
    }
}

test "hasher state accepts any bit pattern" {
    // The WebAssembly layer copies the hasher in from host memory, so every
    // byte of it except `options` can hold anything. This must not trip a
    // safety check in `update` or `final`, and `final` must still reset.
    var prng = std.Random.DefaultPrng.init(0x7153_4821);
    const random = prng.random();
    var data: [600]u8 = undefined;
    inline for (all_variants) |T| {
        var round: usize = 0;
        while (round < 3000) : (round += 1) {
            var h: T = undefined;
            const raw = std.mem.asBytes(&h);
            switch (round % 4) {
                0 => random.bytes(raw),
                1 => @memset(raw, 0xFF),
                2 => @memset(raw, 0x80),
                else => {
                    random.bytes(raw);
                    // Byte counts near the limits.
                    h.count = switch (random.uintLessThan(u8, 5)) {
                        0 => max_input_length - random.uintLessThan(u64, 700),
                        1 => std.math.maxInt(u64) - random.uintLessThan(u64, 700),
                        2 => random.uintLessThan(u64, 700),
                        3 => (1 << 32) - random.uintLessThan(u64, 700),
                        else => random.int(u64),
                    };
                },
            }
            const options: Options = .{ .conservative = random.boolean() };
            h.options = options;

            random.bytes(&data);
            var pos: usize = 0;
            while (pos < data.len) {
                const len = @min(random.uintLessThan(usize, 40), data.len - pos);
                h.update(data[pos..][0..len]);
                pos += len;
            }
            if (h.final()) |digest| {
                var buf: [T.max_string_length]u8 = undefined;
                const text = digest.toString(&buf, .{ .prefix = false });
                try testing.expectEqualDeep(digest, try T.Digest.parse(text));
                try testing.expectEqual(0, T.diff(digest, digest, .{}));
            } else |_| {}
            try testing.expectEqualDeep(T.init(options), h);
        }
    }
}

test "distance terms" {
    // Distance rules, on digests built field by field. The
    // same cases are checked against py-tlsh in the generated table.
    const D = T1.Digest;
    const base: D = .{ .checksum = .{0x42}, .lvalue = 40, .q1ratio = 3, .q2ratio = 9, .body = @splat(0x1B) };
    try testing.expectEqual(0, T1.diff(base, base, .{}));

    // Length codes: a circle of 256 values; 0 and 1 count as they are.
    const length_cases = [_][3]u32{
        .{ 40, 41, 1 },    .{ 40, 42, 24 },   .{ 40, 39, 1 },   .{ 0, 255, 1 },
        .{ 0, 128, 1536 }, .{ 0, 129, 1524 }, .{ 250, 5, 132 }, .{ 9, 169, 1152 },
    };
    for (length_cases) |case| {
        var a = base;
        var b = base;
        a.lvalue = @truncate(case[0]);
        b.lvalue = @truncate(case[1]);
        try testing.expectEqual(case[2], T1.diff(a, b, .{}));
        try testing.expectEqual(case[2], T1.diff(b, a, .{}));
        try testing.expectEqual(0, T1.diff(a, b, .{ .include_length = false }));
    }

    // Ratios: a circle of 16 values; beyond 1 the cost is 12 * (d - 1).
    const ratio_cases = [_][3]u32{
        .{ 3, 4, 1 },  .{ 3, 5, 12 },  .{ 3, 11, 84 }, .{ 3, 12, 72 },
        .{ 0, 15, 1 }, .{ 0, 14, 12 }, .{ 0, 8, 84 },  .{ 15, 7, 84 },
    };
    for (ratio_cases) |case| {
        var a = base;
        var b = base;
        a.q1ratio = @truncate(case[0]);
        b.q1ratio = @truncate(case[1]);
        try testing.expectEqual(case[2], T1.diff(a, b, .{}));
        a = base;
        b = base;
        a.q2ratio = @truncate(case[1]);
        b.q2ratio = @truncate(case[0]);
        try testing.expectEqual(case[2], T1.diff(a, b, .{ .include_length = false }));
    }

    // Checksum: 1 if any byte differs.
    var other = base;
    other.checksum[0] = 0x43;
    try testing.expectEqual(1, T1.diff(base, other, .{}));
    const T3 = all_variants[3];
    const base3: T3.Digest = .{ .checksum = .{ 1, 2, 3 }, .lvalue = 40, .q1ratio = 3, .q2ratio = 9, .body = @splat(0) };
    inline for (0..3) |k| {
        var changed = base3;
        changed.checksum[k] ^= 0x80;
        try testing.expectEqual(1, T3.diff(base3, changed, .{}));
    }
    var all_changed = base3;
    all_changed.checksum = .{ 9, 9, 9 };
    try testing.expectEqual(1, T3.diff(base3, all_changed, .{}));

    // Body: each 2-bit cell costs 0, 1, 2 or 6 for a difference of 0..3.
    const cost = [4]u32{ 0, 1, 2, 6 };
    var x: u32 = 0;
    while (x < 256) : (x += 1) {
        var y: u32 = 0;
        while (y < 256) : (y += 1) {
            var expected: u32 = 0;
            for (0..4) |cell| {
                const cx = (x >> @as(u5, @truncate(2 * cell))) & 3;
                const cy = (y >> @as(u5, @truncate(2 * cell))) & 3;
                expected += cost[if (cx > cy) cx - cy else cy - cx];
            }
            var a = base;
            var b = base;
            a.body[x % 32] = @truncate(x);
            b.body[x % 32] = @truncate(y);
            try testing.expectEqual(expected, T1.diff(a, b, .{}));
        }
    }
    // Largest possible distance of each variant.
    inline for (all_variants) |T| {
        var lo: T.Digest = .{ .checksum = @splat(0), .lvalue = 0, .q1ratio = 0, .q2ratio = 0, .body = @splat(0) };
        var hi: T.Digest = .{ .checksum = @splat(1), .lvalue = 128, .q1ratio = 8, .q2ratio = 8, .body = @splat(0xFF) };
        _ = &lo;
        _ = &hi;
        const body_max: u32 = @truncate(6 * T.effective_buckets);
        try testing.expectEqual(1536 + 84 + 84 + 1 + body_max, T.diff(lo, hi, .{}));
        try testing.expectEqual(84 + 84 + 1 + body_max, T.diff(hi, lo, .{ .include_length = false }));
    }
}

// Test vectors generated from the TLSH 5.0.2 reference programs.
const literal_inputs = [_][]const u8{
    "\x72\x18\xd0\x01\xdf\xb9\xb5\x0a\x41\x98\xb6\xdb\x54\x59\x25\x84\x18\xea\x6f\x19\x1f\x9e\xe3\x89\x25\x62\xc2\x2f\xd7\xc3\x57\x74\x60\x09\xf0\x66\xef\x34\x01\xde\x7b\x5d\xf3\xdb\x16\x4c\xe3\xa8\xa1\xf4",
    "\x82\x86\x82\xe5\x82\xe5\x86\xe5\xe5\x82\xe5\x82\x86\x82\x86\x82\xe5\xe5\x86\x86\x82\x82\xe5\xe5\xe5\x82\x82\x82\x82\xe5\xe5\x86\x86\xe5\xe5\xe5\x86\xe5\xe5\xe5\x86\x82\x82\x82\x82\x82\x82\x82\x82\xe5\x86\x82\x86\xe5\xe5\x86\xe5\x86\xe5\x82\x86\x86\x86\x86\x86\xe5\x86\xe5\x82\x86\x86\x82\xe5\xe5\x86\x86\xe5\x86\x82\x86\x82\x82\xe5\x82\x82\xe5\xe5\xe5\x82\x86\x82\x86\x86\x4c\xca\x33\x92\xd4\x6b\xcc\xb6\xeb\x47",
    "\x82\x86\x82\xe5\x82\xe5\x86\xe5\xe5\x82\xe5\x82\x86\x82\x86\x82\xe5\xe5\x86\x86\x82\x82\xe5\xe5\xe5\x82\x82\x82\x82\xe5\xe5\x86\x86\xe5\xe5\xe5\x86\xe5\xe5\xe5\x86\x82\x82\x82\x82\x82\x82\x82\x82\xe5\x86\x82\x86\xe5\xe5\x86\xe5\x86\xe5\x82\x86\x86\x86\x86\x86\xe5\x86\xe5\x82\x86\x86\x82\xe5\xe5\x86\x86\xe5\x86\x82\x86\x82\x82\xe5\x82\x82\xe5\xe5\xe5\x82\x86\x82\x86\x86\x4c\xca\x33\x92\xd4\x6b\xcc\xb6\xeb\x47\x36\xf6\x3e\x16",
    "\x46\x1e\x53\xbe\x83\x6a\xcd\xd5\x5a\xc1\x6f\x17\xaf\x8e\xa7\xbe\xd4\x9c\x96\x82\x98\x3a\x2f\x15\x23\x53\x48\xe3\x61\x75\x71\x2c\x4a\xbd\xcc\x53\x95\xd8\xb0\xbe\x9d\x8c\x8f\xc1\xdf\xf7\x0b\x72\x9b\xe8\xb4\x63\x90\x70\x98\xa3",
    "\x50\x50\xfb\xfb\x50\x50\x50\x50\x50\xbf\xbf\x50\xfb\xbf\xbf\xbf\xbf\xfb\xfb\x50\x50\xbf\xfb\xfb\x50\xfb\x50\x50\xfb\xfb\xbf\xfb\xfb\xfb\x50\x50\xbf\xfb\xfb\xbf\x50\x50\xfb\xbf\x50\x50\xbf\x50\x50\x50\xbf\x50\xfb\x50\xfb\xfb\xfb\xbf\x50\xbf\xfb\xfb\xbf\xfb\x50\xbf\x50\xbf\xfb\x50\x59\xab\x98\xf1\x87\xc0\x06\x7e\xe5\xb7",
    "\x50\x50\xfb\xfb\x50\x50\x50\x50\x50\xbf\xbf\x50\xfb\xbf\xbf\xbf\xbf\xfb\xfb\x50\x50\xbf\xfb\xfb\x50\xfb\x50\x50\xfb\xfb\xbf\xfb\xfb\xfb\x50\x50\xbf\xfb\xfb\xbf\x50\x50\xfb\xbf\x50\x50\xbf\x50\x50\x50\xbf\x50\xfb\x50\xfb\xfb\xfb\xbf\x50\xbf\xfb\xfb\xbf\xfb\x50\xbf\x50\xbf\xfb\x50\x59\xab\x98\xf1\x87\xc0\x06\x7e\xe5\xb7\x58\x42\xf5\x2f",
};

const oracle_vectors = [_]Vector{
    .{
        .kind = .random,
        .seed = 49,
        .len = 49,
        .param = 0,
        .digests = .{
            "TooShort",
            "TooShort",
            "TooShort",
            "TooShort",
        },
        .conservative = .same,
    },
    .{
        .kind = .random,
        .seed = 50,
        .len = 50,
        .param = 0,
        .digests = .{
            "T1709002A1001B6483DB0561821290245D854511A096594A5B355F54B84A684461D9E458",
            "T170E6F09002A1001B6483DB0561821290245D854511A096594A5B355F54B84A684461D9E458",
            "T170900285183605530423458D9115616131704280C941455415454321A43049166E74D1A1001B6483DB0561821290245D854511A096594A5B355F54B84A684461D9E458",
            "T170E6F0900285183605530423458D9115616131704280C941455415454321A43049166E74D1A1001B6483DB0561821290245D854511A096594A5B355F54B84A684461D9E458",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 51,
        .len = 51,
        .param = 0,
        .digests = .{
            "T19B90021C543A0049C0948DC00C556248C4D1419D29D215587DC8B527C842570B6041D5",
            "T19BE3A890021C543A0049C0948DC00C556248C4D1419D29D215587DC8B527C842570B6041D5",
            "T19B900261599AA9A18A51A320D55D5654701068ED514467B01151A6520D4185528400411C543A0049C0948DC00C556248C4D1419D29D215587DC8B527C842570B6041D5",
            "T19BE3A8900261599AA9A18A51A320D55D5654701068ED514467B01151A6520D4185528400411C543A0049C0948DC00C556248C4D1419D29D215587DC8B527C842570B6041D5",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 57,
        .len = 57,
        .param = 0,
        .digests = .{
            "T14E9022C30800C0EA08320220820032808A08008AB000200008038C32A0032E20002083",
            "T14EDFFE9022C30800C0EA08320220820032808A08008AB000200008038C32A0032E20002083",
            "T14E9002E8C98615117071956225B48C451B6D8E047E18110DD6D189D9655510B9230105D31951D5EA18765225821436859A09159AB411245059539D36A5576E21056487",
            "T14EDFFE9002E8C98615117071956225B48C451B6D8E047E18110DD6D189D9655510B9230105D31951D5EA18765225821436859A09159AB411245059539D36A5576E21056487",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 58,
        .len = 58,
        .param = 0,
        .digests = .{
            "T103A00281D2435A8F8D05419ACFD4B4A95B589983997590220FC455D360438A0C255CC9",
            "T1034CD2A00281D2435A8F8D05419ACFD4B4A95B589983997590220FC455D360438A0C255CC9",
            "T103A002F5CD80B84E85519A144CA6D4091D5640B230660155755156428DF5B60043955481D2435A8F8D05419ACFD4B4A95B589983997590220FC455D360438A0C255CC9",
            "T1034CD2A002F5CD80B84E85519A144CA6D4091D5640B230660155755156428DF5B60043955481D2435A8F8D05419ACFD4B4A95B589983997590220FC455D360438A0C255CC9",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 86,
        .len = 86,
        .param = 0,
        .digests = .{
            "T1A8A0125690B10A8500510401218253054A12533E041300137490242929414708B19E00",
            "T1A85E46A0125690B10A8500510401218253054A12533E041300137490242929414708B19E00",
            "T1A8A01268C8F2D500303C8198C6999C41310011601460F42501D982C858847E1778380C5690B10A8500510401218253054A12533E041300137490242929414708B19E00",
            "T1A85E46A01268C8F2D500303C8198C6999C41310011601460F42501D982C858847E1778380C5690B10A8500510401218253054A12533E041300137490242929414708B19E00",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 87,
        .len = 87,
        .param = 0,
        .digests = .{
            "T11FB012E0010640016A10024C64106096824269504A72804103C4E83EB4056967032040",
            "T11F47C2B012E0010640016A10024C64106096824269504A72804103C4E83EB4056967032040",
            "T11FB0121402448220772805E8A156C330E000884232B9A6D854F5424BD7528E359024D2E0010640016A10024C64106096824269504A72804103C4E83EB4056967032040",
            "T11F47C2B0121402448220772805E8A156C330E000884232B9A6D854F5424BD7528E359024D2E0010640016A10024C64106096824269504A72804103C4E83EB4056967032040",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 129,
        .len = 129,
        .param = 0,
        .digests = .{
            "T1F5B02B322D040C0094C8510E3074558031600236108523511804E813D10DAD10B0797E",
            "T1F57939B02B322D040C0094C8510E3074558031600236108523511804E813D10DAD10B0797E",
            "T1F5B02BE9C0022D7C3AF2080354A07626010E4041A706C310A00EF84D3C223411D001A3322D040C0094C8510E3074558031600236108523511804E813D10DAD10B0797E",
            "T1F57939B02BE9C0022D7C3AF2080354A07626010E4041A706C310A00EF84D3C223411D001A3322D040C0094C8510E3074558031600236108523511804E813D10DAD10B0797E",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 130,
        .len = 130,
        .param = 0,
        .digests = .{
            "T165C02BC0F034C418841F40050114C736F102674C806042C1006497D0E437908FC444B1",
            "T165C1D8C02BC0F034C418841F40050114C736F102674C806042C1006497D0E437908FC444B1",
            "T165C02B630708A0424C009768A00CA178104214FC03074540BE8C06304A040BB3677C30C0F034C418841F40050114C736F102674C806042C1006497D0E437908FC444B1",
            "T165C1D8C02B630708A0424C009768A00CA178104214FC03074540BE8C06304A040BB3677C30C0F034C418841F40050114C736F102674C806042C1006497D0E437908FC444B1",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 255,
        .len = 255,
        .param = 0,
        .digests = .{
            "T12AD02B24A96219591094001BF41745BB1C64DF6475E1471CC6748836B1242D739C4C13",
            "T12A6216D02B24A96219591094001BF41745BB1C64DF6475E1471CC6748836B1242D739C4C13",
            "T12AD09550063D18072D551240C4B8F7C2665287340B0519377CA3CA77474504583C1DD734AD721D5D1094001FF41745BF1C64DF6475F1471CC6748836B1243D739C4C13",
            "T12A6216D09550063D18072D551240C4B8F7C2665287340B0519377CA3CA77474504583C1DD734AD721D5D1094001FF41745BF1C64DF6475F1471CC6748836B1243D739C4C13",
        },
        .conservative = .too_short,
    },
    .{
        .kind = .random,
        .seed = 256,
        .len = 256,
        .param = 0,
        .digests = .{
            "T1BAD02BE6F06AD1111FCD263351CE810A13D3D85945297F2601016914692FE320210A9E",
            "T1BABF60D02BE6F06AD1111FCD263351CE810A13D3D85945297F2601016914692FE320210A9E",
            "T1BAD09786E7F1CB3CC11B10067A13954A2EF76F8C0963B87A65FC7A064040826A10034EEBF0AED2211FCD273392CF820A13D3D85A89397F370101AA146E3FE320310AAE",
            "T1BABF60D09786E7F1CB3CC11B10067A13954A2EF76F8C0963B87A65FC7A064040826A10034EEBF0AED2211FCD273392CF820A13D3D85A89397F370101AA146E3FE320310AAE",
        },
        .conservative = .same,
    },
    .{
        .kind = .random,
        .seed = 257,
        .len = 257,
        .param = 0,
        .digests = .{
            "T1CCD0952061C55C467D18C800FE9FD2C511323E54B3114FC6C36B7570183348F5D125B2",
            "T1CCEA1AD0952061C55C467D18C800FE9FD2C511323E54B3114FC6C36B7570183348F5D125B2",
            "T1CCD02B0B4A18C93AB585B35C53B168380561E2B561360E411031BB4689B10851A452892061C55C467D18C800EE9FD28511222E54B3114F86826A7570183248F5D125A2",
            "T1CCEA1AD02B0B4A18C93AB585B35C53B168380561E2B561360E411031BB4689B10851A452892061C55C467D18C800EE9FD28511222E54B3114F86826A7570183248F5D125A2",
        },
        .conservative = .same,
    },
    .{
        .kind = .random,
        .seed = 1000,
        .len = 1000,
        .param = 0,
        .digests = .{
            "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
            "T1E994031108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
            "T1E911C81828AB2E40E9FC820E1C050B18A197E93BBF2FC31EE2BB82531E0634001617DC201B155D3C76AC5E6BD96C33DB4A484E1B972C1CDD2EF4EA7A44626730CBEA31",
            "T1E9940311C81828AB2E40E9FC820E1C050B18A197E93BBF2FC31EE2BB82531E0634001617DC201B155D3C76AC5E6BD96C33DB4A484E1B972C1CDD2EF4EA7A44626730CBEA31",
        },
        .conservative = .same,
    },
    .{
        .kind = .random,
        .seed = 4097,
        .len = 4097,
        .param = 0,
        .digests = .{
            "T11C817FE86037324F30D2B9657194DC9D1828B15D22B793D794D2014FFB3D086D6DB25C",
            "T11C3462817FE86037324F30D2B9657194DC9D1828B15D22B793D794D2014FFB3D086D6DB25C",
            "T11C817FF93837C52F6670861FC225D0A3522D1E14FF24E553DC56CB8C822584B68D5B33E86037324F30D2B9657194DC9D1828B15D22B793D794D2014FFB3D086D6DB25C",
            "T11C3462817FF93837C52F6670861FC225D0A3522D1E14FF24E553DC56CB8C822584B68D5B33E86037324F30D2B9657194DC9D1828B15D22B793D794D2014FFB3D086D6DB25C",
        },
        .conservative = .same,
    },
    .{
        .kind = .random,
        .seed = 65536,
        .len = 65536,
        .param = 0,
        .digests = .{
            "T1D95302C6E396528F61259AE0E14ECBE63C3812F54FA6B2F4D774121DF058A3A2DBC491",
            "T1D9AD7A5302C6E396528F61259AE0E14ECBE63C3812F54FA6B2F4D774121DF058A3A2DBC491",
            "T1D95302840704EA8BDFBB500B28487C1391564C6E534DA94E8B1326345357C2E9B3EDA4C6E39656CF6125DAE0E14ECBE63C3852F94FEAB2F4D778121DF058E3A3DBC492",
            "T1D9AD7A5302840704EA8BDFBB500B28487C1391564C6E534DA94E8B1326345357C2E9B3EDA4C6E39656CF6125DAE0E14ECBE63C3852F94FEAB2F4D778121DF058E3A3DBC492",
        },
        .conservative = .same,
    },
    .{
        .kind = .alphabet,
        .seed = 7,
        .len = 300,
        .param = 2,
        .digests = .{
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
        },
        .conservative = .same,
    },
    .{
        .kind = .alphabet,
        .seed = 8,
        .len = 300,
        .param = 3,
        .digests = .{
            "T1B9E00A10C0E3A2293AE2F0B0CB0CC7C8B082220C4FB20C83AC2EC008302828333700FE",
            "T1B90845E00A10C0E3A2293AE2F0B0CB0CC7C8B082220C4FB20C83AC2EC008302828333700FE",
            "InsufficientVariation",
            "InsufficientVariation",
        },
        .conservative = .same,
    },
    .{
        .kind = .alphabet,
        .seed = 9,
        .len = 2000,
        .param = 4,
        .digests = .{
            "T17E410C1ED7F79A3D7985F5304E06D75AE5D3228F6BB14C83A87E804E742960320764BE",
            "T17E2554410C1ED7F79A3D7985F5304E06D75AE5D3228F6BB14C83A87E804E742960320764BE",
            "T17E41E7951D8909B1A770A7C82C0C713F8C0DCAC1DD18B47D6EDDCBB9205969E36C05531EDBF79A3D7995F6704E06D75AE5D3228E6BB14C83A8BE804EB42964320764BE",
            "T17E255441E7951D8909B1A770A7C82C0C713F8C0DCAC1DD18B47D6EDDCBB9205969E36C05531EDBF79A3D7995F6704E06D75AE5D3228E6BB14C83A8BE804EB42964320764BE",
        },
        .conservative = .same,
    },
    .{
        .kind = .alphabet,
        .seed = 10,
        .len = 5000,
        .param = 26,
        .digests = .{
            "T1B1A17D0E453E969EFEB094CC51C94A0DD25C2D081F912875D8CB938FA93ABBA46306ED",
            "T1B18DA3A17D0E453E969EFEB094CC51C94A0DD25C2D081F912875D8CB938FA93ABBA46306ED",
            "T1B1A17F75251C90D5E3E5B210D2AEE85C1FC555892BBBB964CE784FDE1C053427C89E320E453E969DFDB094CC51C94A0DD25C2D081FD12875D4CBD38FA93ABB646306FD",
            "T1B18DA3A17F75251C90D5E3E5B210D2AEE85C1FC555892BBBB964CE784FDE1C053427C89E320E453E969DFDB094CC51C94A0DD25C2D081FD12875D4CBD38FA93ABB646306FD",
        },
        .conservative = .same,
    },
    .{
        .kind = .periodic,
        .seed = 11,
        .len = 400,
        .param = 1,
        .digests = .{
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
        },
        .conservative = .same,
    },
    .{
        .kind = .periodic,
        .seed = 12,
        .len = 400,
        .param = 7,
        .digests = .{
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
        },
        .conservative = .same,
    },
    .{
        .kind = .periodic,
        .seed = 13,
        .len = 3000,
        .param = 64,
        .digests = .{
            "T1A1510200E96B28EE29AC89D46BF6DB9584C2E702D8212A844968728467240288083A86",
            "T1A1C111510200E96B28EE29AC89D46BF6DB9584C2E702D8212A844968728467240288083A86",
            "T1A1510280632CDA589B6237A860D52521FD8E002CD6A905F2B4DCEA60A8A425387AB68100E96B28EE29AC89D46BF6DB9584C2E702D8212A844968728467240288083A86",
            "T1A1C111510280632CDA589B6237A860D52521FD8E002CD6A905F2B4DCEA60A8A425387AB68100E96B28EE29AC89D46BF6DB9584C2E702D8212A844968728467240288083A86",
        },
        .conservative = .same,
    },
    .{
        .kind = .sparse,
        .seed = 14,
        .len = 20000,
        .param = 16,
        .digests = .{
            "T1AC925B898CA5544CD0B748F197BDF4633A9E16BE7712C8C8A09B67EC720CC656366E83",
            "T1AC31D2925B898CA5544CD0B748F197BDF4633A9E16BE7712C8C8A09B67EC720CC656366E83",
            "T1AC925C9B66AD705351B2E70ECA5F86C5E8806F7D88EF65E912CD887CBE03125C5BD402888CA5540CD0B708F187B9F063395D15BE7702C4C8A09B67EC720CC656326E83",
            "T1AC31D2925C9B66AD705351B2E70ECA5F86C5E8806F7D88EF65E912CD887CBE03125C5BD402888CA5540CD0B708F187B9F063395D15BE7702C4C8A09B67EC720CC656326E83",
        },
        .conservative = .same,
    },
    .{
        .kind = .sparse,
        .seed = 15,
        .len = 70000,
        .param = 100,
        .digests = .{
            "T1F3632AF4B93E6120FD7C2CBCEC6C99462B0C7B4D6B9936347BA464820283A2B1441E36",
            "T1F3211E632AF4B93E6120FD7C2CBCEC6C99462B0C7B4D6B9936347BA464820283A2B1441E36",
            "T1F3632BF0C5AB3D1E107137EE45A821F67615027032E0933CF2A299DE690023E13052FFF4793E6120FD7C2CBCEC6C5946270C7B4D6B99353477A46482018392B1441E35",
            "T1F3211E632BF0C5AB3D1E107137EE45A821F67615027032E0933CF2A299DE690023E13052FFF4793E6120FD7C2CBCEC6C5946270C7B4D6B99353477A46482018392B1441E35",
        },
        .conservative = .same,
    },
    // q3 zero for 128 buckets
    .{
        .kind = .periodic,
        .seed = 1,
        .len = 60,
        .param = 14,
        .digests = .{
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
        },
        .conservative = .too_short,
    },
    // q1 zero for 128 buckets
    .{
        .kind = .periodic,
        .seed = 1,
        .len = 60,
        .param = 33,
        .digests = .{
            "T1C5A0024EDAA40304082A612CC2C1D830E0B34DE8288E48DB8A8300B03201B302022000",
            "T1C5992BA0024EDAA40304082A612CC2C1D830E0B34DE8288E48DB8A8300B03201B302022000",
            "T1C5A00208ED0AE9883A000C182B2738B85DA8E71C808862A30E00720CB8EBB40002E2814EDAA40304082A612CC2C1D830E0B34DE8288E48DB8A8300B03201B302022000",
            "T1C5992BA00208ED0AE9883A000C182B2738B85DA8E71C808862A30E00720CB8EBB40002E2814EDAA40304082A612CC2C1D830E0B34DE8288E48DB8A8300B03201B302022000",
        },
        .conservative = .too_short,
    },
    // q2 q3 tied for 128 buckets
    .{
        .kind = .periodic,
        .seed = 1,
        .len = 150,
        .param = 34,
        .digests = .{
            "T161C0044DCF5401440415517CC1C0CC33D0774DD51C5D44D7C5C304503300F301433000",
            "T161585FC0044DCF5401440415517CC1C0CC33D0774DD51C5D44D7C5C304503300F301433000",
            "T161C00004DD09F5543D010C043B133CB97D54E31C40C411B30D00330CF4E7751001E2814DCA5401440415516CC1C0C833D0774DD51C5D44D6858304503200B301422000",
            "T161585FC00004DD09F5543D010C043B133CB97D54E31C40C411B30D00330CF4E7751001E2814DCA5401440415516CC1C0C833D0774DD51C5D44D6858304503200B301422000",
        },
        .conservative = .too_short,
    },
    // q3 zero for 256 buckets
    .{
        .kind = .alphabet,
        .seed = 1,
        .len = 50,
        .param = 2,
        .digests = .{
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
            "InsufficientVariation",
        },
        .conservative = .too_short,
    },
    // q1 zero for 256 buckets
    .{
        .kind = .periodic,
        .seed = 1,
        .len = 60,
        .param = 31,
        .digests = .{
            "InsufficientVariation",
            "InsufficientVariation",
            "T16DA00208EC0AA9883E410C082B2338B898ACF31C818822B30E00324CA8EBB40006B2818ECE984200082A202CC2C0C830E0B34AE8288E08DA8A8304A03200B342022050",
            "T16D9FC6A00208EC0AA9883E410C082B2338B898ACF31C818822B30E00324CA8EBB40006B2818ECE984200082A202CC2C0C830E0B34AE8288E08DA8A8304A03200B342022050",
        },
        .conservative = .too_short,
    },
    // q2 q3 tied for 256 buckets
    .{
        .kind = .periodic,
        .seed = 1,
        .len = 97,
        .param = 31,
        .digests = .{
            "InsufficientVariation",
            "InsufficientVariation",
            "T175B00404DC0555443D410C0417333474545CF31C414411730D00314C54D774000571414DCD5441000415101CC1C0C430D07345D4144D04D54543045031007341011050",
            "T175F650B00404DC0555443D410C0417333474545CF31C414411730D00314C54D774000571414DCD5441000415101CC1C0C430D07345D4144D04D54543045031007341011050",
        },
        .conservative = .too_short,
    },
    // q1 == q2 == q3 for 128 buckets
    .{
        .kind = .literal,
        .seed = 0,
        .len = 50,
        .param = 0,
        .digests = .{
            "T18C90440000000000000000000000000000000000000000000000000000000000000000",
            "T18CFA6390440000000000000000000000000000000000000000000000000000000000000000",
            "T18C9044000F3CFC03C3CC30300000000CFCC00F03FC33FF03300C3C00030003C00033000000000000000000000000000000000000000000000000000000000000000000",
            "T18CFA639044000F3CFC03C3CC30300000000CFCC00F03FC33FF03300C3C00030003C00033000000000000000000000000000000000000000000000000000000000000000000",
        },
        .conservative = .too_short,
    },
    // exactly 64 non-zero buckets of 128
    .{
        .kind = .literal,
        .seed = 0,
        .len = 103,
        .param = 1,
        .digests = .{
            "InsufficientVariation",
            "InsufficientVariation",
            "T1BFB0092A5F32B0108022A280B6EA10C80F3422E3F0F31D21083FAB3FBC322C02028BB3EA340630000082A60083C032B828AF0221223182180EB350C432050C8FCE302B",
            "T1BF3465B0092A5F32B0108022A280B6EA10C80F3422E3F0F31D21083FAB3FBC322C02028BB3EA340630000082A60083C032B828AF0221223182180EB350C432050C8FCE302B",
        },
        .conservative = .too_short,
    },
    // exactly 65 non-zero buckets of 128
    .{
        .kind = .literal,
        .seed = 0,
        .len = 107,
        .param = 2,
        .digests = .{
            "T104B001EB340630010083A60083C032F82CBF0222223183180FB350C432050CCFCE303F",
            "T104E1A9B001EB340630010083A60083C032F82CBF0222223183180FB350C432050CCFCE303F",
            "T104B0096A5F72F0108023A284BAEA10C85F7422E3F0F31D61083FAB3FBC322C02528BB7EA340630010082A60083C032B828AF0222223182180EB350C432050C8FCE302B",
            "T104E1A9B0096A5F72F0108023A284BAEA10C85F7422E3F0F31D61083FAB3FBC322C02528BB7EA340630010082A60083C032B828AF0222223182180EB350C432050C8FCE302B",
        },
        .conservative = .too_short,
    },
    // q1 == q2 == q3 for 256 buckets
    .{
        .kind = .literal,
        .seed = 0,
        .len = 56,
        .param = 3,
        .digests = .{
            "T124904400000F30300033FC0C00300CC003C30030000000300000000000000000C00000",
            "T1244FC9904400000F30300033FC0C00300CC003C30030000000300000000000000000C00000",
            "T124904433C0030003C0000F3000000C00000000000000000000C000300C00C00C0C003C00000F30300033FC0C00300CC003C30030000000300000000000000000C00000",
            "T1244FC9904433C0030003C0000F3000000C00000000000000000000C000300C00C00C0C003C00000F30300033FC0C00300CC003C30030000000300000000000000000C00000",
        },
        .conservative = .too_short,
    },
    // exactly 128 non-zero buckets of 256
    .{
        .kind = .literal,
        .seed = 0,
        .len = 80,
        .param = 4,
        .digests = .{
            "T1F4A001A238CA14A0C008F3B0099422001E93BCC03B080E88C0B2072236FE2C80EFF001",
            "T1F47F03A001A238CA14A0C008F3B0099422001E93BCC03B080E88C0B2072236FE2C80EFF001",
            "InsufficientVariation",
            "InsufficientVariation",
        },
        .conservative = .too_short,
    },
    // exactly 129 non-zero buckets of 256
    .{
        .kind = .literal,
        .seed = 0,
        .len = 84,
        .param = 5,
        .digests = .{
            "T13FA009A238CA14A08008F3B0099422002A93ACC03A080E88C1B2062236EE2C80EFF001",
            "T13FCB86A009A238CA14A08008F3B0099422002A93ACC03A080E88C1B2062236EE2C80EFF001",
            "T13FA0010F20A70E3F2920888082230007C030FC103F000834F05C0EC1322103202C87C3B238CA14A0C00CF3B0099422002E93BCC03B0C0E88C1B3073236FE2C80EFF001",
            "T13FCB86A0010F20A70E3F2920888082230007C030FC103F000834F05C0EC1322103202C87C3B238CA14A0C00CF3B0099422002E93BCC03B0C0E88C1B3073236FE2C80EFF001",
        },
        .conservative = .too_short,
    },
};

// Distances with and without the length term, per variant.
const oracle_distances = [_]DistanceVector{
    .{ .a = 1, .b = 2, .expected = .{ .{ 173, 173 }, .{ 173, 173 }, .{ 314, 314 }, .{ 314, 314 } } },
    .{ .a = 1, .b = 10, .expected = .{ .{ 326, 278 }, .{ 326, 278 }, .{ 599, 551 }, .{ 599, 551 } } },
    .{ .a = 1, .b = 23, .expected = .{ .{ 857, 317 }, .{ 857, 317 }, .{ 1044, 504 }, .{ 1044, 504 } } },
    .{ .a = 2, .b = 3, .expected = .{ .{ 217, 217 }, .{ 217, 217 }, .{ 357, 357 }, .{ 357, 357 } } },
    .{ .a = 2, .b = 5, .expected = .{ .{ 155, 154 }, .{ 155, 154 }, .{ 314, 313 }, .{ 314, 313 } } },
    .{ .a = 2, .b = 14, .expected = .{ .{ 731, 203 }, .{ 731, 203 }, .{ 923, 395 }, .{ 923, 395 } } },
    .{ .a = 2, .b = 32, .expected = .{ .{ 276, 252 }, .{ 276, 252 }, .{ 518, 494 }, .{ 518, 494 } } },
    .{ .a = 3, .b = 4, .expected = .{ .{ 195, 194 }, .{ 195, 194 }, .{ 306, 305 }, .{ 306, 305 } } },
    .{ .a = 3, .b = 10, .expected = .{ .{ 350, 302 }, .{ 350, 302 }, .{ 562, 514 }, .{ 562, 514 } } },
    .{ .a = 3, .b = 23, .expected = .{ .{ 878, 338 }, .{ 878, 338 }, .{ 978, 438 }, .{ 978, 438 } } },
    .{ .a = 4, .b = 5, .expected = .{ .{ 182, 182 }, .{ 182, 182 }, .{ 364, 364 }, .{ 364, 364 } } },
    .{ .a = 4, .b = 7, .expected = .{ .{ 308, 307 }, .{ 308, 307 }, .{ 494, 493 }, .{ 494, 493 } } },
    .{ .a = 4, .b = 18, .expected = .{ .{ 512, 320 }, .{ 512, 320 }, .{ 679, 487 }, .{ 679, 487 } } },
    .{ .a = 4, .b = 35, .expected = .{ .{ 308, 308 }, .{ 308, 308 }, .{ 501, 501 }, .{ 501, 501 } } },
    .{ .a = 5, .b = 6, .expected = .{ .{ 175, 174 }, .{ 175, 174 }, .{ 354, 353 }, .{ 354, 353 } } },
    .{ .a = 5, .b = 14, .expected = .{ .{ 719, 203 }, .{ 719, 203 }, .{ 991, 475 }, .{ 991, 475 } } },
    .{ .a = 5, .b = 32, .expected = .{ .{ 235, 234 }, .{ 235, 234 }, .{ 503, 502 }, .{ 503, 502 } } },
    .{ .a = 6, .b = 7, .expected = .{ .{ 261, 261 }, .{ 261, 261 }, .{ 479, 479 }, .{ 479, 479 } } },
    .{ .a = 6, .b = 13, .expected = .{ .{ 446, 290 }, .{ 446, 290 }, .{ 658, 502 }, .{ 658, 502 } } },
    .{ .a = 6, .b = 30, .expected = .{ .{ 212, 188 }, .{ 212, 188 }, .{ 484, 460 }, .{ 484, 460 } } },
    .{ .a = 7, .b = 8, .expected = .{ .{ 222, 221 }, .{ 222, 221 }, .{ 484, 483 }, .{ 484, 483 } } },
    .{ .a = 7, .b = 13, .expected = .{ .{ 456, 300 }, .{ 456, 300 }, .{ 653, 497 }, .{ 653, 497 } } },
    .{ .a = 7, .b = 30, .expected = .{ .{ 294, 270 }, .{ 294, 270 }, .{ 610, 586 }, .{ 610, 586 } } },
    .{ .a = 8, .b = 9, .expected = .{ .{ 212, 211 }, .{ 212, 211 }, .{ 554, 553 }, .{ 554, 553 } } },
    .{ .a = 8, .b = 14, .expected = .{ .{ 799, 307 }, .{ 799, 307 }, .{ 990, 498 }, .{ 990, 498 } } },
    .{ .a = 8, .b = 32, .expected = .{ .{ 318, 317 }, .{ 318, 317 }, .{ 503, 502 }, .{ 503, 502 } } },
    .{ .a = 9, .b = 10, .expected = .{ .{ 221, 221 }, .{ 221, 221 }, .{ 508, 508 }, .{ 508, 508 } } },
    .{ .a = 9, .b = 18, .expected = .{ .{ 458, 302 }, .{ 458, 302 }, .{ 674, 518 }, .{ 674, 518 } } },
    .{ .a = 9, .b = 35, .expected = .{ .{ 277, 241 }, .{ 277, 241 }, .{ 616, 580 }, .{ 616, 580 } } },
    .{ .a = 10, .b = 11, .expected = .{ .{ 349, 349 }, .{ 349, 349 }, .{ 515, 515 }, .{ 515, 515 } } },
    .{ .a = 10, .b = 23, .expected = .{ .{ 676, 184 }, .{ 676, 184 }, .{ 1049, 557 }, .{ 1049, 557 } } },
    .{ .a = 11, .b = 12, .expected = .{ .{ 353, 305 }, .{ 353, 305 }, .{ 535, 487 }, .{ 535, 487 } } },
    .{ .a = 11, .b = 14, .expected = .{ .{ 790, 310 }, .{ 790, 310 }, .{ 995, 515 }, .{ 995, 515 } } },
    .{ .a = 11, .b = 32, .expected = .{ .{ 378, 354 }, .{ 378, 354 }, .{ 435, 411 }, .{ 435, 411 } } },
    .{ .a = 12, .b = 13, .expected = .{ .{ 492, 408 }, .{ 492, 408 }, .{ 699, 615 }, .{ 699, 615 } } },
    .{ .a = 12, .b = 23, .expected = .{ .{ 651, 207 }, .{ 651, 207 }, .{ 909, 465 }, .{ 909, 465 } } },
    .{ .a = 13, .b = 14, .expected = .{ .{ 623, 275 }, .{ 623, 275 }, .{ 848, 500 }, .{ 848, 500 } } },
    .{ .a = 13, .b = 18, .expected = .{ .{ 221, 197 }, .{ 221, 197 }, .{ 398, 374 }, .{ 398, 374 } } },
    .{ .a = 13, .b = 35, .expected = .{ .{ 539, 371 }, .{ 539, 371 }, .{ 702, 534 }, .{ 702, 534 } } },
    .{ .a = 14, .b = 32, .expected = .{ .{ 744, 240 }, .{ 744, 240 }, .{ 1093, 589 }, .{ 1093, 589 } } },
    .{ .a = 17, .b = 30, .expected = .{ .{ 540, 408 }, .{ 540, 408 }, .{ 800, 668 }, .{ 800, 668 } } },
    .{ .a = 18, .b = 30, .expected = .{ .{ 580, 376 }, .{ 580, 376 }, .{ 832, 628 }, .{ 832, 628 } } },
    .{ .a = 21, .b = 32, .expected = .{ .{ 352, 232 }, .{ 352, 232 }, .{ 614, 494 }, .{ 614, 494 } } },
    .{ .a = 22, .b = 35, .expected = .{ .{ 656, 284 }, .{ 656, 284 }, .{ 962, 590 }, .{ 962, 590 } } },
    .{ .a = 25, .b = 32, .expected = .{ .{ 244, 243 }, .{ 244, 243 }, .{ 515, 514 }, .{ 515, 514 } } },
    .{ .a = 30, .b = 35, .expected = .{ .{ 304, 303 }, .{ 304, 303 }, .{ 626, 625 }, .{ 626, 625 } } },
};

// 128/1 digest strings and the results of py-tlsh diff and diffxlen.
const oracle_string_distances = [_]StringDistanceVector{
    .{
        .a = "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 0,
        .diffxlen = 0,
    },
    .{
        .a = "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 0,
        .diffxlen = 0,
    },
    .{
        .a = "e91108201b145c3c36ac1e2bd92c33db0a484e1b872c0ccd2ef0ea7a40226730cbea31",
        .b = "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 0,
        .diffxlen = 0,
    },
    .{
        .a = "E90008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E91008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1,
        .diffxlen = 0,
    },
    .{
        .a = "E90008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E92008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 24,
        .diffxlen = 0,
    },
    .{
        .a = "E90008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E9F708201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1524,
        .diffxlen = 0,
    },
    .{
        .a = "E90008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E90808201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1536,
        .diffxlen = 0,
    },
    .{
        .a = "E90008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E91808201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1524,
        .diffxlen = 0,
    },
    .{
        .a = "E90008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E9FF08201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1,
        .diffxlen = 0,
    },
    .{
        .a = "E9EF08201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E93008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 60,
        .diffxlen = 0,
    },
    .{
        .a = "E99008201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E99A08201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1152,
        .diffxlen = 0,
    },
    .{
        .a = "E91100201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E91110201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1,
        .diffxlen = 1,
    },
    .{
        .a = "E91100201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E91120201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 12,
        .diffxlen = 12,
    },
    .{
        .a = "E91100201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E91180201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 84,
        .diffxlen = 84,
    },
    .{
        .a = "E91100201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E91190201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 72,
        .diffxlen = 72,
    },
    .{
        .a = "E91100201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E911F0201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1,
        .diffxlen = 1,
    },
    .{
        .a = "E91100201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E9110F201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1,
        .diffxlen = 1,
    },
    .{
        .a = "E91101201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E9110E201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 24,
        .diffxlen = 24,
    },
    .{
        .a = "E9113C201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "E911C3201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 144,
        .diffxlen = 144,
    },
    .{
        .a = "001108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .b = "011108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
        .diff = 1,
        .diffxlen = 1,
    },
    .{
        .a = "E911080000000000000000000000000000000000000000000000000000000000000000",
        .b = "E91108FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        .diff = 768,
        .diffxlen = 768,
    },
    .{
        .a = "E911080000000000000000000000000000000000000000000000000000000000000000",
        .b = "E911085555555555555555555555555555555555555555555555555555555555555555",
        .diff = 128,
        .diffxlen = 128,
    },
    .{
        .a = "E911080000000000000000000000000000000000000000000000000000000000000000",
        .b = "E91108AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        .diff = 256,
        .diffxlen = 256,
    },
    .{
        .a = "E911081B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B",
        .b = "E91108E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4E4",
        .diff = 448,
        .diffxlen = 448,
    },
    .{
        .a = "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31 trailing text",
        .b = "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31\n",
        .diff = 0,
        .diffxlen = 0,
    },
    .{
        .a = "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31G",
        .b = "E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31/",
        .diff = 0,
        .diffxlen = 0,
    },
};

// 128/1 strings that py-tlsh diff refuses with ValueError.
const oracle_refused_strings = [_][]const u8{
    "",
    "T1",
    "TNULL",
    "E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA3",
    "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA3",
    "E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA310",
    "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31a",
    "E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA3100",
    "t1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
    "t1e91108201b145c3c36ac1e2bd92c33db0a484e1b872c0ccd2ef0ea7a40226730cbea31",
    "T1T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
    " T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
    "E91108201BG45C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA31",
    "T1E91108201B145C3C36AC1E2BD92C33DB0A484E B872C0CCD2EF0EA7A40226730CBEA31",
    "E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA3/",
    "T1E91108201B145C3C36AC1E2BD92C33DB0A484E1B872C0CCD2EF0EA7A40226730CBEA",
    "E91108201B145C3C36AC1E2BD92C33x",
};

// Fields of vector 12 (1000 random bytes) as py-tlsh reports them.
// py-tlsh `bucket_value(i)` is the code of bucket 127 - i.
const oracle_fields = .{
    .checksum = 158,
    .lvalue = 17,
    .q1ratio = 0,
    .q2ratio = 8,
    .bucket_values = [128]u8{
        0, 2, 0, 0, 0, 1, 2, 3, 0, 1, 1, 0, 1, 1, 3, 0, 0, 3, 3, 0, 0, 3, 1, 2, 2, 2, 3, 0, 0, 1, 3, 2,
        0, 2, 2, 3, 3, 1, 2, 1, 0, 2, 3, 0, 0, 3, 0, 3, 3, 1, 2, 3, 0, 0, 2, 2, 1, 0, 2, 0, 1, 0, 3, 2,
        0, 1, 2, 3, 2, 0, 1, 3, 0, 2, 3, 0, 0, 0, 3, 0, 3, 0, 3, 1, 0, 2, 3, 2, 3, 3, 0, 0, 3, 2, 2, 2,
        1, 3, 2, 2, 1, 0, 0, 0, 0, 2, 0, 2, 1, 2, 1, 3, 0, 3, 0, 0, 3, 0, 2, 3, 3, 2, 2, 2, 0, 3, 0, 1,
    },
};
