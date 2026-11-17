// SPDX-License-Identifier: MIT

//! Nilsimsa locality-sensitive digest.
//!
//! The input is read as bytes. Every byte hashes up to eight trigrams (three
//! bytes chosen from a sliding window of the current byte and the four before
//! it) into one of 256 buckets. The digest has one bit per bucket: the bit is
//! set when the bucket was hit more often than the mean. Similar inputs hit
//! similar buckets, so their digests agree in most bits.
//!
//! Output is bit-for-bit compatible with the Python package `nilsimsa` 0.3.8:
//! the same 64-character hex digests and the same comparison scores.
//!
//! Nothing here allocates, recurses or touches the OS, and no input can make
//! it fail. Every index computed from input data is a `u8` (or narrower)
//! into a table that covers the whole range of that type. The remaining
//! indexes are loop counters over fixed-size arrays. So no access can be out
//! of range in any optimize mode, with or without safety checks.

const std = @import("std");

/// Digest size in bytes.
pub const digest_length = 32;
/// Digest size in hex characters.
pub const hex_length = 64;

const bucket_count = 256;

/// Fixed permutation of 0..255 that drives the trigram hash.
const transition = [bucket_count]u8{
    0x02, 0xd6, 0x9e, 0x6f, 0xf9, 0x1d, 0x04, 0xab, 0xd0, 0x22, 0x16, 0x1f, 0xd8, 0x73, 0xa1, 0xac,
    0x3b, 0x70, 0x62, 0x96, 0x1e, 0x6e, 0x8f, 0x39, 0x9d, 0x05, 0x14, 0x4a, 0xa6, 0xbe, 0xae, 0x0e,
    0xcf, 0xb9, 0x9c, 0x9a, 0xc7, 0x68, 0x13, 0xe1, 0x2d, 0xa4, 0xeb, 0x51, 0x8d, 0x64, 0x6b, 0x50,
    0x23, 0x80, 0x03, 0x41, 0xec, 0xbb, 0x71, 0xcc, 0x7a, 0x86, 0x7f, 0x98, 0xf2, 0x36, 0x5e, 0xee,
    0x8e, 0xce, 0x4f, 0xb8, 0x32, 0xb6, 0x5f, 0x59, 0xdc, 0x1b, 0x31, 0x4c, 0x7b, 0xf0, 0x63, 0x01,
    0x6c, 0xba, 0x07, 0xe8, 0x12, 0x77, 0x49, 0x3c, 0xda, 0x46, 0xfe, 0x2f, 0x79, 0x1c, 0x9b, 0x30,
    0xe3, 0x00, 0x06, 0x7e, 0x2e, 0x0f, 0x38, 0x33, 0x21, 0xad, 0xa5, 0x54, 0xca, 0xa7, 0x29, 0xfc,
    0x5a, 0x47, 0x69, 0x7d, 0xc5, 0x95, 0xb5, 0xf4, 0x0b, 0x90, 0xa3, 0x81, 0x6d, 0x25, 0x55, 0x35,
    0xf5, 0x75, 0x74, 0x0a, 0x26, 0xbf, 0x19, 0x5c, 0x1a, 0xc6, 0xff, 0x99, 0x5d, 0x84, 0xaa, 0x66,
    0x3e, 0xaf, 0x78, 0xb3, 0x20, 0x43, 0xc1, 0xed, 0x24, 0xea, 0xe6, 0x3f, 0x18, 0xf3, 0xa0, 0x42,
    0x57, 0x08, 0x53, 0x60, 0xc3, 0xc0, 0x83, 0x40, 0x82, 0xd7, 0x09, 0xbd, 0x44, 0x2a, 0x67, 0xa8,
    0x93, 0xe0, 0xc2, 0x56, 0x9f, 0xd9, 0xdd, 0x85, 0x15, 0xb4, 0x8a, 0x27, 0x28, 0x92, 0x76, 0xde,
    0xef, 0xf8, 0xb2, 0xb7, 0xc9, 0x3d, 0x45, 0x94, 0x4b, 0x11, 0x0d, 0x65, 0xd5, 0x34, 0x8b, 0x91,
    0x0c, 0xfa, 0x87, 0xe9, 0x7c, 0x5b, 0xb1, 0x4d, 0xe5, 0xd4, 0xcb, 0x10, 0xa2, 0x17, 0x89, 0xbc,
    0xdb, 0xb0, 0xe2, 0x97, 0x88, 0x52, 0xf7, 0x48, 0xd3, 0x61, 0x2c, 0x3a, 0x2b, 0xd1, 0x8c, 0xfb,
    0xf1, 0xcd, 0xe4, 0x6a, 0xe7, 0xa9, 0xfd, 0xc4, 0x37, 0xc8, 0xd2, 0xf6, 0xdf, 0x58, 0x72, 0x4e,
};

/// Trigram hash, all arithmetic modulo 256:
///
///     H(a, b, c, n) = (T[a + n] XOR (T[b] * (2n + 1))) + T[c XOR T[n]]
///
/// `n` is the trigram number, 0 to 7. It is always known at compile time, so
/// `T[n]` and the multiplier fold to constants.
inline fn trigramHash(a: u8, b: u8, c: u8, comptime n: u3) u8 {
    const number: u8 = n;
    const multiplier: u8 = 2 * number + 1;
    const mixed = transition[a +% number] ^ (transition[b] *% multiplier);
    return mixed +% transition[c ^ transition[number]];
}

/// Streaming Nilsimsa state. A plain value: copying it copies the state, so a
/// hasher can be forked by assignment.
pub const Hasher = struct {
    /// How often each bucket was hit. A bucket grows by at most 8 per input
    /// byte, so 64 bits cannot wrap before 2^61 bytes of input. The additions
    /// wrap instead of trapping to keep `update` defined in every optimize
    /// mode.
    counts: [bucket_count]u64,
    /// Total number of input bytes so far. Saturates instead of wrapping.
    len: u64,
    /// The last four input bytes, newest first. Entry `i` is meaningful only
    /// once more than `i` bytes have been read.
    window: [4]u8,

    /// A hasher that has seen no input. Every field is zero.
    pub fn init() Hasher {
        return .{
            .counts = @splat(0),
            .len = 0,
            .window = @splat(0),
        };
    }

    /// Feeds `bytes` into the hasher. The final digest depends only on the
    /// concatenation of all bytes, not on how they are split across calls.
    pub fn update(self: *Hasher, bytes: []const u8) void {
        var w0 = self.window[0];
        var w1 = self.window[1];
        var w2 = self.window[2];
        var w3 = self.window[3];
        var rest = bytes;

        // Start-up: fewer than four earlier bytes exist, so only some of the
        // trigrams are defined. This runs for at most the first four bytes of
        // the whole stream.
        var earlier: u3 = @min(self.len, 4);
        while (earlier < 4 and rest.len != 0) {
            const x = rest[0];
            rest = rest[1..];
            if (earlier >= 2) {
                self.hit(trigramHash(x, w0, w1, 0));
            }
            if (earlier >= 3) {
                self.hit(trigramHash(x, w0, w2, 1));
                self.hit(trigramHash(x, w1, w2, 2));
            }
            w3 = w2;
            w2 = w1;
            w1 = w0;
            w0 = x;
            earlier += 1;
        }

        // Steady state: a full window, eight trigrams per byte. Trigrams 6
        // and 7 lead with the oldest byte and end with the current one.
        for (rest) |x| {
            self.hit(trigramHash(x, w0, w1, 0));
            self.hit(trigramHash(x, w0, w2, 1));
            self.hit(trigramHash(x, w1, w2, 2));
            self.hit(trigramHash(x, w0, w3, 3));
            self.hit(trigramHash(x, w1, w3, 4));
            self.hit(trigramHash(x, w2, w3, 5));
            self.hit(trigramHash(w3, w0, x, 6));
            self.hit(trigramHash(w3, w2, x, 7));
            w3 = w2;
            w2 = w1;
            w1 = w0;
            w0 = x;
        }

        self.window = .{ w0, w1, w2, w3 };
        self.len +|= bytes.len;
    }

    /// Returns the digest of everything fed so far and resets the hasher to
    /// the all-zero initial state, ready for a new input.
    pub fn final(self: *Hasher) Digest {
        // Number of trigrams counted: none for the first two bytes, 1 for the
        // third, 3 for the fourth, 8 for every byte after that. 128 bits hold
        // 8 * len for any 64-bit length.
        const len = self.len;
        const total: u128 = if (len < 3)
            0
        else if (len == 3)
            1
        else if (len == 4)
            4
        else
            8 * @as(u128, len) - 28;

        // A bucket yields a 1 bit when its count is strictly above the mean,
        // total / 256. Compared as count * 256 > total to stay in integers.
        //
        // Bucket i is bit (i mod 8) of internal byte (i / 8), and the 32
        // internal bytes are emitted in reverse order.
        var digest: Digest = .{ .bytes = @splat(0) };
        for (self.counts, 0..) |count, i| {
            if ((@as(u128, count) << 8) > total) {
                const bucket: u8 = @truncate(i);
                const byte: u5 = @truncate(bucket >> 3);
                const bit: u3 = @truncate(bucket);
                digest.bytes[31 - byte] |= @as(u8, 1) << bit;
            }
        }

        self.* = init();
        return digest;
    }

    inline fn hit(self: *Hasher, bucket: u8) void {
        self.counts[bucket] +%= 1;
    }
};

/// One-shot digest of `bytes`.
pub fn hash(bytes: []const u8) Digest {
    var hasher = Hasher.init();
    hasher.update(bytes);
    return hasher.final();
}

pub const ParseError = error{InvalidFormat};

/// A 256-bit Nilsimsa digest.
pub const Digest = struct {
    /// In output order: `bytes[0]` is the first two hex characters.
    bytes: [digest_length]u8,

    /// Writes 64 lowercase hex characters and returns the written slice.
    pub fn toHex(self: Digest, out: *[hex_length]u8) []const u8 {
        const digits = "0123456789abcdef";
        for (self.bytes, 0..) |byte, k| {
            const high: u4 = @truncate(byte >> 4);
            const low: u4 = @truncate(byte);
            out[2 * k] = digits[high];
            out[2 * k + 1] = digits[low];
        }
        return out;
    }

    /// Exactly 64 hex characters, upper or lower case. Anything else,
    /// including surrounding whitespace, a `0x` prefix or extra characters,
    /// is `InvalidFormat`.
    pub fn parse(text: []const u8) ParseError!Digest {
        if (text.len != hex_length) return error.InvalidFormat;
        const chars: *const [hex_length]u8 = text[0..hex_length];
        var digest: Digest = .{ .bytes = @splat(0) };
        for (&digest.bytes, 0..) |*byte, k| {
            const high = hexValue(chars[2 * k]) orelse return error.InvalidFormat;
            const low = hexValue(chars[2 * k + 1]) orelse return error.InvalidFormat;
            byte.* = (@as(u8, high) << 4) | low;
        }
        return digest;
    }
};

/// Value of one hex digit, or null for any other byte.
fn hexValue(char: u8) ?u4 {
    return switch (char) {
        '0'...'9' => @truncate(char - '0'),
        'a'...'f' => @truncate(char - 'a' + 10),
        'A'...'F' => @truncate(char - 'A' + 10),
        else => null,
    };
}

/// Score from -128 (every bit differs) to 128 (identical): 128 minus the
/// number of differing bits.
pub fn compare(a: Digest, b: Digest) i16 {
    // At most 256 bits differ, so the sum fits easily.
    var differing: i16 = 0;
    for (a.bytes, b.bytes) |x, y| {
        differing += @popCount(x ^ y);
    }
    return 128 - differing;
}

/// Parses both and compares.
pub fn compareStrings(a: []const u8, b: []const u8) ParseError!i16 {
    const digest_a = try Digest.parse(a);
    const digest_b = try Digest.parse(b);
    return compare(digest_a, digest_b);
}

// ---------------------------------------------------------------------------
// Tests
//
// Every expected digest and score comes from the Python package nilsimsa
// 0.3.8, never from this implementation. The parser tests are the
// exception: the package has no parser of its own, so they follow the
// documented format instead.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// SplitMix64, for reproducible test inputs. The expected values were
/// computed from the same generator's bytes.
const TestRng = struct {
    state: u64,

    fn init(seed: u64) TestRng {
        return .{ .state = seed };
    }

    fn next(self: *TestRng) u8 {
        self.state +%= 0x9e3779b97f4a7c15;
        var z = self.state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        z ^= z >> 31;
        return @truncate(z);
    }

    fn fill(self: *TestRng, buffer: []u8) void {
        for (buffer) |*byte| byte.* = self.next();
    }
};

/// SHA-256 over concatenated hex digests, so that a single constant pins a
/// whole series of expected results.
const Rollup = struct {
    sha: std.crypto.hash.sha2.Sha256,

    fn init() Rollup {
        return .{ .sha = .init(.{}) };
    }

    fn add(self: *Rollup, digest: Digest) void {
        var buffer: [hex_length]u8 = undefined;
        self.sha.update(digest.toHex(&buffer));
    }

    fn expect(self: *Rollup, expected_hex: []const u8) !void {
        const hex = std.fmt.bytesToHex(self.sha.finalResult(), .lower);
        try testing.expectEqualStrings(expected_hex, &hex);
    }
};

fn hashByteWise(input: []const u8) Digest {
    var hasher = Hasher.init();
    for (0..input.len) |i| hasher.update(input[i..][0..1]);
    return hasher.final();
}

/// Feeds `input` in pseudo-random chunks: mostly 0 to 18 bytes, now and then
/// up to 4096.
fn hashInChunks(input: []const u8, seed: u64) Digest {
    var rng = TestRng.init(seed);
    var hasher = Hasher.init();
    var rest = input;
    while (rest.len != 0) {
        const a: usize = rng.next();
        const b: usize = rng.next();
        const wanted = if (a < 16) (a * 256 + b) % 4097 else b % 19;
        const size = @min(wanted, rest.len);
        hasher.update(rest[0..size]);
        rest = rest[size..];
    }
    hasher.update(rest);
    return hasher.final();
}

fn expectDigest(expected_hex: []const u8, digest: Digest) !void {
    var buffer: [hex_length]u8 = undefined;
    try testing.expectEqualStrings(expected_hex, digest.toHex(&buffer));
}

/// Hashes `input` in one call, one byte at a time and in pseudo-random
/// chunks. All three must give `expected_hex`.
fn expectHash(expected_hex: []const u8, input: []const u8) !void {
    try expectDigest(expected_hex, hash(input));
    try expectDigest(expected_hex, hashByteWise(input));
    try expectDigest(expected_hex, hashInChunks(input, input.len));
}

/// Checks `compare` in both directions and `compareStrings` on lower case,
/// upper case and mixed input.
fn expectScore(expected: i16, a: Digest, b: Digest) !void {
    try testing.expectEqual(expected, compare(a, b));
    try testing.expectEqual(expected, compare(b, a));

    var buffer_a: [hex_length]u8 = undefined;
    var buffer_b: [hex_length]u8 = undefined;
    _ = a.toHex(&buffer_a);
    _ = b.toHex(&buffer_b);
    try testing.expectEqual(expected, try compareStrings(&buffer_a, &buffer_b));
    for (&buffer_a) |*char| char.* = std.ascii.toUpper(char.*);
    try testing.expectEqual(expected, try compareStrings(&buffer_a, &buffer_b));
    for (&buffer_b) |*char| char.* = std.ascii.toUpper(char.*);
    try testing.expectEqual(expected, try compareStrings(&buffer_a, &buffer_b));
}

fn randomDigest(seed: u64) Digest {
    var digest: Digest = .{ .bytes = undefined };
    var rng = TestRng.init(seed);
    rng.fill(&digest.bytes);
    return digest;
}

/// Writes `times` copies of `pattern` into `buffer` and returns them.
fn repeated(buffer: []u8, pattern: []const u8, times: usize) []const u8 {
    var len: usize = 0;
    for (0..times) |_| {
        @memcpy(buffer[len..][0..pattern.len], pattern);
        len += pattern.len;
    }
    return buffer[0..len];
}

const empty_hex = "0000000000000000000000000000000000000000000000000000000000000000";
const hello_hex = "00210044008200008020081104100044268a8583950424024418045442404424";
const jumps_hex = "02b0b4ae03001086d100c660ab88503545c14ae760282108390a2928020120db";
const jumped_hex = "0292b4ae030550868140c660ab9854d545c048ff602a2308380a2920120120db";

test "transition table is a permutation of 0..255" {
    var seen: [256]bool = @splat(false);
    for (transition) |value| {
        try testing.expect(!seen[value]);
        seen[value] = true;
    }
    for (seen) |was_seen| try testing.expect(was_seen);
}

test "known results" {
    try expectHash(empty_hex, "");
    try expectHash(empty_hex, "a");
    try expectHash(empty_hex, "ab");
    try expectHash("0040000000000000000000000000000000000000000000000000000000000000", "abc");
    try expectHash("0440000000000000000000000000000000100000000000000008000000000000", "abcd");
    try expectHash("0440008000000000000000000000000000100020001200000008001200000050", "abcde");
    try expectHash(hello_hex, "hello world");
    try expectHash(jumps_hex, "The quick brown fox jumps over the lazy dog");
    try expectHash(jumped_hex, "The quick brown fox jumped over the lazy dog");

    var ramp: [1000]u8 = undefined;
    for (&ramp, 0..) |*byte, i| byte.* = @truncate(7 * i + 3);
    try expectHash("7f53b43c252cad2dcc606b6e3037f6fb56c0667bc84ab5383080b99efa003324", &ramp);

    const zeros: [4096]u8 = @splat(0);
    try expectHash("0000000000000200000800004000000200040000200000000010000000800000", &zeros);
}

test "known scores" {
    const jumps = try Digest.parse(jumps_hex);
    const jumped = try Digest.parse(jumped_hex);
    const hello = try Digest.parse(hello_hex);
    try expectScore(128, jumps, jumps);
    try expectScore(106, jumps, jumped);
    try expectScore(18, jumps, hello);

    const all_zero: [hex_length]u8 = @splat('0');
    const all_f: [hex_length]u8 = @splat('f');
    try testing.expectEqual(@as(i16, -128), try compareStrings(&all_zero, &all_f));
    try expectScore(-128, .{ .bytes = @splat(0x00) }, .{ .bytes = @splat(0xff) });
    try expectScore(128, .{ .bytes = @splat(0xff) }, .{ .bytes = @splat(0xff) });
}

test "digest bytes are in output order" {
    // "abc" is a single trigram, so exactly one bit is set: 0x40 in the
    // second output byte, which is bucket 8 * (31 - 1) + 6 = 246.
    const digest = hash("abc");
    for (digest.bytes, 0..) |byte, k| {
        try testing.expectEqual(@as(u8, if (k == 1) 0x40 else 0x00), byte);
    }

    const parsed = try Digest.parse(jumps_hex);
    try testing.expectEqual(@as(u8, 0x02), parsed.bytes[0]);
    try testing.expectEqual(@as(u8, 0xb0), parsed.bytes[1]);
    try testing.expectEqual(@as(u8, 0xdb), parsed.bytes[31]);
}

test "nilsimsa 0.3.8: random content, every length from 0 to 40" {
    var buffer: [40]u8 = undefined;
    for (vectors.random_0_to_40, 0..) |expected, len| {
        const input = buffer[0..len];
        var rng = TestRng.init(len);
        rng.fill(input);
        try expectHash(expected, input);
    }
}

test "nilsimsa 0.3.8: two updates, cut at every position" {
    // Moves the boundary between two `update` calls through the start-up
    // bytes and the steady state.
    var buffer: [40]u8 = undefined;
    for (vectors.random_0_to_40, 0..) |expected, len| {
        const input = buffer[0..len];
        var rng = TestRng.init(len);
        rng.fill(input);
        for (0..len + 1) |cut| {
            var hasher = Hasher.init();
            hasher.update(input[0..cut]);
            hasher.update(input[cut..]);
            try expectDigest(expected, hasher.final());
        }
    }
}

test "nilsimsa 0.3.8: random content, every length from 0 to 1024" {
    var buffer: [1024]u8 = undefined;
    var one_call = Rollup.init();
    var byte_wise = Rollup.init();
    var chunked = Rollup.init();
    for (0..1025) |len| {
        const input = buffer[0..len];
        var rng = TestRng.init(len);
        rng.fill(input);
        one_call.add(hash(input));
        byte_wise.add(hashByteWise(input));
        chunked.add(hashInChunks(input, len));
    }
    try one_call.expect(vectors.random_0_to_1024_sha256);
    try byte_wise.expect(vectors.random_0_to_1024_sha256);
    try chunked.expect(vectors.random_0_to_1024_sha256);
}

test "nilsimsa 0.3.8: four-symbol alphabet, every length from 0 to 512" {
    // Few distinct trigrams, so many buckets tie and sit next to the mean.
    var buffer: [512]u8 = undefined;
    var one_call = Rollup.init();
    var chunked = Rollup.init();
    for (0..513) |len| {
        const input = buffer[0..len];
        var rng = TestRng.init(20000 + len);
        for (input) |*byte| byte.* = "ACGT"[rng.next() & 3];
        one_call.add(hash(input));
        chunked.add(hashInChunks(input, len));
    }
    try one_call.expect(vectors.four_symbols_0_to_512_sha256);
    try chunked.expect(vectors.four_symbols_0_to_512_sha256);
}

test "nilsimsa 0.3.8: runs of a single byte value" {
    var rollup = Rollup.init();
    for (0..256) |value| {
        const run: [100]u8 = @splat(@truncate(value));
        rollup.add(hash(&run));
    }
    try rollup.expect(vectors.byte_runs_sha256);

    var buffer: [4096]u8 = undefined;
    try expectHash(vectors.byte_00_x1000, repeated(&buffer, "\x00", 1000));
    try expectHash(vectors.byte_ff_x4096, repeated(&buffer, "\xff", 4096));
    try expectHash(vectors.byte_61_x33, repeated(&buffer, "a", 33));
    try expectHash(vectors.byte_20_x5, repeated(&buffer, " ", 5));
}

test "nilsimsa 0.3.8: repeated patterns and byte ramps" {
    var buffer: [1024]u8 = undefined;
    try expectHash(vectors.pattern_ab_x500, repeated(&buffer, "ab", 500));
    try expectHash(vectors.pattern_abc_x100, repeated(&buffer, "abc", 100));
    try expectHash(vectors.pattern_00_ff_x128, repeated(&buffer, "\x00\xff", 128));
    try expectHash(vectors.pattern_abcdefg_x37, repeated(&buffer, "abcdefg", 37));

    var ramp: [256]u8 = undefined;
    for (&ramp, 0..) |*byte, i| byte.* = @truncate(i);
    try expectHash(vectors.ramp_ascending, &ramp);
    try expectHash(vectors.ramp_ascending_x4, repeated(&buffer, &ramp, 4));
    for (&ramp, 0..) |*byte, i| byte.* = @truncate(255 - i);
    try expectHash(vectors.ramp_descending, &ramp);
}

const order_head = "Dear customer,\r\n\r\nYour order number ";
const order_tail = ".\r\n\r\nKind regards,\r\nThe shop\r\n";
const order_a = order_head ++ "12345 has shipped and should arrive within three working days" ++ order_tail;
const order_b = order_head ++ "12346 has shipped and should arrive within three working days" ++ order_tail;
const order_c = order_head ++ "12345 has shipped and should arrive within a week or so" ++ order_tail;

test "nilsimsa 0.3.8: text" {
    try expectHash(vectors.text_sentence, "Nilsimsa digests of similar messages share most of their bits.");
    try expectHash(vectors.text_order_a, order_a);
    try expectHash(vectors.text_order_b, order_b);
    try expectHash(vectors.text_order_c, order_c);
    // UTF-8 encoding of a short string with accented Latin letters, kanji
    // and kana, written as escapes to keep this file ASCII.
    try expectHash(
        vectors.text_utf8,
        "na\xc3\xafve caf\xc3\xa9, \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xad\xe3\x82\xb9\xe3\x83\x88",
    );

    try expectScore(vectors.order_a_b_score, hash(order_a), hash(order_b));
    try expectScore(vectors.order_a_c_score, hash(order_a), hash(order_c));
}

test "nilsimsa 0.3.8: about 1 MiB of random content" {
    const mib = 1 << 20;
    const Static = struct {
        var buffer: [mib + 1]u8 = undefined;
    };
    const cases = [_]struct { seed: u64, len: usize, expected: []const u8 }{
        .{ .seed = 0x1234, .len = mib - 1, .expected = vectors.mib_minus_1 },
        .{ .seed = 0x1235, .len = mib, .expected = vectors.mib },
        .{ .seed = 0x1236, .len = mib + 1, .expected = vectors.mib_plus_1 },
    };
    for (cases) |case| {
        const input = Static.buffer[0..case.len];
        var rng = TestRng.init(case.seed);
        rng.fill(input);
        try expectDigest(case.expected, hash(input));
        try expectDigest(case.expected, hashInChunks(input, case.seed));
    }
}

test "nilsimsa 0.3.8: scores of unrelated random digests" {
    for (vectors.random_pair_scores, 0..) |expected, i| {
        try expectScore(expected, randomDigest(5000 + 2 * i), randomDigest(5001 + 2 * i));
    }
}

test "nilsimsa 0.3.8: scores with the leading bits flipped" {
    const flip_counts = [vectors.flipped_bits_scores.len]usize{ 0, 1, 2, 7, 8, 9, 64, 127, 128, 129, 255, 256 };
    const base = randomDigest(6000);
    for (vectors.flipped_bits_scores, flip_counts) |expected, count| {
        var other = base;
        for (0..count) |i| {
            other.bytes[i / 8] ^= @as(u8, 1) << @as(u3, @truncate(i));
        }
        try expectScore(expected, base, other);
    }
}

test "nilsimsa 0.3.8: scores of slightly edited inputs" {
    var base_buffer: [400]u8 = undefined;
    var edit_buffer: [401]u8 = undefined;
    for (0..vectors.edited_input_scores.len / 3) |index| {
        const len = 50 + 13 * index;
        const base = base_buffer[0..len];
        var rng = TestRng.init(7000 + index);
        rng.fill(base);
        const digest = hash(base);

        // One byte substituted.
        @memcpy(edit_buffer[0..len], base);
        edit_buffer[len / 2] ^= 0x01;
        try expectScore(vectors.edited_input_scores[3 * index], digest, hash(edit_buffer[0..len]));

        // One byte deleted.
        const deleted = len / 3;
        @memcpy(edit_buffer[0..deleted], base[0..deleted]);
        @memcpy(edit_buffer[deleted .. len - 1], base[deleted + 1 ..]);
        try expectScore(vectors.edited_input_scores[3 * index + 1], digest, hash(edit_buffer[0 .. len - 1]));

        // One byte inserted.
        const inserted = len / 4;
        @memcpy(edit_buffer[0..inserted], base[0..inserted]);
        edit_buffer[inserted] = 0x2a;
        @memcpy(edit_buffer[inserted + 1 .. len + 1], base[inserted..]);
        try expectScore(vectors.edited_input_scores[3 * index + 2], digest, hash(edit_buffer[0 .. len + 1]));
    }
}

test "final resets the hasher to the zero state" {
    var hasher = Hasher.init();
    hasher.update("The quick brown fox jumps over the lazy dog");
    try expectDigest(jumps_hex, hasher.final());

    for (hasher.counts) |count| try testing.expectEqual(@as(u64, 0), count);
    for (hasher.window) |byte| try testing.expectEqual(@as(u8, 0), byte);
    try testing.expectEqual(@as(u64, 0), hasher.len);

    // Usable again without calling init.
    hasher.update("hello world");
    try expectDigest(hello_hex, hasher.final());
    try expectDigest(empty_hex, hasher.final());
}

test "copying a hasher forks its state" {
    var first = Hasher.init();
    first.update("The quick brown fox jump");
    var second = first;
    first.update("s over the lazy dog");
    second.update("ed over the lazy dog");
    try expectDigest(jumps_hex, first.final());
    try expectDigest(jumped_hex, second.final());
}

test "empty updates change nothing" {
    var hasher = Hasher.init();
    hasher.update("");
    hasher.update("hello");
    hasher.update("");
    hasher.update(" world");
    hasher.update("");
    try expectDigest(hello_hex, hasher.final());
}

test "hasher state stays under 4096 bytes" {
    try testing.expect(@sizeOf(Hasher) < 4096);
}

test "parse accepts lower, upper and mixed case" {
    const upper = "02B0B4AE03001086D100C660AB88503545C14AE760282108390A2928020120DB";
    const mixed = "02b0B4aE03001086d100C660Ab88503545c14Ae760282108390A2928020120dB";
    try expectDigest(jumps_hex, try Digest.parse(jumps_hex));
    try expectDigest(jumps_hex, try Digest.parse(upper));
    try expectDigest(jumps_hex, try Digest.parse(mixed));
    try testing.expectEqual(@as(i16, 106), try compareStrings(upper, jumped_hex));
    try testing.expectEqual(@as(i16, 106), try compareStrings(jumped_hex, mixed));
}

test "parse and toHex round trip" {
    for (0..64) |seed| {
        const digest = randomDigest(9000 + seed);
        var buffer: [hex_length]u8 = undefined;
        const hex = digest.toHex(&buffer);
        try testing.expectEqual(@as(usize, hex_length), hex.len);
        for (hex) |char| try testing.expect(std.ascii.isDigit(char) or (char >= 'a' and char <= 'f'));
        const parsed = try Digest.parse(hex);
        try testing.expectEqualSlices(u8, &digest.bytes, &parsed.bytes);
    }
}

test "parse accepts exactly the hex digits at every position" {
    for (0..hex_length) |position| {
        for (0..256) |value| {
            var text: [hex_length]u8 = jumps_hex.*;
            const char: u8 = @truncate(value);
            text[position] = char;
            if (std.ascii.isHex(char)) {
                _ = try Digest.parse(&text);
            } else {
                try testing.expectError(error.InvalidFormat, Digest.parse(&text));
                try testing.expectError(error.InvalidFormat, compareStrings(&text, jumps_hex));
                try testing.expectError(error.InvalidFormat, compareStrings(jumps_hex, &text));
            }
        }
    }
}

test "parse rejects wrong lengths" {
    const long = jumps_hex ++ jumped_hex ++ hello_hex;
    for (0..long.len + 1) |len| {
        if (len == hex_length) continue;
        try testing.expectError(error.InvalidFormat, Digest.parse(long[0..len]));
        try testing.expectError(error.InvalidFormat, compareStrings(long[0..len], jumps_hex));
        try testing.expectError(error.InvalidFormat, compareStrings(jumps_hex, long[0..len]));
    }
}

test "parse rejects whitespace, prefixes and trailing text" {
    const rejected = [_][]const u8{
        " " ++ jumps_hex,
        jumps_hex ++ " ",
        jumps_hex ++ "\n",
        jumps_hex ++ "\r\n",
        jumps_hex ++ "\x00",
        "0x" ++ jumps_hex,
        "0x" ++ jumps_hex[0..62],
        "0X" ++ jumps_hex[0..62],
        " " ++ jumps_hex[0..63],
        jumps_hex[0..63] ++ " ",
        jumps_hex[0..63] ++ "\n",
        "+" ++ jumps_hex[0..63],
        "-" ++ jumps_hex[0..63],
        jumps_hex[0..31] ++ "_" ++ jumps_hex[32..],
        jumps_hex ++ jumps_hex,
    };
    for (rejected) |text| {
        try testing.expectError(error.InvalidFormat, Digest.parse(text));
        try testing.expectError(error.InvalidFormat, compareStrings(text, jumps_hex));
        try testing.expectError(error.InvalidFormat, compareStrings(jumps_hex, text));
    }
}

// Expected values from the Python package nilsimsa 0.3.8 (generated, do not edit).
const vectors = struct {
    const random_0_to_40 = [41]*const [hex_length]u8{
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000800",
        "0000000000000000000000000008000001000000400000000000000000000400",
        "0000000000240002000202000001000000001006000001020000000000080000",
        "001000000040400010000041010004000400000800a800120008040400020000",
        "000002a00000100080018a0000080080840400040004101200a0012008010000",
        "00501000001000011928001850000002006410101002000420c0000182090026",
        "018004044020000400500030060004010000800b020200209a102052082d1280",
        "03008318820200042010880088b82e000212482a004208002000804005020601",
        "c136008c0432200400c80800048008100908084200331081489e0a2a40051800",
        "14805400888085110202401024c000661848420f02c182143c7260040010001d",
        "20c0300000d2031130980a1c021b020011a9a09620a4190a890205908085d06d",
        "0c028020320d481151c90088444928022754a9e080a1110284086c1408a21001",
        "89ac231189013000e2011949a96088068029042926e0e8771484200e85030b02",
        "0413fe53c200018b00d900480206613d062c24417b0a094888b3a29790430440",
        "9c78062a967041940190d88cd9402835938500bc07887e400148630269241681",
        "736569000a432f027a125685ac00ba74173a0130600f788c362828fc4020c780",
        "06d182b38f9c2998a7420f048e282027dde04904c2ab27c0917a418803ec4a60",
        "8f41d790b5915e2121a00eb105e950020608e8a01b073040d8fba4e34a06d9a1",
        "a8f3085563162dd4790324e0159160cfab427ea5c12041c076454abb0a017c3a",
        "a1b5499202a70b31382309a8f45d3246641055219421b5a1b966fb2ee87e25b5",
        "464f2a821fc031aa3caaeaaa58e4a6a673a4c89fea1a116850a40ee2f6708025",
        "7cd57395387f9110c0d324ca013cd5736d8ae1323e7cbfffb2210da73a08f93b",
        "325d2145a5ae7214dbf5c140d453d3f7cd75466f0d0f916b498c258e54a982d5",
        "938734eff5487344b21d66ba9eb3b3e413c52e0fa8534b1829feb33a65b2a209",
        "fb77cc9cc2adc86947db61163de73b17971066fef7b6bf2e7ec8142f048e0c74",
        "6ff8ffde5f459bdbe8bfbaf01daae93fe25025b56974a37561e978a5b3c68783",
        "0081dfffa61b6e776d8ab17badf9ab6adb59678d08b690886ce39525afe7f4c8",
        "8ef54e133a58ad21ef7adfb8e0f44e185ad8fc52770cebd3d1df71d69cf3262a",
        "66bd386fc325fcb6e6d9fff7cc774b271bd5afbe72ede72fa654af85a91d6aec",
        "79d5e6f03a12fe17993dafb7d5a850b78617bcbe89f4cf3a7e70fcfdfbde9c06",
        "4fbf7ecf30f2754ff54e45b2effbe72c79c27dbfb12ccd3e77c5fad72ccc2cee",
        "f575e680977dcc9f57e77df7cc879e745b1ffcfe73cf2f6dee7bec3037827dd5",
        "3f7dc7857e7e1df91d7dbd3d7a47f99fdfff4f9fbb8966b72fb964fe47e8bd7f",
        "042492880500826818510889c0282291a00229c2128851964d00836c11002042",
        "100004486210251cc00c448208011100a1c1306a028b2a26a0e8281610808ba4",
        "1050057e8511e0201c812201b2541880213002a02f885091426026060c51484c",
        "2072018e8320588262050322400a210aca17200c904a45058584388370522ac8",
        "0510508c50116980c0aa0908b4621081929c31082a884806418136970880281c",
    };
    const random_0_to_1024_sha256 = "05593887b2c341eb678486ec09483592850ef282ec57d199ffde5e1f8f579a8d";
    const byte_runs_sha256 = "a127d524fb4dc46f211fc642897a8c97240deb0217c10fcd388172424973b2bd";
    const four_symbols_0_to_512_sha256 = "4a7cbf40ba0763c460092651041f902f03bb4d6f6d57972c3bb2002b99d277a8";
    const byte_00_x1000 = "0000000000000200000800004000000200040000200000000010000000800000";
    const byte_ff_x4096 = "0400000200200000000001000000102000000000010100000000000000000000";
    const byte_61_x33 = "0000000000009000000000200000080040000000000000040008400000000000";
    const byte_20_x5 = "0000000000020008000000001000000000000000029000000010000000002000";
    const pattern_ab_x500 = "0000028000000000400800200000111440000100220020000008000000000008";
    const pattern_abc_x100 = "00400000440000000005400400003021040408820000000000900000a4200042";
    const pattern_00_ff_x128 = "20410c0100224000002800100010000000000000000002000000100000000020";
    const pattern_abcdefg_x37 = "04e815800080000407800030000a102004388462101308024098203290220978";
    const ramp_ascending = "ff82b79c3d9222156cd841abffadef77ba9695f30c57905f2a386475e749da5a";
    const ramp_descending = "14cccf3ca16e406e417b3536307cc1ea8dae46010dfcc734ffe7d0bfe89c09ee";
    const ramp_ascending_x4 = "ff82b79c3d9222156cd841abffadef77ba9695f30c57905f2a386c75e749da5a";
    const text_sentence = "8e8b0d7f8dc888fe9551b41bccfd9c578723e4ddd5a21b8c470e4038f440f6e8";
    const text_order_a = "57b1ecb717999d85a15b58b9fcece57945e042f591ea72752f670f74403a4ff5";
    const text_order_b = "57b1e4b717198d85a15b58b1fcece57941e042f591ea72759f6f8f74403a4ff5";
    const text_order_c = "15a1eca717c9b985e15b78bbfcec643141cd027cb06272750d670d7440324ef5";
    const text_utf8 = "4c28205a402a281c13624018242b99300491580ac58460030880805ca625320a";
    const mib_minus_1 = "2b15cc5b8022c7e779cb4375f7994dfa91815c5b0d22bf19f4333303051815bc";
    const mib = "6b1c3929ac9089e63518bad16ff8c03a717544cc64f1cc76dd1d88756b9b3d1c";
    const mib_plus_1 = "44547c6f8e583df15299dbd736446cc5632ba5c4880acf35f6c15e128bc9bea7";
    const random_pair_scores = [48]i16{
        -13, -2, -9, 1,  -1, -3, -1,  8,   -3, 10, -13, -4,
        -3,  1,  10, -3, 9,  8,  -1,  0,   2,  2,  5,   19,
        -10, -6, -8, -1, 3,  -9, -14, -6,  -2, 23, -11, -12,
        5,   -4, 13, -3, -2, 8,  11,  -11, 10, 2,  6,   9,
    };
    const flipped_bits_scores = [12]i16{
        128, 127, 126, 121, 120, 119, 64, 1, 0, -1, -127, -128,
    };
    const edited_input_scores = [72]i16{
        110, 109, 109,
        110, 110, 110,
        116, 113, 107,
        114, 117, 119,
        114, 110, 113,
        119, 112, 117,
        116, 119, 113,
        118, 118, 113,
        117, 118, 123,
        122, 116, 119,
        118, 120, 118,
        120, 112, 121,
        121, 119, 116,
        121, 123, 118,
        124, 120, 120,
        124, 118, 122,
        124, 127, 123,
        121, 120, 122,
        121, 124, 117,
        120, 121, 117,
        120, 121, 118,
        121, 121, 92,
        124, 123, 122,
        122, 121, 118,
    };
    const order_a_b_score = 118;
    const order_a_c_score = 95;
};
