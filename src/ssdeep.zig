// SPDX-License-Identifier: MIT
//! Context-triggered piecewise hash compatible with ssdeep 2.14.1.
//!
//! The rolling hash follows Kornblum, Digital Investigation 3S (2006),
//! Figure 2: three unsigned 32-bit states over a 7-byte window.
//! The piece hash is the low 6 bits of an FNV-style mix. Block-size
//! selection, the 32- and 63-character limits, and the comparison score
//! follow the library contract and were checked against the ssdeep program.
//!
//! Level k has block size 3 * 2^k. The hasher keeps per-byte state only for
//! the levels that can still reach the digest:
//!
//! - Levels below `low` are frozen. `low` only moves up when the level above
//!   it already has 32 characters and the input is already longer than
//!   64 block sizes of `low`. From then on the block-size selection in
//!   `finish` cannot pick `low` or anything below it.
//! - Levels at or above `fresh` have never triggered. They all hold the same
//!   piece hash, so one lane (index `fresh`) stands for all of them.
//! - A trigger at level k + 1 is also a trigger at level k, so one test at
//!   level `low` rules out every tracked level.
//!
//! Piece hashes are 6-bit values. Eight of them are packed into one u64 and
//! updated together.

const std = @import("std");

/// 20 digits of block size, ':', 64 characters, ':', 64 characters.
pub const max_string_length = 150;
pub const max_input_length: u64 = 206_158_430_208; // 3 * 2^30 * 64

pub const Options = struct {
    eliminate_sequences: bool = false,
    no_truncate: bool = false,
};

pub const ParseMode = enum { lenient, strict };
pub const ParseError = error{ InvalidFormat, InvalidBlockSize, PartTooLong, InvalidCharacter };

const window_size: usize = 7;
const level_count: usize = 32;
/// Highest level that part 1 can come from. Part 2 comes from one above.
const top_start_level: usize = 30;
const sig_limit: usize = 64;
/// Trigger characters kept per level. One more is appended at the end.
const sig_store: usize = 63;
/// A level needs this many characters before it is used for part 1.
const min_part1_len: usize = 32;
/// The half hash stops following the piece hash at this length.
const half_at: usize = 32;
const piece_init: u8 = 0x27;
const fnv_prime: u32 = 0x01000193;
const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const lanes_per_word: usize = 8;
/// Words used by the scan that covers every level from `low` up.
const wide_words: usize = 5;
/// Lanes are read in whole words starting at `low`, so the arrays are padded.
const lane_count: usize = top_start_level + wide_words * lanes_per_word + 2;

const lane_ones: u64 = 0x0101010101010101;
const lane_low2: u64 = 0x0303030303030303;
const lane_mask: u64 = 0x3f3f3f3f3f3f3f3f;

comptime {
    // The wide scan must reach the lane of `fresh` from any `low`.
    if (wide_words * lanes_per_word < level_count + 1) @compileError("wide scan too narrow");
    if (top_start_level + wide_words * lanes_per_word > lane_count) @compileError("lane arrays too short");
}

const ssdeep = @This();

pub const Hasher = struct {
    // The rest of the API, so that `fuzzyhash.Ssdeep` (this type) carries
    // all of it: `Ssdeep.init`, `Ssdeep.Digest`, `Ssdeep.compare`, ...
    pub const max_string_length = ssdeep.max_string_length;
    pub const max_input_length = ssdeep.max_input_length;
    pub const Options = ssdeep.Options;
    pub const Digest = ssdeep.Digest;
    pub const ParseMode = ssdeep.ParseMode;
    pub const ParseError = ssdeep.ParseError;
    pub const hash = ssdeep.hash;
    pub const compare = ssdeep.compare;
    pub const compareStrings = ssdeep.compareStrings;

    /// Trigger characters of each level, `len[k]` of them in use.
    sig: [level_count][sig_store]u8 = @splat(@splat(0)),
    len: [level_count]u8 = @splat(0),
    /// Piece hash of each level since its last trigger. Lane `fresh` is the
    /// piece hash of every level that has not triggered. Lanes above `fresh`
    /// and below `low` are not meaningful.
    piece: [lane_count]u8 = @splat(piece_init),
    /// Hash since the 31st trigger, for levels `low` to `halved - 1`.
    /// A level with fewer than 32 characters has a half hash equal to its
    /// piece hash, so it is not stored.
    half: [lane_count]u8 = @splat(piece_init),
    /// The last 7 bytes, oldest first.
    window: [window_size]u8 = @splat(0),
    /// Lowest level that is still updated.
    low: u8 = 0,
    /// Lowest level without a trigger.
    fresh: u8 = 0,
    /// Number of levels with at least 32 characters.
    halved: u8 = 0,
    eliminate_sequences: bool = false,
    no_truncate: bool = false,
    overflow: bool = false,
    x: u32 = 0,
    y: u32 = 0,
    z: u32 = 0,
    total: u64 = 0,

    pub fn init(options: ssdeep.Options) Hasher {
        var self = Hasher{};
        self.eliminate_sequences = options.eliminate_sequences;
        self.no_truncate = options.no_truncate;
        return self;
    }

    pub fn update(self: *Hasher, bytes: []const u8) void {
        if (self.overflow) return;
        const len: u64 = @intCast(bytes.len);
        if (self.total > ssdeep.max_input_length or len > ssdeep.max_input_length - self.total) {
            self.overflow = true;
            return;
        }
        // All of `bytes` is consumed below, so the final length is at least
        // this total. `raiseLow` relies on that.
        self.total += len;

        var rest = bytes;
        while (rest.len > 0) {
            self.raiseLow();
            const low: usize = self.low;
            const narrow = @as(usize, self.fresh) < low + 2 * lanes_per_word and
                @as(usize, self.halved) <= low + lanes_per_word;
            const used = if (narrow) self.scan(rest, 2, 1) else self.scan(rest, wide_words, wide_words);
            rest = rest[@min(used, rest.len)..];
        }
    }

    pub fn final(self: *Hasher) error{InputTooLarge}!ssdeep.Digest {
        if (self.overflow or self.total > ssdeep.max_input_length) {
            self.wipe();
            return error.InputTooLarge;
        }
        const digest = self.finish();
        self.wipe();
        return digest;
    }

    /// Zero every byte of the state, padding included.
    fn wipe(self: *Hasher) void {
        @memset(std.mem.asBytes(self), 0);
    }

    /// Stop tracking `low` when `finish` can no longer use it.
    ///
    /// `finish` starts at the smallest level whose block size times 64
    /// covers the input (at most level 30) and steps down while that level
    /// has fewer than 32 characters. If the input is already longer than
    /// 64 blocks of `low`, the start is above `low`. If level `low + 1`
    /// already has 32 characters, the step down stops at `low + 1` or
    /// higher. Lengths and the total never shrink, so both stay true.
    /// Part 1 then comes from `low + 1` or higher and part 2 from one above
    /// that, and level `low` is never read again.
    fn raiseLow(self: *Hasher) void {
        var low: usize = @min(self.low, top_start_level);
        while (low < top_start_level) {
            const span = (@as(u64, 3) << @as(u6, @intCast(low))) * 64;
            if (self.total <= span) break;
            if (self.len[low + 1] < min_part1_len) break;
            low += 1;
        }
        self.low = @intCast(low);
    }

    /// Consume bytes up to and including the first one that triggers level
    /// `low`, or all of `bytes` when none does. Returns the count consumed.
    ///
    /// `piece_words` words of piece lanes and `half_words` words of half
    /// lanes, starting at lane `low`, are carried in locals. The caller
    /// picks counts that cover lanes `low..fresh` and `low..halved - 1`.
    fn scan(self: *Hasher, bytes: []const u8, comptime piece_words: usize, comptime half_words: usize) usize {
        const low: usize = @min(self.low, top_start_level);
        var state: ScanState(piece_words, half_words) = undefined;
        state.x = self.x;
        state.y = self.y;
        state.z = self.z;
        inline for (0..piece_words) |j| state.piece[j] = loadLanes(&self.piece, low + j * lanes_per_word);
        inline for (0..half_words) |j| state.half[j] = loadLanes(&self.half, low + j * lanes_per_word);

        // Level `low` triggers when the low `low` bits of the rolling hash
        // are all ones and the hash is 2 mod 3.
        const ones_mask: u32 = (@as(u32, 1) << @as(u5, @intCast(low))) - 1;
        var used: usize = 0;
        var hit: ?u32 = null;

        // The byte leaving the window comes from the saved window for the
        // first 7 bytes, and from `bytes` itself after that.
        const head = @min(bytes.len, window_size);
        for (bytes[0..head], self.window[0..head]) |byte, old| {
            const rolling = state.step(byte, old);
            used += 1;
            if ((rolling & ones_mask) == ones_mask) {
                // Rare once `low` has moved up. Keeping this a branch keeps
                // the division by 3 out of the common path.
                @branchHint(.unlikely);
                if (rolling % 3 == 2) {
                    hit = rolling;
                    break;
                }
            }
        }
        if (hit == null and bytes.len > window_size) {
            for (bytes[window_size..], bytes[0 .. bytes.len - window_size]) |byte, old| {
                const rolling = state.step(byte, old);
                used += 1;
                if ((rolling & ones_mask) == ones_mask) {
                    @branchHint(.unlikely);
                    if (rolling % 3 == 2) {
                        hit = rolling;
                        break;
                    }
                }
            }
        }

        self.x = state.x;
        self.y = state.y;
        self.z = state.z;
        inline for (0..piece_words) |j| storeLanes(&self.piece, low + j * lanes_per_word, state.piece[j]);
        inline for (0..half_words) |j| storeLanes(&self.half, low + j * lanes_per_word, state.half[j]);
        self.slideWindow(bytes[0..used]);
        if (hit) |rolling| self.trigger(rolling, low);
        return used;
    }

    /// Make `window` the last 7 bytes after `seen` has been consumed.
    fn slideWindow(self: *Hasher, seen: []const u8) void {
        if (seen.len >= window_size) {
            self.window = seen[seen.len - window_size ..][0..window_size].*;
            return;
        }
        const keep = window_size - seen.len;
        var i: usize = 0;
        while (i < keep) : (i += 1) self.window[i] = self.window[i + seen.len];
        for (self.window[keep..], seen) |*slot, byte| slot.* = byte;
    }

    /// Record a trigger. `rolling` is 2 mod 3 and has at least `low`
    /// trailing one bits, so every level from `low` up to its count of
    /// trailing ones has `rolling mod block_size == block_size - 1`.
    fn trigger(self: *Hasher, rolling: u32, low: usize) void {
        const trailing_ones: usize = @ctz(~rolling);
        const top: usize = @min(trailing_ones, level_count - 1);

        // Levels that trigger for the first time take the shared piece hash.
        // The lane above them carries it on for the levels still untouched.
        const fresh: usize = @min(self.fresh, level_count);
        if (top >= fresh) {
            const shared = self.piece[fresh];
            var k: usize = fresh + 1;
            while (k <= top + 1) : (k += 1) self.piece[k] = shared;
            self.fresh = @intCast(top + 1);
        }

        var k: usize = low;
        while (k <= top) : (k += 1) {
            const n: usize = self.len[k];
            // A full level keeps hashing the rest of the input into its
            // last piece.
            if (n >= sig_store) continue;
            const value = self.piece[k] & 0x3f;
            self.sig[k][n] = b64[value];
            self.len[k] = @intCast(n + 1);
            if (n + 1 == half_at) {
                // From here on the half hash is not reset, so the truncated
                // second part can end with the rest of the input.
                self.half[k] = value;
                if (self.halved < k + 1) self.halved = @intCast(k + 1);
            }
            self.piece[k] = piece_init;
        }
    }

    fn finish(self: *const Hasher) ssdeep.Digest {
        const low: usize = @min(self.low, top_start_level);
        var k: usize = 0;
        while (k < top_start_level) {
            const span = (@as(u64, 3) << @as(u6, @intCast(k))) * 64;
            if (span >= self.total) break;
            k += 1;
        }
        // Level `low` is 0 or has at least 32 characters, see `raiseLow`.
        while (k > low and self.len[k] < min_part1_len) k -= 1;

        const rolling: u32 = self.x +% self.y +% self.z;
        const part1 = self.buildPart(k, rolling, false);
        const part2 = self.buildPart(k + 1, rolling, !self.no_truncate);
        return .{
            .block_size = @as(u64, 3) << @as(u6, @intCast(k)),
            .part1 = part1.data,
            .part1_len = part1.len,
            .part2 = part2.data,
            .part2_len = part2.len,
        };
    }

    fn buildPart(self: *const Hasher, level_in: usize, rolling: u32, truncate_half: bool) PartBuf {
        const level: usize = @min(level_in, level_count - 1);
        // A level that never triggered reads the shared lane.
        const lane: usize = @min(level, @as(usize, self.fresh));
        var raw: [sig_limit]u8 = @splat(0);
        var raw_len: usize = @min(@as(usize, self.len[level]), sig_store);
        var tail: u8 = self.piece[lane];
        if (truncate_half and raw_len >= half_at) {
            raw_len = half_at - 1;
            tail = self.half[level];
        }
        var i: usize = 0;
        while (i < raw_len) : (i += 1) raw[i] = self.sig[level][i];
        if (rolling != 0 and i < sig_limit) {
            raw[i] = b64[tail & 0x3f];
            i += 1;
        }
        var out: [sig_limit]u8 = @splat(0);
        const n: usize = if (self.eliminate_sequences) collapseBytes(raw[0..i], &out) else copyBytes(raw[0..i], &out);
        return .{ .data = out, .len = @intCast(n) };
    }
};

/// Rolling hash and packed piece hashes held in locals during a scan.
fn ScanState(comptime piece_words: usize, comptime half_words: usize) type {
    return struct {
        x: u32,
        y: u32,
        z: u32,
        piece: [piece_words]u64,
        half: [half_words]u64,

        /// Feed one byte. `old` is the byte from 7 positions back.
        /// Returns the rolling hash.
        inline fn step(state: *@This(), byte: u8, old: u8) u32 {
            // Figure 2 of the paper, all arithmetic mod 2^32. y is updated
            // from the previous x, then x drops the byte that leaves the
            // window. z shifts away bytes older than the window.
            state.y = state.y -% state.x +% @as(u32, window_size) *% @as(u32, byte);
            state.x = state.x +% @as(u32, byte) -% @as(u32, old);
            state.z = (state.z << 5) ^ @as(u32, byte);
            const spread = @as(u64, byte) * lane_ones;
            inline for (&state.piece) |*word| word.* = laneStep(word.*, spread);
            inline for (&state.half) |*word| word.* = laneStep(word.*, spread);
            return state.x +% state.y +% state.z;
        }
    };
}

/// Piece hash update on eight 6-bit lanes at once. `spread` holds the input
/// byte in every lane.
///
/// Only the low 6 bits of the piece hash are ever used, and they depend only
/// on the low 6 bits of the previous value: h' = (h * 19 xor byte) mod 64,
/// because the FNV prime is 19 mod 64. With h < 64 in each 8-bit lane,
/// 19 * h mod 64 == (3 * h + 16 * (h mod 4)) mod 64, and
/// 3 * h + 16 * (h mod 4) <= 189 + 48, so no lane carries into the next.
inline fn laneStep(word: u64, spread: u64) u64 {
    return ((word *% 3 +% ((word & lane_low2) << 4)) ^ spread) & lane_mask;
}

fn loadLanes(lanes: *const [lane_count]u8, at: usize) u64 {
    const start = @min(at, lane_count - lanes_per_word);
    return @bitCast(lanes[start..][0..lanes_per_word].*);
}

fn storeLanes(lanes: *[lane_count]u8, at: usize, word: u64) void {
    const start = @min(at, lane_count - lanes_per_word);
    lanes[start..][0..lanes_per_word].* = @bitCast(word);
}

pub fn hash(bytes: []const u8, options: Options) error{InputTooLarge}!Digest {
    var hasher = Hasher.init(options);
    hasher.update(bytes);
    return hasher.final();
}

const PartBuf = struct {
    data: [sig_limit]u8,
    len: u8,
};

/// One byte of the piece hash as the paper states it. The hasher uses
/// `laneStep`. This form is kept for the test that ties the two together.
fn pieceUpdate(h: u8, byte: u8) u8 {
    const mixed = (@as(u32, h) *% fnv_prime) ^ @as(u32, byte);
    return @intCast(mixed & 0x3f);
}

fn copyBytes(src: []const u8, dest: *[sig_limit]u8) usize {
    const n = @min(src.len, dest.len);
    var i: usize = 0;
    while (i < n) : (i += 1) dest[i] = src[i];
    return n;
}

/// Copy `src`, keeping at most three of any run of equal characters.
fn collapseBytes(src: []const u8, dest: *[sig_limit]u8) usize {
    var n: usize = 0;
    var run: u8 = 0;
    var prev: u8 = 0;
    for (src) |ch| {
        if (n >= dest.len) break;
        if (n != 0 and ch == prev and run >= 3) continue;
        if (n != 0 and ch == prev) {
            run += 1;
        } else {
            prev = ch;
            run = 1;
        }
        dest[n] = ch;
        n += 1;
    }
    return n;
}

pub const Digest = struct {
    block_size: u64,
    part1: [sig_limit]u8,
    part1_len: u8,
    part2: [sig_limit]u8,
    part2_len: u8,

    /// Write the whole digest. `max_string_length` covers the longest case.
    pub fn toString(self: Digest, out: *[max_string_length]u8) []const u8 {
        var i: usize = 0;
        i = appendU64(out, i, self.block_size);
        i = appendByte(out, i, ':');
        const n1 = @min(@as(usize, self.part1_len), self.part1.len);
        var p: usize = 0;
        while (p < n1) : (p += 1) i = appendByte(out, i, self.part1[p]);
        i = appendByte(out, i, ':');
        const n2 = @min(@as(usize, self.part2_len), self.part2.len);
        p = 0;
        while (p < n2) : (p += 1) i = appendByte(out, i, self.part2[p]);
        return out[0..i];
    }

    /// Read `blocksize:part1:part2`, optionally followed by a comma and
    /// anything else, such as the file name ssdeep prints.
    ///
    /// The block size is the leading decimal digits. At least one is
    /// required. In lenient mode any text between those digits and the
    /// first colon is ignored, so `6x:ABC:DEF` reads like `6:ABC:DEF`.
    /// In strict mode the colon must follow the digits directly.
    ///
    /// The string can be of any length. Each character before the comma is
    /// looked at once, at most 64 characters are kept per part, and nothing
    /// after the comma is read. Runs of more than three equal characters
    /// are shortened to three while reading, so a long run does not make a
    /// part too long.
    pub fn parse(text: []const u8, mode: ParseMode) ParseError!Digest {
        // An empty string, a leading '+' or leading whitespace has no
        // leading digit and is rejected.
        const head = readBlockSize(text) orelse return error.InvalidFormat;
        var i: usize = head.end;
        if (mode == .lenient) {
            // Whatever stands between the digits and the first colon is
            // skipped, as ssdeep does. Strict mode wants the colon here.
            while (i < text.len and text[i] != ':') i += 1;
        }
        if (i >= text.len or text[i] != ':') return error.InvalidFormat;
        i += 1;

        var part1: [sig_limit]u8 = @splat(0);
        var part1_len: u8 = 0;
        i = try readPart(text, i, ':', &part1, &part1_len, mode);
        if (i >= text.len or text[i] != ':') return error.InvalidFormat;
        i += 1;

        var part2: [sig_limit]u8 = @splat(0);
        var part2_len: u8 = 0;
        _ = try readPart(text, i, ',', &part2, &part2_len, mode);

        if (mode == .strict and !isLegalBlockSize(head.value)) return error.InvalidBlockSize;
        return .{
            .block_size = head.value,
            .part1 = part1,
            .part1_len = part1_len,
            .part2 = part2,
            .part2_len = part2_len,
        };
    }
};

const BlockSizeText = struct {
    value: u64,
    /// Index of the first character after the digits.
    end: usize,
};

/// Read the leading decimal digits of `text`. A value too large for 64 bits
/// reads as the largest 64-bit value. Null when `text` has no leading digit.
fn readBlockSize(text: []const u8) ?BlockSizeText {
    var value: u64 = 0;
    var i: usize = 0;
    while (i < text.len and text[i] >= '0' and text[i] <= '9') : (i += 1) {
        const digit: u64 = text[i] - '0';
        value = (value *| 10) +| digit;
    }
    if (i == 0) return null;
    return .{ .value = value, .end = i };
}

fn appendU64(out: *[max_string_length]u8, at: usize, value: u64) usize {
    var tmp: [20]u8 = undefined;
    var n: usize = 0;
    var x = value;
    if (x == 0) {
        return appendByte(out, at, '0');
    }
    while (x > 0 and n < tmp.len) {
        tmp[n] = @intCast('0' + (x % 10));
        n += 1;
        x /= 10;
    }
    var i = at;
    while (n > 0) {
        n -= 1;
        i = appendByte(out, i, tmp[n]);
    }
    return i;
}

fn appendByte(out: *[max_string_length]u8, i: usize, ch: u8) usize {
    if (i >= out.len) return i;
    out[i] = ch;
    return i + 1;
}

fn readPart(
    text: []const u8,
    start: usize,
    delim: u8,
    out: *[sig_limit]u8,
    out_len: *u8,
    mode: ParseMode,
) ParseError!usize {
    var i = start;
    var n: usize = 0;
    var run: u8 = 0;
    var prev: u8 = 0;
    while (i < text.len and text[i] != delim) : (i += 1) {
        const ch = text[i];
        if (mode == .strict and !isB64(ch)) return error.InvalidCharacter;
        if (n != 0 and ch == prev and run >= 3) continue;
        if (n != 0 and ch == prev) {
            run += 1;
        } else {
            prev = ch;
            run = 1;
        }
        if (n >= out.len) return error.PartTooLong;
        out[n] = ch;
        n += 1;
    }
    out_len.* = @intCast(n);
    return i;
}

fn isB64(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '+' or c == '/';
}

/// True for 3 * 2^k with k from 0 to 30, the block sizes the hasher emits.
fn isLegalBlockSize(bs: u64) bool {
    if (bs < 3 or bs % 3 != 0) return false;
    const q = bs / 3;
    if (q > (@as(u64, 1) << top_start_level)) return false;
    return q & (q - 1) == 0;
}

pub fn compare(a: Digest, b: Digest) u8 {
    var a1_buf: [sig_limit]u8 = @splat(0);
    var a2_buf: [sig_limit]u8 = @splat(0);
    var b1_buf: [sig_limit]u8 = @splat(0);
    var b2_buf: [sig_limit]u8 = @splat(0);
    const a1 = a1_buf[0..collapseBytes(partBytes(&a.part1, a.part1_len), &a1_buf)];
    const a2 = a2_buf[0..collapseBytes(partBytes(&a.part2, a.part2_len), &a2_buf)];
    const b1 = b1_buf[0..collapseBytes(partBytes(&b.part1, b.part1_len), &b1_buf)];
    const b2 = b2_buf[0..collapseBytes(partBytes(&b.part2, b.part2_len), &b2_buf)];

    if (a.block_size == b.block_size and std.mem.eql(u8, a1, b1) and std.mem.eql(u8, a2, b2)) {
        return 100;
    }
    if (a.block_size == b.block_size) {
        const s1 = scorePair(a1, b1, a.block_size);
        // Part 2 belongs to twice the block size. When that value does not
        // fit in 64 bits, part 2 is not compared and scores 0.
        const s2 = if (doubled(a.block_size)) |two| scorePair(a2, b2, two) else 0;
        return if (s1 > s2) s1 else s2;
    }
    if (doubled(a.block_size)) |two| {
        if (two == b.block_size) return scorePair(a2, b1, b.block_size);
    }
    if (doubled(b.block_size)) |two| {
        if (two == a.block_size) return scorePair(a1, b2, a.block_size);
    }
    return 0;
}

/// Score two digest strings.
///
/// The block sizes are read first. A string with no leading digit is an
/// error. When the block sizes are neither equal nor one twice the other,
/// the score is 0 and the rest of both strings is not looked at. Otherwise
/// both strings must parse.
pub fn compareStrings(a: []const u8, b: []const u8) ParseError!u8 {
    const head_a = readBlockSize(a) orelse return error.InvalidFormat;
    const head_b = readBlockSize(b) orelse return error.InvalidFormat;
    if (!comparableBlockSizes(head_a.value, head_b.value)) return 0;
    const da = try Digest.parse(a, .lenient);
    const db = try Digest.parse(b, .lenient);
    return compare(da, db);
}

fn comparableBlockSizes(a: u64, b: u64) bool {
    if (a == b) return true;
    if (doubled(a)) |two| {
        if (two == b) return true;
    }
    if (doubled(b)) |two| {
        if (two == a) return true;
    }
    return false;
}

fn partBytes(part: *const [sig_limit]u8, len: u8) []const u8 {
    return part[0..@min(@as(usize, len), part.len)];
}

/// Twice `bs`, or null when that does not fit in 64 bits.
fn doubled(bs: u64) ?u64 {
    if (bs > std.math.maxInt(u64) / 2) return null;
    return bs * 2;
}

fn scorePair(a: []const u8, b: []const u8, block_size: u64) u8 {
    if (a.len < 7 or b.len < 7 or !sharesSubstring(a, b, 7)) return 0;
    const common = @as(usize, lcsLen(a, b));
    const sum = a.len + b.len;
    const dist = sum - 2 * common;
    const scaled = (dist * 64) / sum;
    const percent = (100 * scaled) / 64;
    var score: usize = 100 - percent;
    if (block_size < 45) {
        // block_size is below 45 here, so the cap fits in usize on wasm32.
        const cap: usize = @intCast((block_size / 3) * @min(a.len, b.len));
        if (score > cap) score = cap;
    }
    return @intCast(score);
}

fn sharesSubstring(a: []const u8, b: []const u8, comptime n: usize) bool {
    if (a.len < n or b.len < n) return false;
    var i: usize = 0;
    while (i + n <= a.len) : (i += 1) {
        var j: usize = 0;
        while (j + n <= b.len) : (j += 1) {
            var k: usize = 0;
            var same = true;
            while (k < n) : (k += 1) {
                if (a[i + k] != b[j + k]) {
                    same = false;
                    break;
                }
            }
            if (same) return true;
        }
    }
    return false;
}

fn lcsLen(a: []const u8, b: []const u8) u8 {
    var prev: [sig_limit + 1]u8 = @splat(0);
    var cur: [sig_limit + 1]u8 = @splat(0);
    const width = @min(b.len, sig_limit);
    for (a) |ca| {
        cur[0] = 0;
        var j: usize = 0;
        while (j < width) : (j += 1) {
            if (ca == b[j]) {
                cur[j + 1] = prev[j] + 1;
            } else {
                cur[j + 1] = @max(cur[j], prev[j + 1]);
            }
        }
        prev = cur;
    }
    return prev[width];
}

comptime {
    if (@sizeOf(Hasher) >= 4096) @compileError("Hasher state is 4096 bytes or larger");
}

// Tests. Expected digests and scores were recorded from ssdeep 2.14.1.

const a100: [100]u8 = @splat('a');
const a200: [200]u8 = @splat('a');
const a300: [300]u8 = @splat('a');
const b500: [500]u8 = @splat('b');

fn expectHash(bytes: []const u8, expected: []const u8) !void {
    const d = try hash(bytes, .{});
    var buf: [max_string_length]u8 = undefined;
    const got = d.toString(&buf);
    try std.testing.expectEqualStrings(expected, got);
}

fn optionsFromFlags(flags: u8) Options {
    return .{ .eliminate_sequences = flags & 1 != 0, .no_truncate = flags & 2 != 0 };
}

test "hasher state stays under 3KB" {
    try std.testing.expect(@sizeOf(Hasher) < 3072);
}

test "lane step equals the scalar piece hash" {
    var h: u8 = 0;
    while (h < 64) : (h += 1) {
        var byte: usize = 0;
        while (byte < 256) : (byte += 1) {
            const b: u8 = @intCast(byte);
            // Put h in every lane and a different value next to it, to show
            // that lanes do not disturb each other.
            const other: u8 = 63 - h;
            const word = @as(u64, h) * lane_ones;
            const mixed = (@as(u64, h) * 0x0001000100010001) | (@as(u64, other) * 0x0100010001000100);
            const spread = @as(u64, b) * lane_ones;
            const want = pieceUpdate(h, b);
            const want_other = pieceUpdate(other, b);
            try std.testing.expectEqual(@as(u64, want) * lane_ones, laneStep(word, spread));
            try std.testing.expectEqual(
                (@as(u64, want) * 0x0001000100010001) | (@as(u64, want_other) * 0x0100010001000100),
                laneStep(mixed, spread),
            );
        }
    }
}

test "trigger rule without division matches the modulo form" {
    // rolling mod (3 * 2^k) == 3 * 2^k - 1 exactly when rolling is 2 mod 3
    // and its low k bits are ones.
    var seed: u32 = 0x9e3779b9;
    var n: usize = 0;
    while (n < 20000) : (n += 1) {
        seed = seed *% 1664525 +% 1013904223;
        // Force long runs of trailing ones on some samples.
        const fill: u5 = @intCast((seed >> 27) & 31);
        const rolling: u32 = if (n % 3 == 0) seed | ((@as(u32, 1) << fill) - 1) else seed;
        var k: usize = 0;
        while (k < level_count) : (k += 1) {
            const bs: u64 = @as(u64, 3) << @as(u6, @intCast(k));
            const by_modulo = @as(u64, rolling) % bs == bs - 1;
            const by_bits = rolling % 3 == 2 and @as(usize, @ctz(~rolling)) >= k;
            try std.testing.expectEqual(by_modulo, by_bits);
        }
    }
    try std.testing.expect(@as(u32, 0xffffffff) % 3 != 2);
    try std.testing.expect(@as(u32, 0x7fffffff) % 3 != 2);
    try std.testing.expect(@as(u32, 0xbfffffff) % 3 == 2);
}

test "toString fits a 108-byte digest exactly" {
    var part1: [64]u8 = undefined;
    var part2: [64]u8 = undefined;
    for (&part1, 0..) |*c, i| c.* = 'A' + @as(u8, @intCast(i % 26));
    for (&part2, 0..) |*c, i| c.* = 'a' + @as(u8, @intCast(i % 26));
    const d = Digest{
        .block_size = 3_221_225_472,
        .part1 = part1,
        .part1_len = 64,
        .part2 = part2,
        .part2_len = 32,
    };
    var buf: [max_string_length]u8 = undefined;
    const s = d.toString(&buf);
    try std.testing.expectEqual(@as(usize, 108), s.len);
    try std.testing.expectEqualStrings("3221225472:", s[0..11]);
    try std.testing.expectEqual(@as(u8, ':'), s[75]);
    try std.testing.expectEqualSlices(u8, part1[0..], s[11..75]);
    try std.testing.expectEqualSlices(u8, part2[0..32], s[76..108]);
    const parsed = try Digest.parse(s, .strict);
    try std.testing.expectEqual(d.block_size, parsed.block_size);
    try std.testing.expectEqualSlices(u8, part1[0..], parsed.part1[0..parsed.part1_len]);
    try std.testing.expectEqualSlices(u8, part2[0..32], parsed.part2[0..parsed.part2_len]);
}

test "toString writes the longest digest in full" {
    var part1: [64]u8 = undefined;
    var part2: [64]u8 = undefined;
    for (&part1, 0..) |*c, i| c.* = 'A' + @as(u8, @intCast(i % 26));
    for (&part2, 0..) |*c, i| c.* = 'a' + @as(u8, @intCast(i % 26));
    const d = Digest{
        .block_size = std.math.maxInt(u64),
        .part1 = part1,
        .part1_len = 64,
        .part2 = part2,
        .part2_len = 64,
    };
    var buf: [max_string_length]u8 = undefined;
    const s = d.toString(&buf);
    try std.testing.expectEqual(@as(usize, 150), max_string_length);
    try std.testing.expectEqual(@as(usize, 150), s.len);
    try std.testing.expectEqualStrings("18446744073709551615:", s[0..21]);
    try std.testing.expectEqualSlices(u8, part1[0..], s[21..85]);
    try std.testing.expectEqual(@as(u8, ':'), s[85]);
    try std.testing.expectEqualSlices(u8, part2[0..], s[86..150]);
    const parsed = try Digest.parse(s, .lenient);
    try std.testing.expectEqual(d.block_size, parsed.block_size);
    try std.testing.expectEqual(@as(u8, 64), parsed.part1_len);
    try std.testing.expectEqual(@as(u8, 64), parsed.part2_len);
    try std.testing.expectEqual(@as(u8, 100), compare(d, parsed));
}

test "known digests from ssdeep 2.14.1" {
    try expectHash("", "3::");
    try expectHash("a", "3:E:E");
    try expectHash("A", "3:k:k");
    try expectHash("hello", "3:iKn:p");
    try expectHash("abc", "3:uG:uG");
    try expectHash("aaaa", "3:tt:j");
    try expectHash(&a100, "3:tjx:D");
    try expectHash(&a200, "3:tjt:f");
    try expectHash(&a300, "3:tjp:7");
    try expectHash(&b500, "3:HHHH:n");
    try expectHash("The quick brown fox jumps over the lazy dog", "3:FJKKIUKact:FHIGi");

    var zeros: [16]u8 = @splat(0);
    try expectHash(&zeros, "3::");

    var seq: [256]u8 = undefined;
    for (&seq, 0..) |*b, i| b.* = @intCast(i);
    try expectHash(&seq, "6:Iq103+54vmkCNMvWRQzaLhMvmNKzuxBJB16LO5SfG9YmorO0+7ymBADOMeLsGYba:Iq103+54vmkCNMvWRQzaLhMvmNKzuxB9");
}

const FullCase = struct {
    kind: enum { sequential, mod251_1000, mod251_20000, mixed_5000, b_500 },
    flags: []const u8,
    digest: []const u8,
};

const full_cases = [_]FullCase{
    .{ .kind = .sequential, .flags = &.{ 0, 1 }, .digest = "6:Iq103+54vmkCNMvWRQzaLhMvmNKzuxBJB16LO5SfG9YmorO0+7ymBADOMeLsGYba:Iq103+54vmkCNMvWRQzaLhMvmNKzuxB9" },
    .{ .kind = .sequential, .flags = &.{ 2, 3 }, .digest = "6:Iq103+54vmkCNMvWRQzaLhMvmNKzuxBJB16LO5SfG9YmorO0+7ymBADOMeLsGYba:Iq103+54vmkCNMvWRQzaLhMvmNKzuxBJB16LO5SfG9YmorO0+7ymBADOMeLsGYba" },
    .{ .kind = .mod251_1000, .flags = &.{ 0, 1 }, .digest = "24:X+OmvmLeO22LSeKufL6uS+iv+7ym2/eL+u2/m7muTL2fP+OmvmLeO22LSeKufL6N:XDfLTTLTDfLTTf7fTL377fTLMDfLTTLO" },
    .{ .kind = .mod251_1000, .flags = &.{ 2, 3 }, .digest = "24:X+OmvmLeO22LSeKufL6uS+iv+7ym2/eL+u2/m7muTL2fP+OmvmLeO22LSeKufL6N:XDfLTTLTDfLTTf7fTL377fTLMDfLTTLTDfLTTf7fTL377fTLMDfLTTLTDfLTTf7h" },
    .{ .kind = .mod251_20000, .flags = &.{ 0, 1, 2, 3 }, .digest = "192:znnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknn0:n" },
    .{ .kind = .mixed_5000, .flags = &.{ 0, 1 }, .digest = "96:wXDbvjnbTrXz3LvLb7bv//jHrPXXDbvjnbTrXz3LvLb7bv//jHrPXXDbvjnbTrXA:unnHX3n3XHHnnHX3n3XHHnnHX3n3XHHM" },
    .{ .kind = .mixed_5000, .flags = &.{ 2, 3 }, .digest = "96:wXDbvjnbTrXz3LvLb7bv//jHrPXXDbvjnbTrXz3LvLb7bv//jHrPXXDbvjnbTrXA:unnHX3n3XHHnnHX3n3XHHnnHX3n3XHHnnHX3n3XHHnnHX3n3XHHnnHX3n3XHs" },
    .{ .kind = .b_500, .flags = &.{ 0, 2 }, .digest = "3:HHHH:n" },
    .{ .kind = .b_500, .flags = &.{ 1, 3 }, .digest = "3:HHH:n" },
};

fn fillFullCase(case: FullCase, buf: *[20000]u8) []const u8 {
    switch (case.kind) {
        .sequential => {
            for (buf[0..256], 0..) |*b, i| b.* = @intCast(i);
            return buf[0..256];
        },
        .mod251_1000 => {
            for (buf[0..1000], 0..) |*b, i| b.* = @intCast(i % 251);
            return buf[0..1000];
        },
        .mod251_20000 => {
            for (buf[0..20000], 0..) |*b, i| b.* = @intCast(i % 251);
            return buf[0..20000];
        },
        .mixed_5000 => {
            for (buf[0..5000], 0..) |*b, i| b.* = @intCast((i * 7 + i / 13) % 256);
            return buf[0..5000];
        },
        .b_500 => {
            for (buf[0..500]) |*b| b.* = 'b';
            return buf[0..500];
        },
    }
}

test "full digests for every flag combination" {
    var data: [20000]u8 = undefined;
    var text: [max_string_length]u8 = undefined;
    var text2: [max_string_length]u8 = undefined;
    for (full_cases) |case| {
        const input = fillFullCase(case, &data);
        for (case.flags) |flags| {
            const options = optionsFromFlags(flags);
            const d = try hash(input, options);
            try std.testing.expectEqualStrings(case.digest, d.toString(&text));

            // Streamed in uneven pieces.
            var split = Hasher.init(options);
            var off: usize = 0;
            var step: usize = 1;
            while (off < input.len) {
                const take = @min(step, input.len - off);
                split.update(input[off..][0..take]);
                off += take;
                step = step % 97 + 3;
            }
            const d2 = try split.final();
            try std.testing.expectEqualStrings(case.digest, d2.toString(&text));

            // The printed form reads back to the same digest.
            for ([_]ParseMode{ .lenient, .strict }) |mode| {
                const parsed = try Digest.parse(case.digest, mode);
                try std.testing.expectEqual(d.block_size, parsed.block_size);
                if (flags & 1 != 0 or case.kind != .b_500) {
                    try std.testing.expectEqualStrings(case.digest, parsed.toString(&text2));
                    try std.testing.expectEqualSlices(u8, d.part1[0..d.part1_len], parsed.part1[0..parsed.part1_len]);
                    try std.testing.expectEqualSlices(u8, d.part2[0..d.part2_len], parsed.part2[0..parsed.part2_len]);
                } else {
                    // Parsing keeps at most three of a run, like compare does.
                    try std.testing.expectEqualStrings("3:HHH:n", parsed.toString(&text2));
                }
                try std.testing.expectEqual(@as(u8, 100), compare(d, parsed));
            }
            try std.testing.expectEqual(@as(u8, 100), try compareStrings(case.digest, case.digest));
        }
    }
}

test "chunk splits do not change the digest" {
    const text = "The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs.";
    const whole = try hash(text, .{});
    var buf_a: [max_string_length]u8 = undefined;
    var buf_b: [max_string_length]u8 = undefined;
    const whole_s = whole.toString(&buf_a);

    var step: usize = 1;
    while (step < text.len) : (step += 1) {
        var h = Hasher.init(.{});
        var off: usize = 0;
        while (off < text.len) {
            const n = @min(step, text.len - off);
            h.update(text[off .. off + n]);
            off += n;
        }
        const d = try h.final();
        const got = d.toString(&buf_b);
        try std.testing.expectEqualStrings(whole_s, got);
    }
}

test "chunk splits across level changes do not change the digest" {
    // 40000 bytes move `low` up several times. Every flag combination and
    // several chunk sizes must agree with the one-call digest.
    var data: [40000]u8 = undefined;
    var seed: u32 = 12345;
    for (&data, 0..) |*b, i| {
        seed = seed *% 1103515245 +% 12345;
        // A stretch of low-entropy bytes in the middle.
        b.* = if (i >= 9000 and i < 15000) @intCast((seed >> 16) & 3) else @intCast((seed >> 16) & 0xff);
    }
    const lengths = [_]usize{ 0, 1, 6, 7, 8, 191, 192, 193, 384, 385, 4095, 12288, 12289, 24577, 40000 };
    const steps = [_]usize{ 1, 2, 5, 7, 8, 13, 64, 1000 };
    var flags: u8 = 0;
    while (flags < 4) : (flags += 1) {
        const options = optionsFromFlags(flags);
        for (lengths) |n| {
            const whole = try hash(data[0..n], options);
            var buf_a: [max_string_length]u8 = undefined;
            var buf_b: [max_string_length]u8 = undefined;
            const whole_s = whole.toString(&buf_a);
            for (steps) |step| {
                var h = Hasher.init(options);
                var off: usize = 0;
                while (off < n) {
                    const take = @min(step, n - off);
                    h.update(data[off..][0..take]);
                    off += take;
                }
                const d = try h.final();
                try std.testing.expectEqualStrings(whole_s, d.toString(&buf_b));
            }
        }
    }
}

test "ten megabyte stream recorded from ssdeep 2.14.1" {
    var h = Hasher.init(.{});
    var buf: [8192]u8 = undefined;
    var index: u64 = 0;
    const n: u64 = 10_000_000;
    while (index < n) {
        var filled: usize = 0;
        while (filled < buf.len and index < n) {
            buf[filled] = @intCast(index % 251);
            filled += 1;
            index += 1;
        }
        h.update(buf[0..filled]);
    }
    const d = try h.final();
    var text: [max_string_length]u8 = undefined;
    try std.testing.expectEqualStrings(
        "192:znnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnnknnE:n",
        d.toString(&text),
    );
}

test "copying a hasher forks its state" {
    var h = Hasher.init(.{});
    h.update("The quick ");
    var fork = h;
    h.update("brown fox jumps over the lazy dog");
    fork.update("brown fox jumps over the lazy dog");
    const a = try h.final();
    const b = try fork.final();
    var ba: [max_string_length]u8 = undefined;
    var bb: [max_string_length]u8 = undefined;
    try std.testing.expectEqualStrings(a.toString(&ba), b.toString(&bb));
    try expectHash("The quick brown fox jumps over the lazy dog", a.toString(&ba));
}

test "final zeroes the hasher" {
    var h = Hasher.init(.{ .eliminate_sequences = true });
    h.update("hello");
    const d = try h.final();
    try std.testing.expectEqual(@as(u64, 3), d.block_size);
    try std.testing.expectEqual(@as(u64, 0), h.total);
    try std.testing.expectEqual(false, h.eliminate_sequences);
    try std.testing.expectEqual(@as(u8, 0), h.piece[0]);
    try std.testing.expectEqual(@as(u32, 0), h.x);
    for (std.mem.asBytes(&h)) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    // Using a zeroed hasher without init gives a meaningless digest, but it
    // must not trap.
    h.update("some more bytes after final");
    _ = try h.final();
}

test "input longer than the limit is an error" {
    var h = Hasher.init(.{});
    h.total = max_input_length;
    h.update(&[_]u8{1});
    try std.testing.expectError(error.InputTooLarge, h.final());
    try std.testing.expectEqual(@as(u64, 0), h.total);

    var h2 = Hasher.init(.{});
    h2.total = max_input_length;
    h2.update(&[_]u8{});
    const d = try h2.final();
    var buf: [max_string_length]u8 = undefined;
    try std.testing.expectEqualStrings("3::", d.toString(&buf));
}

test "eliminate_sequences shortens runs in the output" {
    const raw = try hash(&b500, .{});
    const cut = try hash(&b500, .{ .eliminate_sequences = true });
    var br: [max_string_length]u8 = undefined;
    var bc: [max_string_length]u8 = undefined;
    try std.testing.expectEqualStrings("3:HHHH:n", raw.toString(&br));
    try std.testing.expectEqualStrings("3:HHH:n", cut.toString(&bc));
    try std.testing.expectEqual(@as(u8, 100), compare(raw, cut));
}

test "no_truncate keeps a longer second part when the half would cut it" {
    var seq: [256]u8 = undefined;
    for (&seq, 0..) |*b, i| b.* = @intCast(i);
    const cut = try hash(&seq, .{});
    const full = try hash(&seq, .{ .no_truncate = true });
    try std.testing.expect(full.part2_len >= cut.part2_len);
    try std.testing.expect(full.part2_len > 32);
    try std.testing.expectEqualSlices(u8, cut.part1[0..cut.part1_len], full.part1[0..full.part1_len]);

    // Both parts are 64 characters. toString writes all 131 bytes.
    var buf: [max_string_length]u8 = undefined;
    const written = full.toString(&buf);
    try std.testing.expectEqual(@as(usize, 2 + 64 + 1 + 64), written.len);
    try std.testing.expectEqual(@as(u8, 64), full.part1_len);
    try std.testing.expectEqual(@as(u8, 64), full.part2_len);
    try std.testing.expectEqualSlices(u8, full.part2[0..64], written[67..131]);
}

test "parse and compareStrings" {
    const d = try Digest.parse("3:E:E,\"a\"", .strict);
    var buf: [max_string_length]u8 = undefined;
    try std.testing.expectEqualStrings("3:E:E", d.toString(&buf));

    const collapsed = try Digest.parse("3:AAAAAAA:BBBBBBB", .lenient);
    try std.testing.expectEqualStrings("3:AAA:BBB", collapsed.toString(&buf));
    try std.testing.expectEqual(@as(u8, 100), try compareStrings("3:AAAA:AAAA", "3:AAA:AAA"));

    try std.testing.expectError(error.InvalidFormat, Digest.parse(" 3:E:E", .lenient));
    try std.testing.expectError(error.InvalidFormat, Digest.parse("+3:E:E", .strict));
    try std.testing.expectError(error.InvalidFormat, Digest.parse("3:E", .lenient));
    try std.testing.expectError(error.InvalidFormat, Digest.parse("", .lenient));
    try std.testing.expectError(error.InvalidBlockSize, Digest.parse("4:ABCDEFG:ABCDEFG", .strict));
    const odd = try Digest.parse("4:ABCDEFG:ABCDEFG", .lenient);
    try std.testing.expectEqual(@as(u64, 4), odd.block_size);
    try std.testing.expectError(error.InvalidCharacter, Digest.parse("3:ABC-:DEF", .strict));
    _ = try Digest.parse("3:ABC-:DEF", .lenient);

    var long_part: [80]u8 = undefined;
    for (&long_part, 0..) |*c, i| c.* = 'A' + @as(u8, @intCast(i % 26));
    var text: [90]u8 = undefined;
    text[0] = '3';
    text[1] = ':';
    @memcpy(text[2..82], &long_part);
    text[82] = ':';
    text[83] = 'B';
    try std.testing.expectError(error.PartTooLong, Digest.parse(text[0..84], .lenient));

    // 1025 bytes. There is no length limit. The long runs are shortened.
    var huge: [1025]u8 = @splat('A');
    huge[0] = '3';
    huge[1] = ':';
    huge[10] = ':';
    for ([_]ParseMode{ .lenient, .strict }) |mode| {
        const big = try Digest.parse(&huge, mode);
        try std.testing.expectEqualStrings("3:AAA:AAA", big.toString(&buf));
    }

    const padded = try Digest.parse("03:E:E", .strict);
    try std.testing.expectEqual(@as(u64, 3), padded.block_size);
}

test "block sizes are 64-bit and saturate" {
    const max = std.math.maxInt(u64);
    const cases = [_]struct { text: []const u8, value: u64 }{
        .{ .text = "0:E:E", .value = 0 },
        .{ .text = "4294967295:E:E", .value = 4294967295 },
        .{ .text = "4294967296:E:E", .value = 4294967296 },
        .{ .text = "18446744073709551614:E:E", .value = max - 1 },
        .{ .text = "18446744073709551615:E:E", .value = max },
        .{ .text = "18446744073709551616:E:E", .value = max },
        .{ .text = "18446744073709551620:E:E", .value = max },
        .{ .text = "99999999999999999999999:E:E", .value = max },
        .{ .text = "000000000000000000000000000000000000000000000012:E:E", .value = 12 },
    };
    var buf: [max_string_length]u8 = undefined;
    for (cases) |c| {
        const d = try Digest.parse(c.text, .lenient);
        try std.testing.expectEqual(c.value, d.block_size);
        const again = try Digest.parse(d.toString(&buf), .lenient);
        try std.testing.expectEqual(c.value, again.block_size);
    }

    // Strict mode accepts the block sizes the hasher can emit and nothing else.
    _ = try Digest.parse("3:E:E", .strict);
    _ = try Digest.parse("3221225472:E:E", .strict);
    try std.testing.expectError(error.InvalidBlockSize, Digest.parse("0:E:E", .strict));
    try std.testing.expectError(error.InvalidBlockSize, Digest.parse("5:E:E", .strict));
    try std.testing.expectError(error.InvalidBlockSize, Digest.parse("6442450944:E:E", .strict));
    try std.testing.expectError(error.InvalidBlockSize, Digest.parse("13835058055282163712:E:E", .strict));
    try std.testing.expectError(error.InvalidBlockSize, Digest.parse("18446744073709551616:E:E", .strict));

    try std.testing.expectEqual(@as(?u64, 0), doubled(0));
    try std.testing.expectEqual(@as(?u64, max - 1), doubled(max / 2));
    try std.testing.expectEqual(@as(?u64, null), doubled(max / 2 + 1));
    try std.testing.expectEqual(@as(?u64, null), doubled(max));
}

test "comparison scores recorded from ssdeep -x" {
    const cases = [_]struct { a: []const u8, b: []const u8, score: u8 }{
        .{ .a = "48:ABCDEFGHIJ:x", .b = "48:ABCDEFGHIX:y", .score = 91 },
        .{ .a = "3:ABCDEFGHIJ:x", .b = "3:ABCDEFGHIX:y", .score = 10 },
        .{ .a = "24:ABCDEFGHIJ:x", .b = "24:ABCDEFGHIX:y", .score = 80 },
        .{ .a = "12:ABCDEFGHIJ:ABCDEFG", .b = "12:ABCDEFGHIX:ABCDEFG", .score = 56 },
        .{ .a = "3:AAAA:AAAA", .b = "3:AAA:AAA", .score = 100 },
        .{ .a = "3:AAAAAAA:BBBBBBB", .b = "3:AAA:BBB", .score = 100 },
        .{ .a = "3:ABCDEFG:ABCDEFG", .b = "3:ABCDEFG:ABCDEFX", .score = 7 },
        .{ .a = "6:ABCDEFGHIJ:x", .b = "3:ABCDEFG:ABCDEFG", .score = 14 },
        .{ .a = "6:xxxxxxx:ABCDEFG", .b = "12:ABCDEFGHIJ:ABCDEFG", .score = 28 },
        .{ .a = "3:HHHHHHHH:ABCDEFG", .b = "3:HHH:ABCDEFG", .score = 100 },
        .{ .a = "3::", .b = "3::", .score = 100 },
        .{ .a = "3:E:E", .b = "3:E:E", .score = 100 },
        .{ .a = "3:E:E", .b = "6:E:E", .score = 0 },
        .{ .a = "12:ABCDEFG:yyyyyyy", .b = "3:ABCDEFG:xxxxxxx", .score = 0 },
        .{ .a = "3::", .b = "3:E:E", .score = 0 },
    };
    for (cases) |c| {
        const score = try compareStrings(c.a, c.b);
        try std.testing.expectEqual(c.score, score);
        const rev = try compareStrings(c.b, c.a);
        try std.testing.expectEqual(c.score, rev);
    }
}

/// One row of a comparison table. `score` null means ssdeep reported an
/// error, which must be an error here too.
const CompareRow = struct { a: []const u8, b: []const u8, score: ?u8 };

fn expectCompareRows(rows: []const CompareRow) !void {
    for (rows) |row| {
        const pairs = [_][2][]const u8{ .{ row.a, row.b }, .{ row.b, row.a } };
        for (pairs) |pair| {
            const got: ?u8 = compareStrings(pair[0], pair[1]) catch null;
            try std.testing.expectEqual(row.score, got);
        }
    }
}

fn repeatText(comptime unit: []const u8, comptime count: usize) [unit.len * count]u8 {
    var out: [unit.len * count]u8 = undefined;
    for (0..count) |i| @memcpy(out[i * unit.len ..][0..unit.len], unit);
    return out;
}

const p32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
const q32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdeQ";

test "block sizes above 2^32 - 1 compare like ssdeep 2.14.1" {
    const rows = [_]CompareRow{
        .{ .a = "4294967296:ABCDEFGHIJKL:xyz", .b = "4294967296:ABCDEFGHIJKX:xyz", .score = 93 },
        .{ .a = "4294967296:ABCDEFGHIJKL:xyz", .b = "4294967296:ABCDEFGHIJKL:xyz", .score = 100 },
        .{ .a = "4294967296:ABCDEFGHIJKL:xyz", .b = "8589934592:ABCDEFGHIJKL:xyz", .score = 0 },
        .{ .a = "8589934592:xyzw:ABCDEFGHIJKL", .b = "4294967296:ABCDEFGHIJKL:xyzw", .score = 0 },
        .{ .a = "2147483648:x:" ++ p32, .b = "4294967296:" ++ q32 ++ ":x", .score = 97 },
        .{ .a = "2147483648:" ++ p32 ++ ":x", .b = "4294967296:" ++ q32 ++ ":x", .score = 0 },
        .{ .a = "2147483648:x:" ++ p32, .b = "4294967295:" ++ q32 ++ ":x", .score = 0 },
        .{ .a = "18446744073709551615:" ++ p32 ++ ":x", .b = "18446744073709551615:" ++ q32 ++ ":x", .score = 97 },
        .{ .a = "18446744073709551616:" ++ p32 ++ ":x", .b = "18446744073709551615:" ++ q32 ++ ":x", .score = 97 },
        .{ .a = "99999999999999999999999:" ++ p32 ++ ":x", .b = "18446744073709551615:" ++ q32 ++ ":x", .score = 97 },
        .{ .a = "18446744073709551616:x:" ++ p32, .b = "18446744073709551615:" ++ q32 ++ ":x", .score = 0 },
        .{ .a = "18446744073709551616:" ++ p32 ++ ":x", .b = "3:" ++ p32 ++ ":x", .score = 0 },
        .{ .a = "9223372036854775807:x:" ++ p32, .b = "18446744073709551614:" ++ q32 ++ ":x", .score = 97 },
        .{ .a = "9223372036854775807:" ++ p32 ++ ":x", .b = "18446744073709551614:" ++ q32 ++ ":x", .score = 0 },
        .{ .a = "9223372036854775807:x:" ++ p32, .b = "18446744073709551615:" ++ q32 ++ ":x", .score = 0 },
        .{ .a = "9223372036854775808:x:" ++ p32, .b = "18446744073709551615:" ++ q32 ++ ":x", .score = 0 },
        .{ .a = "9223372036854775808:x:" ++ p32, .b = "0:" ++ q32 ++ ":x", .score = 0 },
        .{ .a = "99999999999:" ++ p32 ++ ":" ++ p32, .b = "99999999999:" ++ p32 ++ ":" ++ q32, .score = 100 },
        .{ .a = "06:" ++ p32 ++ ":x", .b = "6:" ++ q32 ++ ":x", .score = 64 },
        .{ .a = "3:E:E", .b = "05:E:E", .score = 0 },
        .{ .a = "0:E:E", .b = "0:E:E", .score = 100 },
        .{ .a = "0:ABCDEFGHIJ:x", .b = "0:ABCDEFGHIX:x", .score = 0 },
    };
    try expectCompareRows(&rows);
}

test "incomparable block sizes are checked before the rest of the string" {
    const long_ab = "6:" ++ repeatText("AB", 40) ++ ":x";
    const rows = [_]CompareRow{
        .{ .a = "12:y", .b = "1", .score = 0 },
        .{ .a = "45:D:", .b = "4", .score = 0 },
        .{ .a = long_ab, .b = "1:QQ,\"f\"", .score = 0 },
        .{ .a = "12:y", .b = "6", .score = null },
        .{ .a = "12:ABCDEFGHIJ", .b = "12:ABCDEFGHIJ:x", .score = null },
        .{ .a = long_ab, .b = "3:QQ:x", .score = null },
        .{ .a = long_ab, .b = "6:QQ:x", .score = null },
        .{ .a = "abc", .b = "3:E:E", .score = null },
        .{ .a = ":E:E", .b = "3:E:E", .score = null },
        .{ .a = "", .b = "3:E:E", .score = null },
        .{ .a = "", .b = "", .score = null },
        .{ .a = "3", .b = "3", .score = null },
        .{ .a = "x:E:E", .b = "y:E:E", .score = null },
    };
    try expectCompareRows(&rows);

    // Leading whitespace and '+' stay errors, even next to an incomparable
    // block size. ssdeep accepts them. That difference is deliberate.
    const strict_rows = [_]CompareRow{
        .{ .a = " 3:E:E", .b = "3:E:E", .score = null },
        .{ .a = "+3:E:E", .b = "3:E:E", .score = null },
        .{ .a = " 3:E:E", .b = "48:E:E", .score = null },
        .{ .a = "+3:E:E", .b = "48:E:E", .score = null },
    };
    try expectCompareRows(&strict_rows);

    try std.testing.expectError(error.InvalidFormat, compareStrings("12:y", "6"));
    try std.testing.expectError(error.PartTooLong, compareStrings(long_ab, "3:QQ:x"));
}

test "equal block sizes with no 64-bit double do not compare part 2" {
    // Recorded from ssdeep 2.14.1. When twice the block size does not fit
    // in 64 bits, only part 1 is scored. Identical digests still score 100.
    const rows = [_]CompareRow{
        .{ .a = "9223372036854775808:x:" ++ p32, .b = "9223372036854775808:y:" ++ q32, .score = 0 },
        .{ .a = "9223372036854775809:x:" ++ p32, .b = "9223372036854775809:y:" ++ q32, .score = 0 },
        .{ .a = "9223372036854775908:x:" ++ p32, .b = "9223372036854775908:y:" ++ q32, .score = 0 },
        .{ .a = "18446744073709551614:x:" ++ p32, .b = "18446744073709551614:y:" ++ q32, .score = 0 },
        .{ .a = "18446744073709551615:x:" ++ p32, .b = "18446744073709551615:y:" ++ q32, .score = 0 },
        .{ .a = "99999999999999999999999:x:" ++ p32, .b = "18446744073709551615:y:" ++ q32, .score = 0 },
        .{ .a = "9223372036854775807:x:" ++ p32, .b = "9223372036854775807:y:" ++ q32, .score = 97 },
        .{ .a = "4611686018427387904:x:" ++ p32, .b = "4611686018427387904:y:" ++ q32, .score = 97 },
        .{ .a = "9223372036854775808:" ++ p32 ++ ":x", .b = "9223372036854775808:" ++ q32 ++ ":y", .score = 97 },
        .{ .a = "18446744073709551615:" ++ p32 ++ ":x", .b = "18446744073709551615:" ++ q32 ++ ":y", .score = 97 },
        .{ .a = "9223372036854775808:" ++ p32 ++ ":" ++ p32, .b = "9223372036854775808:" ++ p32 ++ ":" ++ q32, .score = 100 },
        .{ .a = "9223372036854775808:" ++ p32 ++ ":" ++ q32, .b = "9223372036854775808:" ++ q32 ++ ":" ++ p32, .score = 97 },
        .{ .a = "9223372036854775808:x:" ++ p32, .b = "9223372036854775808:x:" ++ p32, .score = 100 },
        .{ .a = "18446744073709551615:" ++ p32 ++ ":" ++ p32, .b = "18446744073709551615:" ++ p32 ++ ":" ++ p32, .score = 100 },
        .{ .a = "9223372036854775808:x:" ++ p32, .b = "18446744073709551615:x:" ++ q32, .score = 0 },
    };
    try expectCompareRows(&rows);

    // The same rule through `compare` on digest values.
    const a = try Digest.parse("9223372036854775808:x:" ++ p32, .lenient);
    const b = try Digest.parse("9223372036854775808:y:" ++ q32, .lenient);
    try std.testing.expectEqual(@as(u8, 0), compare(a, b));
    try std.testing.expectEqual(@as(u8, 100), compare(a, a));
    // One below 2^63 the double still fits and part 2 is scored.
    const c = try Digest.parse("9223372036854775807:x:" ++ p32, .lenient);
    const d = try Digest.parse("9223372036854775807:y:" ++ q32, .lenient);
    try std.testing.expectEqual(@as(u8, 97), compare(c, d));
}

/// Test helper that writes pieces of text one after another into a buffer.
const TextBuilder = struct {
    buf: []u8,
    len: usize = 0,

    fn add(self: *TextBuilder, piece: []const u8) void {
        const n = @min(piece.len, self.buf.len - self.len);
        @memcpy(self.buf[self.len..][0..n], piece[0..n]);
        self.len += n;
    }

    fn repeat(self: *TextBuilder, ch: u8, count: usize) void {
        const n = @min(count, self.buf.len - self.len);
        @memset(self.buf[self.len..][0..n], ch);
        self.len += n;
    }

    fn text(self: *const TextBuilder) []const u8 {
        return self.buf[0..self.len];
    }
};

var long_text_a: [100_100]u8 = undefined;
var long_text_b: [4_096]u8 = undefined;

const LongTail = union(enum) {
    /// Nothing more.
    none,
    /// One character repeated.
    run: struct { ch: u8, count: usize },
    /// The 64 base64 characters, repeated.
    alphabet: usize,
};

/// One row of the long-string table: `a` is head, then tail, then foot.
const LongRow = struct {
    head: []const u8,
    tail: LongTail,
    foot: []const u8 = "",
    /// Expected length of `a`, where the table states it.
    len: ?usize = null,
    b_head: []const u8,
    b_tail: LongTail = .none,
    score: ?u8,
};

fn buildLong(buf: []u8, head: []const u8, tail: LongTail, foot: []const u8) []const u8 {
    var builder = TextBuilder{ .buf = buf };
    builder.add(head);
    switch (tail) {
        .none => {},
        .run => |r| builder.repeat(r.ch, r.count),
        .alphabet => |count| {
            var n: usize = 0;
            while (n < count) : (n += 1) builder.add(b64);
        },
    }
    builder.add(foot);
    return builder.text();
}

test "digest strings of any length parse and compare" {
    // Recorded from ssdeep 2.14.1.
    const p = "3:" ++ p32 ++ ":x";
    const q = "3:" ++ q32 ++ ":x";
    const rows = [_]LongRow{
        .{ .head = p ++ ",\"", .tail = .{ .run = .{ .ch = 'f', .count = 990 } }, .foot = "\"", .len = 1029, .b_head = q, .score = 32 },
        .{ .head = p ++ ",\"", .tail = .{ .run = .{ .ch = 'f', .count = 5000 } }, .foot = "\"", .b_head = q, .score = 32 },
        .{ .head = p ++ ",", .tail = .{ .run = .{ .ch = 'f', .count = 100000 } }, .b_head = q, .score = 32 },
        .{ .head = p ++ ",", .tail = .{ .run = .{ .ch = 'f', .count = 3000 } }, .b_head = p ++ ",", .b_tail = .{ .run = .{ .ch = 'g', .count = 3000 } }, .score = 100 },
        .{ .head = p, .tail = .{ .run = .{ .ch = 'Z', .count = 988 } }, .len = 1024, .b_head = q, .score = 32 },
        .{ .head = p, .tail = .{ .run = .{ .ch = 'Z', .count = 989 } }, .len = 1025, .b_head = q, .score = 32 },
        .{ .head = p, .tail = .{ .run = .{ .ch = 'Z', .count = 2000 } }, .b_head = q, .score = 32 },
        .{ .head = "3:" ++ p32, .tail = .{ .run = .{ .ch = 'X', .count = 2000 } }, .foot = ":x", .b_head = q, .score = 32 },
        .{ .head = p ++ ":", .tail = .{ .run = .{ .ch = 'y', .count = 2000 } }, .b_head = q, .score = 32 },
        .{ .head = p ++ "\n", .tail = .{ .run = .{ .ch = 'y', .count = 3000 } }, .b_head = q, .score = 32 },
        .{ .head = "6:" ++ p32 ++ ":x,\"", .tail = .{ .run = .{ .ch = 'f', .count = 3000 } }, .foot = "\"", .b_head = "3:x:" ++ q32, .score = 64 },
        .{ .head = "48:" ++ p32 ++ ":x,\"", .tail = .{ .run = .{ .ch = 'f', .count = 3000 } }, .foot = "\"", .b_head = "3:x:" ++ q32, .score = 0 },
        .{ .head = "3:" ++ p32, .tail = .{ .run = .{ .ch = 'Z', .count = 2000 } }, .b_head = q, .score = null },
        .{ .head = "3:", .tail = .{ .alphabet = 20 }, .foot = ":x", .b_head = q, .score = null },
        .{ .head = "3:" ++ p32 ++ ":", .tail = .{ .alphabet = 20 }, .b_head = q, .score = null },
    };
    for (rows) |row| {
        const a = buildLong(&long_text_a, row.head, row.tail, row.foot);
        const b = buildLong(&long_text_b, row.b_head, row.b_tail, "");
        if (row.len) |n| try std.testing.expectEqual(n, a.len);
        const forward: ?u8 = compareStrings(a, b) catch null;
        const backward: ?u8 = compareStrings(b, a) catch null;
        try std.testing.expectEqual(row.score, forward);
        try std.testing.expectEqual(row.score, backward);
    }

    // What the long strings parse to, in both modes.
    var out: [max_string_length]u8 = undefined;
    for ([_]ParseMode{ .lenient, .strict }) |mode| {
        const named = buildLong(&long_text_a, p ++ ",\"", .{ .run = .{ .ch = 'f', .count = 100000 } }, "\"");
        try std.testing.expectEqualStrings(p, (try Digest.parse(named, mode)).toString(&out));

        const run_in_part2 = buildLong(&long_text_a, p, .{ .run = .{ .ch = 'Z', .count = 2000 } }, "");
        try std.testing.expectEqualStrings(p ++ "ZZZ", (try Digest.parse(run_in_part2, mode)).toString(&out));

        const run_in_part1 = buildLong(&long_text_a, "3:" ++ p32, .{ .run = .{ .ch = 'X', .count = 2000 } }, ":x");
        try std.testing.expectEqualStrings("3:" ++ p32 ++ "XXX:x", (try Digest.parse(run_in_part1, mode)).toString(&out));

        // Leading zeros are part of the block size, however many.
        const zeros = buildLong(&long_text_a, "", .{ .run = .{ .ch = '0', .count = 5000 } }, p);
        try std.testing.expectEqualStrings(p, (try Digest.parse(zeros, mode)).toString(&out));

        const no_colon = buildLong(&long_text_a, "3:" ++ p32, .{ .run = .{ .ch = 'Z', .count = 2000 } }, "");
        try std.testing.expectError(error.InvalidFormat, Digest.parse(no_colon, mode));

        const part1_long = buildLong(&long_text_a, "3:", .{ .alphabet = 20 }, ":x");
        try std.testing.expectError(error.PartTooLong, Digest.parse(part1_long, mode));

        const part2_long = buildLong(&long_text_a, "3:" ++ p32 ++ ":", .{ .alphabet = 20 }, "");
        try std.testing.expectError(error.PartTooLong, Digest.parse(part2_long, mode));

        // Leading whitespace and '+' stay errors at any length.
        const spaced = buildLong(&long_text_a, " " ++ p ++ ",", .{ .run = .{ .ch = 'f', .count = 3000 } }, "");
        try std.testing.expectError(error.InvalidFormat, Digest.parse(spaced, mode));
        const plus = buildLong(&long_text_a, "+" ++ p ++ ",", .{ .run = .{ .ch = 'f', .count = 3000 } }, "");
        try std.testing.expectError(error.InvalidFormat, Digest.parse(plus, mode));
    }

    // Strict mode still checks every character before the comma, and
    // nothing after it.
    const bad_char = buildLong(&long_text_a, p, .{ .run = .{ .ch = 'Z', .count = 2000 } }, "-");
    try std.testing.expectError(error.InvalidCharacter, Digest.parse(bad_char, .strict));
    _ = try Digest.parse(bad_char, .lenient);
    const bad_after_comma = buildLong(&long_text_a, p ++ ",", .{ .run = .{ .ch = '-', .count = 2000 } }, "");
    _ = try Digest.parse(bad_after_comma, .strict);
}

test "text between the block size and the first colon is skipped in lenient mode" {
    // Recorded from ssdeep 2.14.1.
    const p = ":" ++ p32 ++ ":x";
    const q = ":" ++ q32 ++ ":x";
    const long_ab = "6x:" ++ repeatText("AB", 40) ++ ":x";
    const rows = [_]CompareRow{
        .{ .a = "6x:ABC:DEF", .b = "6:ABC:DEF", .score = 100 },
        .{ .a = "6x:ABC:DEF", .b = "12:ABC:DEF", .score = 0 },
        .{ .a = "6x::", .b = "6::", .score = 100 },
        .{ .a = "6x" ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6x" ++ p, .b = "6y" ++ q, .score = 64 },
        .{ .a = "6x!!" ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6 " ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6," ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6,\"f\"" ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6-5" ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6.5" ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6e3" ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6\n" ++ p, .b = "6" ++ q, .score = 64 },
        .{ .a = "6xx" ++ p ++ ",\"a\"", .b = "6" ++ q, .score = 64 },
        .{ .a = "3x" ++ p, .b = "3" ++ q, .score = 32 },
        .{ .a = "12x" ++ p, .b = "6:x:" ++ q32, .score = 97 },
        .{ .a = "0x" ++ p, .b = "0" ++ q, .score = 0 },
        .{ .a = "6999x" ++ p, .b = "6" ++ q, .score = 0 },
        .{ .a = "6x", .b = "6:ABC:DEF", .score = null },
        .{ .a = "6x" ++ p32 ++ ":x", .b = "6" ++ q, .score = null },
        .{ .a = "6x" ++ p32, .b = "6" ++ q, .score = null },
        .{ .a = long_ab, .b = "6" ++ q, .score = null },
        .{ .a = long_ab, .b = "48" ++ q, .score = 0 },
    };
    try expectCompareRows(&rows);

    // The row with 5000 characters between the digits and the colon.
    const stuffed = buildLong(&long_text_a, "6", .{ .run = .{ .ch = 'z', .count = 5000 } }, p);
    try std.testing.expectEqual(@as(usize, 1 + 5000 + 1 + 32 + 2), stuffed.len);
    try std.testing.expectEqual(@as(u8, 64), try compareStrings(stuffed, "6" ++ q));
    try std.testing.expectEqual(@as(u8, 64), try compareStrings("6" ++ q, stuffed));

    // Why two of the rows are errors.
    try std.testing.expectError(error.InvalidFormat, compareStrings("6x", "6:ABC:DEF"));
    // The skipped text ends at the colon after p, so part 1 is "x" and
    // there is no second colon.
    try std.testing.expectError(error.InvalidFormat, compareStrings("6x" ++ p32 ++ ":x", "6" ++ q));
    try std.testing.expectError(error.PartTooLong, compareStrings(long_ab, "6" ++ q));

    // Lenient mode reads the digits, skips to the colon and goes on as
    // before. Strict mode still wants the colon right after the digits.
    var out: [max_string_length]u8 = undefined;
    const loose = try Digest.parse("6x:ABC:DEF", .lenient);
    try std.testing.expectEqual(@as(u64, 6), loose.block_size);
    try std.testing.expectEqualStrings("ABC", loose.part1[0..loose.part1_len]);
    try std.testing.expectEqualStrings("DEF", loose.part2[0..loose.part2_len]);
    try std.testing.expectEqualStrings("6:ABC:DEF", loose.toString(&out));
    try std.testing.expectError(error.InvalidFormat, Digest.parse("6x:ABC:DEF", .strict));
    try std.testing.expectError(error.InvalidFormat, Digest.parse("6 :ABC:DEF", .strict));
    try std.testing.expectError(error.InvalidFormat, Digest.parse(stuffed, .strict));
    _ = try Digest.parse("6:ABC:DEF", .strict);

    // Digits after the skipped text are not part of the block size.
    const mixed = try Digest.parse("6x12:ABC:DEF", .lenient);
    try std.testing.expectEqual(@as(u64, 6), mixed.block_size);
    const stuffed_digest = try Digest.parse(stuffed, .lenient);
    try std.testing.expectEqualStrings("6" ++ p, stuffed_digest.toString(&out));
    // Still an error without any colon, or without a leading digit.
    try std.testing.expectError(error.InvalidFormat, Digest.parse("6x", .lenient));
    try std.testing.expectError(error.InvalidFormat, Digest.parse("x6:ABC:DEF", .lenient));
}

test "a leading minus is rejected on purpose" {
    // ssdeep 2.14.1 reads a leading '-' the way strtoull does and scores
    // the first three rows 0, 100 and 97. Here a string without a leading
    // digit is an error, like leading whitespace and '+'.
    const rows = [_]CompareRow{
        .{ .a = "-3:E:E", .b = "3:E:E", .score = null },
        .{ .a = "-3:E:E", .b = "-3:E:E", .score = null },
        .{ .a = "-1:" ++ p32 ++ ":x", .b = "18446744073709551615:" ++ q32 ++ ":x", .score = null },
        .{ .a = "-:E:E", .b = "0:E:E", .score = null },
    };
    try expectCompareRows(&rows);
    for ([_]ParseMode{ .lenient, .strict }) |mode| {
        try std.testing.expectError(error.InvalidFormat, Digest.parse("-3:E:E", mode));
        try std.testing.expectError(error.InvalidFormat, Digest.parse("-1:" ++ p32 ++ ":x", mode));
        try std.testing.expectError(error.InvalidFormat, Digest.parse("-:E:E", mode));
    }
    try std.testing.expectError(error.InvalidFormat, compareStrings("-3:E:E", "3:E:E"));
    try std.testing.expectError(error.InvalidFormat, compareStrings("-3:E:E", "48:E:E"));
}

test "every hashed sample compares equal to itself" {
    const samples = [_][]const u8{
        "",
        "a",
        "hello",
        &a300,
        &b500,
        "The quick brown fox jumps over the lazy dog",
    };
    for (samples) |s| {
        const d = try hash(s, .{});
        try std.testing.expectEqual(@as(u8, 100), compare(d, d));
    }
}

test "high bits of a byte do not affect the piece hash on their own" {
    // 0x01, 0x41 and 0x81 share the low 6 bits. None of them triggers, so
    // ssdeep 2.14.1 reports the same digest for each.
    try expectHash(&[_]u8{0x01}, "3:k:k");
    try expectHash(&[_]u8{0x41}, "3:k:k");
    try expectHash(&[_]u8{0x81}, "3:k:k");
}
