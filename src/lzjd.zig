// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! LZJD (Lempel-Ziv Jaccard Distance) digests and similarity.
//!
//! The output is meant to be identical to pyLZJD at commit
//! e2c24bdd1be634cbdeff5f9e711dc2ae7c61ccf8: the int32 digests of its default
//! mode, the float32 digests of its "SuperHash" mode, the set sizes and the
//! similarity values.
//!
//! Method (Raff and Nicholas, KDD 2017, and Digital Investigation 24, 2018):
//! the input is split into Lempel-Ziv phrases, where a phrase ends as soon as
//! its hash has not been seen before. The set of phrase hashes is then
//! reduced to a fixed-size digest, either by keeping `hash_size` of the hashes
//! (default mode) or by SuperMinHash (Ertl, arXiv:1706.05698).
//!
//! Nothing here allocates, recurses, or touches the OS. All working memory
//! comes from the caller's `scratch` buffer, see `scratchLen`.

const std = @import("std");

pub const Error = error{
    /// `scratch.len < scratchLen(input.len, opts.hash_size)`.
    ScratchTooSmall,
    /// `out.len < opts.hash_size`.
    OutputTooSmall,
    /// `hash_size == 0` in SuperHash mode.
    InvalidHashSize,
    /// The input is longer than `max_input_len`.
    InputTooLarge,
};

pub const Options = struct {
    /// Maximum number of digest entries (default mode) or exact number of
    /// digest entries (SuperHash mode).
    hash_size: u32 = 1024,
    /// Probability with which a phrase that has not been seen is treated as
    /// seen. The stochastic variant is on only for `0 < false_seen_prob < 1`.
    false_seen_prob: f32 = 0,
    /// Seed of the generator behind `false_seen_prob`. Seed 0 accepts every
    /// phrase, which gives the same result as `false_seen_prob = 0`.
    seed: u32 = 0,
};

pub const Digest = struct {
    /// A slice of `out`, sorted ascending, at most `hash_size` entries.
    values: []i32,
    /// Number of distinct phrase hashes (pyLZJD's second tuple element).
    set_size: u32,
};

pub const SuperDigest = struct {
    /// A slice of `out`, exactly `hash_size` entries, in pyLZJD's order.
    values: []f32,
    /// Number of distinct phrase hashes (pyLZJD's second tuple element).
    set_size: u32,
};

/// Slot counts of the phrase hash table. All of them are prime (there is a
/// test for it), which the probe sequence in `findSlot` relies on.
const table_sizes = [_]u32{
    7,        13,        19,        43,        73,         139,
    271,      523,       1033,      2083,      4129,       8221,
    16453,    32803,     65539,     131113,    262153,     524353,
    1048891,  2097259,   4194583,   8388619,   16777291,   33554503,
    67109323, 134217781, 268435579, 536871019, 1073741833, 2147482951,
};

/// Longest input that `digest` and `digestSuper` accept, in bytes.
pub const max_input_len: u32 = table_sizes[table_sizes.len - 1] / 2;

/// Worst-case padding needed to bring an arbitrary `scratch` pointer to a
/// 4-byte boundary.
const align_slack = 3;

/// The table size for an input: the first size whose half is at least the
/// input length. The table therefore never becomes more than half full.
fn tableSlots(input_len: usize) ?u32 {
    for (table_sizes) |slots| {
        if (slots / 2 >= input_len) return slots;
    }
    return null;
}

/// Scratch bytes for a table of `slots` slots and `hash_size` digest entries,
/// in 64 bits so that it cannot overflow: the largest value is below 2^36.
fn scratchNeed(slots: u32, hash_size: u32) u64 {
    const s: u64 = slots;
    const m: u64 = hash_size;
    return align_slack + 4 * s + (s + 7) / 8 + 12 * m;
}

/// Bytes of scratch that `digest` and `digestSuper` need. 0 when the input is
/// too large (longer than `max_input_len`).
///
/// With `P` the table size for `input_len` (the first entry of the size list
/// with `P / 2 >= input_len`), the result is
///
///     3 + 4 * P + ceil(P / 8) + 12 * hash_size
///
/// that is: up to 3 bytes to align the buffer, one i32 key per table slot,
/// one "slot in use" bit per table slot, and three u32 arrays of `hash_size`
/// entries for SuperMinHash. `P` is between 2 and about 4 times `input_len`
/// (7 at least). The same length is required by both functions, although
/// `digest` leaves the last `12 * hash_size` bytes untouched.
///
/// If the result does not fit in `usize` (possible on 32-bit targets), the
/// largest `usize` is returned; `digest` and `digestSuper` then fail with
/// `error.ScratchTooSmall` whatever buffer they are given.
pub fn scratchLen(input_len: usize, hash_size: u32) usize {
    const slots = tableSlots(input_len) orelse return 0;
    const need = scratchNeed(slots, hash_size);
    const max: usize = std.math.maxInt(usize);
    return if (need > max) max else @intCast(need);
}

/// The caller's scratch buffer, cut into typed arrays.
const Workspace = struct {
    /// One key per table slot. After `collectKeys` the front of this array is
    /// the list of stored keys in slot order.
    keys: []i32,
    /// One bit per table slot: set when the slot holds a key.
    used: []u8,
    /// SuperMinHash state, `hash_size` entries each.
    q: []u32,
    p: []u32,
    b: []u32,

    /// Validates sizes and lays the arrays out inside `scratch`. Nothing in
    /// `scratch` is read or written here.
    fn init(input_len: usize, hash_size: u32, scratch: []u8) Error!Workspace {
        const slots = tableSlots(input_len) orelse return error.InputTooLarge;
        const need = scratchNeed(slots, hash_size);
        if (scratch.len < need) return error.ScratchTooSmall;

        // From here on need <= scratch.len, so every size below fits in usize
        // and every array lies inside scratch:
        //   pad + 4 * slots + 12 * hash_size + used_len <= need, with pad <= 3.
        const pad: usize = (4 - (@intFromPtr(scratch.ptr) & 3)) & 3;
        const n_slots: usize = @intCast(slots);
        const m: usize = @intCast(hash_size);
        const used_len: usize = (n_slots + 7) / 8;

        // scratch.ptr + pad is a multiple of 4. The 32-bit arrays follow each
        // other from there, then the bitmap.
        const words: [*]u32 = @ptrCast(@alignCast(scratch.ptr + pad));
        const keys: [*]i32 = @ptrCast(words);
        const q = words + n_slots;
        const p = q + m;
        const b = p + m;
        const used_start = pad + 4 * n_slots + 12 * m;
        return .{
            .keys = keys[0..n_slots],
            .used = scratch[used_start .. used_start + used_len],
            .q = q[0..m],
            .p = p[0..m],
            .b = b[0..m],
        };
    }
};

/// MurmurHash3_x86_32 mixing of one key word.
inline fn mixKey(k: u32) u32 {
    return std.math.rotl(u32, k *% 0xcc9e2d51, 15) *% 0x1b873593;
}

/// MurmurHash3 32-bit finalizer.
inline fn fmix32(x: u32) u32 {
    var h = x;
    h ^= h >> 16;
    h *%= 0x85ebca6b;
    h ^= h >> 13;
    h *%= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

/// xorshift32. A state of 0 stays 0.
inline fn xorshift32(state: u32) u32 {
    var x = state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

/// Incremental hash of the current phrase: MurmurHash3_x86_32 with seed 0,
/// except for the tail (the 1 to 3 bytes after the last full 4-byte block).
/// pyLZJD keeps all 8 bits of the first tail byte but only the lowest bit of
/// the second and third. Phrases of length 2 or 3 modulo 4 therefore hash
/// differently from plain MurmurHash3; lengths 0 and 1 modulo 4 do not.
const PhraseHasher = struct {
    /// MurmurHash3 state after the full blocks of the phrase.
    h: u32 = 0,
    /// Bytes of the unfinished block in little-endian order, complete, for
    /// the block mix once the fourth byte arrives.
    block: u32 = 0,
    /// The same bytes the way the tail mix sees them.
    tail: u32 = 0,
    /// Phrase length in bytes.
    len: u32 = 0,

    /// Appends one byte and returns the hash of the phrase so far.
    inline fn push(self: *PhraseHasher, byte: u8) i32 {
        const v: u32 = byte;
        var h = self.h;
        switch (@as(u2, @truncate(self.len))) {
            0 => {
                self.block = v;
                self.tail = v;
                h ^= mixKey(self.tail);
            },
            1 => {
                self.block |= v << 8;
                self.tail |= (v & 1) << 8;
                h ^= mixKey(self.tail);
            },
            2 => {
                self.block |= v << 16;
                self.tail |= (v & 1) << 16;
                h ^= mixKey(self.tail);
            },
            3 => {
                h ^= mixKey(self.block | (v << 24));
                h = std.math.rotl(u32, h, 13) *% 5 +% 0xe6546b64;
                self.h = h;
            },
        }
        // Cannot wrap: a phrase is never longer than the input, and the
        // input is at most max_input_len bytes.
        self.len +%= 1;
        return @bitCast(fmix32(h ^ self.len));
    }
};

inline fn isUsed(used: []const u8, slot: u32) bool {
    return (used[slot >> 3] >> @as(u3, @truncate(slot))) & 1 != 0;
}

/// Open addressing with double hashing: returns the slot that holds `key`,
/// or the free slot where it belongs.
///
/// Termination: the table has a prime number of slots P and the step c is in
/// [1, P - 2], so the probe sequence visits all P slots before it repeats.
/// At most input.len <= P / 2 slots are ever in use, so a free slot exists
/// and is reached. Slot indices stay in [0, P): the start is a remainder
/// modulo P, and a step maps i to i - c or i - c + P, whichever is in range.
inline fn findSlot(keys: []const i32, used: []const u8, key: i32) u32 {
    const slots: u32 = @intCast(keys.len);
    const h: u32 = @as(u32, @bitCast(key)) & 0x7fffffff;
    var i: u32 = h % slots;
    if (!isUsed(used, i) or keys[i] == key) return i;
    const c: u32 = 1 + h % (slots - 2);
    while (true) {
        // i < slots and c < slots < 2^31, so i + slots - c cannot overflow.
        i = if (i >= c) i - c else i + slots - c;
        if (!isUsed(used, i) or keys[i] == key) return i;
    }
}

/// Splits the input into phrases and stores the phrase hashes in the table.
/// Returns the number of stored hashes.
///
/// `keys.len` must be the table size for `input.len` and `used` must have one
/// bit per slot. Membership is decided by the hash alone. A phrase that is
/// still open at the end of the input is not stored.
fn buildPhraseSet(input: []const u8, opts: Options, keys: []i32, used: []u8) u32 {
    @memset(used, 0);

    // The stochastic variant: a phrase that is not in the table is stored
    // only if the next xorshift32 output is below the threshold. Written so
    // that NaN turns it off.
    const prob = opts.false_seen_prob;
    const stochastic = prob > 0 and prob < 1;
    var threshold: u32 = 0;
    if (stochastic) {
        // In double precision, from the float32 value. 0 < prob < 1 as a
        // float32 means 2^-24 <= 1 - prob <= 1, so the product is in
        // [255, 4294967295] and the truncation fits in u32.
        const t: f64 = (1.0 - @as(f64, prob)) * 4294967295.0;
        threshold = @intFromFloat(t);
    }
    var rng = opts.seed;

    var size: u32 = 0;
    var phrase: PhraseHasher = .{};
    for (input) |byte| {
        const key = phrase.push(byte);
        const slot = findSlot(keys, used, key);
        if (isUsed(used, slot)) continue; // seen before: the phrase grows
        if (stochastic) {
            rng = xorshift32(rng);
            if (rng >= threshold) continue; // treated as seen: the phrase grows
        }
        keys[slot] = key;
        used[slot >> 3] |= @as(u8, 1) << @as(u3, @truncate(slot));
        size += 1; // at most one per input byte, so no overflow
        phrase = .{};
    }
    return size;
}

/// Moves the stored keys to the front of `keys`, in increasing slot order,
/// and returns that list. The write position never passes the read position,
/// so this works in place. Bits are only ever set for slots below `keys.len`.
fn collectKeys(keys: []i32, used: []const u8) []i32 {
    var n: usize = 0;
    for (used, 0..) |bits, byte_index| {
        var rest = bits;
        while (rest != 0) {
            const slot = byte_index * 8 + @ctz(rest);
            keys[n] = keys[slot];
            n += 1;
            rest &= rest - 1;
        }
    }
    return keys[0..n];
}

/// Hoare partition of a[left..right) around the pivot a[left]. Returns the
/// final position of the right-hand cursor.
///
/// Requires 0 <= left < right <= a.len. Every index used is in [left, right):
///
/// First round: `i` stops at `left` at once because a[left] is the pivot and
/// is not below itself. `j` walks down from right - 1 and stops at `left` at
/// the latest, for the same reason. So left = i <= j <= right - 1.
///
/// Later rounds come after a swap of a[i] and a[j] with i < j. Before the
/// swap a[i] was not below the pivot and a[j] was not above it, so after it
/// a[i] <= pivot <= a[j]. The next upward walk starts at i + 1 <= j and
/// stops at the old j at the latest, because a[j] is not below the pivot.
/// The next downward walk starts at j - 1 >= i and stops at the old i at the
/// latest, because a[i] is not above the pivot. Both cursors therefore stay
/// between the previous i and the previous j, which are in [left, right).
///
/// The cursors move strictly towards each other, so the loop ends, and the
/// returned j satisfies left <= j <= right - 1.
fn partition(a: []i32, left: isize, right: isize) isize {
    const pivot = a[@intCast(left)];
    var i = left - 1;
    var j = right;
    while (true) {
        i += 1;
        while (a[@intCast(i)] < pivot) i += 1;
        j -= 1;
        while (a[@intCast(j)] > pivot) j -= 1;
        if (i >= j) return j;
        const t = a[@intCast(i)];
        a[@intCast(i)] = a[@intCast(j)];
        a[@intCast(j)] = t;
    }
}

/// pyLZJD's partial selection. Afterwards a[0..k] is what pyLZJD keeps; these
/// are NOT always the k smallest values: when the search continues on the
/// left side, the element at the partition point itself is dropped from the
/// range, wherever it belongs. This is reproduced on purpose.
///
/// Requires k < a.len. The loop keeps left <= k < right: it holds at the
/// start (left = 0, right = a.len); `right = p` is taken only when k < p and
/// `left = p + 1` only when p < k. So the range handed to `partition` is
/// never empty. Each round that does not stop removes at least one element
/// from the range (left <= p <= right - 1), so the loop ends.
///
/// Expected time is linear in a.len, but like any quickselect with a fixed
/// pivot choice it is quadratic in the worst case.
fn selectQuirk(a: []i32, k: usize) void {
    const target: isize = @intCast(k);
    var left: isize = 0;
    var right: isize = @intCast(a.len);
    while (true) {
        const p = partition(a, left, right);
        if (p == target or right - left <= 1) return;
        if (target < p) {
            right = p;
        } else {
            left = p + 1;
        }
    }
}

/// Restores the max-heap property below `root` in items[0..end).
/// With root < end / 2 the left child 2 * root + 1 is at most end - 1, so
/// the child indices cannot overflow or leave the range.
fn siftDown(items: []i32, start: usize, end: usize) void {
    var root = start;
    while (root < end / 2) {
        var child = 2 * root + 1;
        if (child + 1 < end and items[child] < items[child + 1]) child += 1;
        if (items[root] >= items[child]) return;
        const t = items[root];
        items[root] = items[child];
        items[child] = t;
        root = child;
    }
}

/// In-place heapsort, ascending. No recursion and no extra memory.
fn sortAscending(items: []i32) void {
    const n = items.len;
    if (n < 2) return;
    var start = n / 2;
    while (start > 0) {
        start -= 1;
        siftDown(items, start, n);
    }
    var end = n;
    while (end > 1) {
        end -= 1;
        const t = items[0];
        items[0] = items[end];
        items[end] = t;
        siftDown(items, 0, end);
    }
}

/// The default-mode digest of `input`: pyLZJD's `digest(data, hash_size=k)`,
/// with `false_seen_prob` and `seed` when the stochastic variant is wanted.
///
/// `out` must hold at least `opts.hash_size` entries and `scratch` at least
/// `scratchLen(input.len, opts.hash_size)` bytes of any alignment. `scratch`
/// and `out` must not overlap each other or `input`. With `hash_size = 0`
/// the digest is empty and the set size is still reported.
///
/// Errors are checked in this order, before `scratch` or `out` is touched:
/// OutputTooSmall, InputTooLarge, ScratchTooSmall.
pub fn digest(input: []const u8, opts: Options, scratch: []u8, out: []i32) Error!Digest {
    const k = opts.hash_size;
    if (out.len < k) return error.OutputTooSmall;
    const ws = try Workspace.init(input.len, k, scratch);

    const set_size = buildPhraseSet(input, opts, ws.keys, ws.used);
    const set = collectKeys(ws.keys, ws.used);

    // k <= out.len, so k fits in usize.
    var count: usize = set.len;
    if (set.len > k) {
        count = @intCast(k);
        // With k = 0 nothing of the selection result would be kept.
        if (count != 0) selectQuirk(set, count);
    }
    const values = out[0..count];
    @memcpy(values, set[0..count]);
    sortAscending(values);
    return .{ .values = values, .set_size = set_size };
}

/// SuperMinHash (Ertl 2017, Algorithm 1) over `set` in the given order, with
/// pyLZJD's generator and constants. All four arrays have m >= 1 entries.
///
/// Index safety: j <= a <= m - 1 inside the loop. k = j + d with
/// d = floor(u * (m - 1 - j) / (2^32 - 1)) <= m - 1 - j because u <= 2^32 - 1,
/// so k <= m - 1. p[] is only read at positions that were written for the
/// current element (q[] says so), and only j and k values are written, so
/// every p entry that is read is below m.
fn superMinHash(set: []const i32, h: []f32, q: []u32, p: []u32, b: []u32) void {
    const m: u32 = @intCast(h.len);
    const last: u32 = m - 1;
    @memset(h, 4294967296.0);
    @memset(q, 0xffffffff);
    @memset(b, 0);
    b[last] = m;
    var a: u32 = last;

    // float32(m - 1), rounded to nearest. Exact for m <= 2^24 + 1.
    const cap: f32 = @floatFromInt(last);
    const m_exact: f64 = @floatFromInt(m);

    for (set, 0..) |key, index| {
        // The element number. It is below 2^30, so it never equals the
        // initial 0xffffffff in q.
        const i: u32 = @intCast(index);
        // Seeded with max(1, key) on the signed key: zero and every negative
        // key seed the generator with 1.
        var state: u32 = if (key > 1) @bitCast(key) else 1;

        // `a` can shrink inside the loop; the condition reads it every time.
        // j + 1 cannot overflow because j <= a <= m - 1 < 2^32 - 1.
        var j: u32 = 0;
        while (j <= a) : (j += 1) {
            state = xorshift32(state);
            // 23 random bits over 2^24: exact in float32, in [0, 0.5).
            const r: f32 = @as(f32, @floatFromInt(state >> 9)) / 16777216.0;
            state = xorshift32(state);
            const d: u64 = (@as(u64, state) * (last - j)) / 0xffffffff;
            const k: u32 = j + @as(u32, @intCast(d));

            if (q[j] != i) {
                q[j] = i;
                p[j] = j;
            }
            if (q[k] != i) {
                q[k] = i;
                p[k] = k;
            }
            const pj = p[k];
            p[k] = p[j];
            p[j] = pj;

            const rj: f32 = r + @as(f32, @floatFromInt(j));
            const old = h[pj];
            if (rj < old) {
                // The histogram bucket of the value being replaced:
                // min(floor(old), float32(m - 1)). old is never negative or
                // NaN, so this is a non-negative whole number.
                const bucket: f32 = @min(@floor(old), cap);
                h[pj] = rj;
                // For m > 2^24 + 1, float32(m - 1) can round up to m or more.
                // The reference algorithm would then index past the end of
                // b; here that one decrement is left out and jp = m stands
                // for "past the end". In every other case the bucket is
                // below m and converts exactly.
                const in_range = @as(f64, bucket) < m_exact;
                const jp: u32 = if (in_range) @intFromFloat(bucket) else m;
                if (j < jp) {
                    if (in_range) b[jp] -%= 1;
                    b[j] +%= 1;
                    // For m <= 2^24 + 1, b counts the h values per bucket
                    // and sums to m, so some b[x] is non-zero and `a` stops
                    // there. The `a > 0` test only matters beyond that
                    // size, where float32 rounding can break the count.
                    while (a > 0 and b[a] == 0) a -= 1;
                }
            }
        }
    }
}

/// The SuperHash-mode digest of `input`: pyLZJD's
/// `digest(data, hash_size=k, mode="SuperHash")`, with `false_seen_prob` and
/// `seed` when the stochastic variant is wanted.
///
/// `out` must hold at least `opts.hash_size` entries and `scratch` at least
/// `scratchLen(input.len, opts.hash_size)` bytes of any alignment. `scratch`
/// and `out` must not overlap each other or `input`. The digest has exactly
/// `hash_size` entries and is not sorted. An empty input gives `hash_size`
/// copies of 2^32.
///
/// Errors are checked in this order, before `scratch` or `out` is touched:
/// InvalidHashSize, OutputTooSmall, InputTooLarge, ScratchTooSmall.
pub fn digestSuper(input: []const u8, opts: Options, scratch: []u8, out: []f32) Error!SuperDigest {
    const m = opts.hash_size;
    if (m == 0) return error.InvalidHashSize;
    if (out.len < m) return error.OutputTooSmall;
    const ws = try Workspace.init(input.len, m, scratch);

    const set_size = buildPhraseSet(input, opts, ws.keys, ws.used);
    const set = collectKeys(ws.keys, ws.used);

    // m <= out.len, so m fits in usize.
    const values = out[0..@intCast(m)];
    superMinHash(set, values, ws.q, ws.p, ws.b);
    return .{ .values = values, .set_size = set_size };
}

/// pyLZJD's `sim` on two default-mode digests: the Jaccard similarity
/// |A and B| / |A or B| of the two digests taken as sets.
///
/// Both slices must be sorted ascending without duplicates, which is what
/// `digest` returns. They may differ in length. Returns null when both are
/// empty (pyLZJD raises ZeroDivisionError). Input that is not sorted or has
/// duplicates cannot cause a fault; the result is then whatever this merge
/// walk counts (in tests pyLZJD returned the same for such arrays).
pub fn similarity(a: []const i32, b: []const i32) ?f64 {
    var i: usize = 0;
    var j: usize = 0;
    var both: u64 = 0;
    while (i < a.len and j < b.len) {
        if (a[i] < b[j]) {
            i += 1;
        } else if (a[i] > b[j]) {
            j += 1;
        } else {
            both += 1;
            i += 1;
            j += 1;
        }
    }
    // both <= min(a.len, b.len), so the subtraction cannot go below zero.
    const either: u64 = @as(u64, a.len) + @as(u64, b.len) - both;
    if (either == 0) return null;
    return @as(f64, @floatFromInt(both)) / @as(f64, @floatFromInt(either));
}

/// pyLZJD's `sim` on two SuperHash digests of the same length: the number of
/// positions where the two values are equal, divided by the length.
///
/// Outside that contract the result is NaN: for two empty digests (pyLZJD
/// also returns NaN there) and for digests of different lengths (pyLZJD
/// raises ValueError, except where numpy broadcasting applies).
pub fn similaritySuper(a: []const f32, b: []const f32) f64 {
    if (a.len != b.len or a.len == 0) return std.math.nan(f64);
    var equal: u64 = 0;
    for (a, b) |x, y| {
        if (x == y) equal += 1;
    }
    return @as(f64, @floatFromInt(equal)) / @as(f64, @floatFromInt(a.len));
}

// ---------------------------------------------------------------------------
// Tests.
//
// Every expected digest, set size and similarity value below was produced by
// pyLZJD at commit e2c24bd, never by this code. Expected error codes and the
// scratchLen formula follow the documented API.
// ---------------------------------------------------------------------------

const testing = std.testing;

const fox = "The quick brown fox jumps over the lazy dog";
const cat = "The quick brown fox jumps over the lazy cat";
const hex40 = "\x4a\x58\xb7\x91\xdf\x6a\xf1\xd8\x30\x3e\x61\xcd\xc4\xbb\x86\xc3\xd1\xc4\x27\x10" ++
    "\x3c\x34\x4c\x41\x89\xeb\x2f\x1e\x7b\xd5\xd4\x7e\x44\x6f\xce\xc2\xa3\xd8\x11\x73";

/// bytes(range(256)) * 4
const ramp4: [1024]u8 = blk: {
    @setEvalBranchQuota(4000);
    var bytes: [1024]u8 = undefined;
    for (&bytes, 0..) |*x, i| x.* = @truncate(i);
    break :blk bytes;
};

// Static buffers for the tests, sized for the largest input and hash size
// that any test uses.
const test_max_len = 1048629;
const test_max_k = 4096;
const test_guard = 16;
const test_scratch_len: usize = @intCast(scratchNeed(tableSlots(test_max_len).?, test_max_k));

var test_input: [test_max_len]u8 = undefined;
var test_scratch: [test_scratch_len + 8 + test_guard]u8 = undefined;
var test_out: [test_max_k + 1]i32 = undefined;
var test_out_f: [test_max_k + 1]f32 = undefined;
var test_keep: [1024]i32 = undefined;
var test_keep_f: [1024]f32 = undefined;

const out_guard: u32 = 0x5a5a5a5a;

/// A scratch buffer of exactly scratchLen bytes, `offset` bytes into the
/// static buffer (so its alignment varies), filled with `fill`, followed by
/// guard bytes.
fn testScratch(input_len: usize, hash_size: u32, offset: usize, fill: u8) []u8 {
    const need = scratchLen(input_len, hash_size);
    const scratch = test_scratch[offset..][0..need];
    @memset(scratch, fill);
    @memset(test_scratch[offset + need ..][0..test_guard], 0xa5);
    return scratch;
}

fn expectScratchGuard(scratch: []const u8) !void {
    const after = (scratch.ptr + scratch.len)[0..test_guard];
    for (after) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
}

/// `digest` with an exactly sized scratch and output buffer, checking that
/// nothing next to either buffer is written.
fn runDigest(input: []const u8, opts: Options, offset: usize, fill: u8) !Digest {
    const k: usize = @intCast(opts.hash_size);
    const scratch = testScratch(input.len, opts.hash_size, offset, fill);
    test_out[k] = @bitCast(out_guard);
    const d = try digest(input, opts, scratch, test_out[0..k]);
    try expectScratchGuard(scratch);
    try testing.expectEqual(out_guard, @as(u32, @bitCast(test_out[k])));
    try testing.expect(d.values.ptr == test_out[0..k].ptr);
    try testing.expect(d.values.len <= k);
    var i: usize = 1;
    while (i < d.values.len) : (i += 1) try testing.expect(d.values[i - 1] < d.values[i]);
    return d;
}

/// The same for `digestSuper`.
fn runDigestSuper(input: []const u8, opts: Options, offset: usize, fill: u8) !SuperDigest {
    const k: usize = @intCast(opts.hash_size);
    const scratch = testScratch(input.len, opts.hash_size, offset, fill);
    test_out_f[k] = @bitCast(out_guard);
    const d = try digestSuper(input, opts, scratch, test_out_f[0..k]);
    try expectScratchGuard(scratch);
    try testing.expectEqual(out_guard, @as(u32, @bitCast(test_out_f[k])));
    try testing.expect(d.values.ptr == test_out_f[0..k].ptr);
    try testing.expectEqual(k, d.values.len);
    return d;
}

test "table sizes are increasing primes below 2^31" {
    var prev: u32 = 0;
    for (table_sizes) |p| {
        try testing.expect(p > prev);
        try testing.expect(p < (1 << 31));
        prev = p;
        var d: u32 = 2;
        while (d <= p / d) : (d += 1) {
            try testing.expect(p % d != 0);
        }
    }
}

test "table size for an input length" {
    try testing.expectEqual(@as(?u32, 7), tableSlots(0));
    try testing.expectEqual(@as(?u32, 7), tableSlots(3));
    try testing.expectEqual(@as(?u32, 13), tableSlots(4));
    try testing.expectEqual(@as(?u32, 13), tableSlots(6));
    try testing.expectEqual(@as(?u32, 19), tableSlots(7));
    try testing.expectEqual(@as(?u32, 2097259), tableSlots(1048629));
    try testing.expectEqual(@as(?u32, 4194583), tableSlots(1048630));
    try testing.expectEqual(@as(?u32, 2147482951), tableSlots(max_input_len));
    try testing.expectEqual(@as(?u32, null), tableSlots(@as(usize, max_input_len) + 1));
    try testing.expectEqual(@as(u32, 1073741475), max_input_len);
}

test "scratchLen formula" {
    // 3 + 4 * P + ceil(P / 8) + 12 * hash_size
    try testing.expectEqual(@as(usize, 3 + 28 + 1), scratchLen(0, 0));
    try testing.expectEqual(@as(usize, 3 + 28 + 1), scratchLen(3, 0));
    try testing.expectEqual(@as(usize, 3 + 52 + 2), scratchLen(4, 0));
    try testing.expectEqual(@as(usize, 3 + 28 + 1 + 12 * 1024), scratchLen(1, 1024));
    try testing.expectEqual(@as(usize, 3 + 4 * 2097259 + 262158 + 12 * 16), scratchLen(1 << 20, 16));
    try testing.expectEqual(@as(usize, 0), scratchLen(@as(usize, max_input_len) + 1, 16));
    try testing.expectEqual(@as(usize, 0), scratchLen(std.math.maxInt(usize), 0));

    // The largest table, and the largest request of all. Where usize cannot
    // hold the result it saturates.
    const big: u64 = 3 + 4 * 2147482951 + 268435369;
    const max: usize = std.math.maxInt(usize);
    const want_big: usize = if (big > max) max else @intCast(big);
    try testing.expectEqual(want_big, scratchLen(max_input_len, 0));
    const biggest: u64 = big + 12 * 4294967295;
    const want_biggest: usize = if (biggest > max) max else @intCast(biggest);
    try testing.expectEqual(want_biggest, scratchLen(max_input_len, 0xffffffff));
}

test "phrase hash" {
    // The digests of "a" and "aaa" (16 entries) are [1009084850] and
    // [1009084850, 1660139966], so these are the hashes of "a" and "aa".
    var one: PhraseHasher = .{};
    try testing.expectEqual(@as(i32, 1009084850), one.push('a'));
    try testing.expectEqual(@as(i32, 1660139966), one.push('a'));
}

const Known = struct {
    input: []const u8,
    k: u32,
    prob: f32 = 0,
    seed: u32 = 0,
    size: u32,
    values: []const i32,
};

test "known results, default mode" {
    const fox8 = [_]i32{ -2128973781, -1737498726, -1261379688, -1248839937, -1112552363, -1040803305, -809654831, -729632045 };
    const cases = [_]Known{
        .{ .input = "a", .k = 16, .size = 1, .values = &.{1009084850} },
        .{ .input = "aaa", .k = 16, .size = 2, .values = &.{ 1009084850, 1660139966 } },
        .{ .input = "\xfe\xfe\xfe", .k = 16, .size = 2, .values = &.{ -1831963392, 1172860420 } },
        .{ .input = &@as([6]u8, @splat(0xfe)), .k = 16, .size = 3, .values = &.{ -1831963392, 595955331, 1172860420 } },
        .{ .input = &@as([10]u8, @splat(0xff)), .k = 16, .size = 4, .values = &.{ -751751554, -43192051, 594344554, 1982413648 } },
        .{ .input = "abcdabcdabcd", .k = 16, .size = 7, .values = &.{ -1780580861, -516762017, -107865855, 655955059, 1009084850, 1867108634, 2138758248 } },
        .{ .input = "abcabcabcd", .k = 4, .size = 7, .values = &.{ -1780580861, -516762017, 1009084850, 1183463189 } },
        .{ .input = "", .k = 4, .size = 0, .values = &.{} },
        .{ .input = fox, .k = 8, .size = 28, .values = &fox8 },
        .{ .input = fox, .k = 0, .size = 28, .values = &.{} },
        .{ .input = fox, .k = 8, .prob = 0.5, .seed = 1, .size = 23, .values = &.{ -2128973781, -1817299494, -1743510865, -967714644, -921209975, -851106666, -711804034, -516762017 } },
        // State 0 accepts every phrase.
        .{ .input = fox, .k = 8, .prob = 0.5, .seed = 0, .size = 28, .values = &fox8 },
        .{ .input = &ramp4, .k = 6, .size = 597, .values = &.{ -2140763568, -2128973781, -2122690691, -2119853753, -2119369539, -2118138929 } },
        .{ .input = &@as([100]u8, @splat('a')), .k = 3, .size = 13, .values = &.{ -2146952433, -1878433872, -1570253143 } },
        // The selection quirk at work: the true 5 smallest start with -2122690691.
        .{ .input = hex40, .k = 5, .size = 38, .values = &.{ -1727679682, -1711807540, -1482984597, -1300379323, -1067663553 } },
    };
    for (cases, 0..) |c, index| {
        const opts: Options = .{ .hash_size = c.k, .false_seen_prob = c.prob, .seed = c.seed };
        const d = try runDigest(c.input, opts, index % 8, 0xff);
        try testing.expectEqual(c.size, d.set_size);
        try testing.expectEqualSlices(i32, c.values, d.values);
    }
}

const KnownSuper = struct {
    input: []const u8,
    k: u32,
    prob: f32 = 0,
    seed: u32 = 0,
    size: u32,
    /// Bit patterns of the float32 values.
    bits: []const u32,
};

test "known results, SuperHash mode" {
    const cases = [_]KnownSuper{
        .{ .input = fox, .k = 4, .size = 28, .bits = &.{ 0x38040000, 0x3e25b470, 0x3e5aa954, 0x4040decf } },
        .{ .input = fox, .k = 8, .size = 28, .bits = &.{ 0x38040000, 0x3eb37f46, 0x3e5e8834, 0x3f82a0b8, 0x3e25b470, 0x3ea8da96, 0x3e5aa954, 0x40e0536b } },
        .{ .input = cat, .k = 8, .size = 29, .bits = &.{ 0x38040000, 0x3eb37f46, 0x3e5e8834, 0x3dbdd700, 0x3e25b470, 0x400fca51, 0x3e5aa954, 0x40e0536b } },
        .{ .input = fox, .k = 4, .prob = 0.5, .seed = 1, .size = 23, .bits = &.{ 0x38040000, 0x3deae010, 0x3e5aa954, 0x40412afe } },
        .{ .input = "", .k = 4, .size = 0, .bits = &.{ 0x4f800000, 0x4f800000, 0x4f800000, 0x4f800000 } },
    };
    for (cases, 0..) |c, index| {
        const opts: Options = .{ .hash_size = c.k, .false_seen_prob = c.prob, .seed = c.seed };
        const d = try runDigestSuper(c.input, opts, index % 8, 0xff);
        try testing.expectEqual(c.size, d.set_size);
        try testing.expectEqual(c.bits.len, d.values.len);
        for (c.bits, d.values) |want, got| {
            try testing.expectEqual(want, @as(u32, @bitCast(got)));
        }
    }
}

test "known results, similarity" {
    const a = try runDigest(fox, .{ .hash_size = 8 }, 0, 0);
    @memcpy(test_keep[0..a.values.len], a.values);
    const b = try runDigest(cat, .{ .hash_size = 8 }, 0, 0);
    try testing.expectEqual(@as(?f64, 0.6), similarity(test_keep[0..a.values.len], b.values));

    const sa = try runDigestSuper(fox, .{ .hash_size = 8 }, 0, 0);
    @memcpy(test_keep_f[0..8], sa.values);
    const sb = try runDigestSuper(cat, .{ .hash_size = 8 }, 0, 0);
    try testing.expectEqual(@as(f64, 0.75), similaritySuper(test_keep_f[0..8], sb.values));
}

test "similarity edge cases" {
    const none = [_]i32{};
    const some = [_]i32{ -3, 5, 9 };
    try testing.expectEqual(@as(?f64, null), similarity(&none, &none));
    try testing.expectEqual(@as(?f64, 1.0), similarity(&some, &some));

    // Not digests (unsorted, duplicates): no fault, and the same values as
    // pyLZJD's sim gives for these arrays.
    const messy = [_]i32{ 9, 9, -3, 5, 5, 2 };
    try testing.expectEqual(@as(?f64, 0.125), similarity(&messy, &some));
    try testing.expectEqual(@as(?f64, 0.125), similarity(&some, &messy));
    try testing.expectEqual(@as(?f64, 1.0), similarity(&messy, &messy));

    // similaritySuper outside its contract: NaN, no fault.
    const f3 = [_]f32{ 0.25, 1.5, 2.5 };
    const f2 = [_]f32{ 0.25, 7.5 };
    const f0 = [_]f32{};
    try testing.expectEqual(@as(f64, 1.0), similaritySuper(&f3, &f3));
    try testing.expect(std.math.isNan(similaritySuper(&f3, &f2)));
    try testing.expect(std.math.isNan(similaritySuper(&f2, &f3)));
    try testing.expect(std.math.isNan(similaritySuper(&f3, &f0)));
    try testing.expect(std.math.isNan(similaritySuper(&f0, &f0)));
}

test "errors and their order" {
    var scratch: [1024]u8 = undefined;
    var out: [8]i32 = undefined;
    var out_f: [8]f32 = undefined;
    const need = scratchLen(fox.len, 8);
    try testing.expect(need <= scratch.len);

    // Exactly enough is enough; one byte or one entry less is not.
    _ = try digest(fox, .{ .hash_size = 8 }, scratch[0..need], &out);
    _ = try digestSuper(fox, .{ .hash_size = 8 }, scratch[0..need], &out_f);
    try testing.expectError(error.ScratchTooSmall, digest(fox, .{ .hash_size = 8 }, scratch[0 .. need - 1], &out));
    try testing.expectError(error.ScratchTooSmall, digestSuper(fox, .{ .hash_size = 8 }, scratch[0 .. need - 1], &out_f));
    try testing.expectError(error.ScratchTooSmall, digest(fox, .{ .hash_size = 8 }, scratch[0..0], &out));
    try testing.expectError(error.ScratchTooSmall, digest("", .{ .hash_size = 0 }, scratch[0..31], out[0..0]));
    try testing.expectError(error.OutputTooSmall, digest(fox, .{ .hash_size = 8 }, &scratch, out[0..7]));
    try testing.expectError(error.OutputTooSmall, digestSuper(fox, .{ .hash_size = 8 }, &scratch, out_f[0..7]));
    try testing.expectError(error.OutputTooSmall, digest(fox, .{ .hash_size = 0xffffffff }, &scratch, &out));
    try testing.expectError(error.InvalidHashSize, digestSuper(fox, .{ .hash_size = 0 }, &scratch, &out_f));
    try testing.expectError(error.InvalidHashSize, digestSuper(fox, .{ .hash_size = 0 }, &scratch, out_f[0..0]));

    // hash_size 0 in default mode: empty digest, set size still reported.
    const empty = try digest(fox, .{ .hash_size = 0 }, &scratch, out[0..0]);
    try testing.expectEqual(@as(usize, 0), empty.values.len);
    try testing.expectEqual(@as(u32, 28), empty.set_size);

    // An input that is too long. Only its length is looked at, so a slice
    // that claims the length without having the bytes is safe to pass.
    const byte = [_]u8{0};
    const too_long = @as([*]const u8, &byte)[0 .. @as(usize, max_input_len) + 1];
    try testing.expectError(error.InputTooLarge, digest(too_long, .{ .hash_size = 8 }, &scratch, &out));
    try testing.expectError(error.InputTooLarge, digestSuper(too_long, .{ .hash_size = 8 }, &scratch, &out_f));

    // Order: InvalidHashSize, OutputTooSmall, InputTooLarge, ScratchTooSmall.
    try testing.expectError(error.InvalidHashSize, digestSuper(too_long, .{ .hash_size = 0 }, scratch[0..0], out_f[0..0]));
    try testing.expectError(error.OutputTooSmall, digest(too_long, .{ .hash_size = 8 }, scratch[0..0], out[0..7]));
    try testing.expectError(error.OutputTooSmall, digestSuper(too_long, .{ .hash_size = 8 }, scratch[0..0], out_f[0..7]));
    try testing.expectError(error.InputTooLarge, digest(too_long, .{ .hash_size = 8 }, scratch[0..0], &out));
    try testing.expectError(error.InputTooLarge, digestSuper(too_long, .{ .hash_size = 8 }, scratch[0..0], &out_f));

    // The longest allowed input needs the largest table: a small scratch is
    // rejected by its size alone, again without reading the input.
    const longest = @as([*]const u8, &byte)[0..max_input_len];
    try testing.expectError(error.ScratchTooSmall, digest(longest, .{ .hash_size = 8 }, &scratch, &out));
}

test "a failed call leaves scratch and out untouched" {
    var scratch: [1024]u8 = undefined;
    var out: [8]i32 = @splat(0x11111111);
    var out_f: [8]f32 = @splat(1.5);
    @memset(&scratch, 0x77);
    const need = scratchLen(fox.len, 8);
    const byte = [_]u8{0};
    const too_long = @as([*]const u8, &byte)[0 .. @as(usize, max_input_len) + 1];

    try testing.expectError(error.ScratchTooSmall, digest(fox, .{ .hash_size = 8 }, scratch[0 .. need - 1], &out));
    try testing.expectError(error.ScratchTooSmall, digestSuper(fox, .{ .hash_size = 8 }, scratch[0 .. need - 1], &out_f));
    try testing.expectError(error.OutputTooSmall, digest(fox, .{ .hash_size = 8 }, &scratch, out[0..7]));
    try testing.expectError(error.OutputTooSmall, digestSuper(fox, .{ .hash_size = 8 }, &scratch, out_f[0..7]));
    try testing.expectError(error.InvalidHashSize, digestSuper(fox, .{ .hash_size = 0 }, &scratch, &out_f));
    try testing.expectError(error.InputTooLarge, digest(too_long, .{ .hash_size = 8 }, &scratch, &out));
    try testing.expectError(error.InputTooLarge, digestSuper(too_long, .{ .hash_size = 8 }, &scratch, &out_f));

    for (scratch) |x| try testing.expectEqual(@as(u8, 0x77), x);
    for (out) |x| try testing.expectEqual(@as(i32, 0x11111111), x);
    for (out_f) |x| try testing.expectEqual(@as(f32, 1.5), x);
}

test "results do not depend on scratch alignment or contents" {
    const fox8 = [_]i32{ -2128973781, -1737498726, -1261379688, -1248839937, -1112552363, -1040803305, -809654831, -729632045 };
    const fox8_super = [_]u32{ 0x38040000, 0x3eb37f46, 0x3e5e8834, 0x3f82a0b8, 0x3e25b470, 0x3ea8da96, 0x3e5aa954, 0x40e0536b };
    for (0..8) |offset| {
        for ([_]u8{ 0x00, 0xff, 0x5c }) |fill| {
            const d = try runDigest(fox, .{ .hash_size = 8 }, offset, fill);
            try testing.expectEqual(@as(u32, 28), d.set_size);
            try testing.expectEqualSlices(i32, &fox8, d.values);

            const s = try runDigestSuper(fox, .{ .hash_size = 8 }, offset, fill);
            try testing.expectEqual(@as(u32, 28), s.set_size);
            for (fox8_super, s.values) |want, got| {
                try testing.expectEqual(want, @as(u32, @bitCast(got)));
            }
        }
    }
}

// Generated inputs. The expected results of each vector come from pyLZJD
// run on the same generators.

const TestKind = enum { random, single, two, words, sparse, cycle };

const test_words = [_][]const u8{ "ab", "abc", "lzjd ", "\x00\x01", "fuzzy hash " };

fn fillTestInput(buf: []u8, kind: TestKind, seed: u32) void {
    var s = seed;
    switch (kind) {
        .random => for (buf) |*x| {
            s = xorshift32(s);
            x.* = @truncate(s >> 24);
        },
        .single => @memset(buf, @truncate(seed)),
        .two => for (buf) |*x| {
            s = xorshift32(s);
            x.* = if ((s >> 16) & 1 != 0) 0xff else 0x80;
        },
        .words => {
            const word = test_words[seed % test_words.len];
            for (buf, 0..) |*x, i| x.* = word[i % word.len];
        },
        .sparse => for (buf) |*x| {
            s = xorshift32(s);
            x.* = switch (s % 97) {
                0 => 0x01,
                1 => 0x80,
                2 => 0xff,
                else => 0x00,
            };
        },
        .cycle => for (buf, 0..) |*x, i| {
            x.* = @truncate(i +% seed);
        },
    }
}

/// FNV-1a (64-bit) over 32-bit words taken as 4 little-endian bytes each.
fn checksum(comptime T: type, values: []const T) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (values) |value| {
        const word: u32 = @bitCast(value);
        for (0..4) |i| {
            h ^= (word >> @intCast(8 * i)) & 0xff;
            h *%= 0x100000001b3;
        }
    }
    return h;
}

const Vector = struct {
    kind: TestKind,
    len: u32,
    seed: u32,
    k: u32,
    prob: f32 = 0,
    rng: u32 = 0,
    super: bool = false,
    /// Expected set size, digest length and digest checksum.
    size: u32,
    count: u32,
    sum: u64,
};

fn checkVector(v: Vector, index: usize) !void {
    const input = test_input[0..v.len];
    fillTestInput(input, v.kind, v.seed);
    const opts: Options = .{ .hash_size = v.k, .false_seen_prob = v.prob, .seed = v.rng };
    const fill: u8 = if (index % 2 == 0) 0x00 else 0xff;
    if (v.super) {
        const d = try runDigestSuper(input, opts, index % 8, fill);
        try testing.expectEqual(v.size, d.set_size);
        try testing.expectEqual(@as(usize, v.count), d.values.len);
        try testing.expectEqual(v.sum, checksum(f32, d.values));
    } else {
        const d = try runDigest(input, opts, index % 8, fill);
        try testing.expectEqual(v.size, d.set_size);
        try testing.expectEqual(@as(usize, v.count), d.values.len);
        try testing.expectEqual(v.sum, checksum(i32, d.values));
    }
}

test "pyLZJD vectors" {
    // Reports the index of the first vector that fails.
    var first_failure: ?usize = null;
    for (vectors, 0..) |v, index| {
        checkVector(v, index) catch {
            if (first_failure == null) first_failure = index;
        };
    }
    try testing.expectEqual(@as(?usize, null), first_failure);
}

/// A vector with a literal input, built to reach rare table paths.
const CraftedVector = struct {
    input: []const u8,
    k: u32,
    super: bool,
    size: u32,
    count: u32,
    sum: u64,
};

fn checkCraftedVector(v: CraftedVector, index: usize) !void {
    const opts: Options = .{ .hash_size = v.k };
    if (v.super) {
        const d = try runDigestSuper(v.input, opts, index % 8, 0xff);
        try testing.expectEqual(v.size, d.set_size);
        try testing.expectEqual(@as(usize, v.count), d.values.len);
        try testing.expectEqual(v.sum, checksum(f32, d.values));
    } else {
        const d = try runDigest(v.input, opts, index % 8, 0xff);
        try testing.expectEqual(v.size, d.set_size);
        try testing.expectEqual(@as(usize, v.count), d.values.len);
        try testing.expectEqual(v.sum, checksum(i32, d.values));
    }
}

test "pyLZJD vectors for crafted inputs" {
    var first_failure: ?usize = null;
    for (crafted_vectors, 0..) |v, index| {
        checkCraftedVector(v, index) catch {
            if (first_failure == null) first_failure = index;
        };
    }
    try testing.expectEqual(@as(?usize, null), first_failure);
}

const Spec = struct { kind: TestKind, len: u32, seed: u32, k: u32 };

const SimVector = struct {
    a: Spec,
    b: Spec,
    super: bool,
    /// pyLZJD's sim; null where it raises ZeroDivisionError.
    sim: ?f64,
};

fn checkSimVector(v: SimVector, index: usize) !void {
    const input_a = test_input[0..v.a.len];
    fillTestInput(input_a, v.a.kind, v.a.seed);
    if (v.super) {
        const a = try runDigestSuper(input_a, .{ .hash_size = v.a.k }, index % 8, 0xff);
        const kept = test_keep_f[0..a.values.len];
        @memcpy(kept, a.values);
        const input_b = test_input[0..v.b.len];
        fillTestInput(input_b, v.b.kind, v.b.seed);
        const b = try runDigestSuper(input_b, .{ .hash_size = v.b.k }, index % 8, 0x00);
        try testing.expectEqual(v.sim, @as(?f64, similaritySuper(kept, b.values)));
        try testing.expectEqual(v.sim, @as(?f64, similaritySuper(b.values, kept)));
    } else {
        const a = try runDigest(input_a, .{ .hash_size = v.a.k }, index % 8, 0xff);
        const kept = test_keep[0..a.values.len];
        @memcpy(kept, a.values);
        const input_b = test_input[0..v.b.len];
        fillTestInput(input_b, v.b.kind, v.b.seed);
        const b = try runDigest(input_b, .{ .hash_size = v.b.k }, index % 8, 0x00);
        try testing.expectEqual(v.sim, similarity(kept, b.values));
        try testing.expectEqual(v.sim, similarity(b.values, kept));
    }
}

test "pyLZJD similarity vectors" {
    var first_failure: ?usize = null;
    for (sim_vectors, 0..) |v, index| {
        checkSimVector(v, index) catch {
            if (first_failure == null) first_failure = index;
        };
    }
    try testing.expectEqual(@as(?usize, null), first_failure);
}

const LiteralSim = struct { a: []const i32, b: []const i32, sim: f64 };

test "pyLZJD similarity of literal arrays" {
    for (literal_sims) |v| {
        try testing.expectEqual(@as(?f64, v.sim), similarity(v.a, v.b));
    }
}

// BEGIN GENERATED (values from pyLZJD)

const vectors = [_]Vector{
    .{ .kind = .random, .len = 0, .seed = 0x9e3779b9, .k = 1024, .size = 0, .count = 0, .sum = 0xcbf29ce484222325 },
    .{ .kind = .random, .len = 0, .seed = 0x9e3779b9, .k = 8, .super = true, .size = 0, .count = 8, .sum = 0xc5283b30e0144a65 },
    .{ .kind = .random, .len = 1, .seed = 0x9e3779ba, .k = 16, .size = 1, .count = 1, .sum = 0x60f1b06c01ae03b2 },
    .{ .kind = .random, .len = 1, .seed = 0x9e3779ba, .k = 8, .super = true, .size = 1, .count = 8, .sum = 0x3ac4de38fb93290e },
    .{ .kind = .random, .len = 2, .seed = 0x9e3779bb, .k = 1024, .size = 2, .count = 2, .sum = 0x8dc1ca3dd2626971 },
    .{ .kind = .random, .len = 2, .seed = 0x9e3779bb, .k = 8, .super = true, .size = 2, .count = 8, .sum = 0x93003a0195a49fe4 },
    .{ .kind = .random, .len = 3, .seed = 0x9e3779bc, .k = 16, .size = 3, .count = 3, .sum = 0xdc97d23523a4aae7 },
    .{ .kind = .random, .len = 3, .seed = 0x9e3779bc, .k = 8, .super = true, .size = 3, .count = 8, .sum = 0x8c0fa0a0a4e46d7b },
    .{ .kind = .random, .len = 4, .seed = 0x9e3779bd, .k = 1024, .size = 4, .count = 4, .sum = 0xdb7ce29c16b32003 },
    .{ .kind = .random, .len = 4, .seed = 0x9e3779bd, .k = 8, .super = true, .size = 4, .count = 8, .sum = 0xfde7199eafcce211 },
    .{ .kind = .random, .len = 5, .seed = 0x9e3779be, .k = 16, .size = 5, .count = 5, .sum = 0x953f2315bd0d91a7 },
    .{ .kind = .random, .len = 5, .seed = 0x9e3779be, .k = 8, .super = true, .size = 5, .count = 8, .sum = 0x93003a0195a49fe4 },
    .{ .kind = .random, .len = 7, .seed = 0x9e3779bf, .k = 1024, .size = 7, .count = 7, .sum = 0x5d4f6a28cf748d3c },
    .{ .kind = .random, .len = 7, .seed = 0x9e3779bf, .k = 8, .super = true, .size = 7, .count = 8, .sum = 0xbb3c836b90b5b856 },
    .{ .kind = .random, .len = 8, .seed = 0x9e3779c0, .k = 16, .size = 8, .count = 8, .sum = 0xbcb246f7e19c7882 },
    .{ .kind = .random, .len = 8, .seed = 0x9e3779c0, .k = 8, .super = true, .size = 8, .count = 8, .sum = 0x8e9c6823a015fbad },
    .{ .kind = .random, .len = 15, .seed = 0x9e3779c1, .k = 1024, .size = 15, .count = 15, .sum = 0xf138a4321111ecf6 },
    .{ .kind = .random, .len = 15, .seed = 0x9e3779c1, .k = 8, .super = true, .size = 15, .count = 8, .sum = 0x76cc5f39abbad41a },
    .{ .kind = .random, .len = 16, .seed = 0x9e3779c2, .k = 16, .size = 16, .count = 16, .sum = 0x85307397cda2faf0 },
    .{ .kind = .random, .len = 16, .seed = 0x9e3779c2, .k = 8, .super = true, .size = 16, .count = 8, .sum = 0xe9e6185bf656cd8a },
    .{ .kind = .random, .len = 17, .seed = 0x9e3779c3, .k = 1024, .size = 17, .count = 17, .sum = 0x30ffff7bf3463c29 },
    .{ .kind = .random, .len = 17, .seed = 0x9e3779c3, .k = 8, .super = true, .size = 17, .count = 8, .sum = 0xe837348569b85251 },
    .{ .kind = .random, .len = 31, .seed = 0x9e3779c4, .k = 16, .size = 28, .count = 16, .sum = 0x1d903e3bb1e2ba12 },
    .{ .kind = .random, .len = 31, .seed = 0x9e3779c4, .k = 8, .super = true, .size = 28, .count = 8, .sum = 0x8ad1a368228a4236 },
    .{ .kind = .random, .len = 32, .seed = 0x9e3779c5, .k = 1024, .size = 32, .count = 32, .sum = 0x21df64bffb1fc756 },
    .{ .kind = .random, .len = 32, .seed = 0x9e3779c5, .k = 8, .super = true, .size = 32, .count = 8, .sum = 0x1d55a2344ee2d174 },
    .{ .kind = .random, .len = 33, .seed = 0x9e3779c6, .k = 16, .size = 31, .count = 16, .sum = 0x3d6626b4db8194da },
    .{ .kind = .random, .len = 33, .seed = 0x9e3779c6, .k = 8, .super = true, .size = 31, .count = 8, .sum = 0xbd81aa10abb60e17 },
    .{ .kind = .random, .len = 63, .seed = 0x9e3779c7, .k = 1024, .size = 56, .count = 56, .sum = 0xd2ffde982e17b69e },
    .{ .kind = .random, .len = 63, .seed = 0x9e3779c7, .k = 8, .super = true, .size = 56, .count = 8, .sum = 0x556f82a55b4ba740 },
    .{ .kind = .random, .len = 64, .seed = 0x9e3779c8, .k = 16, .size = 59, .count = 16, .sum = 0xf25cbc328ca29107 },
    .{ .kind = .random, .len = 64, .seed = 0x9e3779c8, .k = 8, .super = true, .size = 59, .count = 8, .sum = 0x25cc673d9c7993bc },
    .{ .kind = .random, .len = 65, .seed = 0x9e3779c9, .k = 1024, .size = 59, .count = 59, .sum = 0x38bdf314d089e667 },
    .{ .kind = .random, .len = 65, .seed = 0x9e3779c9, .k = 8, .super = true, .size = 59, .count = 8, .sum = 0x0ef62aee24da3dfa },
    .{ .kind = .random, .len = 100, .seed = 0x9e3779ca, .k = 16, .size = 89, .count = 16, .sum = 0xcce87133ed31964d },
    .{ .kind = .random, .len = 100, .seed = 0x9e3779ca, .k = 8, .super = true, .size = 89, .count = 8, .sum = 0x14e42919f8d906d7 },
    .{ .kind = .random, .len = 255, .seed = 0x9e3779cb, .k = 1024, .size = 201, .count = 201, .sum = 0x2e1176d93b7a4567 },
    .{ .kind = .random, .len = 255, .seed = 0x9e3779cb, .k = 8, .super = true, .size = 201, .count = 8, .sum = 0x696d084cda127013 },
    .{ .kind = .random, .len = 256, .seed = 0x9e3779cc, .k = 16, .size = 199, .count = 16, .sum = 0x36e165b6726dccef },
    .{ .kind = .random, .len = 256, .seed = 0x9e3779cc, .k = 8, .super = true, .size = 199, .count = 8, .sum = 0xa7ba925d72d5b446 },
    .{ .kind = .random, .len = 257, .seed = 0x9e3779cd, .k = 1024, .size = 195, .count = 195, .sum = 0x2e9f1a01d650c3f6 },
    .{ .kind = .random, .len = 257, .seed = 0x9e3779cd, .k = 8, .super = true, .size = 195, .count = 8, .sum = 0xacdf9d97c6be9b5d },
    .{ .kind = .random, .len = 1000, .seed = 0x9e3779ce, .k = 16, .size = 561, .count = 16, .sum = 0x957e9a0e5120b014 },
    .{ .kind = .random, .len = 1000, .seed = 0x9e3779ce, .k = 8, .super = true, .size = 561, .count = 8, .sum = 0xf9d88cdba6df9161 },
    .{ .kind = .random, .len = 4096, .seed = 0x9e3779cf, .k = 1024, .size = 1576, .count = 1024, .sum = 0x59f32eaff96d2922 },
    .{ .kind = .random, .len = 4096, .seed = 0x9e3779cf, .k = 8, .super = true, .size = 1576, .count = 8, .sum = 0xefcb557660392724 },
    .{ .kind = .random, .len = 20000, .seed = 0x9e3779d0, .k = 16, .size = 5702, .count = 16, .sum = 0x4591e19b70303316 },
    .{ .kind = .random, .len = 20000, .seed = 0x9e3779d0, .k = 8, .super = true, .size = 5702, .count = 8, .sum = 0x99cbf95a73438d59 },
    .{ .kind = .random, .len = 70000, .seed = 0x9e3779d1, .k = 1024, .size = 18204, .count = 1024, .sum = 0x8bfc2a919d125bfd },
    .{ .kind = .random, .len = 70000, .seed = 0x9e3779d1, .k = 8, .super = true, .size = 18204, .count = 8, .sum = 0x73e68871f05062ca },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 1, .size = 1844, .count = 1, .sum = 0x5174f16b09f7ac44 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 2, .size = 1844, .count = 2, .sum = 0x4b323d26225a0f33 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 3, .size = 1844, .count = 3, .sum = 0xf6e0ded283771819 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 8, .size = 1844, .count = 8, .sum = 0xc8a64329d3544693 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 16, .size = 1844, .count = 16, .sum = 0xe44bf7ea895f4c2a },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 64, .size = 1844, .count = 64, .sum = 0xf4c6066366c1aa02 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 128, .size = 1844, .count = 128, .sum = 0xedb0a3b1b5de85a3 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 1024, .size = 1844, .count = 1024, .sum = 0x6717b79b91dae835 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 5, .size = 1844, .count = 5, .sum = 0xc8fd6380df6d2272 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 7, .size = 1844, .count = 7, .sum = 0x8095a0e1762c258f },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 1000, .size = 1844, .count = 1000, .sum = 0x4cd49da0aa7dc7de },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 1023, .size = 1844, .count = 1023, .sum = 0xbb46d48b7a5ca423 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 1025, .size = 1844, .count = 1025, .sum = 0x10847dc289b31d1b },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 4096, .size = 1844, .count = 1844, .sum = 0x9faf9478c0f7933c },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 1, .super = true, .size = 1844, .count = 1, .sum = 0x4d17c67f9dc25e89 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 2, .super = true, .size = 1844, .count = 2, .sum = 0x56da45de6e62c194 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 3, .super = true, .size = 1844, .count = 3, .sum = 0x7fa09b1d980fd982 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 8, .super = true, .size = 1844, .count = 8, .sum = 0x939131dcb2d3a15d },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 16, .super = true, .size = 1844, .count = 16, .sum = 0xbf5e0c762f63123c },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 64, .super = true, .size = 1844, .count = 64, .sum = 0xeeeea87fb1783cf7 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 128, .super = true, .size = 1844, .count = 128, .sum = 0x0ea33e5650a8f429 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 5, .super = true, .size = 1844, .count = 5, .sum = 0x40288cc1d0dc41e4 },
    .{ .kind = .random, .len = 5000, .seed = 0x3039, .k = 100, .super = true, .size = 1844, .count = 100, .sum = 0xe9bdf50a68f1e94c },
    .{ .kind = .random, .len = 2000, .seed = 0x309, .k = 1024, .super = true, .size = 932, .count = 1024, .sum = 0xe986673cc513b5bf },
    .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1251, .size = 1254, .count = 1251, .sum = 0xe2e5271d8b0b875f },
    .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1252, .size = 1254, .count = 1252, .sum = 0x77903f9096734466 },
    .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1253, .size = 1254, .count = 1253, .sum = 0xefc922e85771dd89 },
    .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1254, .size = 1254, .count = 1254, .sum = 0x73c022e0458e3f12 },
    .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1255, .size = 1254, .count = 1254, .sum = 0x73c022e0458e3f12 },
    .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 627, .size = 1254, .count = 627, .sum = 0x13521651d5c90d82 },
    .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 1237, .size = 1240, .count = 1237, .sum = 0xd012e36115292554 },
    .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 1238, .size = 1240, .count = 1238, .sum = 0x70296e6a26ddfefb },
    .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 1239, .size = 1240, .count = 1239, .sum = 0x296232e2fda00a0d },
    .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 1240, .size = 1240, .count = 1240, .sum = 0x3fd91dc0942ce2c2 },
    .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 1241, .size = 1240, .count = 1240, .sum = 0x3fd91dc0942ce2c2 },
    .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 620, .size = 1240, .count = 620, .sum = 0x52dc8ff9ac376ff6 },
    .{ .kind = .random, .len = 3000, .seed = 0x3, .k = 1253, .size = 1256, .count = 1253, .sum = 0x45344037670f9342 },
    .{ .kind = .random, .len = 3000, .seed = 0x3, .k = 1254, .size = 1256, .count = 1254, .sum = 0xb3dd48282f01b369 },
    .{ .kind = .random, .len = 3000, .seed = 0x3, .k = 1255, .size = 1256, .count = 1255, .sum = 0xa31cde1de88c39bc },
    .{ .kind = .random, .len = 3000, .seed = 0x3, .k = 1256, .size = 1256, .count = 1256, .sum = 0xf4bca36afd124c3d },
    .{ .kind = .random, .len = 3000, .seed = 0x3, .k = 1257, .size = 1256, .count = 1256, .sum = 0xf4bca36afd124c3d },
    .{ .kind = .random, .len = 3000, .seed = 0x3, .k = 628, .size = 1256, .count = 628, .sum = 0xf50ceaee65ffb712 },
    .{ .kind = .two, .len = 3000, .seed = 0x9, .k = 424, .size = 425, .count = 424, .sum = 0xb309bed78f5059e1 },
    .{ .kind = .sparse, .len = 3000, .seed = 0x9, .k = 157, .size = 158, .count = 157, .sum = 0x770d183b4ab98622 },
    .{ .kind = .cycle, .len = 3000, .seed = 0x9, .k = 1111, .size = 1112, .count = 1111, .sum = 0xe299ab442d7bf5f8 },
    .{ .kind = .single, .len = 1, .seed = 0x0, .k = 1024, .size = 1, .count = 1, .sum = 0xc46dbb0d162484f7 },
    .{ .kind = .single, .len = 10, .seed = 0x0, .k = 8, .size = 4, .count = 4, .sum = 0x332f26f10d47c682 },
    .{ .kind = .single, .len = 100, .seed = 0x0, .k = 1024, .size = 13, .count = 13, .sum = 0x030eaf32f0849f5f },
    .{ .kind = .single, .len = 1000, .seed = 0x0, .k = 8, .size = 44, .count = 8, .sum = 0xe8435828ef85ba33 },
    .{ .kind = .single, .len = 20000, .seed = 0x0, .k = 1024, .size = 199, .count = 199, .sum = 0x4468458855b8837e },
    .{ .kind = .single, .len = 70000, .seed = 0x0, .k = 8, .size = 373, .count = 8, .sum = 0x1c412d7b284f66d0 },
    .{ .kind = .single, .len = 20000, .seed = 0x0, .k = 16, .super = true, .size = 199, .count = 16, .sum = 0x6ce0e471870e5c96 },
    .{ .kind = .single, .len = 100, .seed = 0x0, .k = 3, .super = true, .size = 13, .count = 3, .sum = 0xa44ce11f14f0a8b1 },
    .{ .kind = .single, .len = 1, .seed = 0x61, .k = 1024, .size = 1, .count = 1, .sum = 0x067f9937faae6ded },
    .{ .kind = .single, .len = 10, .seed = 0x61, .k = 8, .size = 4, .count = 4, .sum = 0x56505b309d295c1a },
    .{ .kind = .single, .len = 100, .seed = 0x61, .k = 1024, .size = 13, .count = 13, .sum = 0x95d771335cc22a23 },
    .{ .kind = .single, .len = 1000, .seed = 0x61, .k = 8, .size = 44, .count = 8, .sum = 0x3bae88b201a03c57 },
    .{ .kind = .single, .len = 20000, .seed = 0x61, .k = 1024, .size = 199, .count = 199, .sum = 0x8defc4966a3399ce },
    .{ .kind = .single, .len = 70000, .seed = 0x61, .k = 8, .size = 373, .count = 8, .sum = 0x17ee0909b926fab1 },
    .{ .kind = .single, .len = 20000, .seed = 0x61, .k = 16, .super = true, .size = 199, .count = 16, .sum = 0xbffe55fb589d7b27 },
    .{ .kind = .single, .len = 100, .seed = 0x61, .k = 3, .super = true, .size = 13, .count = 3, .sum = 0x664602ab9b15c388 },
    .{ .kind = .single, .len = 1, .seed = 0xfe, .k = 1024, .size = 1, .count = 1, .sum = 0x63ef5f604d799da8 },
    .{ .kind = .single, .len = 10, .seed = 0xfe, .k = 8, .size = 4, .count = 4, .sum = 0xa58ced2c433f1d72 },
    .{ .kind = .single, .len = 100, .seed = 0xfe, .k = 1024, .size = 13, .count = 13, .sum = 0xea749a03701e78f0 },
    .{ .kind = .single, .len = 1000, .seed = 0xfe, .k = 8, .size = 44, .count = 8, .sum = 0x627af9e71b8c9ca3 },
    .{ .kind = .single, .len = 20000, .seed = 0xfe, .k = 1024, .size = 199, .count = 199, .sum = 0xf543471591d7b7a6 },
    .{ .kind = .single, .len = 70000, .seed = 0xfe, .k = 8, .size = 373, .count = 8, .sum = 0xfb16a67cbef3b7c5 },
    .{ .kind = .single, .len = 20000, .seed = 0xfe, .k = 16, .super = true, .size = 199, .count = 16, .sum = 0xa59685a7ea6de745 },
    .{ .kind = .single, .len = 100, .seed = 0xfe, .k = 3, .super = true, .size = 13, .count = 3, .sum = 0x8174473dec071ead },
    .{ .kind = .single, .len = 1, .seed = 0xff, .k = 1024, .size = 1, .count = 1, .sum = 0x1661c0940b7159a8 },
    .{ .kind = .single, .len = 10, .seed = 0xff, .k = 8, .size = 4, .count = 4, .sum = 0x1801b5db801e9b7f },
    .{ .kind = .single, .len = 100, .seed = 0xff, .k = 1024, .size = 13, .count = 13, .sum = 0xab7eb8a27b90f53c },
    .{ .kind = .single, .len = 1000, .seed = 0xff, .k = 8, .size = 44, .count = 8, .sum = 0x5fc4e6c50b2963f5 },
    .{ .kind = .single, .len = 20000, .seed = 0xff, .k = 1024, .size = 199, .count = 199, .sum = 0xcfb77a8f1729ad60 },
    .{ .kind = .single, .len = 70000, .seed = 0xff, .k = 8, .size = 373, .count = 8, .sum = 0x768b62d56bbf8e6c },
    .{ .kind = .single, .len = 20000, .seed = 0xff, .k = 16, .super = true, .size = 199, .count = 16, .sum = 0x7a0e466795a4db6b },
    .{ .kind = .single, .len = 100, .seed = 0xff, .k = 3, .super = true, .size = 13, .count = 3, .sum = 0x4c995045e38e6b0e },
    .{ .kind = .two, .len = 1, .seed = 0x5, .k = 1024, .size = 1, .count = 1, .sum = 0xfc207820bda3af2c },
    .{ .kind = .two, .len = 10, .seed = 0x5, .k = 8, .size = 5, .count = 5, .sum = 0xd74045a1b0e60295 },
    .{ .kind = .two, .len = 100, .seed = 0x5, .k = 1024, .size = 28, .count = 28, .sum = 0x8fff8ef3e5d72563 },
    .{ .kind = .two, .len = 1000, .seed = 0x5, .k = 8, .size = 172, .count = 8, .sum = 0xd40ade701b569ae1 },
    .{ .kind = .two, .len = 20000, .seed = 0x5, .k = 1024, .size = 2139, .count = 1024, .sum = 0x88a779370719746c },
    .{ .kind = .two, .len = 70000, .seed = 0x5, .k = 8, .size = 6407, .count = 8, .sum = 0x1a93eef650a63183 },
    .{ .kind = .two, .len = 20000, .seed = 0x5, .k = 16, .super = true, .size = 2139, .count = 16, .sum = 0xa5247a927012b464 },
    .{ .kind = .two, .len = 100, .seed = 0x5, .k = 3, .super = true, .size = 28, .count = 3, .sum = 0xc3a00723432df1aa },
    .{ .kind = .two, .len = 1, .seed = 0x6, .k = 1024, .size = 1, .count = 1, .sum = 0xfc207820bda3af2c },
    .{ .kind = .two, .len = 10, .seed = 0x6, .k = 8, .size = 6, .count = 6, .sum = 0x8e0e5f0ba81fe560 },
    .{ .kind = .two, .len = 100, .seed = 0x6, .k = 1024, .size = 28, .count = 28, .sum = 0x0061816d9283a768 },
    .{ .kind = .two, .len = 1000, .seed = 0x6, .k = 8, .size = 172, .count = 8, .sum = 0x2e194814352e72b4 },
    .{ .kind = .two, .len = 20000, .seed = 0x6, .k = 1024, .size = 2144, .count = 1024, .sum = 0xeb6f8791841fe50c },
    .{ .kind = .two, .len = 70000, .seed = 0x6, .k = 8, .size = 6408, .count = 8, .sum = 0xf24ae6d0eeac7bbb },
    .{ .kind = .two, .len = 20000, .seed = 0x6, .k = 16, .super = true, .size = 2144, .count = 16, .sum = 0xce60f3e37ebffd3c },
    .{ .kind = .two, .len = 100, .seed = 0x6, .k = 3, .super = true, .size = 28, .count = 3, .sum = 0x7f7543271fcde53a },
    .{ .kind = .words, .len = 1, .seed = 0x0, .k = 1024, .size = 1, .count = 1, .sum = 0x067f9937faae6ded },
    .{ .kind = .words, .len = 10, .seed = 0x0, .k = 8, .size = 5, .count = 5, .sum = 0x23cc91fbea65a3a7 },
    .{ .kind = .words, .len = 100, .seed = 0x0, .k = 1024, .size = 19, .count = 19, .sum = 0x374c9344a2ac553c },
    .{ .kind = .words, .len = 1000, .seed = 0x0, .k = 8, .size = 62, .count = 8, .sum = 0x406b3b7139250eac },
    .{ .kind = .words, .len = 20000, .seed = 0x0, .k = 1024, .size = 281, .count = 281, .sum = 0x81f5e7af273a0645 },
    .{ .kind = .words, .len = 70000, .seed = 0x0, .k = 8, .size = 528, .count = 8, .sum = 0xdac2ba9d2b6bd510 },
    .{ .kind = .words, .len = 20000, .seed = 0x0, .k = 16, .super = true, .size = 281, .count = 16, .sum = 0x3e7933ca46462241 },
    .{ .kind = .words, .len = 100, .seed = 0x0, .k = 3, .super = true, .size = 19, .count = 3, .sum = 0xb550423e272be375 },
    .{ .kind = .words, .len = 1, .seed = 0x1, .k = 1024, .size = 1, .count = 1, .sum = 0x067f9937faae6ded },
    .{ .kind = .words, .len = 10, .seed = 0x1, .k = 8, .size = 6, .count = 6, .sum = 0x8d93b37fe382d73c },
    .{ .kind = .words, .len = 100, .seed = 0x1, .k = 1024, .size = 23, .count = 23, .sum = 0x9ceb19043972145a },
    .{ .kind = .words, .len = 1000, .seed = 0x1, .k = 8, .size = 75, .count = 8, .sum = 0x88e7ee54570132a6 },
    .{ .kind = .words, .len = 20000, .seed = 0x1, .k = 1024, .size = 344, .count = 344, .sum = 0x3d8ff3e86c47a5d1 },
    .{ .kind = .words, .len = 70000, .seed = 0x1, .k = 8, .size = 646, .count = 8, .sum = 0x0a6af9a2ff65884d },
    .{ .kind = .words, .len = 20000, .seed = 0x1, .k = 16, .super = true, .size = 344, .count = 16, .sum = 0xfbb055d659f9146e },
    .{ .kind = .words, .len = 100, .seed = 0x1, .k = 3, .super = true, .size = 23, .count = 3, .sum = 0x8e0995ecfa64b412 },
    .{ .kind = .words, .len = 1, .seed = 0x2, .k = 1024, .size = 1, .count = 1, .sum = 0x62b5069562881c95 },
    .{ .kind = .words, .len = 10, .seed = 0x2, .k = 8, .size = 7, .count = 7, .sum = 0xbf2c70f453c71d8e },
    .{ .kind = .words, .len = 100, .seed = 0x2, .k = 1024, .size = 29, .count = 29, .sum = 0x3be872a8896c547f },
    .{ .kind = .words, .len = 1000, .seed = 0x2, .k = 8, .size = 97, .count = 8, .sum = 0x32e02b764c32abe8 },
    .{ .kind = .words, .len = 20000, .seed = 0x2, .k = 1024, .size = 444, .count = 444, .sum = 0x7c50c1f2ec5f5908 },
    .{ .kind = .words, .len = 70000, .seed = 0x2, .k = 8, .size = 834, .count = 8, .sum = 0x6672ba3b4321b427 },
    .{ .kind = .words, .len = 20000, .seed = 0x2, .k = 16, .super = true, .size = 444, .count = 16, .sum = 0x478dbcdf2b01a16c },
    .{ .kind = .words, .len = 100, .seed = 0x2, .k = 3, .super = true, .size = 29, .count = 3, .sum = 0x419afa53c0edfba2 },
    .{ .kind = .words, .len = 1, .seed = 0x3, .k = 1024, .size = 1, .count = 1, .sum = 0xc46dbb0d162484f7 },
    .{ .kind = .words, .len = 10, .seed = 0x3, .k = 8, .size = 5, .count = 5, .sum = 0x21c73f27162d1344 },
    .{ .kind = .words, .len = 100, .seed = 0x3, .k = 1024, .size = 19, .count = 19, .sum = 0x3fa5f36a840b3dfd },
    .{ .kind = .words, .len = 1000, .seed = 0x3, .k = 8, .size = 62, .count = 8, .sum = 0x480adf8f80ddeb24 },
    .{ .kind = .words, .len = 20000, .seed = 0x3, .k = 1024, .size = 281, .count = 281, .sum = 0x3ccee4b9ce865357 },
    .{ .kind = .words, .len = 70000, .seed = 0x3, .k = 8, .size = 528, .count = 8, .sum = 0x07c2a99abd35c01a },
    .{ .kind = .words, .len = 20000, .seed = 0x3, .k = 16, .super = true, .size = 281, .count = 16, .sum = 0xb37ec28286cace53 },
    .{ .kind = .words, .len = 100, .seed = 0x3, .k = 3, .super = true, .size = 19, .count = 3, .sum = 0x3d34d08f00cd85c2 },
    .{ .kind = .words, .len = 1, .seed = 0x4, .k = 1024, .size = 1, .count = 1, .sum = 0x53a0b942a767bbe7 },
    .{ .kind = .words, .len = 10, .seed = 0x4, .k = 8, .size = 8, .count = 8, .sum = 0x8cca407c22a1b17d },
    .{ .kind = .words, .len = 100, .seed = 0x4, .k = 1024, .size = 36, .count = 36, .sum = 0x93650c5418861313 },
    .{ .kind = .words, .len = 1000, .seed = 0x4, .k = 8, .size = 138, .count = 8, .sum = 0xc5908109f26ecc66 },
    .{ .kind = .words, .len = 20000, .seed = 0x4, .k = 1024, .size = 652, .count = 652, .sum = 0x1a53e26e2edaa8e8 },
    .{ .kind = .words, .len = 70000, .seed = 0x4, .k = 8, .size = 1230, .count = 8, .sum = 0xe820aa7226142d29 },
    .{ .kind = .words, .len = 20000, .seed = 0x4, .k = 16, .super = true, .size = 652, .count = 16, .sum = 0x03aed713a1d1b217 },
    .{ .kind = .words, .len = 100, .seed = 0x4, .k = 3, .super = true, .size = 36, .count = 3, .sum = 0x9aab417ad7572635 },
    .{ .kind = .sparse, .len = 1, .seed = 0x7, .k = 1024, .size = 1, .count = 1, .sum = 0xc46dbb0d162484f7 },
    .{ .kind = .sparse, .len = 10, .seed = 0x7, .k = 8, .size = 4, .count = 4, .sum = 0x332f26f10d47c682 },
    .{ .kind = .sparse, .len = 100, .seed = 0x7, .k = 1024, .size = 15, .count = 15, .sum = 0x09acabe6a643de72 },
    .{ .kind = .sparse, .len = 1000, .seed = 0x7, .k = 8, .size = 58, .count = 8, .sum = 0x8fba12f390e7726f },
    .{ .kind = .sparse, .len = 20000, .seed = 0x7, .k = 1024, .size = 652, .count = 652, .sum = 0x20c5eb796b03b5f1 },
    .{ .kind = .sparse, .len = 70000, .seed = 0x7, .k = 8, .size = 1974, .count = 8, .sum = 0x5a3254b5a9c2b8e3 },
    .{ .kind = .sparse, .len = 20000, .seed = 0x7, .k = 16, .super = true, .size = 652, .count = 16, .sum = 0x11092577d360cd01 },
    .{ .kind = .sparse, .len = 100, .seed = 0x7, .k = 3, .super = true, .size = 15, .count = 3, .sum = 0xa44ce11f14f0a8b1 },
    .{ .kind = .sparse, .len = 1, .seed = 0x8, .k = 1024, .size = 1, .count = 1, .sum = 0xc46dbb0d162484f7 },
    .{ .kind = .sparse, .len = 10, .seed = 0x8, .k = 8, .size = 4, .count = 4, .sum = 0x332f26f10d47c682 },
    .{ .kind = .sparse, .len = 100, .seed = 0x8, .k = 1024, .size = 14, .count = 14, .sum = 0xa8a13fae232abba7 },
    .{ .kind = .sparse, .len = 1000, .seed = 0x8, .k = 8, .size = 62, .count = 8, .sum = 0xf1018e08134bdacc },
    .{ .kind = .sparse, .len = 20000, .seed = 0x8, .k = 1024, .size = 673, .count = 673, .sum = 0x22f4d9345c7988a5 },
    .{ .kind = .sparse, .len = 70000, .seed = 0x8, .k = 8, .size = 2020, .count = 8, .sum = 0x17e757cf9c998c88 },
    .{ .kind = .sparse, .len = 20000, .seed = 0x8, .k = 16, .super = true, .size = 673, .count = 16, .sum = 0x69ecb7a02c72c293 },
    .{ .kind = .sparse, .len = 100, .seed = 0x8, .k = 3, .super = true, .size = 14, .count = 3, .sum = 0xa44ce11f14f0a8b1 },
    .{ .kind = .cycle, .len = 1, .seed = 0x0, .k = 1024, .size = 1, .count = 1, .sum = 0xc46dbb0d162484f7 },
    .{ .kind = .cycle, .len = 10, .seed = 0x0, .k = 8, .size = 10, .count = 8, .sum = 0xde43d0a950fcaa00 },
    .{ .kind = .cycle, .len = 100, .seed = 0x0, .k = 1024, .size = 100, .count = 100, .sum = 0xdbd1556174d80822 },
    .{ .kind = .cycle, .len = 1000, .seed = 0x0, .k = 8, .size = 589, .count = 8, .sum = 0xa8147612f82064bf },
    .{ .kind = .cycle, .len = 20000, .seed = 0x0, .k = 1024, .size = 3074, .count = 1024, .sum = 0x250a8f7fc89cf674 },
    .{ .kind = .cycle, .len = 70000, .seed = 0x0, .k = 8, .size = 5859, .count = 8, .sum = 0xa2c60a3cc46144ea },
    .{ .kind = .cycle, .len = 20000, .seed = 0x0, .k = 16, .super = true, .size = 3074, .count = 16, .sum = 0x5559887ba9eed295 },
    .{ .kind = .cycle, .len = 100, .seed = 0x0, .k = 3, .super = true, .size = 100, .count = 3, .sum = 0xc54d8009d853928a },
    .{ .kind = .cycle, .len = 1, .seed = 0xc8, .k = 1024, .size = 1, .count = 1, .sum = 0x5b31b28cb0a63355 },
    .{ .kind = .cycle, .len = 10, .seed = 0xc8, .k = 8, .size = 10, .count = 8, .sum = 0x6f7beae3c557c0b6 },
    .{ .kind = .cycle, .len = 100, .seed = 0xc8, .k = 1024, .size = 100, .count = 100, .sum = 0xb467d967cac6ab5f },
    .{ .kind = .cycle, .len = 1000, .seed = 0xc8, .k = 8, .size = 589, .count = 8, .sum = 0xb497bfc342503a9e },
    .{ .kind = .cycle, .len = 20000, .seed = 0xc8, .k = 1024, .size = 3074, .count = 1024, .sum = 0xf190eeb0cf83d01f },
    .{ .kind = .cycle, .len = 70000, .seed = 0xc8, .k = 8, .size = 5859, .count = 8, .sum = 0xa67cc4974eaac635 },
    .{ .kind = .cycle, .len = 20000, .seed = 0xc8, .k = 16, .super = true, .size = 3074, .count = 16, .sum = 0x5559887ba9eed295 },
    .{ .kind = .cycle, .len = 100, .seed = 0xc8, .k = 3, .super = true, .size = 100, .count = 3, .sum = 0x08449bafb7160752 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.0, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.0, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.0, .rng = 0x1, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.0, .rng = 0x1, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.0, .rng = 0xdeadbeef, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.0, .rng = 0xdeadbeef, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = 0.0, .rng = 0xdeadbeef, .super = true, .size = 5702, .count = 8, .sum = 0xd7d2a8c96d88f470 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.0, .rng = 0x1, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 1.0, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 1.0, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 1.0, .rng = 0x1, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 1.0, .rng = 0x1, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 1.0, .rng = 0xdeadbeef, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 1.0, .rng = 0xdeadbeef, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = 1.0, .rng = 0xdeadbeef, .super = true, .size = 5702, .count = 8, .sum = 0xd7d2a8c96d88f470 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 1.0, .rng = 0x1, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = -1.0, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = -1.0, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = -1.0, .rng = 0x1, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = -1.0, .rng = 0x1, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = -1.0, .rng = 0xdeadbeef, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = -1.0, .rng = 0xdeadbeef, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = -1.0, .rng = 0xdeadbeef, .super = true, .size = 5702, .count = 8, .sum = 0xd7d2a8c96d88f470 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = -1.0, .rng = 0x1, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 1e-09, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 1e-09, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 1e-09, .rng = 0x1, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 1e-09, .rng = 0x1, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 1e-09, .rng = 0xdeadbeef, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 1e-09, .rng = 0xdeadbeef, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = 1e-09, .rng = 0xdeadbeef, .super = true, .size = 5702, .count = 8, .sum = 0xd7d2a8c96d88f470 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 1e-09, .rng = 0x1, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 3e-08, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 3e-08, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 3e-08, .rng = 0x1, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 3e-08, .rng = 0x1, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 3e-08, .rng = 0xdeadbeef, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 3e-08, .rng = 0xdeadbeef, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = 3e-08, .rng = 0xdeadbeef, .super = true, .size = 5702, .count = 8, .sum = 0xd7d2a8c96d88f470 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 3e-08, .rng = 0x1, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.001, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.001, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.001, .rng = 0x1, .size = 5699, .count = 64, .sum = 0xa125287f519964b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.001, .rng = 0x1, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.001, .rng = 0xdeadbeef, .size = 5702, .count = 64, .sum = 0xf987195f19ef8ea7 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.001, .rng = 0xdeadbeef, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = 0.001, .rng = 0xdeadbeef, .super = true, .size = 5702, .count = 8, .sum = 0x4404f87d761684ba },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.001, .rng = 0x1, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.5, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.5, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.5, .rng = 0x1, .size = 4854, .count = 64, .sum = 0x4dc810d5fa5e3287 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.5, .rng = 0x1, .size = 220, .count = 64, .sum = 0x741882bb4a578342 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.5, .rng = 0xdeadbeef, .size = 4878, .count = 64, .sum = 0x2488286a8e232767 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.5, .rng = 0xdeadbeef, .size = 220, .count = 64, .sum = 0x87e9d0800e8f3dd2 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = 0.5, .rng = 0xdeadbeef, .super = true, .size = 4878, .count = 8, .sum = 0xf722a3d06cfd5c88 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.5, .rng = 0x1, .super = true, .size = 142, .count = 8, .sum = 0xc5bcbdd35ca69638 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.9, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.9, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.9, .rng = 0x1, .size = 1944, .count = 64, .sum = 0xd1d86a0ccdc8c4e0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.9, .rng = 0x1, .size = 208, .count = 64, .sum = 0x00b227f8d2d67988 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.9, .rng = 0xdeadbeef, .size = 1857, .count = 64, .sum = 0x17d36ad12dc53384 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.9, .rng = 0xdeadbeef, .size = 209, .count = 64, .sum = 0x4125c46d68e8f1e5 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = 0.9, .rng = 0xdeadbeef, .super = true, .size = 1857, .count = 8, .sum = 0x4a587d1908a5b88a },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.9, .rng = 0x1, .super = true, .size = 42, .count = 8, .sum = 0x44f703754f2c242b },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.999, .rng = 0x0, .size = 5702, .count = 64, .sum = 0xf5b38c24a53b58b0 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.999, .rng = 0x0, .size = 221, .count = 64, .sum = 0x30aa8f3c8f0be77d },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.999, .rng = 0x1, .size = 18, .count = 18, .sum = 0x242924d20975d370 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.999, .rng = 0x1, .size = 6, .count = 6, .sum = 0x9f122c901a3baf4b },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 64, .prob = 0.999, .rng = 0xdeadbeef, .size = 17, .count = 17, .sum = 0xc23eba9a0deac2a7 },
    .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64, .prob = 0.999, .rng = 0xdeadbeef, .size = 2, .count = 2, .sum = 0xdac114fcdb2f25f6 },
    .{ .kind = .random, .len = 20000, .seed = 0x1092, .k = 8, .prob = 0.999, .rng = 0xdeadbeef, .super = true, .size = 17, .count = 8, .sum = 0x0ff9c36a1e21f367 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.999, .rng = 0x1, .super = true, .size = 1, .count = 8, .sum = 0x859145d1893c4f29 },
    .{ .kind = .random, .len = 3, .seed = 0x7a6c, .k = 8, .size = 3, .count = 3, .sum = 0x3e0389d8bdeab45c },
    .{ .kind = .random, .len = 4, .seed = 0x7a6c, .k = 8, .size = 4, .count = 4, .sum = 0xf4b2858f4a521327 },
    .{ .kind = .random, .len = 6, .seed = 0x7a6f, .k = 8, .size = 6, .count = 6, .sum = 0x9962f7cafa569088 },
    .{ .kind = .random, .len = 7, .seed = 0x7a6f, .k = 8, .size = 7, .count = 7, .sum = 0xde5b951a8bc59345 },
    .{ .kind = .random, .len = 9, .seed = 0x7a72, .k = 8, .size = 8, .count = 8, .sum = 0x26f7ff3ee195b97f },
    .{ .kind = .random, .len = 10, .seed = 0x7a72, .k = 8, .size = 9, .count = 8, .sum = 0xe3b9c435f82e238c },
    .{ .kind = .random, .len = 21, .seed = 0x7a7e, .k = 8, .size = 20, .count = 8, .sum = 0xd97e607ab7e201a2 },
    .{ .kind = .random, .len = 22, .seed = 0x7a7e, .k = 8, .size = 21, .count = 8, .sum = 0xa24320cbad01c669 },
    .{ .kind = .random, .len = 36, .seed = 0x7a8d, .k = 8, .size = 33, .count = 8, .sum = 0xf3c59cc5434022e1 },
    .{ .kind = .random, .len = 37, .seed = 0x7a8d, .k = 8, .size = 34, .count = 8, .sum = 0x8621407eb16cdb78 },
    .{ .kind = .random, .len = 69, .seed = 0x7aae, .k = 8, .size = 59, .count = 8, .sum = 0xe3e78ca39de699e4 },
    .{ .kind = .random, .len = 70, .seed = 0x7aae, .k = 8, .size = 60, .count = 8, .sum = 0x0055a36b38586fae },
    .{ .kind = .random, .len = 135, .seed = 0x7af0, .k = 8, .size = 116, .count = 8, .sum = 0x1624c0e4e0e6ed0e },
    .{ .kind = .random, .len = 136, .seed = 0x7af0, .k = 8, .size = 117, .count = 8, .sum = 0x1624c0e4e0e6ed0e },
    .{ .kind = .random, .len = 261, .seed = 0x7b6e, .k = 8, .size = 188, .count = 8, .sum = 0x6b603eb5085fda2f },
    .{ .kind = .random, .len = 262, .seed = 0x7b6e, .k = 8, .size = 189, .count = 8, .sum = 0xb3eb7c91f5f1e21c },
    .{ .kind = .random, .len = 516, .seed = 0x7c6d, .k = 8, .size = 344, .count = 8, .sum = 0x371f25ef8433de8c },
    .{ .kind = .random, .len = 517, .seed = 0x7c6d, .k = 8, .size = 344, .count = 8, .sum = 0x5c7c611adef3147c },
    .{ .kind = .random, .len = 1041, .seed = 0x7e7a, .k = 8, .size = 571, .count = 8, .sum = 0x470c1e03ee015d2c },
    .{ .kind = .random, .len = 1042, .seed = 0x7e7a, .k = 8, .size = 571, .count = 8, .sum = 0x9cc76367f7fdd178 },
    .{ .kind = .random, .len = 2064, .seed = 0x8279, .k = 8, .size = 960, .count = 8, .sum = 0x3818e6525765ea62 },
    .{ .kind = .random, .len = 2065, .seed = 0x8279, .k = 8, .size = 961, .count = 8, .sum = 0xf4443f4d00c75a28 },
    .{ .kind = .random, .len = 4110, .seed = 0x8a77, .k = 8, .size = 1582, .count = 8, .sum = 0x4a0750a7ad1ea4dc },
    .{ .kind = .random, .len = 4111, .seed = 0x8a77, .k = 8, .size = 1582, .count = 8, .sum = 0x5b0d1c5ced31f783 },
    .{ .kind = .random, .len = 8226, .seed = 0x9a8b, .k = 8, .size = 2707, .count = 8, .sum = 0x487105b16290bfc0 },
    .{ .kind = .random, .len = 8227, .seed = 0x9a8b, .k = 8, .size = 2707, .count = 8, .sum = 0x487105b16290bfc0 },
    .{ .kind = .random, .len = 16401, .seed = 0xba7a, .k = 8, .size = 4799, .count = 8, .sum = 0x5bb702190c8937e2 },
    .{ .kind = .random, .len = 16402, .seed = 0xba7a, .k = 8, .size = 4800, .count = 8, .sum = 0x9ccb1e671a8418f2 },
    .{ .kind = .random, .len = 32769, .seed = 0xfa6a, .k = 8, .size = 8896, .count = 8, .sum = 0x688228494efe32e0 },
    .{ .kind = .random, .len = 32770, .seed = 0xfa6a, .k = 8, .size = 8896, .count = 8, .sum = 0xff983460e928a6be },
    .{ .kind = .random, .len = 65556, .seed = 0x17a7d, .k = 8, .size = 17093, .count = 8, .sum = 0xdffe088bf5946e1d },
    .{ .kind = .random, .len = 65557, .seed = 0x17a7d, .k = 8, .size = 17093, .count = 8, .sum = 0x48a35950f5b0c71e },
    .{ .kind = .random, .len = 131076, .seed = 0x27a6d, .k = 8, .size = 33473, .count = 8, .sum = 0xd84867a4f80b555b },
    .{ .kind = .random, .len = 131077, .seed = 0x27a6d, .k = 8, .size = 33473, .count = 8, .sum = 0x57f7adfde4a267d6 },
    .{ .kind = .random, .len = 262176, .seed = 0x47a89, .k = 8, .size = 66248, .count = 8, .sum = 0x87f00e121b838a86 },
    .{ .kind = .random, .len = 262177, .seed = 0x47a89, .k = 8, .size = 66248, .count = 8, .sum = 0xae3838808b00c95e },
    .{ .kind = .random, .len = 524445, .seed = 0x87b06, .k = 8, .size = 131814, .count = 8, .sum = 0xb3d30923e7eafb9c },
    .{ .kind = .random, .len = 524446, .seed = 0x87b06, .k = 8, .size = 131815, .count = 8, .sum = 0xe209ccf5f490ba3d },
    .{ .kind = .random, .len = 2064, .seed = 0x63, .k = 4, .super = true, .size = 953, .count = 4, .sum = 0xe79442c6f00e07b3 },
    .{ .kind = .random, .len = 2065, .seed = 0x63, .k = 4, .super = true, .size = 953, .count = 4, .sum = 0xe79442c6f00e07b3 },
    .{ .kind = .random, .len = 1048576, .seed = 0x7ea, .k = 1024, .size = 262845, .count = 1024, .sum = 0xc47074ace1b923ba },
    .{ .kind = .random, .len = 1048576, .seed = 0x7ea, .k = 8, .super = true, .size = 262845, .count = 8, .sum = 0x94a061e9516cb75f },
    .{ .kind = .random, .len = 1048629, .seed = 0x7eb, .k = 8, .size = 262857, .count = 8, .sum = 0x35d37286d54f807e },
    .{ .kind = .random, .len = 1000003, .seed = 0x7ec, .k = 1024, .prob = 0.5, .rng = 0x7, .size = 200787, .count = 1024, .sum = 0xae70acd9972892d1 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.5, .rng = 0x24d939ce, .size = 149, .count = 64, .sum = 0x2ded6402dbbadc27 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.5, .rng = 0x86e7b81, .size = 51, .count = 51, .sum = 0x0497a44cce514b70 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.5, .rng = 0xd66cbce7, .size = 131, .count = 64, .sum = 0xa7f42adb61d994a8 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.5, .rng = 0x5bfb6782, .size = 51, .count = 51, .sum = 0x1b0c39456343ffc2 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.5, .rng = 0xd66cbce7, .super = true, .size = 131, .count = 8, .sum = 0xe320791e870970b1 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.3, .rng = 0x14963cbe, .size = 187, .count = 64, .sum = 0xd0c0dd8142a96d33 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.3, .rng = 0xb20228f0, .size = 51, .count = 51, .sum = 0x6db83f81a18832e2 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.3, .rng = 0xe623b997, .size = 176, .count = 64, .sum = 0x600361642c4cacaf },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.3, .rng = 0xe19734f3, .size = 51, .count = 51, .sum = 0xf001a5965bd01f92 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.3, .rng = 0xe623b997, .super = true, .size = 176, .count = 8, .sum = 0xcba66ef8cfad4307 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.9, .rng = 0x72288fd7, .size = 29, .count = 29, .sum = 0x7a226f01181d6f3f },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.9, .rng = 0x14a2a9f9, .size = 26, .count = 26, .sum = 0x7f9615a94cc4bed8 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.9, .rng = 0x809d0afe, .size = 38, .count = 38, .sum = 0x26895e5a7dd76aaf },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.9, .rng = 0x4737b5fa, .size = 27, .count = 27, .sum = 0x2d60f3ae026e3086 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.9, .rng = 0x809d0afe, .super = true, .size = 38, .count = 8, .sum = 0xbeb54dbbbd9d4b0c },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.001, .rng = 0xfec2a352, .size = 222, .count = 64, .sum = 0x05b6c5f8552f42e7 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.001, .rng = 0x5679d75b, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.001, .rng = 0xc77267b, .size = 222, .count = 64, .sum = 0xc0823ae31c73a8ff },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.001, .rng = 0x5eccb58, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.001, .rng = 0xc77267b, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 1e-09, .rng = 0x65d14210, .size = 222, .count = 64, .sum = 0x31d224a8adb2a673 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 1e-09, .rng = 0xa154dd6c, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 1e-09, .rng = 0x720fcd6b, .size = 222, .count = 64, .sum = 0xc0823ae31c73a8ff },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 1e-09, .rng = 0x41eb5968, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 1e-09, .rng = 0x720fcd6b, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 3e-08, .rng = 0x75d1c214, .size = 222, .count = 64, .sum = 0x31d224a8adb2a673 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 3e-08, .rng = 0x18b3c0c1, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 3e-08, .rng = 0x620f4d6f, .size = 222, .count = 64, .sum = 0xc0823ae31c73a8ff },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 3e-08, .rng = 0xf80c44c5, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 3e-08, .rng = 0x620f4d6f, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 1e-45, .rng = 0xacd979ce, .size = 222, .count = 64, .sum = 0x31d224a8adb2a673 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 1e-45, .rng = 0xb3f6ef05, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 1e-45, .rng = 0x5e6cfce7, .size = 222, .count = 64, .sum = 0xc0823ae31c73a8ff },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 1e-45, .rng = 0xe063f306, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 1e-45, .rng = 0x5e6cfce7, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.99999997, .rng = 0x2842def0, .size = 1, .count = 1, .sum = 0x1cae57749aeb18d1 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.99999997, .rng = 0xe3b5457d, .size = 1, .count = 1, .sum = 0x6f784383dc36fd0e },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.99999997, .rng = 0xdaf75bd9, .size = 0, .count = 0, .sum = 0xcbf29ce484222325 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.99999997, .rng = 0xb020597e, .size = 0, .count = 0, .sum = 0xcbf29ce484222325 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.99999997, .rng = 0xdaf75bd9, .super = true, .size = 0, .count = 8, .sum = 0xc5283b30e0144a65 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.0, .rng = 0xacd979ce, .size = 222, .count = 64, .sum = 0x31d224a8adb2a673 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.0, .rng = 0xb3f6ef05, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 0.0, .rng = 0x5e6cfce7, .size = 222, .count = 64, .sum = 0x31d224a8adb2a673 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 0.0, .rng = 0xe063f306, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 0.0, .rng = 0x5e6cfce7, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 1e-46, .rng = 0xacd979ce, .size = 222, .count = 64, .sum = 0x31d224a8adb2a673 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 1e-46, .rng = 0xb3f6ef05, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 64, .prob = 1e-46, .rng = 0x5e6cfce7, .size = 222, .count = 64, .sum = 0x31d224a8adb2a673 },
    .{ .kind = .words, .len = 300, .seed = 0x2, .k = 64, .prob = 1e-46, .rng = 0xe063f306, .size = 52, .count = 52, .sum = 0x9bc8c15b33e138cf },
    .{ .kind = .random, .len = 300, .seed = 0x1093, .k = 8, .prob = 1e-46, .rng = 0x5e6cfce7, .super = true, .size = 222, .count = 8, .sum = 0x21ffa210626fa4e6 },
};

const sim_vectors = [_]SimVector{
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 64 }, .super = false, .sim = 0.4065934065934066 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 64 }, .super = false, .sim = 1.0 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1024 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 1024 }, .super = false, .sim = 0.956064947468959 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 16 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 1024 }, .super = false, .sim = 0.015625 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1024 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 8 }, .super = false, .sim = 0.0078125 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 128 }, .b = .{ .kind = .random, .len = 6000, .seed = 0x1, .k = 64 }, .super = false, .sim = 0.18518518518518517 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .super = false, .sim = 1.0 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 8 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .super = false, .sim = 0.125 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .b = .{ .kind = .random, .len = 0, .seed = 0x1, .k = 64 }, .super = false, .sim = 0.0 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .b = .{ .kind = .random, .len = 1, .seed = 0x1, .k = 64 }, .super = false, .sim = 0.0 },
    .{ .a = .{ .kind = .random, .len = 0, .seed = 0x1, .k = 8 }, .b = .{ .kind = .random, .len = 0, .seed = 0x2, .k = 8 }, .super = false, .sim = null },
    .{ .a = .{ .kind = .random, .len = 0, .seed = 0x1, .k = 8 }, .b = .{ .kind = .single, .len = 5, .seed = 0x2, .k = 8 }, .super = false, .sim = 0.0 },
    .{ .a = .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64 }, .b = .{ .kind = .words, .len = 5100, .seed = 0x2, .k = 64 }, .super = false, .sim = 0.9393939393939394 },
    .{ .a = .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64 }, .b = .{ .kind = .words, .len = 5000, .seed = 0x4, .k = 16 }, .super = false, .sim = 0.0 },
    .{ .a = .{ .kind = .cycle, .len = 2000, .seed = 0x0, .k = 32 }, .b = .{ .kind = .cycle, .len = 2000, .seed = 0x3, .k = 32 }, .super = false, .sim = 0.7297297297297297 },
    .{ .a = .{ .kind = .sparse, .len = 20000, .seed = 0x7, .k = 64 }, .b = .{ .kind = .sparse, .len = 21000, .seed = 0x7, .k = 64 }, .super = false, .sim = 0.8823529411764706 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 1 }, .super = true, .sim = 1.0 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 1 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 1 }, .super = true, .sim = 1.0 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 4 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 4 }, .super = true, .sim = 1.0 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 4 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 4 }, .super = true, .sim = 0.5 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 8 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 8 }, .super = true, .sim = 1.0 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 8 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 8 }, .super = true, .sim = 0.375 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 64 }, .super = true, .sim = 0.984375 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 64 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 64 }, .super = true, .sim = 0.421875 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 256 }, .b = .{ .kind = .random, .len = 3100, .seed = 0x1, .k = 256 }, .super = true, .sim = 0.96875 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 256 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x2, .k = 256 }, .super = true, .sim = 0.45703125 },
    .{ .a = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 16 }, .b = .{ .kind = .random, .len = 3000, .seed = 0x1, .k = 16 }, .super = true, .sim = 1.0 },
    .{ .a = .{ .kind = .random, .len = 0, .seed = 0x1, .k = 8 }, .b = .{ .kind = .random, .len = 0, .seed = 0x2, .k = 8 }, .super = true, .sim = 1.0 },
    .{ .a = .{ .kind = .words, .len = 5000, .seed = 0x2, .k = 64 }, .b = .{ .kind = .words, .len = 5100, .seed = 0x2, .k = 64 }, .super = true, .sim = 0.984375 },
};

/// Special keys and generator seeds, 26 crafted keys (260 bytes).
const crafted_generator =
    "\x7a\x7a\x9b\x7a\x9b\x47\x7a\x9b\x47\xc2\x86\x86\x43\x86\x43\x6a\x86\x43\x6a\xd5" ++
    "\x55\x55\x07\x55\x07\x6f\x55\x07\x6f\x83\xb4\xb4\xf3\xb4\xf3\xc7\xb4\xf3\xc7\x77" ++
    "\x50\x50\x0d\x50\x0d\x47\x50\x0d\x47\x3b\x6e\x6e\x6b\x6e\x6b\xd3\x6e\x6b\xd3\xed" ++
    "\x6c\x6c\x0b\x6c\x0b\xde\x6c\x0b\xde\x45\x0a\x0a\x63\x0a\x63\xf8\x0a\x63\xf8\x17" ++
    "\x28\x28\xc2\x28\xc2\x5b\x28\xc2\x5b\xe6\xf6\xf6\xd8\xf6\xd8\x30\xf6\xd8\x30\x2d" ++
    "\xda\xda\x92\xda\x92\xf7\xda\x92\xf7\x3a\xdc\xdc\x3d\xdc\x3d\xa1\xdc\x3d\xa1\x07" ++
    "\xf2\xf2\x8d\xf2\x8d\xbd\xf2\x8d\xbd\x0c\x36\x36\xef\x36\xef\x59\x36\xef\x59\xda" ++
    "\x10\x10\xcd\x10\xcd\x23\x10\xcd\x23\x85\x13\x13\x06\x13\x06\x04\x13\x06\x04\xf5" ++
    "\x7f\x7f\x93\x7f\x93\x5e\x7f\x93\x5e\xa1\x3e\x3e\xe7\x3e\xe7\x8d\x3e\xe7\x8d\x23" ++
    "\xf4\xf4\x3f\xf4\x3f\x0c\xf4\x3f\x0c\x3e\x94\x94\x11\x94\x11\xac\x94\x11\xac\x6d" ++
    "\xbf\xbf\x0e\xbf\x0e\x6f\xbf\x0e\x6f\xc6\x26\x26\x24\x26\x24\xd7\x26\x24\xd7\x48" ++
    "\xad\xad\x33\xad\x33\xd3\xad\x33\xd3\x1d\x83\x83\x5b\x83\x5b\xc8\x83\x5b\xc8\xc2" ++
    "\xa7\xa7\xa9\xa7\xa9\x9d\xa7\xa9\x9d\x8b\x9f\x9f\xc2\x9f\xc2\x3f\x9f\xc2\x3f\x44";

/// Table of 271 slots, 14 crafted keys, longest probe 17 steps (135 bytes).
const crafted_chain =
    "\xd6\xd6\x1c\xd6\x1c\x7a\xd6\x1c\x7a\x31\x3a\x3a\x4a\x3a\x4a\x0f\x3a\x4a\x0f\xde" ++
    "\xdb\xdb\x82\xdb\x82\xcc\xdb\x82\xcc\xe9\x6f\x6f\x9d\x6f\x9d\x7f\x6f\x9d\x7f\x19" ++
    "\x36\x36\xbd\x36\xbd\x4b\x36\xbd\x4b\xae\xeb\xeb\xb4\xeb\xb4\x6b\xeb\xb4\x6b\x49" ++
    "\xe8\xe8\x94\xe8\x94\xb1\xe8\x94\xb1\xb5\xf6\xf6\x37\xf6\x37\x48\xf6\x37\x48\xc3" ++
    "\xf3\xf3\x6f\xf3\x6f\xf7\xf3\x6f\xf7\x8c\xe3\xe3\x52\xe3\x52\xca\xe3\x52\xca\xb9" ++
    "\x37\x37\x1e\x37\x1e\x8e\x37\x1e\x8e\x13\x64\x64\x01\x64\x01\xac\x64\x01\xac\x8f" ++
    "\x4d\x4d\x17\x4d\x17\x66\x4d\x17\x66\xbd\x64\xed\x74\x06\x00";

const crafted_vectors = [_]CraftedVector{
    .{ .input = crafted_generator, .k = 1, .super = false, .size = 104, .count = 1, .sum = 0x4d24f67f9dcd3a75 },
    .{ .input = crafted_generator, .k = 8, .super = false, .size = 104, .count = 8, .sum = 0x78b44d4abb72ac53 },
    .{ .input = crafted_generator, .k = 103, .super = false, .size = 104, .count = 103, .sum = 0xee30616956fc8a33 },
    .{ .input = crafted_generator, .k = 1024, .super = false, .size = 104, .count = 104, .sum = 0x2a1e0dd3984b6dbf },
    .{ .input = crafted_generator, .k = 2, .super = true, .size = 104, .count = 2, .sum = 0xec2ec68cfe3f304d },
    .{ .input = crafted_generator, .k = 4, .super = true, .size = 104, .count = 4, .sum = 0xdf5f0594b279047e },
    .{ .input = crafted_generator, .k = 7, .super = true, .size = 104, .count = 7, .sum = 0xe7235d58f7077f1e },
    .{ .input = crafted_generator, .k = 16, .super = true, .size = 104, .count = 16, .sum = 0x8f46f8efad840751 },
    .{ .input = crafted_generator, .k = 64, .super = true, .size = 104, .count = 64, .sum = 0x0c6efbae89dccc4d },
    .{ .input = crafted_chain, .k = 1, .super = false, .size = 54, .count = 1, .sum = 0xf0380a32b4fe090f },
    .{ .input = crafted_chain, .k = 8, .super = false, .size = 54, .count = 8, .sum = 0x2663e592c5bb299a },
    .{ .input = crafted_chain, .k = 53, .super = false, .size = 54, .count = 53, .sum = 0x72d9861ad40692ab },
    .{ .input = crafted_chain, .k = 1024, .super = false, .size = 54, .count = 54, .sum = 0x302678568ef4123a },
    .{ .input = crafted_chain, .k = 2, .super = true, .size = 54, .count = 2, .sum = 0x9c2898ad262edfbd },
    .{ .input = crafted_chain, .k = 4, .super = true, .size = 54, .count = 4, .sum = 0xa139ab6d7023e8d0 },
    .{ .input = crafted_chain, .k = 7, .super = true, .size = 54, .count = 7, .sum = 0x0353972275b40c1c },
    .{ .input = crafted_chain, .k = 16, .super = true, .size = 54, .count = 16, .sum = 0x2076cab9b039494e },
    .{ .input = crafted_chain, .k = 64, .super = true, .size = 54, .count = 64, .sum = 0xb602448f40eead1b },
};

const literal_sims = [_]LiteralSim{
    .{ .a = &.{ 1, 2, 3 }, .b = &.{ 2, 3, 4 }, .sim = 0.5 },
    .{ .a = &.{ -5, 0, 7 }, .b = &.{ -5, 0, 7 }, .sim = 1.0 },
    .{ .a = &.{1}, .b = &.{2}, .sim = 0.0 },
    .{ .a = &.{ 1, 2, 3, 4, 5, 6, 7 }, .b = &.{3}, .sim = 0.14285714285714285 },
    .{ .a = &.{3}, .b = &.{ 1, 2, 3, 4, 5, 6, 7 }, .sim = 0.14285714285714285 },
    .{ .a = &.{ -2147483648, -1, 0, 1, 2147483647 }, .b = &.{ -2147483648, 2147483647 }, .sim = 0.4 },
    .{ .a = &.{ 1, 2, 3 }, .b = &.{}, .sim = 0.0 },
    .{ .a = &.{}, .b = &.{ 1, 2, 3 }, .sim = 0.0 },
    .{ .a = &.{ 1, 3, 5, 7, 9, 11 }, .b = &.{ 2, 3, 4, 7, 8, 11, 12, 13, 14 }, .sim = 0.25 },
};

// END GENERATED
