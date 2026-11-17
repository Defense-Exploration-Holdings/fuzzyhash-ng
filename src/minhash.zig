// SPDX-License-Identifier: MIT
//! MinHash compatible with datasketch 2.0.0 (`datasketch.MinHash`) and its
//! default SHA-1 hash functions.
//!
//! The permutation parameters come from numpy's legacy
//! `RandomState(seed).randint`, reproduced here (MT19937 and the masked
//! rejection sampler), so a given `num_perm` and `seed` give the same hash
//! values as datasketch.

const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;

pub const Scheme = enum {
    /// datasketch's default since 2.0.0: odd `a`, 32-bit affine maps after
    /// a MurmurHash3 finalizer.
    affine32,
    /// 64-bit version of `affine32`, fed by the first 8 bytes of SHA-1.
    affine64,
    /// datasketch before 2.0.0 (`scheme="legacy"`): `(a*h + b) mod (2^61-1)`
    /// truncated to 32 bits.
    legacy,
};

/// numpy's legacy MT19937 as `RandomState(seed)` seeds it.
const Mt19937 = struct {
    key: [624]u32,
    pos: usize,

    fn init(seed: u32) Mt19937 {
        var self: Mt19937 = .{ .key = undefined, .pos = 624 };
        var s = seed;
        for (0..624) |i| {
            self.key[i] = s;
            s = 1812433253 *% (s ^ (s >> 30)) +% @as(u32, @intCast(i + 1));
        }
        return self;
    }

    fn generate(self: *Mt19937) void {
        const upper: u32 = 0x80000000;
        const lower: u32 = 0x7fffffff;
        const matrix: u32 = 0x9908b0df;
        for (0..624) |i| {
            const y = (self.key[i] & upper) | (self.key[(i + 1) % 624] & lower);
            self.key[i] = self.key[(i + 397) % 624] ^ (y >> 1) ^ (if (y & 1 != 0) matrix else 0);
        }
        self.pos = 0;
    }

    fn next32(self: *Mt19937) u32 {
        if (self.pos == 624) self.generate();
        var y = self.key[self.pos];
        self.pos += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;
        return y;
    }

    fn next64(self: *Mt19937) u64 {
        const hi: u64 = self.next32();
        return (hi << 32) | self.next32();
    }

    fn mask(rng: u64) u64 {
        var m = rng;
        m |= m >> 1;
        m |= m >> 2;
        m |= m >> 4;
        m |= m >> 8;
        m |= m >> 16;
        m |= m >> 32;
        return m;
    }

    /// `randint(low, high, dtype=uint32)`, legacy masked sampling.
    fn randint32(self: *Mt19937, low: u32, high: u64) u32 {
        const rng: u32 = @intCast(high - 1 - low);
        if (rng == 0) return low;
        if (rng == 0xffffffff) return low +% self.next32();
        const m: u32 = @intCast(mask(rng));
        while (true) {
            const v = self.next32() & m;
            if (v <= rng) return low + v;
        }
    }

    /// `randint(low, high, dtype=uint64)`, legacy masked sampling.
    fn randint64(self: *Mt19937, low: u64, high: u65) u64 {
        const rng: u64 = @intCast(high - 1 - low);
        if (rng == 0) return low;
        if (rng <= 0xffffffff) {
            const r32: u32 = @intCast(rng);
            if (r32 == 0xffffffff) return low +% self.next32();
            const m: u32 = @intCast(mask(r32));
            while (true) {
                const v = self.next32() & m;
                if (v <= r32) return low + v;
            }
        }
        if (rng == std.math.maxInt(u64)) return low +% self.next64();
        const m = mask(rng);
        while (true) {
            const v = self.next64() & m;
            if (v <= rng) return low + v;
        }
    }
};

const mersenne_prime: u64 = (1 << 61) - 1;

fn fmix32(h0: u32) u32 {
    var h = h0;
    h ^= h >> 16;
    h *%= 0x85ebca6b;
    h ^= h >> 13;
    h *%= 0xc2b2ae35;
    return h ^ (h >> 16);
}

fn fmix64(h0: u64) u64 {
    var h = h0;
    h ^= h >> 33;
    h *%= 0xff51afd7ed558ccd;
    h ^= h >> 33;
    h *%= 0xc4ceb9fe1a85ec53;
    return h ^ (h >> 33);
}

/// `datasketch.hashfunc.sha1_hash32`.
pub fn sha1Hash32(data: []const u8) u32 {
    var d: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(data, &d, .{});
    return std.mem.readInt(u32, d[0..4], .little);
}

/// `datasketch.hashfunc.sha1_hash64`.
pub fn sha1Hash64(data: []const u8) u64 {
    var d: [Sha1.digest_length]u8 = undefined;
    Sha1.hash(data, &d, .{});
    return std.mem.readInt(u64, d[0..8], .little);
}

/// `MinHash(num_perm=num_perm, seed=..., scheme=...)` with the default hash
/// function for the scheme.
pub fn MinHash(comptime scheme: Scheme, comptime num_perm: usize) type {
    if (num_perm < 1) @compileError("num_perm must be positive");
    return struct {
        const Self = @This();

        /// Hash value type: u32 for affine32, u64 otherwise (legacy values
        /// fit in 32 bits but datasketch stores them as uint64).
        pub const Value = if (scheme == .affine32) u32 else u64;
        const max_hash: Value = switch (scheme) {
            .affine32 => std.math.maxInt(u32),
            .affine64 => std.math.maxInt(u64),
            .legacy => std.math.maxInt(u32),
        };

        seed: u32,
        a: [num_perm]Value,
        b: [num_perm]Value,
        /// datasketch's `hashvalues` (and `digest()`).
        hashvalues: [num_perm]Value,

        /// numpy accepts seeds from 0 to 2^32 - 1.
        pub fn init(seed: u32) Self {
            var self: Self = .{ .seed = seed, .a = undefined, .b = undefined, .hashvalues = @splat(max_hash) };
            var g = Mt19937.init(seed);
            switch (scheme) {
                .legacy => for (0..num_perm) |i| {
                    self.a[i] = g.randint64(1, mersenne_prime);
                    self.b[i] = g.randint64(0, mersenne_prime);
                },
                .affine32 => {
                    for (&self.a) |*x| x.* = g.randint32(0, 1 << 31) *% 2 +% 1;
                    for (&self.b) |*x| x.* = g.randint32(0, 1 << 32);
                },
                .affine64 => {
                    for (&self.a) |*x| x.* = g.randint64(0, 1 << 63) *% 2 +% 1;
                    for (&self.b) |*x| x.* = g.randint64(0, 1 << 64);
                },
            }
            return self;
        }

        /// `update(b)` with the default SHA-1 hash function.
        pub fn update(self: *Self, data: []const u8) void {
            switch (scheme) {
                .legacy => self.updateHash(sha1Hash32(data)),
                .affine32 => self.updateHash(sha1Hash32(data)),
                .affine64 => self.updateHash(sha1Hash64(data)),
            }
        }

        /// `update` for a value already hashed by the scheme's hash function
        /// (or a custom one of the same width).
        pub fn updateHash(self: *Self, hv0: if (scheme == .affine64) u64 else u32) void {
            switch (scheme) {
                .legacy => {
                    const hv: u64 = hv0;
                    for (&self.hashvalues, self.a, self.b) |*h, a, b| {
                        const phv = ((a *% hv +% b) % mersenne_prime) & max_hash;
                        if (phv < h.*) h.* = phv;
                    }
                },
                .affine32 => {
                    const hv = fmix32(hv0);
                    for (&self.hashvalues, self.a, self.b) |*h, a, b| {
                        const phv = a *% hv +% b;
                        if (phv < h.*) h.* = phv;
                    }
                },
                .affine64 => {
                    const hv = fmix64(hv0);
                    for (&self.hashvalues, self.a, self.b) |*h, a, b| {
                        const phv = a *% hv +% b;
                        if (phv < h.*) h.* = phv;
                    }
                },
            }
        }

        /// `jaccard(other)`: the share of equal hash values. Both sketches
        /// must come from the same seed.
        pub fn jaccard(self: *const Self, other: *const Self) f64 {
            std.debug.assert(self.seed == other.seed);
            var n: usize = 0;
            for (self.hashvalues, other.hashvalues) |x, y| n += @intFromBool(x == y);
            return @as(f64, @floatFromInt(n)) / @as(f64, @floatFromInt(num_perm));
        }

        /// `merge(other)`: element-wise minimum.
        pub fn merge(self: *Self, other: *const Self) void {
            std.debug.assert(self.seed == other.seed);
            for (&self.hashvalues, other.hashvalues) |*x, y| x.* = @min(x.*, y);
        }

        /// `is_empty()`.
        pub fn isEmpty(self: *const Self) bool {
            for (self.hashvalues) |x| if (x != max_hash) return false;
            return true;
        }

        /// `clear()`.
        pub fn clear(self: *Self) void {
            self.hashvalues = @splat(max_hash);
        }
    };
}

test "MT19937 matches the reference output for seed 5489" {
    var g = Mt19937.init(5489);
    try std.testing.expectEqual(@as(u32, 3499211612), g.next32());
    for (0..9998) |_| _ = g.next32();
    try std.testing.expectEqual(@as(u32, 4123659995), g.next32());
}

fn sketch(comptime s: Scheme, words: []const []const u8) MinHash(s, 4) {
    var m = MinHash(s, 4).init(1);
    for (words) |w| m.update(w);
    return m;
}

test "hash values match datasketch 2.0.0" {
    const a = [_][]const u8{ "apple", "banana", "cherry" };
    const b = [_][]const u8{ "apple", "banana", "durian" };
    {
        const x = sketch(.affine32, &a);
        const y = sketch(.affine32, &b);
        try std.testing.expectEqualSlices(u32, &.{ 2768035780, 1408816900, 566888802, 1241074002 }, &x.hashvalues);
        try std.testing.expectEqualSlices(u32, &.{ 3290934046, 1408816900, 1754355200, 806757354 }, &y.hashvalues);
        try std.testing.expectEqual(@as(f64, 0.25), x.jaccard(&y));
    }
    {
        const x = sketch(.affine64, &a);
        const y = sketch(.affine64, &b);
        try std.testing.expectEqualSlices(u64, &.{ 7039238282077315608, 4828253167237522537, 4215037185060595620, 2548981726163406561 }, &x.hashvalues);
        try std.testing.expectEqualSlices(u64, &.{ 7039238282077315608, 2650765772089795298, 4215037185060595620, 1811195931053607927 }, &y.hashvalues);
        try std.testing.expectEqual(@as(f64, 0.5), x.jaccard(&y));
    }
    {
        const x = sketch(.legacy, &a);
        try std.testing.expectEqualSlices(u64, &.{ 3288333326, 787179128, 1541446482, 222800236 }, &x.hashvalues);
    }
    const p = MinHash(.affine32, 2).init(7);
    try std.testing.expectEqualSlices(u32, &.{ 655483231, 1952827785 }, &p.a);
    try std.testing.expectEqualSlices(u32, &.{ 3349725721, 1369975286 }, &p.b);
}

test "merge, clear and isEmpty" {
    var x = sketch(.affine32, &.{ "apple", "banana" });
    const y = sketch(.affine32, &.{"cherry"});
    const both = sketch(.affine32, &.{ "apple", "banana", "cherry" });
    x.merge(&y);
    try std.testing.expectEqualSlices(u32, &both.hashvalues, &x.hashvalues);
    try std.testing.expect(!x.isEmpty());
    x.clear();
    try std.testing.expect(x.isEmpty());
}
