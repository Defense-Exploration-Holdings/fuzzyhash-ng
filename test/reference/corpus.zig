// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! The generated test corpus behind `vectors.zig`. Must produce the same bytes
//! as the `generate` and `mutate` functions in scripts/reference-vectors.mjs.

const std = @import("std");

pub const Kind = enum { random, text, runs };

pub const Input = struct {
    kind: Kind,
    len: usize,
    seed: u32,
    /// Seed for the edits; unused when `edits` is 0.
    mutate_seed: u32,
    edits: u32,
};

const words = [_][]const u8{
    "the",    "of",     "and",    "to",     "in",     "is",     "that",   "for",
    "it",     "as",     "was",    "with",   "be",     "by",     "on",     "not",
    "he",     "this",   "are",    "or",     "his",    "from",   "at",     "which",
    "but",    "have",   "an",     "had",    "they",   "you",    "were",   "their",
    "one",    "all",    "we",     "can",    "her",    "has",    "there",  "been",
    "if",     "more",   "when",   "will",   "would",  "who",    "so",     "no",
    "file",   "hash",   "block",  "digest", "sample", "packet", "header", "section",
    "import", "export", "string", "buffer", "kernel", "module", "driver", "signature",
};

/// xorshift32. The seed must not be 0.
const Rng = struct {
    x: u32,

    fn next(self: *Rng) u32 {
        var x = self.x;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.x = x;
        return x;
    }

    fn byte(self: *Rng) u8 {
        return @intCast(self.next() >> 24);
    }
};

fn generate(out: []u8, kind: Kind, seed: u32) void {
    var r: Rng = .{ .x = seed };
    var i: usize = 0;
    switch (kind) {
        .random => while (i < out.len) : (i += 1) {
            out[i] = r.byte();
        },
        .text => while (i < out.len) {
            const w = words[r.next() % words.len];
            for (w) |c| {
                if (i == out.len) break;
                out[i] = c;
                i += 1;
            }
            if (i < out.len) {
                out[i] = if (r.next() % 8 == 0) '\n' else ' ';
                i += 1;
            }
        },
        .runs => while (i < out.len) {
            const alphabet = "ACGT";
            const b = alphabet[r.next() % 4];
            var run = 1 + r.next() % 32;
            while (run > 0 and i < out.len) : (run -= 1) {
                out[i] = b;
                i += 1;
            }
        },
    }
}

/// The bytes of `input`. Caller owns the result.
pub fn bytes(gpa: std.mem.Allocator, input: Input) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    try buf.resize(gpa, input.len);
    generate(buf.items, input.kind, input.seed);
    if (input.edits > 0) {
        var r: Rng = .{ .x = input.mutate_seed };
        for (0..input.edits) |_| {
            const op = r.next() % 3;
            if (buf.items.len == 0 and op != 1) continue;
            const span: u32 = @intCast(buf.items.len + @intFromBool(op == 1));
            const pos = r.next() % span;
            switch (op) {
                0 => buf.items[pos] = r.byte(),
                1 => try buf.insert(gpa, pos, r.byte()),
                else => _ = buf.orderedRemove(pos),
            }
        }
    }
    return buf.toOwnedSlice(gpa);
}
