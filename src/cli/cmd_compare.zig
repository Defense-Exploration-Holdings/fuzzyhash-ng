// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! `fuzzyhash compare A B`: the similarity score or distance of two digests
//! of the same kind.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const Tlsh = fuzzyhash.Tlsh;
const Ctx = @import("Ctx.zig");
const Args = @import("Args.zig");
const lzjd_text = @import("lzjd_text.zig");
const Exit = @import("main.zig").Exit;

pub const usage =
    \\usage: fuzzyhash compare [--xlen] [--json] DIGEST DIGEST
    \\
    \\Compare two digests of the same kind and print the result:
    \\
    \\  ssdeep    score from 0 (no match) to 100
    \\  TLSH      distance from 0 (identical) up; telfhash digests too
    \\  Nilsimsa  score from -128 to 128 (identical)
    \\  LZJD      similarity from 0 to 1
    \\
    \\The kind is detected from the text. TLSH digests of all four variants are
    \\accepted, with or without the "T1" prefix.
    \\
    \\Options:
    \\  --xlen      leave the length term out of the TLSH distance
    \\  --json      print a JSON object
    \\  -h, --help  print this help and exit
    \\
;

pub const Kind = enum { ssdeep, tlsh_128_1, tlsh_128_3, tlsh_256_1, tlsh_256_3, nilsimsa, lzjd };

/// Which kind of digest `text` looks like. Only the shape is checked here;
/// the parser of that kind decides whether it is valid.
pub fn detect(text: []const u8) ?Kind {
    if (std.mem.startsWith(u8, text, lzjd_text.prefix)) return .lzjd;
    if (std.mem.indexOfScalar(u8, text, ':') != null) return .ssdeep;
    var hex = text;
    const prefixed = hex.len >= 2 and (hex[0] == 'T' or hex[0] == 't') and hex[1] == '1';
    if (prefixed) hex = hex[2..];
    for (hex) |c| if (!std.ascii.isHex(c)) return null;
    return switch (hex.len) {
        64 => if (prefixed) null else .nilsimsa,
        70 => .tlsh_128_1,
        74 => .tlsh_128_3,
        134 => .tlsh_256_1,
        138 => .tlsh_256_3,
        else => null,
    };
}

pub fn run(ctx: *Ctx, args: []const []const u8) !Exit {
    var xlen = false;
    var as_json = false;
    var digests: [2][]const u8 = undefined;
    var n: usize = 0;
    var p = Args.init(args);
    while (p.next()) |t| switch (t) {
        .operand => |a| {
            if (n == 2) return usageError(ctx, "expected two digests", .{});
            digests[n] = a;
            n += 1;
        },
        .short => |c| switch (c) {
            'h' => {
                try ctx.out.writeAll(usage);
                return .ok;
            },
            else => return usageError(ctx, "unrecognized option '-{c}'", .{c}),
        },
        .long => |name| {
            if (std.mem.eql(u8, name, "help")) {
                try ctx.out.writeAll(usage);
                return .ok;
            } else if (std.mem.eql(u8, name, "xlen")) {
                xlen = true;
            } else if (std.mem.eql(u8, name, "json")) {
                as_json = true;
            } else {
                return usageError(ctx, "unrecognized option '--{s}'", .{name});
            }
        },
    };
    if (n != 2) return usageError(ctx, "expected two digests", .{});

    const a = digests[0];
    const b = digests[1];
    const ka = detect(a) orelse return invalid(ctx, a);
    const kb = detect(b) orelse return invalid(ctx, b);
    if (ka != kb) {
        ctx.fail("the digests are of different kinds ({s} and {s})", .{ kindName(ka), kindName(kb) });
        return .failure;
    }

    const out = ctx.out;
    switch (ka) {
        .ssdeep => {
            const score = fuzzyhash.Ssdeep.compareStrings(a, b) catch return invalidPair(ctx, a, b);
            try printInt(out, as_json, "ssdeep", "score", score);
        },
        .nilsimsa => {
            const score = fuzzyhash.Nilsimsa.compareStrings(a, b) catch return invalidPair(ctx, a, b);
            try printInt(out, as_json, "nilsimsa", "score", score);
        },
        .lzjd => {
            const va = lzjd_text.decode(ctx.gpa, a) catch |e| return if (e == error.OutOfMemory) e else invalid(ctx, a);
            defer ctx.gpa.free(va);
            const vb = lzjd_text.decode(ctx.gpa, b) catch |e| return if (e == error.OutOfMemory) e else invalid(ctx, b);
            defer ctx.gpa.free(vb);
            const sim = fuzzyhash.Lzjd.similarity(va, vb) orelse {
                ctx.fail("both LZJD digests are empty", .{});
                return .failure;
            };
            if (as_json) {
                try out.print("{{\"family\":\"lzjd\",\"similarity\":{d}}}\n", .{sim});
            } else {
                try out.print("{d}\n", .{sim});
            }
        },
        inline .tlsh_128_1, .tlsh_128_3, .tlsh_256_1, .tlsh_256_3 => |k| {
            const T = Tlsh.Tlsh(comptime tlshVariant(k));
            var ua: [T.max_string_length]u8 = undefined;
            var ub: [T.max_string_length]u8 = undefined;
            const d = T.diffStrings(upper(&ua, T, a), upper(&ub, T, b), .{ .include_length = !xlen }) catch
                return invalidPair(ctx, a, b);
            try printInt(out, as_json, "tlsh", "distance", d);
        },
    }
    return .ok;
}

fn tlshVariant(comptime k: Kind) Tlsh.Variant {
    return switch (k) {
        .tlsh_128_1 => .{ .buckets = .b128, .checksum = .one },
        .tlsh_128_3 => .{ .buckets = .b128, .checksum = .three },
        .tlsh_256_1 => .{ .buckets = .b256, .checksum = .one },
        .tlsh_256_3 => .{ .buckets = .b256, .checksum = .three },
        else => unreachable,
    };
}

/// `s` in upper case, so that telfhash's lower-case digests parse as TLSH.
/// `fuzzyhash tlsh` prints "T1" for every variant, but only the 128-1
/// parser takes it, so it is removed for the others. `detect` has checked
/// the length, so `s` fits.
fn upper(buf: []u8, comptime T: type, s: []const u8) []const u8 {
    const body = if (!T.parses_prefix and s.len == T.hex_length + 2) s[2..] else s;
    for (buf[0..body.len], body) |*d, c| d.* = std.ascii.toUpper(c);
    return buf[0..body.len];
}

fn kindName(k: Kind) []const u8 {
    return switch (k) {
        .ssdeep => "ssdeep",
        .tlsh_128_1 => "TLSH",
        .tlsh_128_3 => "TLSH 128-3",
        .tlsh_256_1 => "TLSH 256-1",
        .tlsh_256_3 => "TLSH 256-3",
        .nilsimsa => "Nilsimsa",
        .lzjd => "LZJD",
    };
}

fn printInt(out: *std.Io.Writer, as_json: bool, family: []const u8, field: []const u8, value: anytype) !void {
    if (as_json) {
        try out.print("{{\"family\":\"{s}\",\"{s}\":{d}}}\n", .{ family, field, value });
    } else {
        try out.print("{d}\n", .{value});
    }
}

fn invalid(ctx: *Ctx, text: []const u8) Exit {
    ctx.fail("not a digest: '{s}'", .{text});
    return .failure;
}

fn invalidPair(ctx: *Ctx, a: []const u8, b: []const u8) Exit {
    ctx.fail("not a valid pair of digests: '{s}', '{s}'", .{ a, b });
    return .failure;
}

fn usageError(ctx: *Ctx, comptime fmt: []const u8, args: anytype) !Exit {
    try ctx.err.print("fuzzyhash compare: " ++ fmt ++ "\n", args);
    try ctx.err.writeAll(usage);
    return .usage;
}

const testing = std.testing;

/// `n` copies of the character `c`, at compile time.
fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const a: [n]u8 = @splat(c);
    return &a;
}

test "detect" {
    try testing.expectEqual(Kind.ssdeep, detect("3:iKn:p").?);
    try testing.expectEqual(Kind.lzjd, detect("lzjd:AAAA").?);
    try testing.expectEqual(Kind.nilsimsa, detect(rep('a', 64)).?);
    try testing.expectEqual(Kind.tlsh_128_1, detect("T1" ++ rep('A', 70)).?);
    try testing.expectEqual(Kind.tlsh_128_1, detect("t1" ++ rep('a', 70)).?);
    try testing.expectEqual(Kind.tlsh_128_1, detect(rep('A', 70)).?);
    try testing.expectEqual(Kind.tlsh_128_3, detect(rep('A', 74)).?);
    try testing.expectEqual(Kind.tlsh_256_1, detect(rep('A', 134)).?);
    try testing.expectEqual(Kind.tlsh_256_3, detect(rep('A', 138)).?);
    try testing.expectEqual(Kind.tlsh_256_3, detect("T1" ++ rep('A', 138)).?);
    try testing.expectEqual(@as(?Kind, null), detect("T1" ++ rep('A', 64)));
    try testing.expectEqual(@as(?Kind, null), detect("xyz"));
    try testing.expectEqual(@as(?Kind, null), detect(""));
}
