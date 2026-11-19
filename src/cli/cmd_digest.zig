// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! The commands that print one `digest<TAB>path` line per file: tlsh,
//! imphash, telfhash, lzjd and nilsimsa.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const Tlsh = fuzzyhash.Tlsh;
const Ctx = @import("Ctx.zig");
const Args = @import("Args.zig");
const walk = @import("walk.zig");
const input = @import("input.zig");
const json = @import("json.zig");
const lzjd_text = @import("lzjd_text.zig");
const Exit = @import("main.zig").Exit;

pub const Family = enum {
    tlsh,
    imphash,
    telfhash,
    lzjd,
    nilsimsa,

    pub fn usage(f: Family) []const u8 {
        return switch (f) {
            .tlsh => usage_tlsh,
            .imphash => usage_imphash,
            .telfhash => usage_telfhash,
            .lzjd => usage_lzjd,
            .nilsimsa => usage_nilsimsa,
        };
    }
};

const common_options =
    \\  -r          hash the files in directories, recursively
    \\  --follow    in -r mode, follow symbolic links that leave the tree
    \\  --json      print one JSON object per line
    \\  -h, --help  print this help and exit
    \\
;

const usage_tlsh =
    \\usage: fuzzyhash tlsh [-r] [--conservative] [--old] [--variant V] [--json] [PATH...]
    \\
    \\Print the TLSH digest of each file as "digest<TAB>path". A file that has
    \\no digest (too short, or too little variation) is reported on stderr and
    \\listed as TNULL. With no PATH, or with PATH "-", standard input is hashed.
    \\
    \\Options:
    \\  --conservative  require 256 bytes of input instead of 50
    \\  --old           print digests without the "T1" prefix
    \\  --variant V     buckets and checksum bytes: 128-1 (default), 128-3,
    \\                  256-1 or 256-3
    \\
++ common_options;

const usage_imphash =
    \\usage: fuzzyhash imphash [-r] [--json] [PATH...]
    \\
    \\Print the import hash of each PE file as "digest<TAB>path". A file with no
    \\imports is listed as "-".
    \\
    \\Options:
    \\
++ common_options;

const usage_telfhash =
    \\usage: fuzzyhash telfhash [-r] [--json] [PATH...]
    \\
    \\Print the telfhash of each ELF file as "digest<TAB>path". As in telfhash,
    \\"tnull" means the symbol list was too short for TLSH and "-" means there
    \\were no symbols to hash.
    \\
    \\Options:
    \\
++ common_options;

const usage_lzjd =
    \\usage: fuzzyhash lzjd [-r] [--hash-size N] [--json] [PATH...]
    \\
    \\Print the LZJD digest of each file as "digest<TAB>path". The digest is
    \\written as "lzjd:" and the base64 of its values as little-endian 32-bit
    \\integers. "fuzzyhash compare" reads it back.
    \\
    \\Options:
    \\  --hash-size N   at most N values (default 1024)
    \\
++ common_options;

const usage_nilsimsa =
    \\usage: fuzzyhash nilsimsa [-r] [--json] [PATH...]
    \\
    \\Print the Nilsimsa digest of each file as "digest<TAB>path".
    \\
    \\Options:
    \\
++ common_options;

const TlshVariant = enum { @"128-1", @"128-3", @"256-1", @"256-3" };

const Options = struct {
    family: Family,
    walk: walk.Options = .{},
    json: bool = false,
    conservative: bool = false,
    old: bool = false,
    variant: TlshVariant = .@"128-1",
    hash_size: u32 = 1024,
};

pub fn run(ctx: *Ctx, family: Family, args: []const []const u8) !Exit {
    var o: Options = .{ .family = family };
    var operands: std.ArrayList([]const u8) = .empty;
    defer operands.deinit(ctx.gpa);
    var p = Args.init(args);
    while (p.next()) |t| switch (t) {
        .operand => |a| try operands.append(ctx.gpa, a),
        .short => |c| switch (c) {
            'h' => {
                try ctx.out.writeAll(family.usage());
                return .ok;
            },
            'r' => o.walk.recursive = true,
            else => return usageError(ctx, family, "unrecognized option '-{c}'", .{c}),
        },
        .long => |name| {
            const is = struct {
                fn f(a: []const u8, b: []const u8) bool {
                    return std.mem.eql(u8, a, b);
                }
            }.f;
            if (is(name, "help")) {
                try ctx.out.writeAll(family.usage());
                return .ok;
            } else if (is(name, "json")) {
                o.json = true;
            } else if (is(name, "follow")) {
                o.walk.follow = true;
            } else if (family == .tlsh and is(name, "conservative")) {
                o.conservative = true;
            } else if (family == .tlsh and is(name, "old")) {
                o.old = true;
            } else if (family == .tlsh and is(name, "variant")) {
                const v = p.value() orelse return usageError(ctx, family, "--variant needs a value", .{});
                o.variant = std.meta.stringToEnum(TlshVariant, v) orelse
                    return usageError(ctx, family, "unknown TLSH variant '{s}'", .{v});
            } else if (family == .lzjd and is(name, "hash-size")) {
                const v = p.value() orelse return usageError(ctx, family, "--hash-size needs a number", .{});
                o.hash_size = std.fmt.parseInt(u32, v, 10) catch 0;
                if (o.hash_size == 0 or o.hash_size > lzjd_text.max_values)
                    return usageError(ctx, family, "--hash-size takes a number from 1 to {d}, not '{s}'", .{ lzjd_text.max_values, v });
            } else {
                return usageError(ctx, family, "unrecognized option '--{s}'", .{name});
            }
        },
    };

    var v: Visitor = .{ .ctx = ctx, .o = &o };
    try walk.each(ctx, o.walk, operands.items, &v);
    return if (ctx.failed) .failure else .ok;
}

fn usageError(ctx: *Ctx, family: Family, comptime fmt: []const u8, args: anytype) !Exit {
    try ctx.err.print("fuzzyhash {s}: " ++ fmt ++ "\n", .{@tagName(family)} ++ args);
    try ctx.err.writeAll(family.usage());
    return .usage;
}

/// What a file gave: a digest, or a result that is not a digest. `text` is
/// what the plain output shows in both cases.
const Result = struct {
    text: []const u8,
    is_digest: bool = true,
};

const Visitor = struct {
    ctx: *Ctx,
    o: *const Options,

    pub fn visit(v: *Visitor, item: walk.Item, file: std.Io.File) !void {
        const ctx = v.ctx;
        var buf: [256]u8 = undefined;
        var owned: ?[]u8 = null;
        defer if (owned) |b| ctx.gpa.free(b);
        const result = v.digest(item, file, &buf, &owned) catch |e| {
            if (e == error.OutOfMemory) return e;
            ctx.fail("{s}: {s}", .{ item.display, Ctx.describe(e) });
            return;
        } orelse return;

        const out = ctx.out;
        if (v.o.json) {
            try out.print("{{\"family\":\"{s}\",\"path\":", .{@tagName(v.o.family)});
            try json.string(out, item.display);
            if (result.is_digest) {
                try out.print(",\"digest\":\"{s}\"}}\n", .{result.text});
            } else {
                try out.writeAll(",\"digest\":null}\n");
            }
            return;
        }
        try out.print("{s}\t{s}\n", .{ result.text, item.display });
    }

    /// Null when the input was reported and nothing should be printed.
    fn digest(v: *Visitor, item: walk.Item, file: std.Io.File, buf: *[256]u8, owned: *?[]u8) !?Result {
        const ctx = v.ctx;
        const o = v.o;
        switch (o.family) {
            .tlsh => switch (o.variant) {
                inline else => |tag| {
                    const T = Tlsh.Tlsh(comptime variantOf(tag));
                    var h = T.init(.{ .conservative = o.conservative });
                    _ = try input.stream(ctx, file, &h);
                    const d = h.final() catch |e| switch (e) {
                        error.TooShort, error.InsufficientVariation => {
                            ctx.note("{s}: {s}", .{ item.display, if (e == error.TooShort) "too short for a TLSH digest" else "too little variation for a TLSH digest" });
                            return .{ .text = "TNULL", .is_digest = false };
                        },
                        error.InputTooLarge => return e,
                    };
                    return .{ .text = d.toString(buf[0..T.max_string_length], .{ .prefix = !o.old }) };
                },
            },
            .nilsimsa => {
                var h = fuzzyhash.Nilsimsa.Hasher.init();
                _ = try input.stream(ctx, file, &h);
                return .{ .text = h.final().toHex(buf[0..fuzzyhash.Nilsimsa.hex_length]) };
            },
            .imphash => {
                const data = try input.readAll(ctx, file);
                defer ctx.gpa.free(data);
                const ws = try ctx.gpa.create(fuzzyhash.Imphash.Workspace);
                defer ctx.gpa.destroy(ws);
                const d = fuzzyhash.Imphash.hash(ws, data) catch |e| switch (e) {
                    error.InvalidPe => return error.NotAPeFile,
                } orelse return .{ .text = "-", .is_digest = false };
                return .{ .text = fuzzyhash.Imphash.toHex(d, buf[0..fuzzyhash.Imphash.hex_length]) };
            },
            .telfhash => {
                const T = fuzzyhash.Telfhash;
                const data = try input.readAll(ctx, file);
                defer ctx.gpa.free(data);
                const scratch = try ctx.gpa.alloc(u32, T.scratchLength(data.len));
                defer ctx.gpa.free(scratch);
                const r = T.hash(data, scratch) catch |e| switch (e) {
                    error.InvalidElf => return error.NotAnElfFile,
                    else => return e,
                };
                return .{ .text = T.toString(r, buf[0..T.max_string_length]), .is_digest = r == .digest };
            },
            .lzjd => {
                const data = try input.readAll(ctx, file);
                defer ctx.gpa.free(data);
                const values = try lzjd_text.digestFile(ctx.gpa, data, o.hash_size);
                defer ctx.gpa.free(values);
                owned.* = try lzjd_text.encode(ctx.gpa, values);
                return .{ .text = owned.*.? };
            },
        }
    }
};

fn variantOf(comptime v: TlshVariant) Tlsh.Variant {
    return switch (v) {
        .@"128-1" => .{ .buckets = .b128, .checksum = .one },
        .@"128-3" => .{ .buckets = .b128, .checksum = .three },
        .@"256-1" => .{ .buckets = .b256, .checksum = .one },
        .@"256-3" => .{ .buckets = .b256, .checksum = .three },
    };
}
