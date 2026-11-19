// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! `fuzzyhash ssdeep`: hash files in the ssdeep 1.1 file format and match
//! them against known signatures. Standard output follows the `ssdeep`
//! 2.14.1 program for the same options.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const Ssdeep = fuzzyhash.Ssdeep;
const Ctx = @import("Ctx.zig");
const Args = @import("Args.zig");
const walk = @import("walk.zig");
const input = @import("input.zig");
const json = @import("json.zig");
const sigfile = @import("sigfile.zig");
const Exit = @import("main.zig").Exit;

pub const usage =
    \\usage: fuzzyhash ssdeep [-r] [-l|-b] [-cs] [--json] [--follow] [PATH...]
    \\       fuzzyhash ssdeep -m KNOWN [-m KNOWN...] [-a] [-t N] [-r] [-l|-b] [-cs] [PATH...]
    \\       fuzzyhash ssdeep -k KNOWN [-a] [-t N] [-c] SIGFILE...
    \\       fuzzyhash ssdeep -x [-a] [-t N] [-c] SIGFILE...
    \\
    \\Hash files with ssdeep. Output is the ssdeep 1.1 signature file format.
    \\With no PATH, or with PATH "-", standard input is hashed.
    \\
    \\Options:
    \\  -r          hash the files in directories, recursively
    \\  -l          print paths as given (default: absolute paths)
    \\  -b          print file names only
    \\  -c          print matches as CSV
    \\  -s          do not print messages about inputs
    \\  -m KNOWN    match the files against the signatures in KNOWN
    \\  -k KNOWN    match the signatures in each SIGFILE against those in KNOWN
    \\  -x          match the signatures in the SIGFILEs against each other
    \\  -a          print every match, whatever its score
    \\  -t N        print only matches that score above N (0 to 100, default 0)
    \\  --follow    in -r mode, follow symbolic links that leave the tree
    \\  --json      print one JSON object per line
    \\  -h, --help  print this help and exit
    \\
;

/// Files of at most this many bytes give digests that ssdeep warns about.
const small_file_bytes = 4096;

const Mode = enum { hash, match_files, match_sigs, match_all };

const Options = struct {
    mode: Mode = .hash,
    walk: walk.Options = .{ .naming = .absolute, .stdin_name = "stdin" },
    csv: bool = false,
    json: bool = false,
    all: bool = false,
    threshold: u8 = 0,
    known: std.ArrayList([]const u8) = .empty,
    operands: std.ArrayList([]const u8) = .empty,
};

pub fn run(ctx: *Ctx, args: []const []const u8) !Exit {
    var o: Options = .{};
    defer o.known.deinit(ctx.gpa);
    defer o.operands.deinit(ctx.gpa);
    var relative = false;
    var bare = false;
    var p = Args.init(args);
    while (p.next()) |t| switch (t) {
        .operand => |a| try o.operands.append(ctx.gpa, a),
        .short => |c| switch (c) {
            'h' => {
                try ctx.out.writeAll(usage);
                return .ok;
            },
            'r' => o.walk.recursive = true,
            'l' => relative = true,
            'b' => bare = true,
            'c' => o.csv = true,
            's' => ctx.silent = true,
            'a' => o.all = true,
            'x' => try setMode(ctx, &o, .match_all) orelse return .usage,
            'm', 'k' => {
                try setMode(ctx, &o, if (c == 'm') .match_files else .match_sigs) orelse return .usage;
                const v = p.value() orelse return usageError(ctx, "option -{c} needs a file", .{c});
                try o.known.append(ctx.gpa, v);
            },
            't' => {
                const v = p.value() orelse return usageError(ctx, "option -t needs a number", .{});
                o.threshold = std.fmt.parseInt(u8, v, 10) catch 255;
                if (o.threshold > 100) return usageError(ctx, "-t takes a number from 0 to 100, not '{s}'", .{v});
            },
            'd', 'p', 'g', 'v' => return usageError(ctx, "option -{c} is not supported", .{c}),
            else => return usageError(ctx, "unrecognized option '-{c}'", .{c}),
        },
        .long => |name| {
            if (std.mem.eql(u8, name, "help")) {
                try ctx.out.writeAll(usage);
                return .ok;
            } else if (std.mem.eql(u8, name, "json")) {
                o.json = true;
            } else if (std.mem.eql(u8, name, "follow")) {
                o.walk.follow = true;
            } else {
                return usageError(ctx, "unrecognized option '--{s}'", .{name});
            }
        },
    };
    if (bare and relative) return usageError(ctx, "-l and -b cannot be combined", .{});
    if (bare) {
        o.walk.naming = .bare;
    } else if (relative) {
        o.walk.naming = .relative;
    }

    switch (o.mode) {
        .hash, .match_files => try hashFiles(ctx, &o),
        .match_sigs => try matchSigs(ctx, &o),
        .match_all => try matchAll(ctx, &o),
    }
    return if (ctx.failed) .failure else .ok;
}

fn setMode(ctx: *Ctx, o: *Options, mode: Mode) !?void {
    if (o.mode == .hash or o.mode == mode) {
        o.mode = mode;
        return {};
    }
    _ = try usageError(ctx, "-m, -k and -x cannot be combined", .{});
    return null;
}

fn usageError(ctx: *Ctx, comptime fmt: []const u8, args: anytype) !Exit {
    try ctx.err.print("fuzzyhash ssdeep: " ++ fmt ++ "\n", args);
    try ctx.err.writeAll(usage);
    return .usage;
}

/// Signature files given with -m or -k, loaded. Owns the file contents.
const Known = struct {
    entries: std.ArrayList(sigfile.Entry) = .empty,
    texts: std.ArrayList([]u8) = .empty,

    fn deinit(k: *Known, gpa: std.mem.Allocator) void {
        k.entries.deinit(gpa);
        for (k.texts.items) |t| gpa.free(t);
        k.texts.deinit(gpa);
    }

    /// Loads `path` and reports problems. Returns false when the file could
    /// not be used at all.
    fn add(k: *Known, ctx: *Ctx, path: []const u8) !bool {
        const text = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.gpa, .unlimited) catch |e| {
            if (e == error.OutOfMemory) return e;
            ctx.fail("{s}: {s}", .{ path, Ctx.describe(e) });
            return false;
        };
        try k.texts.append(ctx.gpa, text);
        sigfile.load(ctx.gpa, &k.entries, text, path, BadLines{ .ctx = ctx }) catch |e| switch (e) {
            error.InvalidHeader => {
                ctx.fail("{s}: not an ssdeep signature file", .{path});
                return false;
            },
            else => return e,
        };
        return true;
    }
};

const BadLines = struct {
    ctx: *Ctx,
    pub fn badLine(b: BadLines, source: []const u8, line: usize) void {
        b.ctx.note("{s}: bad signature in line {d}, skipped", .{ source, line });
    }
};

fn hashFiles(ctx: *Ctx, o: *Options) !void {
    var known: Known = .{};
    defer known.deinit(ctx.gpa);
    if (o.mode == .match_files) {
        var any = false;
        for (o.known.items) |k| any = (try known.add(ctx, k)) or any;
        if (!any) {
            ctx.fail("no signatures loaded", .{});
            return;
        }
    }

    var h: Hasher = .{ .ctx = ctx, .o = o, .known = known.entries.items };
    try walk.each(ctx, o.walk, o.operands.items, &h);
    if (h.files > 0 and !h.big) ctx.note("did not process files large enough to produce meaningful results", .{});
}

const Hasher = struct {
    ctx: *Ctx,
    o: *const Options,
    known: []const sigfile.Entry,
    header_written: bool = false,
    /// Files hashed (standard input not counted).
    files: usize = 0,
    /// Whether one of them was larger than `small_file_bytes`.
    big: bool = false,

    pub fn visit(h: *Hasher, item: walk.Item, file: std.Io.File) !void {
        const ctx = h.ctx;
        var hasher = Ssdeep.init(.{});
        const n = input.stream(ctx, file, &hasher) catch |e| {
            ctx.fail("{s}: {s}", .{ item.open orelse item.display, Ctx.describe(e) });
            return;
        };
        const d = hasher.final() catch |e| {
            ctx.fail("{s}: {s}", .{ item.open orelse item.display, Ctx.describe(e) });
            return;
        };
        if (item.open != null) {
            h.files += 1;
            if (n > small_file_bytes) h.big = true;
        }
        var buf: [Ssdeep.max_string_length]u8 = undefined;
        const text = d.toString(&buf);
        const out = ctx.out;

        if (h.o.mode == .match_files) {
            for (h.known) |k| _ = try printMatch(ctx, h.o, null, item.display, k, Ssdeep.compare(d, k.digest));
            return;
        }
        if (h.o.json) {
            try out.writeAll("{\"family\":\"ssdeep\",\"path\":");
            try json.string(out, item.display);
            try out.print(",\"digest\":\"{s}\"}}\n", .{text});
            return;
        }
        if (!h.header_written) {
            try out.writeAll(sigfile.header ++ "\n");
            h.header_written = true;
        }
        try out.print("{s},", .{text});
        try sigfile.writeQuoted(out, item.display);
        try out.writeByte('\n');
    }
};

/// Prints one match if its score passes the threshold. `source` is the
/// signature file of `name` in -k and -x modes. Returns whether it printed.
fn printMatch(
    ctx: *Ctx,
    o: *const Options,
    source: ?[]const u8,
    name: []const u8,
    k: sigfile.Entry,
    score: u8,
) !bool {
    if (!o.all and score <= o.threshold) return false;
    const out = ctx.out;
    if (o.json) {
        try out.writeAll("{\"family\":\"ssdeep\",\"path\":");
        try json.string(out, name);
        if (source) |s| {
            try out.writeAll(",\"path_source\":");
            try json.string(out, s);
        }
        try out.writeAll(",\"match\":");
        try json.string(out, k.name);
        try out.writeAll(",\"match_source\":");
        try json.string(out, k.source);
        try out.print(",\"score\":{d}}}\n", .{score});
    } else if (o.csv) {
        try sigfile.writeQuoted(out, name);
        try out.writeByte(',');
        try sigfile.writeQuoted(out, k.name);
        try out.print(",{d}\n", .{score});
    } else {
        if (source) |s| try out.print("{s}:", .{s});
        try out.print("{s} matches {s}:{s} ({d})\n", .{ name, k.source, k.name, score });
    }
    return true;
}

fn matchSigs(ctx: *Ctx, o: *Options) !void {
    var known: Known = .{};
    defer known.deinit(ctx.gpa);
    var any = false;
    for (o.known.items) |k| any = (try known.add(ctx, k)) or any;
    if (!any) {
        ctx.fail("no signatures loaded", .{});
        return;
    }
    for (o.operands.items) |path| {
        var sigs: Known = .{};
        defer sigs.deinit(ctx.gpa);
        if (!try sigs.add(ctx, path)) continue;
        for (sigs.entries.items) |e| {
            for (known.entries.items) |k| _ = try printMatch(ctx, o, path, e.name, k, Ssdeep.compare(e.digest, k.digest));
        }
    }
}

fn matchAll(ctx: *Ctx, o: *Options) !void {
    var sigs: Known = .{};
    defer sigs.deinit(ctx.gpa);
    for (o.operands.items) |path| _ = try sigs.add(ctx, path);
    const all = sigs.entries.items;
    for (all, 0..) |a, i| {
        var printed = false;
        for (all, 0..) |b, j| {
            if (i == j) continue;
            if (try printMatch(ctx, o, a.source, a.name, b, Ssdeep.compare(a.digest, b.digest))) printed = true;
        }
        if (printed and !o.json) try ctx.out.writeByte('\n');
    }
}
