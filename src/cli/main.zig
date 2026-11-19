// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! The `fuzzyhash` command-line tool.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const Ctx = @import("Ctx.zig");
const cmd_ssdeep = @import("cmd_ssdeep.zig");
const cmd_digest = @import("cmd_digest.zig");
const cmd_compare = @import("cmd_compare.zig");

const usage =
    \\usage: fuzzyhash COMMAND [OPTIONS] [ARGS...]
    \\       fuzzyhash [--help] [--version]
    \\
    \\Commands:
    \\  ssdeep     ssdeep digests in the ssdeep file format, and matching
    \\  tlsh       TLSH digests
    \\  imphash    import hashes of PE files
    \\  telfhash   symbol hashes of ELF files
    \\  lzjd       LZJD digests
    \\  nilsimsa   Nilsimsa digests
    \\  compare    compare two digests
    \\
    \\Run "fuzzyhash COMMAND --help" for the options of a command.
    \\
    \\Options:
    \\  -h, --help       print this help and exit
    \\  -V, --version    print the version and exit
    \\
    \\Exit status: 0 on success, 1 if an input could not be read or hashed,
    \\2 for a usage error.
    \\
;

/// Process exit codes.
pub const Exit = enum(u8) {
    ok = 0,
    failure = 1,
    usage = 2,
};

pub const Command = union(enum) {
    help,
    version,
    ssdeep: []const []const u8,
    digest: struct { family: cmd_digest.Family, args: []const []const u8 },
    compare: []const []const u8,
    /// An argument the tool does not understand, with the offending text.
    unknown: []const u8,
    /// No arguments at all.
    missing,
};

/// Decide what to do from the arguments after the program name.
pub fn parse(args: []const []const u8) Command {
    if (args.len == 0) return .missing;
    const first = args[0];
    const rest = args[1..];
    if (std.mem.eql(u8, first, "-h") or std.mem.eql(u8, first, "--help") or std.mem.eql(u8, first, "help")) return .help;
    if (std.mem.eql(u8, first, "-V") or std.mem.eql(u8, first, "--version")) return .version;
    if (std.mem.eql(u8, first, "ssdeep")) return .{ .ssdeep = rest };
    if (std.mem.eql(u8, first, "compare")) return .{ .compare = rest };
    if (std.meta.stringToEnum(cmd_digest.Family, first)) |f| return .{ .digest = .{ .family = f, .args = rest } };
    return .{ .unknown = first };
}

/// Run `command` and return the exit code.
pub fn run(ctx: *Ctx, command: Command) !Exit {
    switch (command) {
        .help => {
            try ctx.out.writeAll(usage);
            return .ok;
        },
        .version => {
            try ctx.out.print("fuzzyhash {s}\n", .{fuzzyhash.version_string});
            return .ok;
        },
        .missing => {
            try ctx.err.writeAll(usage);
            return .usage;
        },
        .unknown => |arg| {
            try ctx.err.print("fuzzyhash: unrecognized argument '{s}'\n", .{arg});
            try ctx.err.writeAll(usage);
            return .usage;
        },
        .ssdeep => |args| return cmd_ssdeep.run(ctx, args),
        .digest => |d| return cmd_digest.run(ctx, d.family, d.args),
        .compare => |args| return cmd_compare.run(ctx, args),
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args: []const []const u8 = if (argv.len > 0) argv[1..] else &.{};

    var out_buf: [64 * 1024]u8 = undefined;
    var err_buf: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    var stderr = std.Io.File.stderr().writer(io, &err_buf);
    var ctx: Ctx = .{ .io = io, .gpa = init.gpa, .out = &stdout.interface, .err = &stderr.interface };

    const code = run(&ctx, parse(args)) catch |e| switch (e) {
        // stdout closed early, as with `| head`: stop quietly.
        error.WriteFailed => if (stdout.err != null) return @backingInt(Exit.failure) else return e,
        else => {
            stdout.interface.flush() catch {};
            ctx.err.print("fuzzyhash: {s}\n", .{Ctx.describe(e)}) catch {};
            ctx.err.flush() catch {};
            return @backingInt(Exit.failure);
        },
    };
    stdout.interface.flush() catch return @backingInt(Exit.failure);
    stderr.interface.flush() catch {};
    return @backingInt(code);
}

test {
    _ = @import("Args.zig");
    _ = @import("paths.zig");
    _ = @import("json.zig");
    _ = @import("sigfile.zig");
    _ = @import("lzjd_text.zig");
    _ = @import("cmd_compare.zig");
    _ = @import("tests.zig");
}

const testing = std.testing;

/// `n` copies of the character `c`, at compile time.
fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const a: [n]u8 = @splat(c);
    return &a;
}

/// Runs the CLI on `args` with in-memory output.
const Run = struct {
    out: std.Io.Writer.Allocating,
    err: std.Io.Writer.Allocating,
    code: Exit,

    fn init(args: []const []const u8) !Run {
        var r: Run = .{ .out = .init(testing.allocator), .err = .init(testing.allocator), .code = .ok };
        var ctx: Ctx = .{ .io = testing.io, .gpa = testing.allocator, .out = &r.out.writer, .err = &r.err.writer };
        r.code = try run(&ctx, parse(args));
        return r;
    }

    fn deinit(r: *Run) void {
        r.out.deinit();
        r.err.deinit();
    }
};

test "parse: no arguments" {
    try testing.expectEqual(Command.missing, parse(&.{}));
}

test "parse: help and version flags, short and long" {
    try testing.expectEqual(Command.help, parse(&.{"-h"}));
    try testing.expectEqual(Command.help, parse(&.{"--help"}));
    try testing.expectEqual(Command.version, parse(&.{"-V"}));
    try testing.expectEqual(Command.version, parse(&.{"--version"}));
}

test "parse: commands" {
    try testing.expectEqual(@as(usize, 1), parse(&.{ "ssdeep", "x" }).ssdeep.len);
    try testing.expectEqual(cmd_digest.Family.lzjd, parse(&.{"lzjd"}).digest.family);
    try testing.expectEqual(@as(usize, 2), parse(&.{ "compare", "a", "b" }).compare.len);
}

test "parse: anything else is reported with the first argument" {
    const c = parse(&.{ "frobnicate", "file.bin" });
    try testing.expectEqualStrings("frobnicate", c.unknown);
}

test "run: version prints the package version" {
    var r = try Run.init(&.{"--version"});
    defer r.deinit();
    try testing.expectEqual(Exit.ok, r.code);
    const want = try std.fmt.allocPrint(testing.allocator, "fuzzyhash {s}\n", .{fuzzyhash.version_string});
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, r.out.written());
    try testing.expectEqual(@as(usize, 0), r.err.written().len);
}

test "run: an unknown argument is a usage error on stderr" {
    var r = try Run.init(&.{"nope"});
    defer r.deinit();
    try testing.expectEqual(Exit.usage, r.code);
    try testing.expectEqual(@as(usize, 0), r.out.written().len);
    try testing.expect(std.mem.startsWith(u8, r.err.written(), "fuzzyhash: unrecognized argument 'nope'\n"));
}

test "compare: ssdeep, TLSH, Nilsimsa" {
    {
        var r = try Run.init(&.{ "compare", "3:iKn:p", "3:iKn:p" });
        defer r.deinit();
        try testing.expectEqualStrings("100\n", r.out.written());
    }
    {
        const a = "T1" ++ rep('0', 70);
        var r = try Run.init(&.{ "compare", "--json", a, a });
        defer r.deinit();
        try testing.expectEqualStrings("{\"family\":\"tlsh\",\"distance\":0}\n", r.out.written());
    }
    {
        const a = rep('0', 64);
        const b = "f" ++ rep('0', 63);
        var r = try Run.init(&.{ "compare", a, b });
        defer r.deinit();
        try testing.expectEqualStrings("124\n", r.out.written());
    }
}

test "compare: digests of different kinds fail" {
    var r = try Run.init(&.{ "compare", "3:iKn:p", rep('0', 64) });
    defer r.deinit();
    try testing.expectEqual(Exit.failure, r.code);
    try testing.expectEqual(@as(usize, 0), r.out.written().len);
}

test "compare: usage errors" {
    var r = try Run.init(&.{ "compare", "3:iKn:p" });
    defer r.deinit();
    try testing.expectEqual(Exit.usage, r.code);
}

test "ssdeep: -m, -k and -x cannot be combined" {
    var r = try Run.init(&.{ "ssdeep", "-m", "a", "-x", "b" });
    defer r.deinit();
    try testing.expectEqual(Exit.usage, r.code);
}

test "ssdeep: -t out of range" {
    var r = try Run.init(&.{ "ssdeep", "-t", "101", "x" });
    defer r.deinit();
    try testing.expectEqual(Exit.usage, r.code);
}
