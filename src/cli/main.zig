// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! The `fuzzyhash` command-line tool.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");

const usage =
    \\usage: fuzzyhash [--help] [--version]
    \\
    \\Options:
    \\  -h, --help       print this help and exit
    \\  -V, --version    print the version and exit
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
    /// An argument the tool does not understand, with the offending text.
    unknown: []const u8,
    /// No arguments at all.
    missing,
};

/// Decide what to do from the arguments after the program name. The first
/// help or version flag wins; anything else is an error.
pub fn parse(args: []const []const u8) Command {
    if (args.len == 0) return .missing;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) return .version;
    }
    return .{ .unknown = args[0] };
}

/// Write the response to `command` and return the exit code.
pub fn run(command: Command, out: *std.Io.Writer, err: *std.Io.Writer) std.Io.Writer.Error!Exit {
    switch (command) {
        .help => {
            try out.writeAll(usage);
            return .ok;
        },
        .version => {
            try out.print("fuzzyhash {s}\n", .{fuzzyhash.version_string});
            return .ok;
        },
        .missing => {
            try err.writeAll(usage);
            return .usage;
        },
        .unknown => |arg| {
            try err.print("fuzzyhash: unrecognized argument '{s}'\n", .{arg});
            try err.writeAll(usage);
            return .usage;
        },
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args: []const []const u8 = if (argv.len > 0) argv[1..] else &.{};

    var out_buf: [4096]u8 = undefined;
    var err_buf: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    var stderr = std.Io.File.stderr().writer(io, &err_buf);

    const code = try run(parse(args), &stdout.interface, &stderr.interface);
    try stdout.interface.flush();
    try stderr.interface.flush();
    return @intFromEnum(code);
}

const testing = std.testing;

test "parse: no arguments" {
    try testing.expectEqual(Command.missing, parse(&.{}));
}

test "parse: help and version flags, short and long" {
    try testing.expectEqual(Command.help, parse(&.{"-h"}));
    try testing.expectEqual(Command.help, parse(&.{"--help"}));
    try testing.expectEqual(Command.version, parse(&.{"-V"}));
    try testing.expectEqual(Command.version, parse(&.{"--version"}));
}

test "parse: the first recognized flag wins" {
    try testing.expectEqual(Command.version, parse(&.{ "--version", "--help" }));
    try testing.expectEqual(Command.help, parse(&.{ "x", "--help" }));
}

test "parse: anything else is reported with the first argument" {
    const c = parse(&.{ "frobnicate", "file.bin" });
    try testing.expectEqualStrings("frobnicate", c.unknown);
}

test "run: version prints the package version" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    try testing.expectEqual(Exit.ok, try run(.version, &out.writer, &err.writer));
    const want = try std.fmt.allocPrint(testing.allocator, "fuzzyhash {s}\n", .{fuzzyhash.version_string});
    defer testing.allocator.free(want);
    try testing.expectEqualStrings(want, out.written());
    try testing.expectEqual(@as(usize, 0), err.written().len);
}

test "run: an unknown argument is a usage error on stderr" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    try testing.expectEqual(Exit.usage, try run(.{ .unknown = "nope" }, &out.writer, &err.writer));
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try testing.expect(std.mem.startsWith(u8, err.written(), "fuzzyhash: unrecognized argument 'nope'\n"));
}
