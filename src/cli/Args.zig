// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Command-line tokenizer in the style of getopt_long: short options can be
//! grouped (`-rl`), a short option's value can follow it directly (`-t50`)
//! or be the next argument, long options take `--name=value` or
//! `--name value`, options and operands can be mixed, and `--` ends the
//! options. A lone `-` is an operand.

const std = @import("std");
const Args = @This();

args: []const []const u8,
index: usize = 0,
/// Rest of a group of short options, after the one just returned.
group: []const u8 = "",
/// Value attached to the long option just returned (`--name=value`).
attached: ?[]const u8 = null,
only_operands: bool = false,

pub const Token = union(enum) {
    short: u8,
    long: []const u8,
    operand: []const u8,
};

pub fn init(args: []const []const u8) Args {
    return .{ .args = args };
}

pub fn next(p: *Args) ?Token {
    p.attached = null;
    if (p.group.len > 0) {
        const c = p.group[0];
        p.group = p.group[1..];
        return .{ .short = c };
    }
    if (p.index >= p.args.len) return null;
    const a = p.args[p.index];
    p.index += 1;
    if (p.only_operands or a.len < 2 or a[0] != '-') return .{ .operand = a };
    if (std.mem.eql(u8, a, "--")) {
        p.only_operands = true;
        return p.next();
    }
    if (a[1] == '-') {
        const body = a[2..];
        if (std.mem.indexOfScalar(u8, body, '=')) |eq| {
            p.attached = body[eq + 1 ..];
            return .{ .long = body[0..eq] };
        }
        return .{ .long = body };
    }
    p.group = a[2..];
    return .{ .short = a[1] };
}

/// The value of the option just returned: the rest of a short group, the
/// part after `=`, or the next argument. Null when there is none.
pub fn value(p: *Args) ?[]const u8 {
    if (p.attached) |v| {
        p.attached = null;
        return v;
    }
    if (p.group.len > 0) {
        const v = p.group;
        p.group = "";
        return v;
    }
    if (p.index >= p.args.len) return null;
    const v = p.args[p.index];
    p.index += 1;
    return v;
}

/// Whether the long option just returned carried `=value`.
pub fn hasAttached(p: *const Args) bool {
    return p.attached != null;
}

const testing = std.testing;

test "groups, attached values, operands and --" {
    var p = Args.init(&.{ "-rl", "-t50", "a", "--json", "-t", "7", "--x=1", "-", "--", "-b" });
    try testing.expectEqual(@as(u8, 'r'), p.next().?.short);
    try testing.expectEqual(@as(u8, 'l'), p.next().?.short);
    try testing.expectEqual(@as(u8, 't'), p.next().?.short);
    try testing.expectEqualStrings("50", p.value().?);
    try testing.expectEqualStrings("a", p.next().?.operand);
    try testing.expectEqualStrings("json", p.next().?.long);
    try testing.expectEqual(@as(u8, 't'), p.next().?.short);
    try testing.expectEqualStrings("7", p.value().?);
    try testing.expectEqualStrings("x", p.next().?.long);
    try testing.expect(p.hasAttached());
    try testing.expectEqualStrings("1", p.value().?);
    try testing.expectEqualStrings("-", p.next().?.operand);
    try testing.expectEqualStrings("-b", p.next().?.operand);
    try testing.expectEqual(@as(?Token, null), p.next());
}

test "a missing value is null" {
    var p = Args.init(&.{"-t"});
    _ = p.next();
    try testing.expectEqual(@as(?[]const u8, null), p.value());
}
