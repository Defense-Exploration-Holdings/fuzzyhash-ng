// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! The ssdeep 1.1 signature file format: a header line, then one
//! `blocksize:hash:hash,"file name"` line per file, with `"` in names
//! written as `\"`.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const Ssdeep = fuzzyhash.Ssdeep;

pub const header = "ssdeep,1.1--blocksize:hash:hash,filename";

/// Writes `name` between double quotes, with `"` written as `\"`.
pub fn writeQuoted(w: *std.Io.Writer, name: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    var start: usize = 0;
    for (name, 0..) |c, i| {
        if (c == '"') {
            try w.writeAll(name[start..i]);
            try w.writeAll("\\\"");
            start = i + 1;
        }
    }
    try w.writeAll(name[start..]);
    try w.writeByte('"');
}

pub const Entry = struct {
    digest: Ssdeep.Digest,
    /// The file name, unquoted. Points into the file contents.
    name: []const u8,
    /// The signature file as named on the command line.
    source: []const u8,
};

pub const LoadError = error{InvalidHeader} || std.mem.Allocator.Error;

/// Appends the entries of the signature file `text` to `list`. Lines that
/// do not hold a digest and a quoted name are passed to `bad` with their
/// line number (the header is line 1) and skipped. The returned names
/// point into `text`, so it must outlive `list`. A name's `\"` escapes are
/// undone in place.
pub fn load(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(Entry),
    text: []u8,
    source: []const u8,
    bad: anytype,
) LoadError!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    const first = lines.next() orelse return error.InvalidHeader;
    if (!std.mem.eql(u8, trimCr(first), header)) return error.InvalidHeader;
    var number: usize = 1;
    while (lines.next()) |raw| {
        number += 1;
        const line = trimCr(raw);
        if (line.len == 0) continue;
        const entry = parseLine(@constCast(line), source) orelse {
            bad.badLine(source, number);
            continue;
        };
        try list.append(gpa, entry);
    }
}

fn trimCr(line: []const u8) []const u8 {
    return if (line.len > 0 and line[line.len - 1] == '\r') line[0 .. line.len - 1] else line;
}

fn parseLine(line: []u8, source: []const u8) ?Entry {
    const comma = std.mem.indexOfScalar(u8, line, ',') orelse return null;
    const digest = Ssdeep.Digest.parse(line[0..comma], .strict) catch return null;
    const quoted = line[comma + 1 ..];
    if (quoted.len < 2 or quoted[0] != '"' or quoted[quoted.len - 1] != '"') return null;
    const inner = quoted[1 .. quoted.len - 1];
    // Undo \" in place.
    var n: usize = 0;
    var i: usize = 0;
    while (i < inner.len) : (i += 1) {
        if (inner[i] == '\\' and i + 1 < inner.len and inner[i + 1] == '"') i += 1;
        inner[n] = inner[i];
        n += 1;
    }
    return .{ .digest = digest, .name = inner[0..n], .source = source };
}

const testing = std.testing;

const NoBad = struct {
    lines: std.ArrayList(usize) = .empty,
    fn badLine(self: *NoBad, _: []const u8, n: usize) void {
        self.lines.append(testing.allocator, n) catch {};
    }
};

test "writeQuoted escapes double quotes only" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try writeQuoted(&out.writer, "a\"b\\c,d");
    try testing.expectEqualStrings("\"a\\\"b\\c,d\"", out.written());
}

test "load reads entries and reports bad lines" {
    const src =
        header ++ "\n" ++
        "3:wn:wn,\"a\"\"b\"\n" ++
        "bad line\n" ++
        "3:wn:wn,noquote\n" ++
        "3:wn:wn,\"x\\\"y\"\r\n";
    const text = try testing.allocator.dupe(u8, src);
    defer testing.allocator.free(text);
    var list: std.ArrayList(Entry) = .empty;
    defer list.deinit(testing.allocator);
    var bad: NoBad = .{};
    defer bad.lines.deinit(testing.allocator);
    try load(testing.allocator, &list, text, "k.txt", &bad);
    try testing.expectEqual(@as(usize, 2), list.items.len);
    try testing.expectEqualStrings("a\"\"b", list.items[0].name);
    try testing.expectEqualStrings("x\"y", list.items[1].name);
    try testing.expectEqualStrings("k.txt", list.items[1].source);
    try testing.expectEqualSlices(usize, &.{ 3, 4 }, bad.lines.items);
}

test "load rejects a missing header" {
    const text = try testing.allocator.dupe(u8, "junk\n");
    defer testing.allocator.free(text);
    var list: std.ArrayList(Entry) = .empty;
    defer list.deinit(testing.allocator);
    var bad: NoBad = .{};
    try testing.expectError(error.InvalidHeader, load(testing.allocator, &list, text, "j", &bad));
}
