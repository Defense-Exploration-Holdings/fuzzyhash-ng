// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Path text handling for the CLI. Nothing here touches the file system.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const windows = builtin.os.tag == .windows;
pub const sep: u8 = if (windows) '\\' else '/';

pub fn isSep(c: u8) bool {
    return c == '/' or (windows and c == '\\');
}

/// Length of the root part of an absolute path: "/" on POSIX; "C:\" or
/// "\\server\share\" style prefixes are left to `isAbsolute` on Windows,
/// where only drive roots are handled here.
fn rootLen(path: []const u8) usize {
    if (windows) {
        if (path.len >= 3 and path[1] == ':' and isSep(path[2])) return 3;
        if (path.len >= 1 and isSep(path[0])) return 1;
        return 0;
    }
    return if (path.len >= 1 and path[0] == '/') 1 else 0;
}

pub fn isAbsolute(path: []const u8) bool {
    return rootLen(path) > 0;
}

/// The absolute form of `path` that ssdeep prints by default: `path` is
/// appended to `cwd` when it is relative, then "." and ".." components are
/// resolved as text, without looking at the file system, and repeated
/// separators collapse. The result ends with a separator when `path` does,
/// when its last component is "." or "..", or when `path` is empty, unless
/// the result is the root itself.
pub fn absolute(gpa: Allocator, cwd: []const u8, path: []const u8) Allocator.Error![]u8 {
    const joined = if (isAbsolute(path))
        try gpa.dupe(u8, path)
    else
        try std.mem.concat(gpa, u8, &.{ cwd, &.{sep}, path });
    defer gpa.free(joined);

    const root = rootLen(joined);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, joined[0..root]);
    if (windows and root == 3) out.items[2] = sep;

    var trailing = false;
    var it = std.mem.tokenizeAny(u8, joined[root..], if (windows) "/\\" else "/");
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, ".")) {
            trailing = true;
        } else if (std.mem.eql(u8, part, "..")) {
            trailing = true;
            if (out.items.len > root) {
                var i = out.items.len - 1;
                while (i > root and out.items[i] != sep) i -= 1;
                out.shrinkRetainingCapacity(i);
            }
        } else {
            trailing = false;
            if (out.items.len > root) try out.append(gpa, sep);
            try out.appendSlice(gpa, part);
        }
    }
    if (path.len == 0 or isSep(path[path.len - 1])) trailing = true;
    if (trailing and out.items.len > root) try out.append(gpa, sep);
    return out.toOwnedSlice(gpa);
}

/// `dir` and `name` joined by one separator. A separator is not added when
/// `dir` already ends with one.
pub fn join(gpa: Allocator, dir: []const u8, name: []const u8) Allocator.Error![]u8 {
    if (dir.len > 0 and isSep(dir[dir.len - 1])) return std.mem.concat(gpa, u8, &.{ dir, name });
    return std.mem.concat(gpa, u8, &.{ dir, &.{sep}, name });
}

/// `dir`, a separator and `name`, always, as ssdeep builds paths in
/// relative mode ("sub/" and "c.bin" give "sub//c.bin").
pub fn joinVerbatim(gpa: Allocator, dir: []const u8, name: []const u8) Allocator.Error![]u8 {
    return std.mem.concat(gpa, u8, &.{ dir, &.{sep}, name });
}

/// The last component of `path`. A trailing separator is ignored.
pub fn basename(path: []const u8) []const u8 {
    var end = path.len;
    while (end > 0 and isSep(path[end - 1])) end -= 1;
    var start = end;
    while (start > 0 and !isSep(path[start - 1])) start -= 1;
    return path[start..end];
}

/// Whether the canonical path `inner` is `outer` or below it.
pub fn isWithin(outer: []const u8, inner: []const u8) bool {
    if (!std.mem.startsWith(u8, inner, outer)) return false;
    if (inner.len == outer.len) return true;
    if (outer.len > 0 and isSep(outer[outer.len - 1])) return true;
    return isSep(inner[outer.len]);
}

const testing = std.testing;

fn expectAbsolute(want: []const u8, cwd: []const u8, path: []const u8) !void {
    const got = try absolute(testing.allocator, cwd, path);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "absolute resolves dot components as text" {
    if (windows) return error.SkipZigTest;
    const cwd = "/tmp/w";
    try expectAbsolute("/tmp/w/", cwd, ".");
    try expectAbsolute("/tmp/w/", cwd, "./");
    try expectAbsolute("/tmp/w/", cwd, "");
    try expectAbsolute("/tmp/w/sub/", cwd, "sub/");
    try expectAbsolute("/tmp/w/sub/", cwd, "sub/.");
    try expectAbsolute("/tmp/w/", cwd, "sub/..");
    try expectAbsolute("/tmp/", cwd, "..");
    try expectAbsolute("/tmp/w/", cwd, "a/b/../..");
    try expectAbsolute("/", cwd, "/");
    try expectAbsolute("/", cwd, "//");
    try expectAbsolute("/", cwd, "/..");
    try expectAbsolute("/", cwd, "../../../..");
    try expectAbsolute("/tmp/w/x/y", cwd, "x//y");
    try expectAbsolute("/tmp/w/x", cwd, "./x");
    try expectAbsolute("/tmp/w/x/y", cwd, "x/./y");
    try expectAbsolute("/tmp/y", cwd, "x/../../y");
    try expectAbsolute("/tmp/w/...", cwd, "...");
    try expectAbsolute("/tmp/w/.x", cwd, ".x");
    try expectAbsolute("/tmp/w", cwd, "/tmp/w/../w");
    try expectAbsolute("/tmp/w/x/y/", cwd, "x/y/");
    try expectAbsolute("/a/b", "/", "a/b");
}

test "join and joinVerbatim" {
    const a = testing.allocator;
    const j1 = try join(a, "sub", "c");
    defer a.free(j1);
    const j2 = try join(a, "sub" ++ [_]u8{sep}, "c");
    defer a.free(j2);
    const j3 = try joinVerbatim(a, "sub" ++ [_]u8{sep}, "c");
    defer a.free(j3);
    try testing.expectEqualStrings("sub" ++ [_]u8{sep} ++ "c", j1);
    try testing.expectEqualStrings("sub" ++ [_]u8{sep} ++ "c", j2);
    try testing.expectEqualStrings("sub" ++ [_]u8{ sep, sep } ++ "c", j3);
}

test "basename" {
    try testing.expectEqualStrings("c.bin", basename("a/b/c.bin"));
    try testing.expectEqualStrings("b", basename("a/b/"));
    try testing.expectEqualStrings("c", basename("c"));
    try testing.expectEqualStrings("", basename(""));
}

test "isWithin" {
    try testing.expect(isWithin("/a/b", "/a/b"));
    try testing.expect(isWithin("/a/b", "/a/b/c"));
    try testing.expect(!isWithin("/a/b", "/a/bc"));
    try testing.expect(!isWithin("/a/b", "/a"));
    try testing.expect(isWithin("/", "/x"));
}
