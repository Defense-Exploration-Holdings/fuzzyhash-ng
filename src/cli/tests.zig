// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Tests that run CLI commands on files in a temporary directory.

const std = @import("std");
const builtin = @import("builtin");
const fuzzyhash = @import("fuzzyhash");
const main = @import("main.zig");
const Ctx = @import("Ctx.zig");
const testing = std.testing;
const io = testing.io;
const gpa = testing.allocator;
const sep = std.fs.path.sep_str;

const Run = struct {
    out: std.Io.Writer.Allocating,
    err: std.Io.Writer.Allocating,
    code: main.Exit,

    fn init(args: []const []const u8) !Run {
        var r: Run = .{ .out = .init(gpa), .err = .init(gpa), .code = .ok };
        errdefer r.deinit();
        var ctx: Ctx = .{ .io = io, .gpa = gpa, .out = &r.out.writer, .err = &r.err.writer };
        r.code = try main.run(&ctx, main.parse(args));
        return r;
    }

    fn deinit(r: *Run) void {
        r.out.deinit();
        r.err.deinit();
    }

    fn lines(r: *Run) !std.ArrayList([]const u8) {
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, r.out.written(), '\n');
        while (it.next()) |l| if (l.len > 0) try list.append(gpa, l);
        return list;
    }
};

/// A temporary directory and its absolute path.
const Tmp = struct {
    tmp: testing.TmpDir,
    path: []u8,

    fn init() !Tmp {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const n = try tmp.dir.realPath(io, &buf);
        return .{ .tmp = tmp, .path = try gpa.dupe(u8, buf[0..n]) };
    }

    fn deinit(t: *Tmp) void {
        gpa.free(t.path);
        t.tmp.cleanup();
    }

    fn write(t: *Tmp, name: []const u8, data: []const u8) !void {
        try t.tmp.dir.writeFile(io, .{ .sub_path = name, .data = data });
    }

    /// Absolute path of `name`; freed by the caller.
    fn abs(t: *Tmp, name: []const u8) ![]u8 {
        return std.mem.concat(gpa, u8, &.{ t.path, sep, name });
    }
};

/// Bytes with enough variation for TLSH.
fn sample(buf: []u8, seed: u64) []u8 {
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(buf);
    return buf;
}

test "ssdeep: file format, -l keeps the path as given, quotes are escaped" {
    var t = try Tmp.init();
    defer t.deinit();
    try t.write("a.txt", "hello");
    try t.write("q\"x.txt", "hello");
    const a = try t.abs("a.txt");
    defer gpa.free(a);
    const q = try t.abs("q\"x.txt");
    defer gpa.free(q);

    var r = try Run.init(&.{ "ssdeep", "-l", "-s", a, q });
    defer r.deinit();
    try testing.expectEqual(main.Exit.ok, r.code);
    const want = try std.mem.concat(gpa, u8, &.{
        "ssdeep,1.1--blocksize:hash:hash,filename\n",
        "3:iKn:p,\"",
        a,
        "\"\n",
        "3:iKn:p,\"",
        t.path,
        sep,
        "q\\\"x.txt\"\n",
    });
    defer gpa.free(want);
    try testing.expectEqualStrings(want, r.out.written());
}

test "ssdeep: -b prints file names only, -r walks directories" {
    var t = try Tmp.init();
    defer t.deinit();
    try t.tmp.dir.createDirPath(io, "sub" ++ sep ++ "deep");
    try t.write("sub" ++ sep ++ "one", "hello");
    try t.write("sub" ++ sep ++ "deep" ++ sep ++ "two", "");

    var r = try Run.init(&.{ "ssdeep", "-b", "-r", "-s", t.path });
    defer r.deinit();
    var lines = try r.lines();
    defer lines.deinit(gpa);
    try testing.expectEqual(@as(usize, 3), lines.items.len);
    try testing.expectEqualStrings("ssdeep,1.1--blocksize:hash:hash,filename", lines.items[0]);
    // Directory order is up to the file system.
    const rest = lines.items[1..];
    std.mem.sort([]const u8, rest, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);
    try testing.expectEqualStrings("3::,\"two\"", rest[0]);
    try testing.expectEqualStrings("3:iKn:p,\"one\"", rest[1]);
}

test "ssdeep: a directory without -r and a missing file fail the run" {
    var t = try Tmp.init();
    defer t.deinit();
    const missing = try t.abs("missing");
    defer gpa.free(missing);
    var r = try Run.init(&.{ "ssdeep", t.path, missing });
    defer r.deinit();
    try testing.expectEqual(main.Exit.failure, r.code);
    try testing.expectEqualStrings("", r.out.written());
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "Is a directory") != null);
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "No such file or directory") != null);
}

test "ssdeep: small files give a warning, -s silences it" {
    var t = try Tmp.init();
    defer t.deinit();
    try t.write("small", "hello");
    const p = try t.abs("small");
    defer gpa.free(p);
    {
        var r = try Run.init(&.{ "ssdeep", p });
        defer r.deinit();
        try testing.expectEqual(main.Exit.ok, r.code);
        try testing.expect(std.mem.indexOf(u8, r.err.written(), "large enough") != null);
    }
    {
        var r = try Run.init(&.{ "ssdeep", "-s", p });
        defer r.deinit();
        try testing.expectEqualStrings("", r.err.written());
    }
}

test "ssdeep: -m matches files against known signatures" {
    var t = try Tmp.init();
    defer t.deinit();
    var buf: [20000]u8 = undefined;
    const data = sample(&buf, 1);
    try t.write("a.bin", data);
    data[10000] ^= 0xff;
    try t.write("b.bin", data);
    try t.write("known.txt", "ssdeep,1.1--blocksize:hash:hash,filename\n");
    const a = try t.abs("a.bin");
    defer gpa.free(a);
    const b = try t.abs("b.bin");
    defer gpa.free(b);

    // Build the known file with the tool itself.
    var hashed = try Run.init(&.{ "ssdeep", "-l", a });
    defer hashed.deinit();
    try t.write("known.txt", hashed.out.written());
    const known = try t.abs("known.txt");
    defer gpa.free(known);

    var r = try Run.init(&.{ "ssdeep", "-l", "-m", known, a, b });
    defer r.deinit();
    var lines = try r.lines();
    defer lines.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), lines.items.len);
    const first = try std.mem.concat(gpa, u8, &.{ a, " matches ", known, ":", a, " (100)" });
    defer gpa.free(first);
    try testing.expectEqualStrings(first, lines.items[0]);
    try testing.expect(std.mem.startsWith(u8, lines.items[1], b));
    try testing.expect(!std.mem.endsWith(u8, lines.items[1], "(100)"));

    var csv = try Run.init(&.{ "ssdeep", "-l", "-c", "-t", "99", "-m", known, a, b });
    defer csv.deinit();
    const want = try std.mem.concat(gpa, u8, &.{ "\"", a, "\",\"", a, "\",100\n" });
    defer gpa.free(want);
    try testing.expectEqualStrings(want, csv.out.written());
}

test "ssdeep: -x compares signature files with each other" {
    var t = try Tmp.init();
    defer t.deinit();
    try t.write("s.txt",
        \\ssdeep,1.1--blocksize:hash:hash,filename
        \\3:wn:wn,"one"
        \\3:wn:wn,"two"
        \\3:AAAA:AAAA,"three"
        \\
    );
    const s = try t.abs("s.txt");
    defer gpa.free(s);
    var r = try Run.init(&.{ "ssdeep", "-x", "-c", s });
    defer r.deinit();
    try testing.expectEqualStrings("\"one\",\"two\",100\n\n\"two\",\"one\",100\n\n", r.out.written());
}

test "tlsh: digest per file, TNULL for short input" {
    var t = try Tmp.init();
    defer t.deinit();
    var buf: [1000]u8 = undefined;
    const data = sample(&buf, 2);
    try t.write("a.bin", data);
    try t.write("short", "abc");
    const a = try t.abs("a.bin");
    defer gpa.free(a);
    const short = try t.abs("short");
    defer gpa.free(short);

    const T1 = fuzzyhash.Tlsh.T1;
    var dbuf: [T1.max_string_length]u8 = undefined;
    const d = (try T1.hash(data, .{})).toString(&dbuf, .{});

    var r = try Run.init(&.{ "tlsh", a, short });
    defer r.deinit();
    try testing.expectEqual(main.Exit.ok, r.code);
    const want = try std.mem.concat(gpa, u8, &.{ d, "\t", a, "\nTNULL\t", short, "\n" });
    defer gpa.free(want);
    try testing.expectEqualStrings(want, r.out.written());
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "too short") != null);

    var old = try Run.init(&.{ "tlsh", "--old", "--json", a });
    defer old.deinit();
    try testing.expect(std.mem.indexOf(u8, old.out.written(), d[2..]) != null);
    try testing.expect(std.mem.indexOf(u8, old.out.written(), d) == null);
}

test "nilsimsa and lzjd digests compare with themselves" {
    var t = try Tmp.init();
    defer t.deinit();
    var buf: [5000]u8 = undefined;
    try t.write("a.bin", sample(&buf, 3));
    const a = try t.abs("a.bin");
    defer gpa.free(a);

    const cases = [_]struct { cmd: []const u8, same: []const u8 }{
        .{ .cmd = "nilsimsa", .same = "128\n" },
        .{ .cmd = "lzjd", .same = "1\n" },
        .{ .cmd = "tlsh", .same = "0\n" },
        .{ .cmd = "ssdeep", .same = "100\n" },
    };
    for (cases) |c| {
        var r = try Run.init(&.{ c.cmd, "--json", a });
        defer r.deinit();
        const out = r.out.written();
        const key = "\"digest\":\"";
        const start = (std.mem.indexOf(u8, out, key) orelse return error.NoDigest) + key.len;
        const end = std.mem.indexOfScalarPos(u8, out, start, '"').?;
        const digest = out[start..end];
        var cmp = try Run.init(&.{ "compare", digest, digest });
        defer cmp.deinit();
        try testing.expectEqualStrings(c.same, cmp.out.written());
    }
}

test "imphash and telfhash report files they cannot read" {
    var t = try Tmp.init();
    defer t.deinit();
    try t.write("text", "not an executable");
    const p = try t.abs("text");
    defer gpa.free(p);
    for ([_][]const u8{ "imphash", "telfhash" }) |cmd| {
        var r = try Run.init(&.{ cmd, p });
        defer r.deinit();
        try testing.expectEqual(main.Exit.failure, r.code);
        try testing.expectEqualStrings("", r.out.written());
    }
}

test "-r does not follow a symbolic link out of the tree unless --follow" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var t = try Tmp.init();
    defer t.deinit();
    try t.tmp.dir.createDirPath(io, "tree");
    try t.tmp.dir.createDirPath(io, "outside");
    try t.write("outside/x", "hello");
    try t.write("tree/y", "hello");
    const outside = try t.abs("outside");
    defer gpa.free(outside);
    try t.tmp.dir.symLink(io, outside, "tree/out", .{ .is_directory = true });
    try t.tmp.dir.symLink(io, "y", "tree/ylink", .{});
    const tree = try t.abs("tree");
    defer gpa.free(tree);

    {
        var r = try Run.init(&.{ "ssdeep", "-r", "-b", tree });
        defer r.deinit();
        try testing.expect(std.mem.indexOf(u8, r.out.written(), "\"x\"") == null);
        try testing.expect(std.mem.indexOf(u8, r.out.written(), "\"ylink\"") != null);
        try testing.expect(std.mem.indexOf(u8, r.err.written(), "--follow") != null);
    }
    {
        var r = try Run.init(&.{ "ssdeep", "-r", "-b", "--follow", tree });
        defer r.deinit();
        try testing.expect(std.mem.indexOf(u8, r.out.written(), "\"x\"") != null);
    }
}

test "-r reports a symbolic link back to the tree as a cycle" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var t = try Tmp.init();
    defer t.deinit();
    try t.tmp.dir.createDirPath(io, "tree");
    try t.write("tree/y", "hello");
    try t.tmp.dir.symLink(io, ".", "tree/loop", .{ .is_directory = true });
    const tree = try t.abs("tree");
    defer gpa.free(tree);
    var r = try Run.init(&.{ "tlsh", "-r", tree });
    defer r.deinit();
    try testing.expect(std.mem.indexOf(u8, r.err.written(), "cycle") != null);
    var lines = try r.lines();
    defer lines.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), lines.items.len);
}
