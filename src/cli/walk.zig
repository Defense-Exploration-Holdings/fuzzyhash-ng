// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Turns the path arguments of a command into opened files.
//!
//! Directories are read in the order the file system lists them, and each
//! subdirectory is walked as soon as it is listed. In a recursive walk a
//! symbolic link is followed only when its target is inside the tree given
//! on the command line, unless `follow` is set. A directory that is already
//! being walked higher up is reported as a cycle and not entered again.

const std = @import("std");
const Ctx = @import("Ctx.zig");
const paths = @import("paths.zig");
const File = std.Io.File;
const Dir = std.Io.Dir;

/// How a path is opened and shown.
pub const Naming = enum {
    /// As given; children are joined with one separator.
    given,
    /// ssdeep default: the absolute path, resolved as text, is opened and shown.
    absolute,
    /// ssdeep `-l`: as given; children are `dir`, a separator and the name.
    relative,
    /// ssdeep `-b`: the absolute path is opened, the last component is shown.
    bare,
};

pub const Options = struct {
    naming: Naming = .given,
    recursive: bool = false,
    follow: bool = false,
    /// The name shown for standard input.
    stdin_name: []const u8 = "-",
};

/// One input: the path that is opened (null for standard input) and the
/// name that is shown.
pub const Item = struct {
    open: ?[]const u8,
    display: []const u8,
};

/// Calls `visitor.visit(item, file)` for every file named by `args`, in
/// order. With no arguments, standard input is the only input. "-" also
/// stands for standard input. Problems are reported through `ctx` and the
/// walk continues.
pub fn each(ctx: *Ctx, opts: Options, args: []const []const u8, visitor: anytype) !void {
    var w: Walker(@TypeOf(visitor)) = .{ .ctx = ctx, .opts = opts, .visitor = visitor };
    defer w.deinit();
    if (args.len == 0) return w.stdin();
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-")) {
            try w.stdin();
        } else {
            try w.arg(arg);
        }
    }
}

/// Canonical path of `name` in `d`, without a sentinel so that it can be
/// freed like any other slice.
fn realPath(ctx: *Ctx, d: Dir, name: []const u8) ![]u8 {
    var buf: [Dir.max_path_bytes]u8 = undefined;
    const n = try d.realPathFile(ctx.io, name, &buf);
    return ctx.gpa.dupe(u8, buf[0..n]);
}

fn Walker(comptime V: type) type {
    return struct {
        const Self = @This();

        ctx: *Ctx,
        opts: Options,
        visitor: V,
        cwd: ?[]u8 = null,
        /// Canonical paths of the directories being walked, outermost first.
        stack: std.ArrayList([]u8) = .empty,
        /// Canonical path of the argument being walked.
        root: ?[]u8 = null,

        fn deinit(w: *Self) void {
            const gpa = w.ctx.gpa;
            if (w.cwd) |c| gpa.free(c);
            for (w.stack.items) |p| gpa.free(p);
            w.stack.deinit(gpa);
            if (w.root) |r| gpa.free(r);
        }

        fn stdin(w: *Self) !void {
            try w.visitor.visit(.{ .open = null, .display = w.opts.stdin_name }, File.stdin());
        }

        fn currentDir(w: *Self) ![]const u8 {
            if (w.cwd == null) {
                var buf: [Dir.max_path_bytes]u8 = undefined;
                const n = try std.process.currentPath(w.ctx.io, &buf);
                w.cwd = try w.ctx.gpa.dupe(u8, buf[0..n]);
            }
            return w.cwd.?;
        }

        fn arg(w: *Self, raw: []const u8) !void {
            const gpa = w.ctx.gpa;
            var open: []const u8 = raw;
            var display: []const u8 = raw;
            var owned: ?[]u8 = null;
            defer if (owned) |o| gpa.free(o);
            switch (w.opts.naming) {
                .given, .relative => {},
                .absolute, .bare => {
                    owned = try paths.absolute(gpa, try w.currentDir(), raw);
                    open = owned.?;
                    display = if (w.opts.naming == .bare) paths.basename(owned.?) else owned.?;
                },
            }

            const st = Dir.cwd().statFile(w.ctx.io, open, .{}) catch |e| {
                w.ctx.fail("{s}: {s}", .{ open, Ctx.describe(e) });
                return;
            };
            if (st.kind != .directory) return w.file(open, display);
            if (!w.opts.recursive) {
                w.ctx.fail("{s}: {s}", .{ open, Ctx.describe(error.IsDir) });
                return;
            }
            if (w.root) |r| gpa.free(r);
            w.root = null;
            w.root = realPath(w.ctx, Dir.cwd(), open) catch |e| {
                w.ctx.fail("{s}: {s}", .{ open, Ctx.describe(e) });
                return;
            };
            try w.dir(open, display, try gpa.dupe(u8, w.root.?));
        }

        fn file(w: *Self, open: []const u8, display: []const u8) !void {
            const f = Dir.cwd().openFile(w.ctx.io, open, .{ .allow_directory = false }) catch |e| {
                w.ctx.fail("{s}: {s}", .{ open, Ctx.describe(e) });
                return;
            };
            defer f.close(w.ctx.io);
            try w.visitor.visit(.{ .open = open, .display = display }, f);
        }

        fn childPath(w: *Self, dir_path: []const u8, name: []const u8) ![]u8 {
            return switch (w.opts.naming) {
                .relative => paths.joinVerbatim(w.ctx.gpa, dir_path, name),
                else => paths.join(w.ctx.gpa, dir_path, name),
            };
        }

        /// Walks `open`, whose canonical path is `real` (owned by the walk
        /// from here on).
        fn dir(w: *Self, open: []const u8, display: []const u8, real: []u8) anyerror!void {
            const gpa = w.ctx.gpa;
            const io = w.ctx.io;
            for (w.stack.items) |p| {
                if (std.mem.eql(u8, p, real)) {
                    gpa.free(real);
                    w.ctx.note("{s}: symlink creates cycle", .{open});
                    return;
                }
            }
            w.stack.append(gpa, real) catch |e| {
                gpa.free(real);
                return e;
            };
            defer {
                const top = w.stack.pop().?;
                gpa.free(top);
            }

            var d = Dir.cwd().openDir(io, open, .{ .iterate = true }) catch |e| {
                w.ctx.fail("{s}: {s}", .{ open, Ctx.describe(e) });
                return;
            };
            defer d.close(io);
            var it = d.iterate();
            while (true) {
                const entry = it.next(io) catch |e| {
                    w.ctx.fail("{s}: {s}", .{ open, Ctx.describe(e) });
                    return;
                } orelse break;

                const child_open = try w.childPath(open, entry.name);
                defer gpa.free(child_open);
                const child_display = if (w.opts.naming == .bare) entry.name else try w.childPath(display, entry.name);
                defer if (w.opts.naming != .bare) gpa.free(child_display);

                var kind = entry.kind;
                if (kind == .unknown) {
                    const st = d.statFile(io, entry.name, .{ .follow_symlinks = false }) catch |e| {
                        w.ctx.fail("{s}: {s}", .{ child_open, Ctx.describe(e) });
                        continue;
                    };
                    kind = st.kind;
                }
                switch (kind) {
                    .file => try w.file(child_open, child_display),
                    .directory => {
                        const child_real = try paths.join(gpa, real, entry.name);
                        try w.dir(child_open, child_display, child_real);
                    },
                    .sym_link => try w.link(d, entry.name, child_open, child_display),
                    // Devices, pipes and sockets inside a tree are not read.
                    else => {},
                }
            }
        }

        fn link(w: *Self, d: Dir, name: []const u8, open: []const u8, display: []const u8) anyerror!void {
            const gpa = w.ctx.gpa;
            const io = w.ctx.io;
            const st = d.statFile(io, name, .{}) catch |e| {
                w.ctx.fail("{s}: {s}", .{ open, Ctx.describe(e) });
                return;
            };
            if (st.kind != .file and st.kind != .directory) return;
            const real = realPath(w.ctx, d, name) catch |e| {
                w.ctx.fail("{s}: {s}", .{ open, Ctx.describe(e) });
                return;
            };
            if (!w.opts.follow and !paths.isWithin(w.root.?, real)) {
                gpa.free(real);
                w.ctx.note("{s}: symlink leaves the tree, not followed (use --follow)", .{open});
                return;
            }
            if (st.kind == .file) {
                gpa.free(real);
                return w.file(open, display);
            }
            return w.dir(open, display, real);
        }
    };
}
