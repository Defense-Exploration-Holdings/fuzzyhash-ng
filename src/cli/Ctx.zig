// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! What every command needs: I/O, an allocator, the two output streams and
//! the error state of the run.

const std = @import("std");
const Ctx = @This();

io: std.Io,
gpa: std.mem.Allocator,
out: *std.Io.Writer,
err: *std.Io.Writer,
/// Suppress messages about inputs (ssdeep `-s`).
silent: bool = false,
/// Set when an input could not be read or hashed.
failed: bool = false,

/// Report a problem with one input and remember that the run failed.
pub fn fail(ctx: *Ctx, comptime fmt: []const u8, args: anytype) void {
    ctx.failed = true;
    ctx.note(fmt, args);
}

/// A message on stderr that does not fail the run.
pub fn note(ctx: *Ctx, comptime fmt: []const u8, args: anytype) void {
    if (ctx.silent) return;
    ctx.err.print("fuzzyhash: " ++ fmt ++ "\n", args) catch {};
}

/// Text for an I/O error, worded like the C library's messages where one
/// applies.
pub fn describe(e: anyerror) []const u8 {
    return switch (e) {
        error.FileNotFound => "No such file or directory",
        error.AccessDenied, error.PermissionDenied => "Permission denied",
        error.IsDir => "Is a directory",
        error.NotDir => "Not a directory",
        error.SymLinkLoop => "Too many levels of symbolic links",
        error.NameTooLong => "File name too long",
        error.OutOfMemory => "Out of memory",
        error.InputOutput => "Input/output error",
        error.InputTooLarge => "input is too large",
        error.NotAPeFile => "not a PE file that pefile can read",
        error.NotAnElfFile => "not an ELF file that telfhash can read",
        error.CompressedCode => "the code section is compressed, which is not supported",
        error.Endless => "telfhash does not finish on this file (e_phoff and e_phentsize are 0)",
        error.NonAsciiSymbol => "a symbol name is not ASCII; telfhash gives no result",
        else => @errorName(e),
    };
}
