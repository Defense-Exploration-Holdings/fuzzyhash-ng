// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Reading inputs: streamed in fixed chunks, or whole for the formats that
//! need random access (PE and ELF files, LZJD).

const std = @import("std");
const Ctx = @import("Ctx.zig");

pub const chunk_size = 64 * 1024;

/// Feeds the whole of `file` to `hasher.update` and returns the number of
/// bytes read. Memory use does not depend on the file size.
pub fn stream(ctx: *Ctx, file: std.Io.File, hasher: anytype) !u64 {
    var buf: [chunk_size]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const n = file.readStreaming(ctx.io, &.{&buf}) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        hasher.update(buf[0..n]);
        total += n;
    }
    return total;
}

/// The whole of `file`. The caller frees it with `ctx.gpa`.
pub fn readAll(ctx: *Ctx, file: std.Io.File) ![]u8 {
    var buf: [chunk_size]u8 = undefined;
    var r = file.readerStreaming(ctx.io, &buf);
    return r.interface.allocRemaining(ctx.gpa, .unlimited) catch |e| switch (e) {
        error.ReadFailed => return r.err orelse error.InputOutput,
        else => return e,
    };
}
