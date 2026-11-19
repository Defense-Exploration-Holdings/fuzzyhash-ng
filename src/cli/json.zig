// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! JSON string output for `--json`.

const std = @import("std");

/// Writes `bytes` as a JSON string. File names need not be UTF-8: each byte
/// that is not part of a valid UTF-8 sequence is written as U+FFFD.
pub fn string(w: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    var i: usize = 0;
    while (i < bytes.len) {
        const c = bytes[i];
        if (c < 0x80) {
            switch (c) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                '\n' => try w.writeAll("\\n"),
                '\r' => try w.writeAll("\\r"),
                '\t' => try w.writeAll("\\t"),
                0...8, 11, 12, 14...0x1f, 0x7f => try w.print("\\u{x:0>4}", .{c}),
                else => try w.writeByte(c),
            }
            i += 1;
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(c) catch 0;
        if (len == 0 or i + len > bytes.len or !std.unicode.utf8ValidateSlice(bytes[i .. i + len])) {
            try w.writeAll("\\ufffd");
            i += 1;
            continue;
        }
        try w.writeAll(bytes[i .. i + len]);
        i += len;
    }
    try w.writeByte('"');
}

const testing = std.testing;

fn expectString(want: []const u8, in: []const u8) !void {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try string(&out.writer, in);
    try testing.expectEqualStrings(want, out.written());
}

test "escapes and invalid UTF-8" {
    try expectString("\"a\\\"b\\\\c\"", "a\"b\\c");
    try expectString("\"\\n\\t\\u0001\"", "\n\t\x01");
    try expectString("\"\xc3\xbc\"", "\xc3\xbc");
    try expectString("\"\\ufffd\\ufffd\"", "\xff\xfe");
    try expectString("\"\\ufffdx\"", "\xc3x");
}
