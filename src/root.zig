// SPDX-License-Identifier: MIT
//! fuzzyhash: ssdeep and TLSH similarity digests for Zig.
//!
//! This is the module root. It is target-agnostic: no WebAssembly or OS code,
//! no allocation. The WebAssembly exports live in `src/wasm/`, the command-line
//! tool in `src/cli/`.

const std = @import("std");
const build_options = @import("build_options");

/// Package version, taken from build.zig.zon at build time.
pub const version: std.SemanticVersion = std.SemanticVersion.parse(build_options.version) catch
    @compileError("build.zig.zon has an invalid version");

/// Version string, as in build.zig.zon.
pub const version_string: []const u8 = build_options.version;

pub const abi = @import("abi.zig");

/// ssdeep 2.14.1 compatible context-triggered piecewise hashing.
/// `Ssdeep` is the hasher; it also carries `Digest`, `Options`, `hash`,
/// `compare` and `compareStrings`.
pub const Ssdeep = @import("ssdeep.zig").Hasher;

test {
    std.testing.refAllDecls(@This());
    _ = @import("ssdeep.zig");
}

test "Ssdeep hashes, prints, parses and compares through the module root" {
    var h = Ssdeep.init(.{});
    h.update("hel");
    h.update("lo");
    const d = try h.final();
    var buf: [Ssdeep.max_string_length]u8 = undefined;
    try std.testing.expectEqualStrings("3:iKn:p", d.toString(&buf));

    const same = try Ssdeep.hash("hello", .{});
    try std.testing.expectEqual(@as(u8, 100), Ssdeep.compare(d, same));

    const parsed = try Ssdeep.Digest.parse("3:iKn:p", .strict);
    try std.testing.expectEqual(@as(u64, 3), parsed.block_size);
    try std.testing.expectEqual(@as(u8, 100), try Ssdeep.compareStrings("3:iKn:p", d.toString(&buf)));
    try std.testing.expectError(error.InvalidFormat, Ssdeep.compareStrings("", "3:iKn:p"));
}
