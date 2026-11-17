// SPDX-License-Identifier: MIT
//! fuzzyhash: ssdeep, TLSH, imphash, telfhash, image hashes, MinHash, SimHash, LZJD and Nilsimsa for Zig.
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

/// TLSH 5.0.2 compatible locality sensitive hash. `Tlsh.T1` is the standard
/// digest; `Tlsh.Tlsh(variant)` builds the other reference variants.
pub const Tlsh = @import("tlsh.zig");

/// Import hash of PE files, compatible with pefile's `get_imphash`.
pub const Imphash = @import("imphash.zig");

/// Symbol hash of ELF files, compatible with telfhash 0.9.8 (with capstone
/// 5.0.9 for files without a symbol table).
pub const Telfhash = @import("telfhash.zig");

/// aHash, dHash and pHash of decoded images, compatible with ImageHash
/// 4.3.2. `ImageHash.Hash` is the 64-bit size; `ImageHash.ImageHash(n)`
/// builds other sizes.
pub const ImageHash = @import("imagehash.zig");

/// MinHash sketches compatible with datasketch 2.0.0.
pub const MinHash = @import("minhash.zig");

/// SimHash fingerprints compatible with the `simhash` 2.1.2 package.
pub const Simhash = @import("simhash.zig");

/// LZJD digests and similarity compatible with pyLZJD (commit e2c24bd).
pub const Lzjd = @import("lzjd.zig");

/// Nilsimsa digests compatible with the `nilsimsa` 0.3.8 package.
pub const Nilsimsa = @import("nilsimsa.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("ssdeep.zig");
    _ = @import("imphash.zig");
    _ = @import("tlsh.zig");
    _ = @import("telfhash.zig");
    _ = @import("imagehash.zig");
    _ = @import("minhash.zig");
    _ = @import("simhash.zig");
    _ = @import("nilsimsa.zig");
    _ = @import("lzjd.zig");
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
