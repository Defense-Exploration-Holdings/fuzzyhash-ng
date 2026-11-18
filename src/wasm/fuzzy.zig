// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! WebAssembly module behind the `fuzzyhash-ng` main entry point: every
//! family.

comptime {
    _ = @import("common.zig");
    _ = @import("heap.zig");
    _ = @import("ssdeep_exports.zig");
    _ = @import("tlsh_exports.zig");
    _ = @import("imphash_exports.zig");
    _ = @import("telfhash_exports.zig");
    _ = @import("imagehash_exports.zig");
    _ = @import("minhash_exports.zig");
    _ = @import("simhash_exports.zig");
    _ = @import("lzjd_exports.zig");
    _ = @import("nilsimsa_exports.zig");
}
