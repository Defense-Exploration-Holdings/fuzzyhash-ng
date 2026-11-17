// SPDX-License-Identifier: MIT
//! WebAssembly module behind the `fuzzyhash-ng` main entry point: ssdeep and
//! TLSH together.

comptime {
    _ = @import("common.zig");
    _ = @import("ssdeep_exports.zig");
}
