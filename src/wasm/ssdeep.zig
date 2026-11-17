// SPDX-License-Identifier: MIT
//! WebAssembly module behind the `fuzzyhash-ng/ssdeep` entry point.

comptime {
    _ = @import("common.zig");
    _ = @import("ssdeep_exports.zig");
}
