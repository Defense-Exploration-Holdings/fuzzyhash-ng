// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! WebAssembly module behind the `fuzzyhash-ng/lzjd` entry point.

comptime {
    _ = @import("common.zig");
    _ = @import("heap.zig");
    _ = @import("lzjd_exports.zig");
}
