// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! WebAssembly module behind the `fuzzyhash-ng/telfhash` entry point.

comptime {
    _ = @import("common.zig");
    _ = @import("heap.zig");
    _ = @import("telfhash_exports.zig");
}
