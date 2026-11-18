// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! WebAssembly module behind the `fuzzyhash-ng/imagehash` entry point.

comptime {
    _ = @import("common.zig");
    _ = @import("heap.zig");
    _ = @import("imagehash_exports.zig");
}
