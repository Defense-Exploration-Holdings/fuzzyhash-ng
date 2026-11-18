// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! WebAssembly module behind the `fuzzyhash-ng/minhash` entry point.

comptime {
    _ = @import("common.zig");
    _ = @import("heap.zig");
    _ = @import("minhash_exports.zig");
}
