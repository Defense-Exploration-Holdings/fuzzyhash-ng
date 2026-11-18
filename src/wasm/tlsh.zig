// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! WebAssembly module behind the `fuzzyhash-ng/tlsh` entry point.

comptime {
    _ = @import("common.zig");
    _ = @import("tlsh_exports.zig");
}
