// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! WebAssembly module behind the `fuzzyhash-ng/ssdeep` entry point.

comptime {
    _ = @import("common.zig");
    _ = @import("ssdeep_exports.zig");
}
