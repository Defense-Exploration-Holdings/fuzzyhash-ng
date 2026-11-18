// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
const std = @import("std");
const fuzzyhash = @import("fuzzyhash");

pub fn main() void {
    std.debug.print("fuzzyhash {s}\n", .{fuzzyhash.version_string});
}

