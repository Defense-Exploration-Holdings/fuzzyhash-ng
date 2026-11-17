// SPDX-License-Identifier: MIT
const std = @import("std");
const fuzzyhash = @import("fuzzyhash");

pub fn main() void {
    std.debug.print("fuzzyhash {s}\n", .{fuzzyhash.version_string});
}

