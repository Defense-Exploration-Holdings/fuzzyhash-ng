// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! A project that uses fuzzyhash as a Zig package. Here the dependency is the
//! repository itself (`.path = "../.."` in build.zig.zon); a real project adds
//! it with `zig fetch --save`, see the README.
//!
//!   zig build run     print the library version

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const fuzzyhash = b.dependency("fuzzyhash", .{ .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "fuzzyhash", .module = fuzzyhash.module("fuzzyhash") }},
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    b.step("run", "Print the library version").dependOn(&run.step);
}
