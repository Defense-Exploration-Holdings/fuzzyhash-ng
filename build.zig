// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Build graph for fuzzyhash-ng.
//!
//!   zig build              build the WebAssembly modules and the CLI into zig-out/
//!   zig build wasm         zig-out/wasm/<module>.wasm, one module per npm entry point
//!   zig build js           embed the modules for the npm package (packages/fuzzyhash-ng/wasm/)
//!   zig build cli          zig-out/bin/fuzzyhash
//!   zig build test         Zig unit tests on the native target
//!   zig build test-js      build and embed the modules, then run the Node test suite
//!   zig build check        every test suite (Zig and JS)
//!
//! Options:
//!   --release=<mode>       small | fast | safe   (omit for debug)
//!   -Doptimize=<mode>      debug | safe | fast | small

const std = @import("std");
const zon = @import("build.zig.zon");

/// Modules built for wasm32. Each root is src/wasm/<name>.zig and is embedded as
/// packages/fuzzyhash-ng/wasm/<name>.mjs, so an npm entry point only loads its own code.
/// `heap` modules link `fuzzy_alloc` / `fuzzy_free` and their memory can grow; the
/// others have a fixed memory.
const WasmModule = struct { name: []const u8, heap: bool };
const wasm_modules = [_]WasmModule{
    .{ .name = "ssdeep", .heap = false },
    .{ .name = "tlsh", .heap = false },
    .{ .name = "nilsimsa", .heap = false },
    .{ .name = "imphash", .heap = true },
    .{ .name = "telfhash", .heap = true },
    .{ .name = "imagehash", .heap = true },
    .{ .name = "minhash", .heap = true },
    .{ .name = "simhash", .heap = true },
    .{ .name = "lzjd", .heap = true },
    .{ .name = "fuzzy", .heap = true },
};

/// Fixed linear memory: 2 pages = 128 KiB (64 KiB scratch, 16 KiB stack, data).
/// initial == max, so memory never grows and JS may keep one view of it.
const wasm_memory_bytes = 2 * 64 * 1024;
const wasm_stack_bytes = 16 * 1024;
/// Heap modules: up to 2 GiB, so that every address is below 2^31, and a 1 MiB
/// stack (pHash and the x86 decoder need more than 16 KiB in debug builds).
const wasm_heap_max_bytes = 2 * 1024 * 1024 * 1024;
const wasm_heap_stack_bytes = 1024 * 1024;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    options.addOption([]const u8, "version", zon.version);
    const options_mod = options.createModule();

    // ---- the Zig package ----------------------------------------------------
    // For projects that depend on this package:
    //   const dep = b.dependency("fuzzyhash", .{ .target = target, .optimize = optimize });
    //   exe.root_module.addImport("fuzzyhash", dep.module("fuzzyhash"));
    const lib_mod = b.addModule("fuzzyhash", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "build_options", .module = options_mod }},
    });

    // ---- WebAssembly --------------------------------------------------------
    // wasm32-freestanding: no libc, no OS, no imports. All I/O happens in JS.
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
        // Every feature here must work in Node LTS and evergreen browsers.
        .cpu_features_add = std.Target.wasm.featureSet(&.{ .bulk_memory, .sign_ext, .nontrapping_fptoint }),
    });
    const wasm_core = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .single_threaded = true,
        .imports = &.{.{ .name = "build_options", .module = options_mod }},
    });

    const wasm_step = b.step("wasm", "Build zig-out/wasm/<module>.wasm");
    const js_step = b.step("js", "Embed the wasm modules for the npm package");
    for (wasm_modules) |m| {
        const name = m.name;
        const mod = b.createModule(.{
            .root_source_file = b.path(b.fmt("src/wasm/{s}.zig", .{name})),
            .target = wasm_target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{.{ .name = "fuzzyhash", .module = wasm_core }},
        });
        const exe = b.addExecutable(.{ .name = name, .root_module = mod });
        exe.entry = .disabled;
        exe.rdynamic = true;
        if (m.heap) {
            exe.stack_size = wasm_heap_stack_bytes;
            exe.max_memory = wasm_heap_max_bytes;
        } else {
            exe.stack_size = wasm_stack_bytes;
            exe.initial_memory = wasm_memory_bytes;
            exe.max_memory = wasm_memory_bytes;
        }

        const install = b.addInstallArtifact(exe, .{ .dest_dir = .{ .override = .{ .custom = "wasm" } } });
        wasm_step.dependOn(&install.step);
        b.getInstallStep().dependOn(&install.step);

        const embed = b.addSystemCommand(&.{ "node", "scripts/embed-wasm.mjs" });
        embed.addFileArg(exe.getEmittedBin());
        embed.addArg(b.fmt("packages/fuzzyhash-ng/wasm/{s}.mjs", .{name}));
        embed.setCwd(b.path("."));
        js_step.dependOn(&embed.step);
    }

    // ---- command-line tool ------------------------------------------------
    const cli = b.addExecutable(.{
        .name = "fuzzyhash",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "fuzzyhash", .module = lib_mod }},
        }),
    });
    const install_cli = b.addInstallArtifact(cli, .{});
    b.step("cli", "Build zig-out/bin/fuzzyhash").dependOn(&install_cli.step);
    b.getInstallStep().dependOn(&install_cli.step);

    const run_cli = b.addRunArtifact(cli);
    run_cli.addPassthruArgs();
    b.step("run", "Run the CLI (zig build run -- <args>)").dependOn(&run_cli.step);

    // ---- tests ------------------------------------------------------------
    const test_step = b.step("test", "Run Zig unit tests (native target)");
    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);
    const cli_tests = b.addTest(.{ .root_module = cli.root_module });
    test_step.dependOn(&b.addRunArtifact(cli_tests).step);

    // The built CLI, run the way a user runs it.
    const cli_version = b.addRunArtifact(cli);
    cli_version.addArg("--version");
    cli_version.expectStdOutEqual(b.fmt("fuzzyhash {s}\n", .{zon.version}));
    cli_version.expectExitCode(0);
    test_step.dependOn(&cli_version.step);
    const cli_bad = b.addRunArtifact(cli);
    cli_bad.addArg("--no-such-option");
    cli_bad.expectStdErrMatch("unrecognized argument '--no-such-option'");
    cli_bad.expectExitCode(2);
    test_step.dependOn(&cli_bad.step);

    const node_tests = b.addSystemCommand(&.{ "node", "--test", "--test-reporter=spec", "test/js/*.test.js" });
    node_tests.setCwd(b.path("."));
    node_tests.step.dependOn(js_step);
    node_tests.has_side_effects = true;
    const test_js_step = b.step("test-js", "Build and embed the wasm modules, then run the Node tests");
    test_js_step.dependOn(&node_tests.step);

    const check_step = b.step("check", "Run every test suite (Zig and JS)");
    check_step.dependOn(test_step);
    check_step.dependOn(test_js_step);
}
