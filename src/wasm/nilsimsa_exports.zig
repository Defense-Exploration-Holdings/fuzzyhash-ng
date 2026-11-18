// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Nilsimsa exports, linked into the `nilsimsa` and `fuzzy` modules. See
//! docs/abi.md. The hasher state lives on the host between calls. Every
//! index Nilsimsa computes from its state is a byte into a 256-entry table,
//! so any state bytes are safe to use.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const common = @import("common.zig");

const Nilsimsa = fuzzyhash.Nilsimsa;
const Hasher = Nilsimsa.Hasher;
const Status = fuzzyhash.abi.Status;

comptime {
    if (@sizeOf(Hasher) > fuzzyhash.abi.state_capacity) @compileError("Nilsimsa state does not fit the state slot");
}

fn status(s: Status) i32 {
    return s.code();
}

fn stateBytes(ptr: u32) ?*[@sizeOf(Hasher)]u8 {
    const bytes = common.scratchSlice(ptr, @sizeOf(Hasher)) orelse return null;
    return bytes[0..@sizeOf(Hasher)];
}

fn load(bytes: *const [@sizeOf(Hasher)]u8) Hasher {
    var h: Hasher = undefined;
    @memcpy(std.mem.asBytes(&h), bytes);
    return h;
}

export fn nilsimsa_state_size() u32 {
    return @sizeOf(Hasher);
}

export fn nilsimsa_init(state: u32) i32 {
    const bytes = stateBytes(state) orelse return status(.invalid_argument);
    const h = Hasher.init();
    @memcpy(bytes, std.mem.asBytes(&h));
    return status(.ok);
}

export fn nilsimsa_update(state: u32, data: u32, len: u32) i32 {
    const bytes = stateBytes(state) orelse return status(.invalid_argument);
    const input = common.scratchSlice(data, len) orelse return status(.invalid_argument);
    var h = load(bytes);
    h.update(input);
    @memcpy(bytes, std.mem.asBytes(&h));
    return status(.ok);
}

/// Write the 64 hex characters of the digest to `out`. The state is reset.
export fn nilsimsa_final(state: u32, out: u32) i32 {
    const bytes = stateBytes(state) orelse return status(.invalid_argument);
    const out_bytes = common.scratchSlice(out, Nilsimsa.hex_length) orelse return status(.invalid_argument);
    var h = load(bytes);
    const d = h.final();
    @memcpy(bytes, std.mem.asBytes(&h));
    _ = d.toHex(out_bytes[0..Nilsimsa.hex_length]);
    return status(.ok);
}

/// Score of two hex digests, -128 to 128, written as a little-endian i32 at
/// `out`.
export fn nilsimsa_compare(a: u32, a_len: u32, b: u32, b_len: u32, out: u32) i32 {
    const sa = common.scratchSlice(a, a_len) orelse return status(.invalid_argument);
    const sb = common.scratchSlice(b, b_len) orelse return status(.invalid_argument);
    const o = common.scratchSlice(out, 4) orelse return status(.invalid_argument);
    const score = Nilsimsa.compareStrings(sa, sb) catch return status(.invalid_digest);
    std.mem.writeInt(i32, o[0..4], score, .little);
    return status(.ok);
}
