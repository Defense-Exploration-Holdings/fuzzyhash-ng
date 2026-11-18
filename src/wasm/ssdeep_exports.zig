// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! ssdeep exports, linked into the `ssdeep` and `fuzzy` modules. See
//! docs/abi.md.
//!
//! The hasher state lives on the host between calls. Every call copies it
//! out of the scratch region, checks it, works on the copy and writes it
//! back, so a state the host changed cannot make the module read or write out
//! of range.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const common = @import("common.zig");

const Ssdeep = fuzzyhash.Ssdeep;
const Status = fuzzyhash.abi.Status;

const flag_eliminate_sequences: u32 = 1;
const flag_no_truncate: u32 = 2;

comptime {
    if (@sizeOf(Ssdeep) > fuzzyhash.abi.state_capacity) @compileError("ssdeep state does not fit the state slot");
    if (Ssdeep.max_string_length > fuzzyhash.abi.output_capacity) @compileError("ssdeep digest does not fit the output slot");
}

fn status(s: Status) i32 {
    return s.code();
}

fn stateBytes(ptr: u32) ?*[@sizeOf(Ssdeep)]u8 {
    const bytes = common.scratchSlice(ptr, @sizeOf(Ssdeep)) orelse return null;
    return bytes[0..@sizeOf(Ssdeep)];
}

/// Copy a state out of `bytes`, or null when it is not one this module could
/// have written. Bools must be 0 or 1 before they are read as bools, and the
/// level counters must be in range.
fn loadState(bytes: *const [@sizeOf(Ssdeep)]u8) ?Ssdeep {
    inline for (.{ "eliminate_sequences", "no_truncate", "overflow" }) |name| {
        if (bytes[@offsetOf(Ssdeep, name)] > 1) return null;
    }
    var h: Ssdeep = undefined;
    @memcpy(std.mem.asBytes(&h), bytes);
    if (h.low > 30 or h.fresh > 32 or h.halved > 32) return null;
    for (h.len) |n| {
        if (n > 63) return null;
    }
    return h;
}

fn storeState(bytes: *[@sizeOf(Ssdeep)]u8, h: *const Ssdeep) void {
    @memcpy(bytes, std.mem.asBytes(h));
}

fn writeLength(ptr: u32, len: usize) bool {
    const out = common.scratchSlice(ptr, 4) orelse return false;
    std.mem.writeInt(u32, out[0..4], @intCast(len), .little);
    return true;
}

export fn ssdeep_state_size() u32 {
    return @sizeOf(Ssdeep);
}

/// Start a hasher. Flags: 1 eliminate_sequences, 2 no_truncate.
export fn ssdeep_init(state: u32, flags: u32) i32 {
    if (flags & ~(flag_eliminate_sequences | flag_no_truncate) != 0) return status(.invalid_argument);
    const bytes = stateBytes(state) orelse return status(.invalid_argument);
    const h = Ssdeep.init(.{
        .eliminate_sequences = flags & flag_eliminate_sequences != 0,
        .no_truncate = flags & flag_no_truncate != 0,
    });
    storeState(bytes, &h);
    return status(.ok);
}

export fn ssdeep_update(state: u32, data: u32, len: u32) i32 {
    const bytes = stateBytes(state) orelse return status(.invalid_argument);
    const input = common.scratchSlice(data, len) orelse return status(.invalid_argument);
    var h = loadState(bytes) orelse return status(.invalid_state);
    h.update(input);
    storeState(bytes, &h);
    return status(.ok);
}

/// Finish the digest into `out` (at least `max_string_length` bytes) and its
/// length into the little-endian u32 at `out_len_ptr`. The state is zeroed.
export fn ssdeep_final(state: u32, out: u32, out_len_ptr: u32) i32 {
    const bytes = stateBytes(state) orelse return status(.invalid_argument);
    const out_bytes = common.scratchSlice(out, Ssdeep.max_string_length) orelse return status(.invalid_argument);
    if (common.scratchSlice(out_len_ptr, 4) == null) return status(.invalid_argument);
    var h = loadState(bytes) orelse return status(.invalid_state);
    const result = h.final();
    storeState(bytes, &h);
    const digest = result catch return status(.input_too_large);
    var text: [Ssdeep.max_string_length]u8 = undefined;
    const str = digest.toString(&text);
    @memcpy(out_bytes[0..str.len], str);
    _ = writeLength(out_len_ptr, str.len);
    return status(.ok);
}

/// Score two digest strings: 0 to 100, or minus a Status code.
export fn ssdeep_compare(a: u32, a_len: u32, b: u32, b_len: u32) i32 {
    const sa = common.scratchSlice(a, a_len) orelse return -status(.invalid_argument);
    const sb = common.scratchSlice(b, b_len) orelse return -status(.invalid_argument);
    const score = Ssdeep.compareStrings(sa, sb) catch return -status(.invalid_digest);
    return score;
}

/// Parse a digest string (mode 0 lenient, 1 strict) and write it back in
/// canonical form, `blocksize:part1:part2`, as `ssdeep_final` does.
export fn ssdeep_parse(text: u32, len: u32, mode: u32, out: u32, out_len_ptr: u32) i32 {
    const parse_mode: Ssdeep.ParseMode = switch (mode) {
        0 => .lenient,
        1 => .strict,
        else => return status(.invalid_argument),
    };
    const input = common.scratchSlice(text, len) orelse return status(.invalid_argument);
    const out_bytes = common.scratchSlice(out, Ssdeep.max_string_length) orelse return status(.invalid_argument);
    if (common.scratchSlice(out_len_ptr, 4) == null) return status(.invalid_argument);
    const digest = Ssdeep.Digest.parse(input, parse_mode) catch return status(.invalid_digest);
    var buf: [Ssdeep.max_string_length]u8 = undefined;
    const str = digest.toString(&buf);
    @memcpy(out_bytes[0..str.len], str);
    _ = writeLength(out_len_ptr, str.len);
    return status(.ok);
}
