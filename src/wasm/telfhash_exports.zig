// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! telfhash exports, linked into the `telfhash` and `fuzzy` modules. See
//! docs/abi.md. The file is passed in a block from `fuzzy_alloc`.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const common = @import("common.zig");
const heap = @import("heap.zig");

const Telfhash = fuzzyhash.Telfhash;
const status = heap.status;

/// Hash the ELF file at `data`. Writes telfhash's text form (the lowercase
/// digest, "tnull" or "-") to `out` and its length to the little-endian
/// u32 at `out_len_ptr`. `invalid_input` where pyelftools cannot read the
/// file, `unsupported_input` where telfhash gives no result.
export fn telfhash_hash(data: u32, len: u32, out: u32, out_len_ptr: u32) i32 {
    const input = heap.slice(data, len) orelse return status(.invalid_argument);
    const out_bytes = common.scratchSlice(out, Telfhash.max_string_length) orelse return status(.invalid_argument);
    const out_len = common.scratchSlice(out_len_ptr, 4) orelse return status(.invalid_argument);
    const scratch = heap.allocator.alloc(u32, Telfhash.scratchLength(input.len)) catch return status(.out_of_memory);
    defer heap.allocator.free(scratch);
    const result = Telfhash.hash(input, scratch) catch |err| return switch (err) {
        error.InvalidElf => status(.invalid_input),
        error.WorkspaceTooSmall => status(.out_of_memory),
        error.CompressedCode, error.Endless, error.NonAsciiSymbol => status(.unsupported_input),
    };
    const str = Telfhash.toString(result, out_bytes[0..Telfhash.max_string_length]);
    std.mem.writeInt(u32, out_len[0..4], @intCast(str.len), .little);
    return status(.ok);
}

/// Distance between two telfhash strings, or minus a Status code.
export fn telfhash_diff(a: u32, a_len: u32, b: u32, b_len: u32) i32 {
    const sa = common.scratchSlice(a, a_len) orelse return -status(.invalid_argument);
    const sb = common.scratchSlice(b, b_len) orelse return -status(.invalid_argument);
    const d = Telfhash.diffStrings(sa, sb) catch return -status(.invalid_digest);
    return @intCast(d);
}
