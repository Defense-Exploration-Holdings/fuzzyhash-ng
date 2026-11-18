// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! imphash exports, linked into the `imphash` and `fuzzy` modules. See
//! docs/abi.md. The file is passed in a block from `fuzzy_alloc`.

const std = @import("std");
const fuzzyhash = @import("fuzzyhash");
const common = @import("common.zig");
const heap = @import("heap.zig");

const Imphash = fuzzyhash.Imphash;
const status = heap.status;

/// Hash the PE file at `data`. Writes 32 lowercase hex characters to `out`
/// and their count to the little-endian u32 at `out_len_ptr`, or a count of
/// 0 where pefile gives an empty string (no imports). `invalid_input` where
/// pefile refuses the file.
export fn imphash_hash(data: u32, len: u32, out: u32, out_len_ptr: u32) i32 {
    const input = heap.slice(data, len) orelse return status(.invalid_argument);
    const out_bytes = common.scratchSlice(out, Imphash.hex_length) orelse return status(.invalid_argument);
    const out_len = common.scratchSlice(out_len_ptr, 4) orelse return status(.invalid_argument);
    const ws = heap.allocator.create(Imphash.Workspace) catch return status(.out_of_memory);
    defer heap.allocator.destroy(ws);
    const result = Imphash.hash(ws, input) catch return status(.invalid_input);
    var n: u32 = 0;
    if (result) |digest| {
        _ = Imphash.toHex(digest, out_bytes[0..Imphash.hex_length]);
        n = Imphash.hex_length;
    }
    std.mem.writeInt(u32, out_len[0..4], n, .little);
    return status(.ok);
}
