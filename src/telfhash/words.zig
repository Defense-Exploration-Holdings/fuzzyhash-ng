// SPDX-License-Identifier: BSD-3-Clause
// Reproduces the output of capstone 5.0.9 (Copyright (c) 2013, COSEINC,
// BSD-3-Clause; see LICENSES/capstone-LICENSE) for the ARM and MIPS
// instructions telfhash looks at.

//! ARM (ARM mode, little-endian) and MIPS32 (big-endian) for telfhash's
//! call extraction. Both use 4-byte instruction words, so whether capstone
//! decodes a word depends on the word alone. `arm_words.zig` and
//! `mips_words.zig` record that for all 2^32 words as a decision diagram:
//! level 0 holds 64-bit leaves (bit `w & 63` of a leaf is the answer), and
//! node `i` of level k is a pair (child for bit 5 + k clear, child for it
//! set) of nodes of level k - 1. The root is node 0 of level 26.

const std = @import("std");
const arm_words = @import("arm_words.zig");
const mips_words = @import("mips_words.zig");

fn lookup(comptime leaves: []const u64, comptime levels: [26][]const [2]u16, w: u32) bool {
    var node: u16 = 0;
    var k: usize = 26;
    while (k > 0) : (k -= 1) {
        const pair = levels[k - 1][node];
        node = pair[(w >> @intCast(5 + k)) & 1];
    }
    return (leaves[node] >> @intCast(w & 63)) & 1 != 0;
}

/// True when capstone decodes `w` in ARM mode.
pub fn armValid(w: u32) bool {
    return lookup(&arm_words.arm_leaves, arm_words.arm_levels, w);
}

/// True when capstone decodes `w` in MIPS32 big-endian mode.
pub fn mipsValid(w: u32) bool {
    return lookup(&mips_words.mips_leaves, mips_words.mips_levels, w);
}

/// For a word capstone decodes: the target of a branch whose mnemonic
/// starts with "bl" and whose operand is printed as "#0x<hex>" (b with the
/// lo, ls, lt or le condition, bl, blx with an immediate). `address` is the
/// word's address.
pub fn armCallTarget(w: u32, address: u64) ?u32 {
    if ((w >> 25) & 7 != 5) return null;
    const cond = w >> 28;
    if (cond != 15) {
        const link = (w >> 24) & 1 != 0;
        const bl_cond = cond == 3 or cond == 9 or cond == 11 or cond == 13;
        if (!link and !bl_cond) return null;
    }
    var off: u32 = (w & 0xffffff) << 2;
    if (off & 0x2000000 != 0) off |= 0xfc000000;
    if (cond == 15) off |= ((w >> 24) & 1) << 1;
    const target = off +% @as(u32, @truncate(address)) +% 8;
    if (target <= 9) return null;
    return target;
}

const mips_regs = [32][]const u8{
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0",   "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0",   "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8",   "t9", "k0", "k1", "gp", "sp", "fp", "ra",
};

/// The longest string `mipsT9Load` writes.
pub const mips_max_len = 16;

/// For `lw $t9, <offset>(<base>)`: the slice `op_str[8:-5]` that telfhash
/// takes from capstone's operand string, written to `buf`. null for other
/// words.
pub fn mipsT9Load(w: u32, buf: *[mips_max_len]u8) ?[]const u8 {
    if (w >> 26 != 0x23 or (w >> 16) & 0x1f != 25) return null;
    var tmp: [32]u8 = undefined;
    const imm: i16 = @bitCast(@as(u16, @truncate(w)));
    const base = mips_regs[(w >> 21) & 0x1f];
    const neg = imm < 0;
    const mag: u32 = @abs(@as(i32, imm));
    const num = if (imm == 0)
        ""
    else if (mag <= 9)
        std.fmt.bufPrint(&tmp, "{s}{d}", .{ if (neg) "-" else "", mag }) catch unreachable
    else
        std.fmt.bufPrint(&tmp, "{s}0x{x}", .{ if (neg) "-" else "", mag }) catch unreachable;
    // op_str is "$t9, " ++ num ++ "(" ++ "$" ++ base ++ ")".
    var op: [32]u8 = undefined;
    const s = std.fmt.bufPrint(&op, "$t9, {s}($" ++ "{s})", .{ num, base }) catch unreachable;
    if (s.len <= 13) return buf[0..0];
    const part = s[8 .. s.len - 5];
    @memcpy(buf[0..part.len], part);
    return buf[0..part.len];
}

test "arm calls" {
    try std.testing.expectEqual(@as(?u32, null), armCallTarget(0xeb000000, 0));
    try std.testing.expectEqual(@as(?u32, 0xa), armCallTarget(0xfb000000, 0));
    try std.testing.expectEqual(@as(?u32, 0x48), armCallTarget(0x0b000010, 0));
    try std.testing.expectEqual(@as(?u32, null), armCallTarget(0xeafffffd, 0));
    try std.testing.expectEqual(@as(?u32, 0x1008), armCallTarget(0x3a000000, 0x1000));
    try std.testing.expect(armValid(0xeb000000) and armValid(0xe12fff33));
}

test "mips t9 loads" {
    var buf: [mips_max_len]u8 = undefined;
    try std.testing.expectEqualStrings("ff0", mipsT9Load(0x8f997ff0, &buf).?);
    try std.testing.expectEqualStrings("7ff0", mipsT9Load(0x8f998010, &buf).?);
    try std.testing.expectEqualStrings("", mipsT9Load(0x8f990008, &buf).?);
    try std.testing.expectEqualStrings("a", mipsT9Load(0x8fb9fff6, &buf).?);
    try std.testing.expectEqualStrings("0($", mipsT9Load(0x8c190010, &buf).?);
    try std.testing.expectEqual(@as(?[]const u8, null), mipsT9Load(0x8f880000, &buf));
}
