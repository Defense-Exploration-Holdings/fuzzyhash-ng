// SPDX-License-Identifier: NCSA
// Ported from capstone 5.0.9 (arch/X86/X86DisassemblerDecoder.c and
// X86Disassembler.c), which derives from the LLVM X86 disassembler.
// Copyright (c) 2003-2013 University of Illinois at Urbana-Champaign;
// capstone changes by Nguyen Anh Quynh, 2013-2019. See
// LICENSES/capstone-LICENSE-LLVM. Changes: rewritten in Zig, reduced to
// what a linear sweep needs (instruction length, whether capstone accepts
// the instruction, and the target of a direct call).

//! The part of capstone's x86 decoder that telfhash depends on. `decode`
//! decodes one instruction in 32-bit or 64-bit mode and gives its length
//! and, for a direct `call` that capstone prints as `call 0x...`, the
//! target. It accepts and rejects exactly the byte sequences capstone 5.0.9
//! does, so a sweep that stops at the first rejected instruction stops
//! where capstone's `disasm` does.

const std = @import("std");
const c = @import("x86_consts.zig");

pub const Mode = enum { x86, x64 };

pub const Instruction = struct {
    len: u8,
    /// Set for a `call rel` that capstone prints as `call 0x<hex>`: the
    /// value of <hex>.
    call_target: ?u64,
};

// ---------------------------------------------------------------------------
// Tables

const blob = @embedFile("x86_tables.bin");

const Layout = struct {
    contexts: usize,
    index: [8]usize,
    dec_type: [8]usize,
    dec_ids: [8]usize,
    modrm_table: usize,
    specs: usize,
    operand_sets: usize,
    eq16_lookup: usize,
    eq16_table: usize,
    is64: usize,
    lock: usize,
    end: usize,
};

const layout: Layout = blk: {
    var l: Layout = undefined;
    var o: usize = 0;
    l.contexts = o;
    o += c.contexts_len;
    for (0..8) |m| {
        l.index[m] = o;
        o += c.ic_max;
    }
    for (0..8) |m| {
        l.dec_type[m] = o;
        o += c.decision_counts[m] * 256;
        l.dec_ids[m] = o;
        o += c.decision_counts[m] * 256 * 2;
    }
    l.modrm_table = o;
    o += c.modrm_table_len * 2;
    l.specs = o;
    o += c.instruction_count * 2;
    l.operand_sets = o;
    o += c.operand_sets_len * 12;
    l.eq16_lookup = o;
    o += c.eq16_lookup_len * 2;
    l.eq16_table = o;
    o += c.eq16_table_len * 4;
    l.is64 = o;
    o += c.id_bitset_len;
    l.lock = o;
    o += c.id_bitset_len;
    l.end = o;
    break :blk l;
};

comptime {
    if (layout.end != blob.len) @compileError("x86_tables.bin does not match x86_consts.zig");
}

fn rd16(off: usize) u16 {
    return std.mem.readInt(u16, blob[off..][0..2], .little);
}

fn idBit(base: usize, id: u16) bool {
    if (id >= c.instruction_count) return false;
    return blob[base + id / 8] & (@as(u8, 1) << @intCast(id % 8)) != 0;
}

const OperandSpec = struct { encoding: u8, type: u8 };

fn operand(set: u16, i: usize) OperandSpec {
    const o = layout.operand_sets + (@as(usize, set) * 6 + i) * 2;
    return .{ .encoding = blob[o], .type = blob[o + 1] };
}

fn specOperands(id: u16) u16 {
    return rd16(layout.specs + @as(usize, id) * 2);
}

// ---------------------------------------------------------------------------
// Decoder state

const OpcodeType = enum(u3) { one_byte = 0, two_byte, three_38, three_3a, xop8, xop9, xopa, three_dnow };
const VecType = enum { none, vex2, vex3, evex, xop };

const ATTR_64BIT = 0x1;
const ATTR_XS = 0x2;
const ATTR_XD = 0x4;
const ATTR_REXW = 0x8;
const ATTR_OPSIZE = 0x10;
const ATTR_ADSIZE = 0x20;
const ATTR_VEX = 0x40;
const ATTR_VEXL = 0x80;
const ATTR_EVEX = 0x100;
const ATTR_EVEXL = 0x200;
const ATTR_EVEXL2 = 0x400;
const ATTR_EVEXK = 0x800;
const ATTR_EVEXKZ = 0x1000;
const ATTR_EVEXB = 0x2000;

const EA_DISP_NONE = 0;
const EA_DISP_8 = 1;
const EA_DISP_16 = 2;
const EA_DISP_32 = 3;

const Fail = error{Fail};

const Insn = struct {
    code: []const u8,
    cursor: usize = 0,
    is64: bool,

    prefix0: u8 = 0,
    prefix1: u8 = 0,
    rex: u8 = 0,
    has_lock: bool = false,
    repeat: u8 = 0,
    mandatory: u8 = 0,
    has_opsize: bool = false,
    has_adsize: bool = false,
    vec: VecType = .none,
    vp: [4]u8 = @splat(0),

    register_size: u8 = 0,
    address_size: u8 = 0,
    displacement_size: u8 = 0,
    immediate_size: u8 = 0,

    opcode_type: OpcodeType = .one_byte,
    opcode: u8 = 0,
    first_byte: u8 = 0,

    consumed_modrm: bool = false,
    modrm: u8 = 0,
    consumed_sib: bool = false,
    sib: u8 = 0,
    sib_index_base: i32 = 0,
    sib_index: i32 = 0,
    sib_scale: u8 = 0,
    sib_base: i32 = 0,
    consumed_disp: bool = false,
    ea_disp: u8 = EA_DISP_NONE,

    reg_base: i32 = 0,
    ea_reg_base: i32 = 0,
    ea_base: i32 = 0,
    reg: i32 = 0,
    vvvv: i32 = 0,
    writemask: i32 = 0,

    id: u16 = 0,
    ops: u16 = 0,

    n_imm: u8 = 0,
    imm: [2]u64 = @splat(0),

    fn look(self: *const Insn) Fail!u8 {
        if (self.cursor >= self.code.len) return error.Fail;
        return self.code[self.cursor];
    }

    fn consume(self: *Insn) Fail!u8 {
        const b = try self.look();
        self.cursor += 1;
        return b;
    }

    fn unconsume(self: *Insn) void {
        self.cursor -= 1;
    }

    fn consumeLe(self: *Insn, comptime n: usize) Fail!u64 {
        if (self.code.len - self.cursor < n) return error.Fail;
        var v: u64 = 0;
        for (0..n) |k| v |= @as(u64, self.code[self.cursor + k]) << @intCast(8 * k);
        self.cursor += n;
        return v;
    }

    fn isRex(self: *const Insn, b: u8) bool {
        return self.is64 and b >= 0x40 and b <= 0x4f;
    }

    fn setPrefixPresent(self: *Insn, prefix: u8) void {
        switch (prefix) {
            0xf0 => {
                self.has_lock = true;
                self.repeat = 0;
            },
            0xf2, 0xf3 => {
                const next = self.look() catch return;
                if (self.isRex(next) or next == 0x0f or next == 0x66) self.mandatory = prefix;
                self.repeat = prefix;
                self.has_lock = false;
            },
            0x66 => {
                const next = self.look() catch return;
                if (self.mandatory == 0 and (next == 0x0f or self.isRex(next))) self.mandatory = prefix;
            },
            else => {},
        }
    }

    fn readPrefixes(self: *Insn) Fail!void {
        var byte: u8 = 0;
        while (true) {
            if (self.is64) {
                byte = try self.consume();
                if (byte & 0xf0 == 0x40) {
                    while (true) {
                        byte = try self.look();
                        if (byte & 0xf0 == 0x40) {
                            _ = try self.consume();
                        } else break;
                    }
                    switch (byte) {
                        0xf2, 0xf3, 0xf0, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67 => {},
                        else => self.unconsume(),
                    }
                } else self.unconsume();
            }
            byte = try self.consume();
            if (self.cursor - 1 == 0 and (byte == 0xf2 or byte == 0xf3)) {
                const next = try self.look();
                if (self.isRex(next)) {
                    _ = try self.consume();
                    _ = try self.look();
                    self.unconsume();
                }
            }
            switch (byte) {
                0xf0, 0xf2, 0xf3 => {
                    self.setPrefixPresent(byte);
                    self.prefix0 = byte;
                },
                0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65 => {
                    self.prefix1 = byte;
                    self.setPrefixPresent(byte);
                },
                0x66 => {
                    self.has_opsize = true;
                    self.setPrefixPresent(byte);
                },
                0x67 => {
                    self.has_adsize = true;
                    self.setPrefixPresent(byte);
                },
                else => break,
            }
        }

        if (byte == 0x62) {
            const b1 = try self.consume();
            if (self.look()) |b2| {
                if ((self.is64 or b1 & 0xc0 == 0xc0) and (~b1 & 0xc) == 0xc and b2 & 0x4 == 0x4) {
                    self.vec = .evex;
                } else {
                    self.unconsume();
                    self.unconsume();
                }
            } else |_| {
                self.unconsume();
                self.unconsume();
            }
            if (self.vec == .evex) {
                self.vp[0] = byte;
                self.vp[1] = b1;
                self.vp[2] = try self.consume();
                self.vp[3] = try self.consume();
                if (self.is64) {
                    self.rex = 0x40 | ((self.vp[2] >> 7) << 3) | (((~self.vp[1] >> 7) & 1) << 2) |
                        (((~self.vp[1] >> 6) & 1) << 1) | ((~self.vp[1] >> 5) & 1);
                }
            }
        } else if (byte == 0xc4) {
            const b1 = try self.look();
            if (self.is64 or b1 & 0xc0 == 0xc0) self.vec = .vex3 else self.unconsume();
            if (self.vec == .vex3) {
                self.vp[0] = byte;
                // capstone does not check these two reads; a short buffer
                // fails at the opcode instead.
                self.vp[1] = self.consume() catch 0;
                self.vp[2] = self.consume() catch 0;
                if (self.is64) {
                    self.rex = 0x40 | ((self.vp[2] >> 7) << 3) | (((~self.vp[1] >> 7) & 1) << 2) |
                        (((~self.vp[1] >> 6) & 1) << 1) | ((~self.vp[1] >> 5) & 1);
                }
            }
        } else if (byte == 0xc5) {
            const b1 = try self.look();
            if (self.is64 or b1 & 0xc0 == 0xc0) self.vec = .vex2 else self.unconsume();
            if (self.vec == .vex2) {
                self.vp[0] = byte;
                self.vp[1] = self.consume() catch 0;
                if (self.is64) self.rex = 0x40 | (((~self.vp[1] >> 7) & 1) << 2);
                if (self.vp[1] & 3 == 1) self.has_opsize = true;
            }
        } else if (byte == 0x8f) {
            const b1 = try self.look();
            if (b1 & 0x38 != 0) self.vec = .xop else self.unconsume();
            if (self.vec == .xop) {
                self.vp[0] = byte;
                self.vp[1] = self.consume() catch 0;
                self.vp[2] = self.consume() catch 0;
                if (self.is64) {
                    self.rex = 0x40 | ((self.vp[2] >> 7) << 3) | (((~self.vp[1] >> 7) & 1) << 2) |
                        (((~self.vp[1] >> 6) & 1) << 1) | ((~self.vp[1] >> 5) & 1);
                }
                if (self.vp[2] & 3 == 1) self.has_opsize = true;
            }
        } else if (self.isRex(byte)) {
            _ = try self.look();
            self.rex = byte;
        } else self.unconsume();

        if (!self.is64) {
            self.register_size = if (self.has_opsize) 2 else 4;
            self.address_size = if (self.has_adsize) 2 else 4;
            self.displacement_size = if (self.has_adsize) 2 else 4;
            self.immediate_size = if (self.has_opsize) 2 else 4;
        } else if (self.rex != 0 and self.rex & 0x8 != 0) {
            self.register_size = 8;
            self.address_size = if (self.has_adsize) 4 else 8;
            self.displacement_size = 4;
            self.immediate_size = 4;
        } else {
            self.register_size = if (self.has_opsize) 2 else 4;
            self.address_size = if (self.has_adsize) 4 else 8;
            self.displacement_size = if (self.has_opsize) 2 else 4;
            self.immediate_size = if (self.has_opsize) 2 else 4;
        }
    }

    fn readOpcode(self: *Insn) Fail!void {
        self.opcode_type = .one_byte;
        switch (self.vec) {
            .evex => {
                self.opcode_type = switch (self.vp[1] & 0x3) {
                    1 => .two_byte,
                    2 => .three_38,
                    3 => .three_3a,
                    else => return error.Fail,
                };
                self.opcode = try self.consume();
                return;
            },
            .vex3 => {
                self.opcode_type = switch (self.vp[1] & 0x1f) {
                    1 => .two_byte,
                    2 => .three_38,
                    3 => .three_3a,
                    else => return error.Fail,
                };
                self.opcode = try self.consume();
                return;
            },
            .vex2 => {
                self.opcode_type = .two_byte;
                self.opcode = try self.consume();
                return;
            },
            .xop => {
                self.opcode_type = switch (self.vp[1] & 0x1f) {
                    8 => .xop8,
                    9 => .xop9,
                    0xa => .xopa,
                    else => return error.Fail,
                };
                self.opcode = try self.consume();
                return;
            },
            .none => {},
        }
        var current = try self.consume();
        self.first_byte = current;
        if (current == 0x0f) {
            current = try self.consume();
            if (current == 0x38) {
                current = try self.consume();
                self.opcode_type = .three_38;
            } else if (current == 0x3a) {
                current = try self.consume();
                self.opcode_type = .three_3a;
            } else if (current == 0x0f) {
                try self.readModRM();
                current = try self.consume();
                self.opcode_type = .three_dnow;
            } else {
                self.opcode_type = .two_byte;
            }
        } else if (self.mandatory != 0) {
            self.mandatory = 0;
        }
        self.opcode = current;
    }

    fn decisionIndex(self: *const Insn, ctx: u8) ?usize {
        const m = @intFromEnum(self.opcode_type);
        const index = blob[layout.index[m] + ctx];
        if (index == 0) return null;
        return (@as(usize, index) - 1) * 256 + self.opcode;
    }

    fn modRMRequired(self: *const Insn, ctx: u8) bool {
        if (self.opcode_type == .three_dnow) return true;
        const d = self.decisionIndex(ctx) orelse return false;
        return blob[layout.dec_type[@intFromEnum(self.opcode_type)] + d] != c.MODRM_ONEENTRY;
    }

    fn decodeId(self: *const Insn, ctx: u8, modrm: u8) u16 {
        const m = @intFromEnum(self.opcode_type);
        var t: u8 = c.MODRM_ONEENTRY;
        var ids: usize = 0;
        if (self.decisionIndex(ctx)) |d| {
            t = blob[layout.dec_type[m] + d];
            ids = rd16(layout.dec_ids[m] + d * 2);
        }
        const mod3 = modrm >> 6 == 3;
        const i: usize = switch (t) {
            c.MODRM_ONEENTRY => ids,
            c.MODRM_SPLITRM => if (mod3) ids + 1 else ids,
            c.MODRM_SPLITREG => if (mod3) ids + ((modrm & 0x38) >> 3) + 8 else ids + ((modrm & 0x38) >> 3),
            c.MODRM_SPLITMISC => if (mod3) ids + (modrm & 0x3f) + 8 else ids + ((modrm & 0x38) >> 3),
            c.MODRM_FULL => ids + modrm,
            else => return 0,
        };
        if (i >= c.modrm_table_len) return 0;
        return rd16(layout.modrm_table + i * 2);
    }

    fn idWithAttr(self: *Insn, attr: u16) Fail!u16 {
        const ctx = blob[layout.contexts + (attr & 0x3fff)];
        if (self.modRMRequired(ctx)) {
            try self.readModRM();
            return self.decodeId(ctx, self.modrm);
        }
        return self.decodeId(ctx, 0);
    }

    fn setId(self: *Insn, id: u16) void {
        self.id = id;
        self.ops = if (id < c.instruction_count) specOperands(id) else 0;
    }

    fn getID(self: *Insn) Fail!void {
        var attr: u16 = 0;
        if (self.is64) attr |= ATTR_64BIT;
        if (self.vec != .none) {
            attr |= if (self.vec == .evex) ATTR_EVEX else ATTR_VEX;
            const pp: u8 = switch (self.vec) {
                .evex, .vex3, .xop => self.vp[2] & 3,
                else => self.vp[1] & 3,
            };
            switch (pp) {
                1 => attr |= ATTR_OPSIZE,
                2 => attr |= ATTR_XS,
                3 => attr |= ATTR_XD,
                else => {},
            }
            switch (self.vec) {
                .evex => {
                    const p3 = self.vp[3];
                    if (p3 & 0x80 != 0) attr |= ATTR_EVEXKZ;
                    if (p3 & 0x10 != 0) attr |= ATTR_EVEXB;
                    if (p3 & 0x7 != 0) attr |= ATTR_EVEXK;
                    if (p3 & 0x20 != 0) attr |= ATTR_EVEXL;
                    if (p3 & 0x40 != 0) attr |= ATTR_EVEXL2;
                },
                .vex3, .xop => if (self.vp[2] & 0x4 != 0) {
                    attr |= ATTR_VEXL;
                },
                .vex2 => if (self.vp[1] & 0x4 != 0) {
                    attr |= ATTR_VEXL;
                },
                .none => unreachable,
            }
        } else if (self.mandatory == 0) {
            if (self.has_opsize) attr |= ATTR_OPSIZE;
            if (self.has_adsize) attr |= ATTR_ADSIZE;
            if (self.opcode_type == .one_byte) {
                if (self.repeat == 0xf3 and self.opcode == 0x90) attr |= ATTR_XS;
            } else {
                if (self.repeat == 0xf2) {
                    attr |= ATTR_XD;
                } else if (self.repeat == 0xf3) attr |= ATTR_XS;
            }
        } else {
            switch (self.mandatory) {
                0xf2 => attr |= ATTR_XD,
                0xf3 => attr |= ATTR_XS,
                0x66 => attr |= ATTR_OPSIZE,
                0x67 => attr |= ATTR_ADSIZE,
                else => {},
            }
        }
        if (self.rex & 0x08 != 0) {
            attr |= ATTR_REXW;
            attr &= ~@as(u16, ATTR_ADSIZE);
        }

        if (self.is64 and self.has_opsize) {
            switch (self.opcode) {
                0xe8, 0xe9 => if (self.opcode_type == .one_byte) {
                    attr ^= ATTR_OPSIZE;
                    self.immediate_size = 4;
                    self.displacement_size = 4;
                },
                0x82...0x8f => if (self.opcode_type == .two_byte) {
                    attr ^= ATTR_OPSIZE;
                    self.immediate_size = 4;
                    self.displacement_size = 4;
                },
                else => {},
            }
        }

        if (!self.is64 and self.vec != .none) {
            const id = try self.idWithAttr(attr);
            const w = switch (self.vec) {
                .evex, .vex3, .xop => self.vp[2] & 0x80 != 0,
                else => false,
            };
            if (w) {
                const id_w = self.idWithAttr(attr | ATTR_REXW) catch {
                    self.setId(id);
                    return;
                };
                if (!idBit(layout.is64, id_w)) {
                    self.setId(id_w);
                    return;
                }
            }
        }

        if ((self.opcode_type == .one_byte and self.opcode & 0xfc == 0xa0) or
            (self.opcode_type == .two_byte and self.opcode == 0xae) or
            (self.opcode_type == .three_38 and self.opcode == 0xf8))
        {
            if (self.has_adsize) attr |= ATTR_ADSIZE;
            if (self.has_opsize) attr |= ATTR_OPSIZE;
            self.setId(try self.idWithAttr(attr));
            return;
        }

        const id = try self.idWithAttr(attr);

        if (self.has_opsize and attr & ATTR_OPSIZE == 0) {
            const id_op = self.idWithAttr(attr | ATTR_OPSIZE) catch {
                self.setId(id);
                return;
            };
            // (mode == 16-bit) ^ hasOpSize is true here.
            if (is16BitEquivalent(id, id_op)) self.setId(id_op) else self.setId(id);
            return;
        }

        if (self.opcode_type == .one_byte and self.opcode == 0x90 and self.rex & 0x01 != 0) {
            self.opcode = 0x91;
            const id_new = self.idWithAttr(attr) catch {
                self.opcode = 0x90;
                self.setId(id);
                return;
            };
            self.opcode = 0x90;
            self.setId(id_new);
            return;
        }
        self.setId(id);
    }

    fn readSIB(self: *Insn) Fail!void {
        if (self.consumed_sib) return;
        self.consumed_sib = true;
        var sib_base_base: i32 = c.SIB_BASE_NONE;
        switch (self.address_size) {
            2 => return error.Fail,
            4 => {
                self.sib_index_base = c.SIB_INDEX_EAX;
                sib_base_base = c.SIB_BASE_EAX;
            },
            8 => {
                self.sib_index_base = c.SIB_INDEX_RAX;
                sib_base_base = c.SIB_BASE_RAX;
            },
            else => {},
        }
        self.sib = try self.consume();
        const index: i32 = ((self.sib >> 3) & 7) | (((self.rex >> 1) & 1) << 3);
        self.sib_index = if (index == 4) c.SIB_INDEX_NONE else self.sib_index_base + index;
        self.sib_scale = @as(u8, 1) << @intCast(self.sib >> 6);
        const base: i32 = (self.sib & 7) | ((self.rex & 1) << 3);
        if (base == 5 or base == 0xd) {
            switch (self.modrm >> 6) {
                0 => {
                    self.ea_disp = EA_DISP_32;
                    self.sib_base = c.SIB_BASE_NONE;
                },
                1 => {
                    self.ea_disp = EA_DISP_8;
                    self.sib_base = sib_base_base + base;
                },
                2 => {
                    self.ea_disp = EA_DISP_32;
                    self.sib_base = sib_base_base + base;
                },
                else => return error.Fail,
            }
        } else self.sib_base = sib_base_base + base;
    }

    fn readDisplacement(self: *Insn) Fail!void {
        if (self.consumed_disp) return;
        self.consumed_disp = true;
        switch (self.ea_disp) {
            EA_DISP_NONE => self.consumed_disp = false,
            EA_DISP_8 => _ = try self.consumeLe(1),
            EA_DISP_16 => _ = try self.consumeLe(2),
            EA_DISP_32 => _ = try self.consumeLe(4),
            else => {},
        }
    }

    fn readModRM(self: *Insn) Fail!void {
        if (self.consumed_modrm) return;
        self.modrm = try self.consume();
        self.consumed_modrm = true;
        if (self.first_byte == 0x0f and self.opcode_type == .two_byte and self.opcode >= 0x20 and self.opcode <= 0x23)
            self.modrm |= 0xc0;
        const mod = self.modrm >> 6;
        var rm: i32 = self.modrm & 7;
        var reg: i32 = (self.modrm >> 3) & 7;
        switch (self.register_size) {
            2 => {
                self.reg_base = c.MODRM_REG_AX;
                self.ea_reg_base = c.EA_REG_AX;
            },
            4 => {
                self.reg_base = c.MODRM_REG_EAX;
                self.ea_reg_base = c.EA_REG_EAX;
            },
            8 => {
                self.reg_base = c.MODRM_REG_RAX;
                self.ea_reg_base = c.EA_REG_RAX;
            },
            else => {},
        }
        reg |= ((self.rex >> 2) & 1) << 3;
        rm |= (self.rex & 1) << 3;
        var evexrm: i32 = 0;
        if (self.vec == .evex and self.is64) {
            reg |= ((~self.vp[1] >> 4) & 1) << 4;
            evexrm = ((~self.vp[1] >> 6) & 1) << 4;
        }
        self.reg = self.reg_base + reg;

        switch (self.address_size) {
            2 => {
                const base: i32 = c.EA_BASE_BX_SI;
                switch (mod) {
                    0 => if (rm == 6) {
                        self.ea_base = c.EA_BASE_NONE;
                        self.ea_disp = EA_DISP_16;
                        try self.readDisplacement();
                    } else {
                        self.ea_base = base + rm;
                        self.ea_disp = EA_DISP_NONE;
                    },
                    1 => {
                        self.ea_base = base + rm;
                        self.ea_disp = EA_DISP_8;
                        self.displacement_size = 1;
                        try self.readDisplacement();
                    },
                    2 => {
                        self.ea_base = base + rm;
                        self.ea_disp = EA_DISP_16;
                        try self.readDisplacement();
                    },
                    else => {
                        self.ea_base = self.ea_reg_base + rm;
                        try self.readDisplacement();
                    },
                }
            },
            4, 8 => {
                const base: i32 = if (self.address_size == 4) c.EA_BASE_EAX else c.EA_BASE_RAX;
                switch (mod) {
                    0 => {
                        self.ea_disp = EA_DISP_NONE;
                        switch (rm & 7) {
                            4 => {
                                self.ea_base = if (self.address_size == 4) c.EA_BASE_sib else c.EA_BASE_sib64;
                                try self.readSIB();
                                try self.readDisplacement();
                            },
                            5 => {
                                self.ea_base = c.EA_BASE_NONE;
                                self.ea_disp = EA_DISP_32;
                                try self.readDisplacement();
                            },
                            else => self.ea_base = base + rm,
                        }
                    },
                    1, 2 => {
                        if (mod == 1) self.displacement_size = 1;
                        self.ea_disp = if (mod == 1) EA_DISP_8 else EA_DISP_32;
                        if (rm & 7 == 4) {
                            self.ea_base = c.EA_BASE_sib;
                            try self.readSIB();
                            try self.readDisplacement();
                        } else {
                            self.ea_base = base + rm;
                            try self.readDisplacement();
                        }
                    },
                    else => {
                        self.ea_disp = EA_DISP_NONE;
                        self.ea_base = self.ea_reg_base + rm + evexrm;
                    },
                }
            },
            else => {},
        }
    }

    /// GENERIC_FIXUP_FUNC: returns null when the field is not valid for the
    /// register class.
    fn fixupValue(self: *const Insn, comptime is_reg: bool, typ: u8, index0: i32) ?i32 {
        const P = if (is_reg) struct {
            const AL = c.MODRM_REG_AL;
            const SPL = c.MODRM_REG_SPL;
            const AX = c.MODRM_REG_AX;
            const EAX = c.MODRM_REG_EAX;
            const RAX = c.MODRM_REG_RAX;
            const ZMM0 = c.MODRM_REG_ZMM0;
            const YMM0 = c.MODRM_REG_YMM0;
            const XMM0 = c.MODRM_REG_XMM0;
            const K0 = c.MODRM_REG_K0;
            const MM0 = c.MODRM_REG_MM0;
            const ES = c.MODRM_REG_ES;
            const DR0 = c.MODRM_REG_DR0;
            const CR0 = c.MODRM_REG_CR0;
            const BND0 = c.MODRM_REG_BND0;
        } else struct {
            const AL = c.EA_REG_AL;
            const SPL = c.EA_REG_SPL;
            const AX = c.EA_REG_AX;
            const EAX = c.EA_REG_EAX;
            const RAX = c.EA_REG_RAX;
            const ZMM0 = c.EA_REG_ZMM0;
            const YMM0 = c.EA_REG_YMM0;
            const XMM0 = c.EA_REG_XMM0;
            const K0 = c.EA_REG_K0;
            const MM0 = c.EA_REG_MM0;
            const ES = c.EA_REG_ES;
            const DR0 = c.EA_REG_DR0;
            const CR0 = c.EA_REG_CR0;
            const BND0 = c.EA_REG_BND0;
        };
        const base = if (is_reg) self.reg_base else self.ea_reg_base;
        const mask: i32 = if (is_reg) 0x1f else 0xf;
        // The C code computes with uint8_t index.
        var index: i32 = index0 & 0xff;
        switch (typ) {
            c.TYPE_Rv => return base + index,
            c.TYPE_R8 => {
                index &= mask;
                if (index > 0xf) return null;
                if (self.rex != 0 and index >= 4 and index <= 7) return P.SPL + (index - 4);
                return P.AL + index;
            },
            c.TYPE_R16 => {
                index &= mask;
                if (index > 0xf) return null;
                return P.AX + index;
            },
            c.TYPE_R32 => {
                index &= mask;
                if (index > 0xf) return null;
                return P.EAX + index;
            },
            c.TYPE_R64 => {
                index &= mask;
                if (index > 0xf) return null;
                return P.RAX + index;
            },
            c.TYPE_ZMM => return P.ZMM0 + index,
            c.TYPE_YMM => return P.YMM0 + index,
            c.TYPE_XMM => return P.XMM0 + index,
            c.TYPE_VK => {
                index &= 0xf;
                if (index > 7) return null;
                return P.K0 + index;
            },
            c.TYPE_MM64 => return P.MM0 + (index & 7),
            c.TYPE_SEGMENTREG => {
                if (index & 7 > 5) return null;
                return P.ES + (index & 7);
            },
            c.TYPE_DEBUGREG => return P.DR0 + index,
            c.TYPE_CONTROLREG => return P.CR0 + index,
            c.TYPE_BNDR => {
                if (index > 3) return null;
                return P.BND0 + index;
            },
            c.TYPE_MVSIBX => return P.XMM0 + index,
            c.TYPE_MVSIBY => return P.YMM0 + index,
            c.TYPE_MVSIBZ => return P.ZMM0 + index,
            else => return null,
        }
    }

    fn fixupReg(self: *Insn, op: OperandSpec) Fail!void {
        switch (op.encoding) {
            c.ENCODING_VVVV => self.vvvv = self.fixupValue(true, op.type, self.vvvv) orelse return error.Fail,
            c.ENCODING_REG => self.reg = self.fixupValue(true, op.type, self.reg - self.reg_base) orelse return error.Fail,
            c.ENCODING_RM...c.ENCODING_RM_CD64 => if (self.ea_base >= self.ea_reg_base) {
                self.ea_base = self.fixupValue(false, op.type, self.ea_base - self.ea_reg_base) orelse return error.Fail;
            },
            else => return error.Fail,
        }
    }

    fn readImmediate(self: *Insn, size0: u8) Fail!void {
        if (self.n_imm == 2) return error.Fail;
        var size = size0;
        if (size == 0) size = self.immediate_size else self.immediate_size = size;
        const v: u64 = switch (size) {
            1 => try self.consumeLe(1),
            2 => try self.consumeLe(2),
            4 => try self.consumeLe(4),
            8 => try self.consumeLe(8),
            else => self.imm[self.n_imm],
        };
        self.imm[self.n_imm] = v;
        self.n_imm += 1;
    }

    fn readOperands(self: *Insn) Fail!void {
        var has_vvvv = true;
        switch (self.vec) {
            .evex => self.vvvv = (@as(i32, (~self.vp[3] >> 3) & 1) << 4) | ((~self.vp[2] >> 3) & 0xf),
            .vex3, .xop => self.vvvv = (~self.vp[2] >> 3) & 0xf,
            .vex2 => self.vvvv = (~self.vp[1] >> 3) & 0xf,
            .none => has_vvvv = false,
        }
        if (has_vvvv and !self.is64) self.vvvv &= 0xf;
        var need_vvvv = has_vvvv and self.vvvv != 0;
        var saw_reg_imm = false;

        for (0..6) |i| {
            const op = operand(self.ops, i);
            switch (op.encoding) {
                c.ENCODING_NONE, c.ENCODING_SI, c.ENCODING_DI => {},
                c.ENCODING_VSIB...c.ENCODING_VSIB_CD64 => {
                    if (need_vvvv) need_vvvv = has_vvvv and (self.vvvv & 0xf) != 0;
                    try self.readModRM();
                    if (self.ea_base != c.EA_BASE_sib and self.ea_base != c.EA_BASE_sib64) return error.Fail;
                    if (self.sib_index == c.SIB_INDEX_NONE) self.sib_index = self.sib_index_base + 4;
                    if (self.vec == .evex and self.is64 and (~self.vp[3] >> 3) & 1 != 0) self.sib_index += 16;
                    switch (op.type) {
                        c.TYPE_MVSIBX => self.sib_index = c.SIB_INDEX_XMM0 + (self.sib_index - self.sib_index_base),
                        c.TYPE_MVSIBY => self.sib_index = c.SIB_INDEX_YMM0 + (self.sib_index - self.sib_index_base),
                        c.TYPE_MVSIBZ => self.sib_index = c.SIB_INDEX_ZMM0 + (self.sib_index - self.sib_index_base),
                        else => return error.Fail,
                    }
                },
                c.ENCODING_REG, c.ENCODING_RM...c.ENCODING_RM_CD64 => {
                    try self.readModRM();
                    try self.fixupReg(op);
                },
                c.ENCODING_IB => {
                    if (saw_reg_imm) {
                        if (self.n_imm < 2) {
                            self.imm[self.n_imm] = self.imm[self.n_imm - 1] & 0xf;
                            self.n_imm += 1;
                        }
                    } else {
                        try self.readImmediate(1);
                        if (op.type == c.TYPE_XMM or op.type == c.TYPE_YMM) saw_reg_imm = true;
                    }
                },
                c.ENCODING_IW => try self.readImmediate(2),
                c.ENCODING_ID => try self.readImmediate(4),
                c.ENCODING_IO => try self.readImmediate(8),
                c.ENCODING_Iv => try self.readImmediate(self.immediate_size),
                c.ENCODING_Ia => try self.readImmediate(self.address_size),
                c.ENCODING_IRC, c.ENCODING_FP, c.ENCODING_DUP, c.ENCODING_WRITEMASK => {
                    if (op.encoding == c.ENCODING_WRITEMASK) {
                        if (self.vec != .evex) return error.Fail;
                        self.writemask = self.vp[3] & 7;
                    }
                },
                c.ENCODING_RB, c.ENCODING_RW, c.ENCODING_RD, c.ENCODING_RO, c.ENCODING_Rv => {},
                c.ENCODING_VVVV => {
                    if (!has_vvvv) return error.Fail;
                    need_vvvv = false;
                    if (!self.is64) self.vvvv &= 0x7;
                    try self.fixupReg(op);
                },
                else => return error.Fail,
            }
        }
        if (need_vvvv) return error.Fail;
    }

    fn checkPrefix(self: *const Insn) bool {
        return self.has_lock and !idBit(layout.lock, self.id);
    }

    // translateInstruction: the operand checks that can fail.

    fn translateRMRegister(self: *const Insn) bool {
        return self.ea_base >= c.EA_REG_AL and self.ea_base < c.EA_max;
    }

    fn translateRMMemory(self: *const Insn) bool {
        if (self.ea_base == c.EA_BASE_sib or self.ea_base == c.EA_BASE_sib64) {
            if (self.sib_base != c.SIB_BASE_NONE and (self.sib_base < 1 or self.sib_base >= c.SIB_BASE_max)) return false;
            if (self.sib_index != c.SIB_INDEX_NONE and (self.sib_index < c.SIB_INDEX_EAX or self.sib_index >= c.SIB_INDEX_max)) return false;
            return true;
        }
        if (self.ea_base == c.EA_BASE_NONE) return self.ea_disp != EA_DISP_NONE;
        return self.ea_base >= 1 and self.ea_base < c.EA_REG_AL;
    }

    fn translateOperand(self: *const Insn, op: OperandSpec, depth: u8) bool {
        switch (op.encoding) {
            c.ENCODING_WRITEMASK => return self.writemask < 8,
            c.ENCODING_RM...c.ENCODING_RM_CD64, c.ENCODING_VSIB...c.ENCODING_VSIB_CD64 => switch (op.type) {
                c.TYPE_R8, c.TYPE_R16, c.TYPE_R32, c.TYPE_R64, c.TYPE_Rv, c.TYPE_MM64, c.TYPE_XMM, c.TYPE_YMM, c.TYPE_ZMM, c.TYPE_VK, c.TYPE_DEBUGREG, c.TYPE_CONTROLREG, c.TYPE_BNDR => return self.translateRMRegister(),
                c.TYPE_M, c.TYPE_MVSIBX, c.TYPE_MVSIBY, c.TYPE_MVSIBZ => return self.translateRMMemory(),
                else => return false,
            },
            c.ENCODING_REG, c.ENCODING_IB, c.ENCODING_IW, c.ENCODING_ID, c.ENCODING_IO, c.ENCODING_Iv, c.ENCODING_Ia, c.ENCODING_IRC, c.ENCODING_SI, c.ENCODING_DI, c.ENCODING_RB, c.ENCODING_RW, c.ENCODING_RD, c.ENCODING_RO, c.ENCODING_Rv, c.ENCODING_FP, c.ENCODING_VVVV => return true,
            c.ENCODING_DUP => {
                if (depth > 5 or op.type < c.TYPE_DUP0 or op.type > c.TYPE_DUP4) return false;
                return self.translateOperand(operand(self.ops, op.type - c.TYPE_DUP0), depth + 1);
            },
            else => return false,
        }
    }

    fn translate(self: *const Insn) bool {
        for (0..6) |i| {
            const op = operand(self.ops, i);
            if (op.encoding != c.ENCODING_NONE and !self.translateOperand(op, 0)) return false;
        }
        return true;
    }
};

fn is16BitEquivalent(orig: u16, equiv: u16) bool {
    if (orig >= c.eq16_lookup_len) return false;
    const idx = rd16(layout.eq16_lookup + @as(usize, orig) * 2);
    if (idx == 0) return false;
    var i: usize = idx - 1;
    while (i < c.eq16_table_len) : (i += 1) {
        const first = rd16(layout.eq16_table + i * 4);
        if (first != orig) break;
        if (rd16(layout.eq16_table + i * 4 + 2) == equiv) return true;
    }
    return false;
}

/// Decodes the instruction at the start of `code`, located at `address`.
/// Returns null where capstone's x86 decoder rejects it.
pub fn decode(code: []const u8, address: u64, mode: Mode) ?Instruction {
    var insn: Insn = .{ .code = code, .is64 = mode == .x64 };
    insn.readPrefixes() catch return null;
    insn.readOpcode() catch return null;
    insn.getID() catch return null;
    if (insn.id == 0 or insn.id >= c.instruction_count) return null;
    if (insn.checkPrefix()) return null;
    insn.readOperands() catch return null;
    if (insn.cursor > 15) return null;
    if (!insn.translate()) return null;
    const len: u8 = @intCast(insn.cursor);
    return .{ .len = len, .call_target = callTarget(&insn, address, len) };
}

fn callTarget(insn: *const Insn, address: u64, len: u8) ?u64 {
    switch (insn.id) {
        c.X86_CALLpcrel16, c.X86_CALLpcrel32, c.X86_CALL64pcrel32 => {},
        else => return null,
    }
    // X86_lockrep: F2 prints as "bnd call", a final 3E as "notrack call".
    if (insn.prefix0 == 0xf2 or insn.prefix1 == 0x3e) return null;
    const op = operand(insn.ops, 0);
    var imm = insn.imm[0];
    // translateImmediate sign-extends TYPE_REL by encoding.
    switch (op.encoding) {
        c.ENCODING_Iv => switch (insn.displacement_size) {
            1 => imm = signExtend(imm, 8),
            2 => imm = signExtend(imm, 16),
            4 => imm = signExtend(imm, 32),
            else => {},
        },
        c.ENCODING_IB => imm = signExtend(imm, 8),
        c.ENCODING_IW => imm = signExtend(imm, 16),
        c.ENCODING_ID => imm = signExtend(imm, 32),
        else => {},
    }
    var target = imm +% len +% address;
    if (insn.is64 == false) target &= 0xffffffff;
    // printImm: negative values print in hex, others in hex above 9.
    const signed: i64 = @bitCast(target);
    if (signed >= 0 and signed <= 9) return null;
    return target;
}

fn signExtend(v: u64, comptime bits: u7) u64 {
    const sign = @as(u64, 1) << (bits - 1);
    if (v & sign != 0) return v | ~((sign << 1) -% 1);
    return v;
}

test "direct calls and lengths" {
    const D = struct {
        fn check(mode: Mode, bytes: []const u8, addr: u64, len: u8, target: ?u64) !void {
            const r = decode(bytes, addr, mode) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(len, r.len);
            try std.testing.expectEqual(target, r.call_target);
        }
    };
    try D.check(.x86, "\xe8\x00\x00\x00\x00", 0x1000, 5, 0x1005);
    try D.check(.x86, "\x66\xe8\x00\x00", 0x1000, 4, 0x1004);
    try D.check(.x86, "\xf2\xe8\x00\x00\x00\x00", 0x1000, 6, null);
    try D.check(.x86, "\x3e\xe8\x00\x00\x00\x00", 0x1000, 6, null);
    try D.check(.x86, "\x3e\x2e\xe8\x00\x00\x00\x00", 0x1000, 7, 0x1007);
    try D.check(.x86, "\xe8\xf0\xff\xff\xff", 0x1000, 5, 0xff5);
    try D.check(.x64, "\xe8\x00\xf0\xff\xff", 0x10, 5, 0xfffffffffffff015);
    try D.check(.x64, "\x66\xe8\x00\x00\x00\x00", 0x10, 6, 0x16);
    try D.check(.x64, "\xe8\x00\x00\x00\x00", 0, 5, null);
    try D.check(.x86, "\x9a\x78\x56\x34\x12\x10\x00", 0, 7, null);
    try D.check(.x64, "\x48\x89\xe5", 0, 3, null);
    try std.testing.expectEqual(@as(?Instruction, null), decode("\xf0\x90", 0, .x64));
    try std.testing.expectEqual(@as(?Instruction, null), decode("\xe8\x00\x00", 0, .x86));
}
