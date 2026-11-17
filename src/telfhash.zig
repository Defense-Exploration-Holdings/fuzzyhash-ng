// SPDX-License-Identifier: Apache-2.0
// Ported from telfhash 0.9.8 (https://github.com/trendmicro/telfhash),
// Copyright 2020 Trend Micro, Apache License 2.0; see LICENSES/telfhash-LICENSE
// and LICENSES/telfhash-NOTICE.txt. Changes: rewritten in Zig on top of
// tlsh.zig, with the ELF parsing done here instead of by pyelftools.
//! telfhash, the symbol hash of ELF files, compatible with telfhash 0.9.8
//! (trendmicro/telfhash) running on pyelftools 0.33 and py-tlsh 5.0.0.
//!
//! The digest is the TLSH (`T1`) of the sorted, lowercased names of the
//! global, default-visibility function symbols in the first non-empty
//! `.dynsym` or `.symtab`, joined by commas, after telfhash's exclusion
//! list. It is printed in lower case.
//!
//! The section walk reproduces what pyelftools checks while it builds each
//! section object up to the symbol table, so files that pyelftools rejects
//! are rejected here too.
//!
//! Files without a symbol table are hashed the way telfhash does it with
//! capstone 5.0.9: the code section (the section holding the entry point,
//! else the last section named `.text`, else the first read-execute
//! PT_LOAD segment from the entry point on) is disassembled from its start
//! until the first instruction capstone rejects, and the targets of direct
//! calls (x86 and x86-64 `call`, ARM `bl*`, MIPS `lw $t9`) are hashed in
//! the order they first appear. Only those four architectures give a
//! digest; telfhash prints "-" for the others.

const std = @import("std");
const tlsh = @import("tlsh.zig");
const x86 = @import("telfhash/x86.zig");
const words = @import("telfhash/words.zig");

pub const T1 = tlsh.T1;

pub const Error = error{
    /// pyelftools fails to read the file; telfhash prints "-".
    InvalidElf,
    /// The code section is zlib-compressed. telfhash decompresses it; this
    /// port does not. Executables never have compressed code sections.
    CompressedCode,
    /// telfhash never finishes: its program header scan for the image base
    /// reads the ELF header over and over when `e_phoff` and `e_phentsize`
    /// are both 0.
    Endless,
    /// A kept symbol name is not ASCII after lowercasing; telfhash raises
    /// UnicodeEncodeError and gives no result.
    NonAsciiSymbol,
    /// `scratch` is too small; `scratchLength` gives a size that is always
    /// enough.
    WorkspaceTooSmall,
};

pub const Result = union(enum) {
    digest: T1.Digest,
    /// The symbol string was too short or too uniform for TLSH: "tnull".
    tlsh_null,
    /// No symbols left after filtering: "-".
    no_symbols,
};

/// "t1" plus 70 hex characters.
pub const max_string_length = T1.max_string_length;

/// telfhash's text form: the lowercase digest, "tnull" or "-".
pub fn toString(result: Result, out: *[max_string_length]u8) []const u8 {
    switch (result) {
        .digest => |d| {
            const s = d.toString(out, .{});
            for (out[0..s.len]) |*c| c.* = std.ascii.toLower(c.*);
            return out[0..s.len];
        },
        .tlsh_null => {
            @memcpy(out[0..5], "tnull");
            return out[0..5];
        },
        .no_symbols => {
            out[0] = '-';
            return out[0..1];
        },
    }
}

/// Distance between two telfhash strings, as telfhash's grouping computes
/// it: both are upper-cased and compared with the TLSH distance, length
/// included.
pub fn diffStrings(a: []const u8, b: []const u8) tlsh.ParseError!u32 {
    var ua: [max_string_length + 1]u8 = undefined;
    var ub: [max_string_length + 1]u8 = undefined;
    return T1.diffStrings(upperPrefix(&ua, a), upperPrefix(&ub, b), .{});
}

fn upperPrefix(buf: *[max_string_length + 1]u8, s: []const u8) []const u8 {
    // TLSH parsing looks at most one character past the digest.
    const n = @min(s.len, buf.len);
    for (buf[0..n], s[0..n]) |*d, c| d.* = std.ascii.toUpper(c);
    return buf[0..n];
}

/// telfhash of an ELF file held in memory. `scratch` holds one entry per
/// kept symbol, or for files without a symbol table a hash set of call
/// targets. `scratchLength(elf.len)` entries are always enough.
pub fn hash(elf: []const u8, scratch: []u32) Error!Result {
    var e = try Elf.open(elf);
    if (try e.findSymbolTable()) |symtab| return e.hashSymbols(symtab, scratch);
    return e.hashCalls(scratch);
}

/// A `scratch` length for `hash` that is enough for any file of `elf_len`
/// bytes. A file has at most `elf_len / 4` call targets.
pub fn scratchLength(elf_len: usize) usize {
    const targets = elf_len / 4 + 1;
    return std.math.ceilPowerOfTwoAssert(usize, targets + targets / 7 + 2);
}

const Shdr = struct {
    name: u32,
    type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entsize: u64,
};

const sht_null = 0;
const sht_symtab = 2;
const sht_strtab = 3;
const sht_rela = 4;
const sht_hash = 5;
const sht_dynamic = 6;
const sht_nobits = 8;
const sht_rel = 9;
const sht_dynsym = 11;
const sht_relr = 19;
const sht_gnu_hash = 0x6ffffff6;
const sht_sunw_ldynsym = 0x6ffffff3;
const sht_sunw_syminfo = 0x6ffffffc;
const sht_gnu_verdef = 0x6ffffffd;
const sht_gnu_verneed = 0x6ffffffe;
const sht_gnu_versym = 0x6fffffff;
const sht_attributes = 0x70000003;
const em_arm = 40;
const em_riscv = 243;
const shf_compressed = 0x800;

const Elf = struct {
    data: []const u8,
    little: bool,
    is64: bool,
    machine: u16,
    entry: u64 = 0,
    phoff: u64 = 0,
    phentsize: u64 = 0,
    phnum: u64 = 0,
    shoff: u64,
    shentsize: u64,
    shnum: u64,
    shstrndx: u64,
    shstrtab_checked: bool = false,
    shstrtab_offset: u64 = 0,

    fn open(data: []const u8) Error!Elf {
        if (data.len < 6 or !std.mem.eql(u8, data[0..4], "\x7fELF")) return error.InvalidElf;
        const is64 = switch (data[4]) {
            1 => false,
            2 => true,
            else => return error.InvalidElf,
        };
        const little = switch (data[5]) {
            1 => true,
            2 => false,
            else => return error.InvalidElf,
        };
        var e = Elf{ .data = data, .little = little, .is64 = is64, .machine = 0, .shoff = 0, .shentsize = 0, .shnum = 0, .shstrndx = 0 };
        const ehdr_size: u64 = if (is64) 64 else 52;
        if (data.len < ehdr_size) return error.InvalidElf;
        e.machine = e.int(u16, 18);
        if (is64) {
            e.entry = e.int(u64, 24);
            e.phoff = e.int(u64, 32);
            e.phentsize = e.int(u16, 54);
            e.phnum = e.int(u16, 56);
            e.shoff = e.int(u64, 40);
            e.shentsize = e.int(u16, 58);
            e.shnum = e.int(u16, 60);
            e.shstrndx = e.int(u16, 62);
        } else {
            e.entry = e.int(u32, 24);
            e.phoff = e.int(u32, 28);
            e.phentsize = e.int(u16, 42);
            e.phnum = e.int(u16, 44);
            e.shoff = e.int(u32, 32);
            e.shentsize = e.int(u16, 46);
            e.shnum = e.int(u16, 48);
            e.shstrndx = e.int(u16, 50);
        }
        return e;
    }

    /// Integer at a checked offset.
    fn int(self: *const Elf, comptime T: type, off: u64) T {
        const p = self.data[@intCast(off)..][0..@sizeOf(T)];
        return std.mem.readInt(T, p, if (self.little) .little else .big);
    }

    fn has(self: *const Elf, off: u64, n: u64) bool {
        return off <= self.data.len and self.data.len - off >= n;
    }

    fn word(self: *const Elf, off: u64) u64 {
        return if (self.is64) self.int(u64, off) else self.int(u32, off);
    }

    fn wordSize(self: *const Elf) u64 {
        return if (self.is64) 8 else 4;
    }

    fn shdrSize(self: *const Elf) u64 {
        return if (self.is64) 64 else 40;
    }

    fn header(self: *const Elf, n: u64) Error!Shdr {
        if (self.shoff > 0 and self.shentsize < self.shdrSize()) return error.InvalidElf;
        const step = std.math.mul(u64, n, self.shentsize) catch return error.InvalidElf;
        const pos = std.math.add(u64, self.shoff, step) catch return error.InvalidElf;
        if (!self.has(pos, self.shdrSize())) return error.InvalidElf;
        if (self.is64) return .{
            .name = self.int(u32, pos),
            .type = self.int(u32, pos + 4),
            .flags = self.int(u64, pos + 8),
            .addr = self.int(u64, pos + 16),
            .offset = self.int(u64, pos + 24),
            .size = self.int(u64, pos + 32),
            .link = self.int(u32, pos + 40),
            .info = self.int(u32, pos + 44),
            .entsize = self.int(u64, pos + 56),
        };
        return .{
            .name = self.int(u32, pos),
            .type = self.int(u32, pos + 4),
            .flags = self.int(u32, pos + 8),
            .addr = self.int(u32, pos + 12),
            .offset = self.int(u32, pos + 16),
            .size = self.int(u32, pos + 20),
            .link = self.int(u32, pos + 24),
            .info = self.int(u32, pos + 28),
            .entsize = self.int(u32, pos + 36),
        };
    }

    fn sectionCount(self: *const Elf) Error!u64 {
        if (self.shoff == 0) return 0;
        if (self.shnum == 0) return (try self.header(0)).size;
        return self.shnum;
    }

    /// Checks done by pyelftools `Section.__init__`.
    fn initSection(self: *const Elf, h: Shdr) Error!void {
        if (h.flags & shf_compressed != 0) {
            const chdr: u64 = if (self.is64) 24 else 12;
            if (!self.has(h.offset, chdr)) return error.InvalidElf;
        }
    }

    /// The section-name string table, built on first use.
    fn checkShstrtab(self: *Elf) Error!void {
        if (self.shstrtab_checked) return;
        const idx: u64 = if (self.shstrndx != 0xffff) self.shstrndx else (try self.header(0)).link;
        const h = try self.header(idx);
        try self.initSection(h);
        self.shstrtab_offset = h.offset;
        self.shstrtab_checked = true;
    }

    fn linkedStrtab(self: *Elf, link: u64) Error!Shdr {
        const h = try self.header(link);
        if (h.type != sht_strtab) return error.InvalidElf;
        try self.makeSection(h);
        return h;
    }

    fn linkedSymtab(self: *Elf, link: u64) Error!void {
        const h = try self.header(link);
        if (h.type != sht_symtab and h.type != sht_dynsym) return error.InvalidElf;
        try self.makeSection(h);
    }

    /// pyelftools `ELFFile._make_section`: only the checks that can fail.
    fn makeSection(self: *Elf, h: Shdr) Error!void {
        try self.checkShstrtab();
        // Reading the name seeks to this position, which Python refuses past 2^63.
        _ = try seekable(self.shstrtab_offset, h.name);
        switch (h.type) {
            sht_symtab, sht_dynsym, sht_sunw_ldynsym => {
                _ = try self.linkedStrtab(h.link);
                try self.initSection(h);
                if (h.entsize == 0) return error.InvalidElf;
                if (h.size % h.entsize != 0) return error.InvalidElf;
            },
            sht_sunw_syminfo, sht_gnu_versym => {
                try self.linkedSymtab(h.link);
                try self.initSection(h);
            },
            sht_gnu_verneed, sht_gnu_verdef => {
                _ = try self.linkedStrtab(h.link);
                try self.initSection(h);
            },
            sht_rel, sht_rela => {
                try self.initSection(h);
                const entry: u64 = if (h.type == sht_rela) 3 * self.wordSize() else 2 * self.wordSize();
                if (h.entsize != entry) return error.InvalidElf;
            },
            sht_dynamic => {
                try self.initSection(h);
                const s = try self.header(h.link);
                if (s.type != sht_strtab and s.type != sht_nobits and s.type != sht_null) return error.InvalidElf;
                try self.makeSection(s);
            },
            sht_attributes => {
                try self.initSection(h);
                if (self.machine == em_arm or self.machine == em_riscv) {
                    if (!self.has(h.offset, 1)) return error.InvalidElf;
                    if (self.data[@intCast(h.offset)] != 'A') return error.InvalidElf;
                }
            },
            sht_hash => {
                try self.linkedSymtab(h.link);
                try self.initSection(h);
                if (h.size != 0) {
                    if (!self.has(h.offset, 8)) return error.InvalidElf;
                    const nbuckets: u64 = self.int(u32, h.offset);
                    const nchains: u64 = self.int(u32, h.offset + 4);
                    if (!self.has(h.offset + 8, 4 * (nbuckets + nchains))) return error.InvalidElf;
                }
            },
            sht_gnu_hash => {
                try self.linkedSymtab(h.link);
                try self.initSection(h);
                if (!self.has(h.offset, 16)) return error.InvalidElf;
                const nbuckets: u64 = self.int(u32, h.offset);
                const bloom_size: u64 = self.int(u32, h.offset + 8);
                if (!self.has(h.offset + 16, bloom_size * self.wordSize() + 4 * nbuckets)) return error.InvalidElf;
            },
            sht_relr => {
                try self.initSection(h);
                if (h.entsize != self.wordSize()) return error.InvalidElf;
            },
            else => try self.initSection(h),
        }
    }

    const SymbolTable = struct { h: Shdr, strtab: Shdr };

    /// telfhash: the first section with a non-zero size that is SHT_DYNSYM or
    /// SHT_SYMTAB, building every section object on the way.
    fn findSymbolTable(self: *Elf) Error!?SymbolTable {
        const count = try self.sectionCount();
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            const h = try self.header(i);
            try self.makeSection(h);
            if (h.size == 0) continue;
            if (h.type == sht_dynsym or h.type == sht_symtab) {
                return .{ .h = h, .strtab = try self.header(h.link) };
            }
        }
        return null;
    }

    fn symSize(self: *const Elf) u64 {
        return if (self.is64) 24 else 16;
    }

    const Sym = struct { name: u32, info: u8, other: u8 };

    fn symbol(self: *const Elf, t: SymbolTable, i: u64) Error!Sym {
        const off = std.math.add(u64, t.h.offset, std.math.mul(u64, i, t.h.entsize) catch return error.InvalidElf) catch return error.InvalidElf;
        if (!self.has(off, self.symSize())) return error.InvalidElf;
        return .{
            .name = self.int(u32, off),
            .info = self.data[@intCast(off + if (self.is64) @as(u64, 4) else 12)],
            .other = self.data[@intCast(off + if (self.is64) @as(u64, 5) else 13)],
        };
    }

    /// pyelftools `StringTableSection.get_string`, as raw bytes: up to the
    /// first NUL, or empty if there is no NUL before the end of the file.
    fn string(self: *const Elf, t: SymbolTable, off: u32) Error![]const u8 {
        const start = try seekable(t.strtab.offset, off);
        if (start >= self.data.len) return "";
        const rest = self.data[@intCast(start)..];
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse return "";
        return rest[0..end];
    }

    fn hashSymbols(self: *const Elf, t: SymbolTable, scratch: []u32) Error!Result {
        const count = t.h.size / t.h.entsize;
        var kept: usize = 0;
        // telfhash reads every symbol before it fails on a non-ASCII name.
        var non_ascii = false;
        var too_many = false;
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            const s = try self.symbol(t, i);
            if (s.info & 0xf != 2) continue; // STT_FUNC
            if (s.info >> 4 != 1) continue; // STB_GLOBAL
            if (s.other & 7 != 0) continue; // STV_DEFAULT
            const name = try self.string(t, s.name);
            if (name.len == 0 or excluded(name)) continue;
            if (!lowersToAscii(name)) {
                non_ascii = true;
                continue;
            }
            if (kept >= scratch.len or i > std.math.maxInt(u32)) {
                too_many = true;
                continue;
            }
            scratch[kept] = @intCast(i);
            kept += 1;
        }
        if (non_ascii) return error.NonAsciiSymbol;
        if (too_many) return error.WorkspaceTooSmall;
        if (kept == 0) return .no_symbols;

        const Ctx = struct {
            elf: *const Elf,
            t: SymbolTable,
            fn name(c: @This(), idx: u32) []const u8 {
                // Both reads succeeded in the loop above.
                const s = c.elf.symbol(c.t, idx) catch unreachable;
                return c.elf.string(c.t, s.name) catch unreachable;
            }
            fn lessThan(c: @This(), a: u32, b: u32) bool {
                return lowerOrder(c.name(a), c.name(b)) == .lt;
            }
        };
        const ctx = Ctx{ .elf = self, .t = t };
        // Equal names are interchangeable, so stability does not matter.
        std.sort.block(u32, scratch[0..kept], ctx, Ctx.lessThan);

        var h = T1.init(.{});
        var buf: [256]u8 = undefined;
        for (scratch[0..kept], 0..) |idx, n| {
            if (n != 0) h.update(",");
            var it = Lower{ .s = ctx.name(idx) };
            var fill: usize = 0;
            while (it.next()) |c| {
                buf[fill] = c;
                fill += 1;
                if (fill == buf.len) {
                    h.update(&buf);
                    fill = 0;
                }
            }
            h.update(buf[0..fill]);
        }
        const d = h.final() catch return .tlsh_null;
        return .{ .digest = d };
    }

    // ---- files without a symbol table ---------------------------------------

    /// telfhash `extract_call_destinations`.
    fn hashCalls(self: *Elf, scratch: []u32) Error!Result {
        var ofs: u64 = undefined;
        var code: []const u8 = undefined;
        if (try self.codeSectionOrSegment()) |found| switch (found) {
            .segment => |p| {
                ofs = self.entry;
                const data = try self.read(p.offset, p.filesz);
                code = sliceFrom(data, @as(i128, self.entry) - p.vaddr);
            },
            .section => |h| {
                // capstone takes the address as a uint64; ctypes drops the high bits.
                ofs = (try self.imageBase()) +% h.offset;
                // pyelftools gives zeros, which decode without a call on every
                // architecture (or do not fit in memory, which also gives "-").
                if (h.type == sht_nobits) return .no_symbols;
                if (h.flags & shf_compressed != 0) {
                    if (self.int(u32, h.offset) != elfcompress_zlib) return error.InvalidElf;
                    if (self.machineArch() == null) return .no_symbols;
                    return error.CompressedCode;
                }
                code = try self.read(h.offset, h.size);
            },
        } else {
            // telfhash reads the image base, then fails on `None["sh_offset"]`.
            _ = try self.imageBase();
            return error.InvalidElf;
        }
        const arch = self.machineArch() orelse return .no_symbols;
        const calls = Calls{ .code = code, .ofs = ofs, .arch = arch };

        // Call targets seen so far: a hash set of code offsets plus one.
        const cap = if (scratch.len == 0) 0 else std.math.floorPowerOfTwo(usize, scratch.len);
        const slots = scratch[0..cap];
        @memset(slots, 0);
        const limit = if (cap == 0) 0 else cap - @max(1, cap / 8);
        var count: usize = 0;

        var h = T1.init(.{});
        var off: usize = 0;
        var buf: [32]u8 = undefined;
        var other: [32]u8 = undefined;
        while (calls.step(off)) |len| : (off += len) {
            const name = calls.target(off, &buf) orelse continue;
            const want = std.hash.Wyhash.hash(0, name);
            var i: usize = undefined;
            const new = for (0..cap) |n| {
                i = @intCast((want +% n) & (cap - 1));
                if (slots[i] == 0) break true;
                if (std.mem.eql(u8, calls.target(slots[i] - 1, &other).?, name)) break false;
            } else true;
            if (!new) continue;
            if (count >= limit or off >= std.math.maxInt(u32)) return error.WorkspaceTooSmall;
            slots[i] = @intCast(off + 1);
            if (count != 0) h.update(",");
            h.update(name);
            count += 1;
        }
        if (count == 0) return .no_symbols;
        const d = h.final() catch return .tlsh_null;
        return .{ .digest = d };
    }

    fn machineArch(self: *const Elf) ?Arch {
        return switch (self.machine) {
            em_386 => .x86,
            em_x86_64 => .x64,
            em_arm => .arm,
            em_mips => .mips,
            else => null,
        };
    }

    const Code = union(enum) { section: Shdr, segment: Phdr };

    /// telfhash `get_ep_section_or_segment`. The sections were all built
    /// once already by `findSymbolTable`, so building them again cannot fail.
    fn codeSectionOrSegment(self: *Elf) Error!?Code {
        const count = try self.sectionCount();
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            const h = try self.header(i);
            if (self.entry >= h.addr and self.entry < @as(u128, h.addr) + h.size) return .{ .section = h };
        }
        // `get_section_by_name` keeps the last section of each name.
        var text: ?Shdr = null;
        i = 0;
        while (i < count) : (i += 1) {
            const h = try self.header(i);
            if (self.sectionNameIs(h, ".text")) text = h;
        }
        if (text) |h| return .{ .section = h };
        const n = try self.segmentCount();
        i = 0;
        while (i < n) : (i += 1) {
            const p = try self.programHeader(i);
            if (p.type == pt_load and p.flags == 5) return .{ .segment = p };
        }
        return null;
    }

    fn sectionNameIs(self: *const Elf, h: Shdr, name: []const u8) bool {
        // makeSection checked that this position is seekable.
        const start = self.shstrtab_offset + h.name;
        if (start >= self.data.len) return false;
        const rest = self.data[@intCast(start)..];
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse return false;
        return std.mem.eql(u8, rest[0..end], name);
    }

    const Phdr = struct { type: u32, flags: u32, offset: u64, vaddr: u64, filesz: u64 };

    fn phdrSize(self: *const Elf) u64 {
        return if (self.is64) 56 else 32;
    }

    /// pyelftools `_get_segment_header`. Nothing checks `n` against e_phnum.
    fn programHeader(self: *const Elf, n: u64) Error!Phdr {
        if (self.phoff > 0 and self.phentsize < self.phdrSize()) return error.InvalidElf;
        const step = std.math.mul(u64, n, self.phentsize) catch return error.InvalidElf;
        const pos = std.math.add(u64, self.phoff, step) catch return error.InvalidElf;
        if (!self.has(pos, self.phdrSize())) return error.InvalidElf;
        if (self.is64) return .{
            .type = self.int(u32, pos),
            .flags = self.int(u32, pos + 4),
            .offset = self.int(u64, pos + 8),
            .vaddr = self.int(u64, pos + 16),
            .filesz = self.int(u64, pos + 32),
        };
        return .{
            .type = self.int(u32, pos),
            .offset = self.int(u32, pos + 4),
            .vaddr = self.int(u32, pos + 8),
            .filesz = self.int(u32, pos + 16),
            .flags = self.int(u32, pos + 24),
        };
    }

    /// pyelftools `num_segments`.
    fn segmentCount(self: *Elf) Error!u64 {
        if (self.phnum < 0xffff) return self.phnum;
        const h = try self.header(0);
        try self.makeSection(h);
        return h.info;
    }

    /// telfhash `elf_get_imagebase`: the p_vaddr of the first PT_LOAD
    /// program header, reading headers until one is found or a read fails.
    fn imageBase(self: *const Elf) Error!u64 {
        if (self.phoff > 0 and self.phentsize < self.phdrSize()) return error.InvalidElf;
        // e_phoff is 0 too, so every read is of the ELF header, whose first
        // word (the magic) is never PT_LOAD.
        if (self.phentsize == 0) return error.Endless;
        var i: u64 = 0;
        while (true) : (i += 1) {
            const p = try self.programHeader(i);
            if (p.type == pt_load) return p.vaddr;
        }
    }

    /// `Section.data` and `Segment.data`: seek to `offset` and read `size`
    /// bytes, which stops at the end of the file.
    fn read(self: *const Elf, offset: u64, size: u64) Error![]const u8 {
        _ = try seekable(offset, 0);
        // CPython allocates `size` bytes before reading. Past the size of the
        // address space that always fails; below it, it depends on the
        // machine's memory, and this port reads as if it succeeded.
        if (size >= max_read) return error.InvalidElf;
        if (offset >= self.data.len) return "";
        const start: usize = @intCast(offset);
        const n: usize = @intCast(@min(size, self.data.len - start));
        return self.data[start..][0..n];
    }
};

const Arch = enum { x86, x64, arm, mips };

/// One linear sweep of capstone's `disasm` over `code`, which starts at
/// address `ofs`.
const Calls = struct {
    code: []const u8,
    ofs: u64,
    arch: Arch,

    /// Length of the instruction at `off`, or null where capstone stops.
    fn step(c: *const Calls, off: usize) ?usize {
        switch (c.arch) {
            .x86, .x64 => {
                const insn = x86.decode(c.code[off..], c.ofs +% off, c.mode()) orelse return null;
                return insn.len;
            },
            .arm => {
                const w = c.word(off) orelse return null;
                return if (words.armValid(w)) 4 else null;
            },
            .mips => {
                const w = c.word(off) orelse return null;
                return if (words.mipsValid(w)) 4 else null;
            },
        }
    }

    /// The string telfhash keeps for the instruction at `off`, which `step`
    /// accepted, or null if it keeps none.
    fn target(c: *const Calls, off: usize, buf: *[32]u8) ?[]const u8 {
        switch (c.arch) {
            .x86, .x64 => {
                const insn = x86.decode(c.code[off..], c.ofs +% off, c.mode()).?;
                return hex(buf, insn.call_target orelse return null);
            },
            .arm => return hex(buf, words.armCallTarget(c.word(off).?, c.ofs +% off) orelse return null),
            .mips => return words.mipsT9Load(c.word(off).?, buf[0..words.mips_max_len]),
        }
    }

    fn mode(c: *const Calls) x86.Mode {
        return if (c.arch == .x64) .x64 else .x86;
    }

    /// ARM is always decoded little-endian and MIPS big-endian, whatever the
    /// file says.
    fn word(c: *const Calls, off: usize) ?u32 {
        if (c.code.len - off < 4) return null;
        return std.mem.readInt(u32, c.code[off..][0..4], if (c.arch == .arm) .little else .big);
    }

    fn hex(buf: *[32]u8, v: u64) []const u8 {
        return std.fmt.bufPrint(buf, "{x}", .{v}) catch unreachable;
    }
};

/// Python's `data[start:]`, where a negative start counts from the end.
fn sliceFrom(data: []const u8, start: i128) []const u8 {
    if (start >= 0) return if (start >= data.len) data[data.len..] else data[@intCast(start)..];
    const from = @as(i128, data.len) + start;
    return if (from < 0) data else data[@intCast(from)..];
}

const pt_load = 1;
const elfcompress_zlib = 1;
const em_386 = 3;
const em_mips = 8;
const em_x86_64 = 62;

/// CPython cannot allocate a buffer this large on any 64-bit system.
const max_read: u64 = 1 << 47;

/// Largest position `lseek` accepts on ext4 with 4 KiB blocks. pyelftools
/// seeks before every read, so a string offset past it fails the whole file.
/// On other file systems the limit differs; it only matters for corrupt
/// files whose string offsets point terabytes past the end.
const max_seek: u64 = (1 << 44) - 4096;

fn seekable(base: u64, off: u64) Error!u64 {
    const pos = std.math.add(u64, base, off) catch return error.InvalidElf;
    if (pos > max_seek) return error.InvalidElf;
    return pos;
}

/// The UTF-8 encoding of U+212A KELVIN SIGN, the only non-ASCII character
/// whose Python lowercase is ASCII ("k").
const kelvin = "\xe2\x84\xaa";

/// Lowercased characters of a symbol name, as Python's `str.lower` gives
/// them for names that pass `lowersToAscii`.
const Lower = struct {
    s: []const u8,
    i: usize = 0,
    fn next(self: *Lower) ?u8 {
        if (self.i >= self.s.len) return null;
        if (std.mem.startsWith(u8, self.s[self.i..], kelvin)) {
            self.i += kelvin.len;
            return 'k';
        }
        const c = self.s[self.i];
        self.i += 1;
        return std.ascii.toLower(c);
    }
};

fn lowersToAscii(name: []const u8) bool {
    var i: usize = 0;
    while (i < name.len) {
        if (name[i] < 0x80) {
            i += 1;
        } else if (std.mem.startsWith(u8, name[i..], kelvin)) {
            i += kelvin.len;
        } else return false;
    }
    return true;
}

fn lowerOrder(a: []const u8, b: []const u8) std.math.Order {
    var x = Lower{ .s = a };
    var y = Lower{ .s = b };
    while (true) {
        const ca = x.next();
        const cb = y.next();
        if (ca == null and cb == null) return .eq;
        if (ca == null) return .lt;
        if (cb == null) return .gt;
        if (ca.? != cb.?) return std.math.order(ca.?, cb.?);
    }
}

const exclusions = [_][]const u8{ "__libc_start_main", "main", "abort", "cachectl", "cacheflush", "puts", "atol", "malloc_trim" };

/// telfhash's exclusion list. The regular expressions `^[_\.].*$`, `^.*64$`,
/// `^str.*$` and `^mem.*$` are matched with Python `re.search`, where `.`
/// does not match a newline and `$` also matches before a final newline.
fn excluded(name: []const u8) bool {
    for (exclusions) |x| if (std.mem.eql(u8, name, x)) return true;
    const body = if (std.mem.endsWith(u8, name, "\n")) name[0 .. name.len - 1] else name;
    if (body.len == 0) return false;
    const one_line = std.mem.indexOfScalar(u8, body, '\n') == null;
    if (!one_line) return false;
    if (body[0] == '_' or body[0] == '.') return true;
    if (std.mem.endsWith(u8, body, "64")) return true;
    if (std.mem.startsWith(u8, body, "str") or std.mem.startsWith(u8, body, "mem")) return true;
    return false;
}

// ---- tests ------------------------------------------------------------------

const testing = std.testing;

test "exclusion list follows Python re.search semantics" {
    try testing.expect(excluded("main"));
    try testing.expect(excluded("_start"));
    try testing.expect(excluded(".hidden"));
    try testing.expect(excluded("lseek64"));
    try testing.expect(excluded("strcpy"));
    try testing.expect(excluded("memcpy"));
    try testing.expect(excluded("memcpy\n"));
    try testing.expect(!excluded("mem\ncpy"));
    try testing.expect(!excluded("_a\nb"));
    try testing.expect(!excluded("Strcpy"));
    try testing.expect(!excluded("printf"));
    try testing.expect(!excluded("mainx"));
}

test "lowercasing and order" {
    try testing.expect(lowersToAscii("Foo"));
    try testing.expect(lowersToAscii("\xe2\x84\xaaelvin"));
    try testing.expect(!lowersToAscii("caf\xc3\xa9"));
    try testing.expectEqual(std.math.Order.eq, lowerOrder("ABC", "abc"));
    try testing.expectEqual(std.math.Order.eq, lowerOrder("\xe2\x84\xaa", "k"));
    try testing.expectEqual(std.math.Order.lt, lowerOrder("ab", "abc"));
    try testing.expectEqual(std.math.Order.lt, lowerOrder("Zeta", "{"));
}

/// A small ELF64 little-endian file: NULL, .dynstr, .dynsym, .shstrtab.
fn buildElf(buf: []u8, names: []const []const u8) []u8 {
    @memset(buf, 0);
    @memcpy(buf[0..4], "\x7fELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    std.mem.writeInt(u16, buf[16..18], 3, .little); // ET_DYN
    std.mem.writeInt(u16, buf[18..20], 62, .little); // x86-64
    // strings at 0x100
    const str_off: usize = 0x100;
    var p: usize = str_off + 1;
    var name_offs: [32]u32 = undefined;
    for (names, 0..) |n, i| {
        name_offs[i] = @intCast(p - str_off);
        @memcpy(buf[p..][0..n.len], n);
        p += n.len + 1;
    }
    const str_size = p - str_off;
    // symbols at 0x400: null symbol, then one per name
    const sym_off: usize = 0x400;
    for (names, 0..) |_, i| {
        const e = buf[sym_off + 24 * (i + 1) ..];
        std.mem.writeInt(u32, e[0..4], name_offs[i], .little);
        e[4] = (1 << 4) | 2; // GLOBAL FUNC
    }
    const sym_size = 24 * (names.len + 1);
    // shstrtab at 0x800
    const shstr = "\x00.dynstr\x00.dynsym\x00.shstrtab\x00";
    @memcpy(buf[0x800..][0..shstr.len], shstr);
    // section headers at 0x900
    const sh: usize = 0x900;
    std.mem.writeInt(u64, buf[40..48], sh, .little);
    std.mem.writeInt(u16, buf[52..54], 64, .little);
    std.mem.writeInt(u16, buf[58..60], 64, .little);
    std.mem.writeInt(u16, buf[60..62], 4, .little);
    std.mem.writeInt(u16, buf[62..64], 3, .little);
    const Sec = struct { name: u32, type: u32, off: u64, size: u64, link: u32, entsize: u64 };
    const secs = [_]Sec{
        .{ .name = 0, .type = 0, .off = 0, .size = 0, .link = 0, .entsize = 0 },
        .{ .name = 1, .type = 3, .off = str_off, .size = str_size, .link = 0, .entsize = 0 },
        .{ .name = 9, .type = 11, .off = sym_off, .size = sym_size, .link = 1, .entsize = 24 },
        .{ .name = 17, .type = 3, .off = 0x800, .size = shstr.len, .link = 0, .entsize = 0 },
    };
    for (secs, 0..) |s, i| {
        const e = buf[sh + 64 * i ..];
        std.mem.writeInt(u32, e[0..4], s.name, .little);
        std.mem.writeInt(u32, e[4..8], s.type, .little);
        std.mem.writeInt(u64, e[24..32], s.off, .little);
        std.mem.writeInt(u64, e[32..40], s.size, .little);
        std.mem.writeInt(u32, e[40..44], s.link, .little);
        std.mem.writeInt(u64, e[56..64], s.entsize, .little);
    }
    return buf[0 .. sh + 64 * secs.len];
}

test "telfhash of a dynamic symbol table matches telfhash" {
    var buf: [4096]u8 = undefined;
    const elf = buildElf(&buf, &.{
        "printf",   "Open",     "socket",  "connect", "send",    "recv",   "close",    "fork",
        "execve",   "getenv",   "_init",   "main",    "strlen",  "memcpy", "lseek64",  "fopen",
        "fread",    "fwrite",   "fclose",  "sleep",   "time",    "rand",   "srand",    "exit",
        "pthread_create", "pthread_join", "dlopen", "dlsym", "kill", "signal", "inet_addr", "htons",
    });
    var scratch: [64]u32 = undefined;
    const r = try hash(elf, &scratch);
    var out: [max_string_length]u8 = undefined;
    try testing.expectEqualStrings("t123c01295e5790c8c46f66c71444459a665433125857409105f84d5d1803f913b24ca67", toString(r, &out));
}

test "few symbols give tnull, none give -, non-ELF input is rejected" {
    var buf: [4096]u8 = undefined;
    var scratch: [64]u32 = undefined;
    var out: [max_string_length]u8 = undefined;
    try testing.expectEqualStrings("tnull", toString(try hash(buildElf(&buf, &.{ "printf", "socket" }), &scratch), &out));
    try testing.expectEqualStrings("-", toString(try hash(buildElf(&buf, &.{ "main", "_init" }), &scratch), &out));
    try testing.expectError(error.InvalidElf, hash("MZ", &scratch));
    try testing.expectError(error.InvalidElf, hash("\x7fELF\x02\x01", &scratch));
}

test "no panic on truncated or corrupted copies" {
    var buf: [4096]u8 = undefined;
    const elf = buildElf(&buf, &.{ "printf", "socket", "connect", "send" });
    var scratch: [8]u32 = undefined;
    var copy: [4096]u8 = undefined;
    for (0..elf.len) |n| _ = hash(elf[0..n], &scratch) catch {};
    var prng = std.Random.DefaultPrng.init(3);
    const r = prng.random();
    for (0..3000) |_| {
        @memcpy(copy[0..elf.len], elf);
        for (0..1 + r.uintLessThan(usize, 6)) |_| copy[r.uintLessThan(usize, elf.len)] = r.int(u8);
        _ = hash(copy[0..elf.len], &scratch) catch {};
    }
}

const Target = struct { machine: u16, is64: bool, big: bool };

/// A small executable without a symbol table: one read-execute PT_LOAD
/// segment at 0x400000 holding the whole file, `code` in `.text` at file
/// offset 0x100 (the entry point), and a section name table.
fn buildStatic(buf: []u8, t: Target, code: []const u8) []u8 {
    @memset(buf, 0);
    const end: std.builtin.Endian = if (t.big) .big else .little;
    const W = struct {
        b: []u8,
        e: std.builtin.Endian,
        is64: bool,
        fn int(w: @This(), comptime T: type, off: usize, v: u64) void {
            std.mem.writeInt(T, w.b[off..][0..@sizeOf(T)], @intCast(v), w.e);
        }
        fn word(w: @This(), off: usize, v: u64) void {
            if (w.is64) w.int(u64, off, v) else w.int(u32, off, v);
        }
    };
    const w = W{ .b = buf, .e = end, .is64 = t.is64 };
    const base: u64 = 0x400000;
    const code_off: usize = 0x100;
    @memcpy(buf[code_off..][0..code.len], code);
    const shstr = "\x00.text\x00.shstrtab\x00";
    const str_off = std.mem.alignForward(usize, code_off + code.len, 8);
    @memcpy(buf[str_off..][0..shstr.len], shstr);
    const sh_off = std.mem.alignForward(usize, str_off + shstr.len, 8);
    const shsize: usize = if (t.is64) 64 else 40;
    const total = sh_off + 3 * shsize;

    @memcpy(buf[0..4], "\x7fELF");
    buf[4] = if (t.is64) 2 else 1;
    buf[5] = if (t.big) 2 else 1;
    buf[6] = 1;
    w.int(u16, 16, 2); // ET_EXEC
    w.int(u16, 18, t.machine);
    w.int(u32, 20, 1);
    w.word(24, base + code_off); // e_entry
    const ph: usize = if (t.is64) 64 else 52;
    if (t.is64) {
        w.int(u64, 32, ph);
        w.int(u64, 40, sh_off);
        w.int(u16, 52, 64);
        w.int(u16, 54, 56);
        w.int(u16, 56, 1);
        w.int(u16, 58, 64);
        w.int(u16, 60, 3);
        w.int(u16, 62, 2);
        w.int(u32, ph, 1); // PT_LOAD
        w.int(u32, ph + 4, 5); // R-X
        w.int(u64, ph + 16, base);
        w.int(u64, ph + 24, base);
        w.int(u64, ph + 32, total);
        w.int(u64, ph + 40, total);
    } else {
        w.int(u32, 28, ph);
        w.int(u32, 32, sh_off);
        w.int(u16, 40, 52);
        w.int(u16, 42, 32);
        w.int(u16, 44, 1);
        w.int(u16, 46, 40);
        w.int(u16, 48, 3);
        w.int(u16, 50, 2);
        w.int(u32, ph, 1);
        w.int(u32, ph + 8, base);
        w.int(u32, ph + 12, base);
        w.int(u32, ph + 16, total);
        w.int(u32, ph + 20, total);
        w.int(u32, ph + 24, 5);
    }
    // name, type, flags, addr, offset, size
    const secs = [_][6]u64{
        .{ 0, 0, 0, 0, 0, 0 },
        .{ 1, 1, 6, base + code_off, code_off, code.len },
        .{ 7, 3, 0, 0, str_off, shstr.len },
    };
    for (secs, 0..) |s, i| {
        const o = sh_off + shsize * i;
        w.int(u32, o, s[0]);
        w.int(u32, o + 4, s[1]);
        if (t.is64) {
            w.int(u64, o + 8, s[2]);
            w.int(u64, o + 16, s[3]);
            w.int(u64, o + 24, s[4]);
            w.int(u64, o + 32, s[5]);
        } else {
            w.int(u32, o + 8, s[2]);
            w.int(u32, o + 12, s[3]);
            w.int(u32, o + 16, s[4]);
            w.int(u32, o + 20, s[5]);
        }
    }
    return buf[0..total];
}

/// Code with 24 direct calls (the first one twice) for `t`, written to `buf`.
fn callCode(buf: []u8, t: Target) []u8 {
    var n: usize = 0;
    var x: u32 = 0x1234567;
    var first: u32 = 0;
    for (0..25) |i| {
        x = x *% 1103515245 +% 12345;
        if (i == 0) first = x;
        const k = if (i == 24) first else x;
        switch (t.machine) {
            62, 3 => {
                buf[n] = 0xe8;
                std.mem.writeInt(u32, buf[n + 1 ..][0..4], k >> 12, .little);
                n += 5;
            },
            40 => {
                std.mem.writeInt(u32, buf[n..][0..4], 0xeb000000 | (k >> 12 & 0xffff), .little);
                n += 4;
            },
            else => {
                std.mem.writeInt(u32, buf[n..][0..4], 0x8f990000 | (k >> 16), .big);
                n += 4;
            },
        }
    }
    return buf[0..n];
}

const static_targets = [_]Target{
    .{ .machine = 62, .is64 = true, .big = false },
    .{ .machine = 3, .is64 = false, .big = false },
    .{ .machine = 40, .is64 = false, .big = false },
    .{ .machine = 8, .is64 = false, .big = true },
};

test "files without a symbol table hash their call targets" {
    const want = [_][]const u8{
        "t1e5c08ca42daed6a1368710ea7712c6e264310c6e19c124f0c8583928de8a7c4996e63b",
        "t1e5c08ca42daed6a1368710ea7712c6e264310c6e19c124f0c8583928de8a7c4996e63b",
        "t1f1c0807064dd9c0666d75c50b347f9815c3815a4c4f731565da44114cfe21c847f0454",
        "t1d8b012014208a999e347dc81114b414984f6b84100d095f37f1ab4489908b643830d04",
    };
    var buf: [2048]u8 = undefined;
    var code: [256]u8 = undefined;
    var scratch: [512]u32 = undefined;
    var out: [max_string_length]u8 = undefined;
    for (static_targets, want) |t, w| {
        const elf = buildStatic(&buf, t, callCode(&code, t));
        try testing.expectEqualStrings(w, toString(try hash(elf, &scratch), &out));
    }
}

test "without sections, the read-execute segment is swept from the entry point" {
    var buf: [2048]u8 = undefined;
    var code: [256]u8 = undefined;
    var scratch: [512]u32 = undefined;
    var out: [max_string_length]u8 = undefined;
    const t = static_targets[2];
    const elf = buildStatic(&buf, t, callCode(&code, t));
    std.mem.writeInt(u32, elf[32..36], 0, .little); // e_shoff
    std.mem.writeInt(u32, elf[24..28], 0x400108, .little); // e_entry, two words in
    try testing.expectEqualStrings(
        "t1a7c08cb068c99c06a6eb6c50b307f981583819a4c4fa30aa9da841188be22c807f0454",
        toString(try hash(elf, &scratch), &out),
    );
}

test "other architectures give -, and some headers never finish in telfhash" {
    var buf: [2048]u8 = undefined;
    var code: [256]u8 = undefined;
    var scratch: [512]u32 = undefined;
    var out: [max_string_length]u8 = undefined;
    const t = static_targets[0];
    const elf = buildStatic(&buf, t, callCode(&code, t));
    std.mem.writeInt(u16, elf[18..20], 183, .little); // AArch64
    try testing.expectEqualStrings("-", toString(try hash(elf, &scratch), &out));
    std.mem.writeInt(u16, elf[18..20], 62, .little);
    std.mem.writeInt(u64, elf[32..40], 0, .little); // e_phoff
    std.mem.writeInt(u16, elf[54..56], 0, .little); // e_phentsize
    try testing.expectError(error.Endless, hash(elf, &scratch));
    try testing.expectError(error.WorkspaceTooSmall, hash(buildStatic(&buf, t, callCode(&code, t)), scratch[0..8]));
}

test "no panic on corrupted files without a symbol table" {
    var buf: [2048]u8 = undefined;
    var code: [256]u8 = undefined;
    var copy: [2048]u8 = undefined;
    var scratch: [512]u32 = undefined;
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    for (static_targets) |t| {
        const elf = buildStatic(&buf, t, callCode(&code, t));
        for (0..elf.len) |n| _ = hash(elf[0..n], &scratch) catch {};
        for (0..2000) |_| {
            @memcpy(copy[0..elf.len], elf);
            for (0..1 + r.uintLessThan(usize, 4)) |_| copy[r.uintLessThan(usize, elf.len)] = r.int(u8);
            _ = hash(copy[0..elf.len], &scratch) catch {};
        }
    }
}

test "scratchLength is enough for the worst case" {
    // Every word a distinct ARM call.
    var buf: [8192]u8 = undefined;
    var code: [4096]u8 = undefined;
    const t = static_targets[2];
    for (0..code.len / 4) |i| std.mem.writeInt(u32, code[4 * i ..][0..4], 0xeb000000 | @as(u32, @intCast(i)), .little);
    const elf = buildStatic(&buf, t, &code);
    var scratch: [4096]u32 = undefined;
    try testing.expect(scratchLength(elf.len) <= scratch.len);
    _ = try hash(elf, scratch[0..scratchLength(elf.len)]);
}
