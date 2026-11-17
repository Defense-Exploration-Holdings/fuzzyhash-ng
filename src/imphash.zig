// SPDX-License-Identifier: MIT
//! Import hash (imphash) of PE files, compatible with pefile 2024.8.26
//! `PE.get_imphash()`.
//!
//! The import table walk follows pefile, including its limits and its
//! handling of damaged tables, so that the result matches pefile for every
//! input, not only for well-formed files. pefile is Copyright (c) 2004-2024
//! Ero Carrera, MIT licence (LICENSES/pefile-LICENSE).
//!
//! Result: the MD5 of the lowercase strings `library.function`, joined by
//! commas, in import table order. The library is the DLL name without a
//! `.dll`, `.ocx` or `.sys` extension. Functions imported by ordinal are
//! named from pefile's tables for oleaut32.dll, ws2_32.dll and wsock32.dll,
//! otherwise `ord<N>`.
//!
//! `hash` returns null where pefile returns an empty string (no import
//! directory, or none of its entries could be read), and `error.InvalidPe`
//! where pefile refuses to open the file.

const std = @import("std");
const ordinals = @import("imphash/ordinals.zig");

pub const Error = error{InvalidPe};

/// 16-byte MD5 digest.
pub const Digest = [16]u8;
pub const hex_length = 32;

/// pefile limits.
const max_sections: usize = 0x800;
const max_import_symbols: u64 = 0x2000;
const max_name_length: u64 = 0x200;
const max_dll_length: u64 = 0x200;
const max_address_spread: u64 = 128 * 1024 * 1024;
const max_repeated_addresses: u32 = 15;

/// A table walk stops once the shared symbol counter passes
/// `max_import_symbols`, so all walks for one descriptor together hold at most
/// this many entries.
const value_capacity: usize = max_import_symbols + 2;

/// Working memory for `hash`, about 68 KiB. Keep it off small stacks.
pub const Workspace = struct {
    /// Parsed sections, as indexes into the section table, sorted by
    /// VirtualAddress (stable).
    order: [max_sections]u16 = undefined,
    /// Thunk values of the current descriptor: the lookup table, then the
    /// address table. Reused for the symbol list.
    values: [value_capacity]u64 = undefined,
};

/// Writes the digest as 32 lowercase hex characters.
pub fn toHex(digest: Digest, out: *[hex_length]u8) []const u8 {
    const chars = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[2 * i] = chars[b >> 4];
        out[2 * i + 1] = chars[b & 15];
    }
    return out;
}

/// Imphash of a PE file held in memory.
pub fn hash(ws: *Workspace, pe: []const u8) Error!?Digest {
    var p = Pe{ .data = pe, .len = pe.len, .ws = ws };
    try p.parseHeaders();
    return p.imphash();
}

const Section = struct {
    va: u64,
    vsize: u64,
    raw_size: u64,
    ptr: u64,
};

const Table = struct {
    /// Start and length in `Workspace.values`.
    start: usize,
    len: usize,
};

/// Outcome of one table walk. pefile distinguishes an empty list (bogus
/// table) from None (read error); both end up the same way in `parseImports`,
/// except that a non-empty list wins.
const Walk = union(enum) {
    table: Table,
    none,
};

const Pe = struct {
    data: []const u8,
    len: u64,
    ws: *Workspace,

    pe64: bool = false,
    section_alignment: u64 = 0,
    file_alignment: u64 = 0,
    entry_point: u64 = 0,
    import_rva: u64 = 0,
    has_import_dir: bool = false,
    sections_offset: u64 = 0,
    section_count: usize = 0,
    header_len: u64 = 0,
    /// pefile caches the last section found by RVA and checks it first.
    last_used: ?usize = null,
    total_symbols: u64 = 0,
    values_used: usize = 0,

    // ---- raw reads ----------------------------------------------------------

    /// Little-endian read with bytes past the end of the file read as zero.
    fn readPadded(self: *const Pe, offset: u64, comptime T: type) T {
        var v: T = 0;
        inline for (0..@sizeOf(T)) |i| {
            const at = offset + i;
            if (at < self.len) v |= @as(T, self.data[@intCast(at)]) << (8 * i);
        }
        return v;
    }

    /// Python `data[start:end]` for non-negative bounds.
    fn slice(self: *const Pe, start: u64, end: u64) []const u8 {
        const s = @min(start, self.len);
        const e = @min(end, self.len);
        if (e <= s) return self.data[0..0];
        return self.data[@intCast(s)..@intCast(e)];
    }

    fn sliceOffset(self: *const Pe, s: []const u8) u64 {
        return @intFromPtr(s.ptr) - @intFromPtr(self.data.ptr);
    }

    // ---- headers -----------------------------------------------------------

    fn parseHeaders(self: *Pe) Error!void {
        if (self.len < 64) return error.InvalidPe;
        const e_magic = self.readPadded(0, u16);
        if (e_magic == 0x4D5A) return error.InvalidPe; // "ZM"
        if (e_magic != 0x5A4D) return error.InvalidPe; // "MZ"
        const nt = self.readPadded(0x3c, u32);
        if (nt > self.len) return error.InvalidPe;

        if (self.len - nt < 4) return error.InvalidPe;
        const signature = self.readPadded(nt, u32);
        if (signature != 0x00004550) return error.InvalidPe;

        const file_header = nt + 4;
        if (self.len < file_header or self.len - file_header < 20) return error.InvalidPe;
        const number_of_sections = self.readPadded(file_header + 2, u16);
        const size_of_optional_header = self.readPadded(file_header + 16, u16);

        const opt = file_header + 20;
        const avail = if (self.len > opt) self.len - opt else 0;
        // The 32-bit layout is read first. Under 96 bytes pefile pads with zeros
        // when at least 69 are present.
        if (avail < 69) return error.InvalidPe;
        const magic = self.readPadded(opt, u16);
        var opt_size: u64 = 96;
        if (magic == 0x10b) {
            self.pe64 = false;
        } else if (magic == 0x20b) {
            self.pe64 = true;
            opt_size = 112;
            if (avail < 73) return error.InvalidPe;
        } else {
            self.pe64 = false; // unknown type: read as PE32
        }
        self.entry_point = self.readPadded(opt + 16, u32);
        self.section_alignment = self.readPadded(opt + 32, u32);
        self.file_alignment = self.readPadded(opt + 36, u32);
        const rva_count: u64 = self.readPadded(opt + opt_size - 4, u32) & 0x7FFF_FFFF;

        // Data directories: entry i at opt + opt_size + 8 i, at most 16. A read
        // starting exactly at the end of the file stops the list; reads past
        // it give zeros.
        var dir_offset = opt + opt_size;
        var i: u64 = 0;
        while (i < @min(rva_count, 16)) : (i += 1) {
            if (dir_offset == self.len) break;
            if (i == 1) {
                self.import_rva = self.readPadded(dir_offset, u32);
                self.has_import_dir = true;
            }
            dir_offset += 8;
        }

        self.sections_offset = opt + size_of_optional_header;
        try self.parseSections(number_of_sections);

        var header_end = self.sections_offset;
        if (number_of_sections > 0 and self.section_count > 0) header_end += 40 * @as(u64, number_of_sections);
        var lowest: ?u64 = null;
        for (self.ws.order[0..self.section_count]) |idx| {
            const s = self.section(idx);
            if (s.ptr > 0) {
                const adj = s.ptr & ~@as(u64, 0x1ff);
                lowest = if (lowest) |l| @min(l, adj) else adj;
            }
        }
        const header_size = if (lowest == null or lowest.? == 0 or lowest.? < header_end) header_end else lowest.?;
        self.header_len = @min(header_size, self.len);

        // pefile looks up the entry point here, which primes the section cache.
        _ = self.sectionByRva(self.entry_point);
    }

    fn sectionHeaderOffset(self: *const Pe, index: usize) u64 {
        return self.sections_offset + 40 * @as(u64, index);
    }

    fn section(self: *const Pe, index: u16) Section {
        const off = self.sectionHeaderOffset(index);
        return .{
            .vsize = self.readPadded(off + 8, u32),
            .va = self.readPadded(off + 12, u32),
            .raw_size = self.readPadded(off + 16, u32),
            .ptr = self.readPadded(off + 20, u32),
        };
    }

    fn parseSections(self: *Pe, count: u16) Error!void {
        var n: usize = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (i >= max_sections) break;
            const off = self.sectionHeaderOffset(i);
            const raw = self.slice(off, off + 40);
            if (raw.len == 40 and std.mem.allEqual(u8, raw, 0)) break;
            if (raw.len == 0) break;
            if (raw.len < 40) return error.InvalidPe;

            const s = self.section(@intCast(i));
            var errors: u32 = 0;
            if (s.raw_size + s.ptr > self.len) errors += 1;
            if ((s.ptr & ~@as(u64, 0x1ff)) > self.len) errors += 1;
            if (s.vsize > 0x1000_0000) errors += 1;
            if (self.alignSection(s.va) > 0x1000_0000) errors += 1;
            if (self.file_alignment != 0 and s.ptr % self.file_alignment != 0) errors += 1;
            if (errors >= 3) break;

            // Stable insertion by VirtualAddress.
            var at = n;
            while (at > 0 and self.section(self.ws.order[at - 1]).va > s.va) : (at -= 1) {
                self.ws.order[at] = self.ws.order[at - 1];
            }
            self.ws.order[at] = @intCast(i);
            n += 1;
        }
        self.section_count = n;
    }

    // ---- address mapping ---------------------------------------------------

    fn alignSection(self: *const Pe, va: u64) u64 {
        var a = self.section_alignment;
        if (a < 0x1000) a = self.file_alignment;
        if (a != 0 and va % a != 0) return a * (va / a);
        return va;
    }

    fn ptrAdj(self: *const Pe, s: Section) u64 {
        if (self.section_alignment < 0x1000 and s.ptr == s.va) return s.va;
        return s.ptr & ~@as(u64, 0x1ff);
    }

    /// pefile `SectionStructure.contains_rva`. `pos` is the place in `order`.
    fn contains(self: *const Pe, pos: usize, rva: u64) bool {
        const s = self.section(self.ws.order[pos]);
        const va_adj: i64 = @intCast(self.alignSection(s.va));
        const room: i64 = @as(i64, @intCast(self.len)) - @as(i64, @intCast(self.ptrAdj(s)));
        var size: i64 = if (room < @as(i64, @intCast(s.raw_size)))
            @intCast(s.vsize)
        else
            @intCast(@max(s.raw_size, s.vsize));
        if (pos + 1 < self.section_count) {
            const next: i64 = @intCast(self.section(self.ws.order[pos + 1]).va);
            if (next > @as(i64, @intCast(s.va)) and va_adj + size > next) size = next - va_adj;
        }
        const r: i64 = @intCast(rva);
        return va_adj <= r and r < va_adj + size;
    }

    fn sectionByRva(self: *Pe, rva: u64) ?usize {
        // RVAs past 2^33 are in no section; this also keeps the i64 math exact.
        if (rva >= 1 << 33) return null;
        if (self.last_used) |pos| {
            if (self.contains(pos, rva)) return pos;
        }
        for (0..self.section_count) |pos| {
            if (self.contains(pos, rva)) {
                self.last_used = pos;
                return pos;
            }
        }
        return null;
    }

    fn sectionData(self: *const Pe, pos: usize, rva: u64, length: u64) []const u8 {
        const s = self.section(self.ws.order[pos]);
        const offset = rva - self.alignSection(s.va) + self.ptrAdj(s);
        var end = offset + length;
        if (end > s.ptr + s.raw_size) end = s.ptr + s.raw_size;
        return self.slice(offset, end);
    }

    /// pefile `PE.get_data`.
    fn getData(self: *Pe, rva: u64, length: u64) error{Unmapped}![]const u8 {
        if (self.sectionByRva(rva)) |pos| return self.sectionData(pos, rva, length);
        if (rva < self.header_len) return self.slice(rva, @min(rva + length, self.header_len));
        if (rva < self.len) return self.slice(rva, rva + length);
        return error.Unmapped;
    }

    /// pefile `PE.get_string_at_rva`: bytes up to the first NUL.
    fn getString(self: *Pe, rva: u64, max_length: u64) []const u8 {
        const raw = if (self.sectionByRva(rva)) |pos|
            self.sectionData(pos, rva, max_length)
        else
            self.slice(rva, rva + max_length);
        const end = std.mem.indexOfScalar(u8, raw, 0) orelse raw.len;
        return raw[0..end];
    }

    // ---- import directory --------------------------------------------------

    fn ordinalFlag(self: *const Pe) u64 {
        return if (self.pe64) 1 << 63 else 1 << 31;
    }

    /// pefile `PE.get_import_table`. Appends entries to `ws.values`.
    fn importTable(self: *Pe, start_rva: u64, max_length: u64) Walk {
        const start = self.values_used;
        const size: u64 = if (self.pe64) 8 else 4;
        const flag = self.ordinalFlag();
        var repeated: u32 = 0;
        var min32: ?u64 = null;
        var max32: u64 = 0;
        var min64: ?u64 = null;
        var max64: u64 = 0;
        var rva = start_rva;
        while (rva != 0) {
            if (rva >= start_rva + max_length) break;
            if (self.total_symbols > max_import_symbols) break;
            self.total_symbols += 1;
            if (repeated >= max_repeated_addresses) return .{ .table = .{ .start = start, .len = 0 } };
            if (min32) |m| if (max32 - m > max_address_spread) return .{ .table = .{ .start = start, .len = 0 } };
            if (min64) |m| if (max64 - m > max_address_spread) return .{ .table = .{ .start = start, .len = 0 } };

            const raw = self.getData(rva, size) catch return .none;
            if (raw.len != size) return .none;
            const value: u64 = if (self.pe64) std.mem.readInt(u64, raw[0..8], .little) else std.mem.readInt(u32, raw[0..4], .little);

            if (value >= start_rva and value <= rva) break;
            if (value != 0) {
                if (value & flag != 0) {
                    if (value & 0x7FFF_FFFF > 0xFFFF) return .{ .table = .{ .start = start, .len = 0 } };
                } else {
                    for (self.ws.values[start..self.values_used]) |seen| {
                        if (seen == value) {
                            repeated += 1;
                            break;
                        }
                    }
                    if (value >= 1 << 32) {
                        min64 = if (min64) |m| @min(m, value) else value;
                        max64 = @max(max64, value);
                    } else {
                        min32 = if (min32) |m| @min(m, value) else value;
                        max32 = @max(max32, value);
                    }
                }
            }
            if (value == 0) break;
            rva += size;
            // Capacity holds by the shared counter; checked anyway.
            if (self.values_used >= value_capacity) return .{ .table = .{ .start = start, .len = 0 } };
            self.ws.values[self.values_used] = value;
            self.values_used += 1;
        }
        return .{ .table = .{ .start = start, .len = self.values_used - start } };
    }

    // Symbol encoding in `ws.values` after `parseImports`.
    const sym_ordinal: u64 = 1 << 62;
    const len_bits = 10;

    /// pefile `PE.parse_imports`. Returns the symbols (in `ws.values`) or
    /// error.Invalid when pefile raises.
    fn parseImports(self: *Pe, oft: u64, ft: u64, max_length: u64) error{Invalid}!Table {
        self.values_used = 0;
        const ilt = self.importTable(oft, max_length);
        const iat = self.importTable(ft, max_length);
        const ilt_len = switch (ilt) {
            .table => |t| t.len,
            .none => 0,
        };
        const iat_len = switch (iat) {
            .table => |t| t.len,
            .none => 0,
        };
        if (ilt_len == 0 and iat_len == 0) return .{ .start = 0, .len = 0 };
        const table = if (ilt_len != 0) ilt.table else iat.table;

        const flag = self.ordinalFlag();
        var out: usize = table.start;
        var num_invalid: usize = 0;
        for (0..table.len) |idx| {
            const value = self.ws.values[table.start + idx];
            var ordinal: ?u64 = null;
            var name: ?[]const u8 = null;
            if (value & flag != 0) {
                ordinal = value & 0xFFFF;
            } else if (self.getData(value, 2)) |_| {
                const s = self.getString(value + 2, max_name_length);
                name = if (validFunctionName(s)) s else "*invalid*";
            } else |_| {}

            if (ordinal == null and name == null) return error.Invalid;
            if (name) |n| if (std.mem.eql(u8, n, "*invalid*")) {
                if (num_invalid > 1000 and num_invalid == idx) return error.Invalid;
                num_invalid += 1;
                continue;
            };
            if (ordinal) |o| {
                if (o != 0) {
                    self.ws.values[out] = sym_ordinal | o;
                    out += 1;
                }
            } else if (name.?.len != 0) {
                const off = self.sliceOffset(name.?);
                self.ws.values[out] = (off << len_bits) | name.?.len;
                out += 1;
            }
        }
        return .{ .start = table.start, .len = out - table.start };
    }

    fn imphash(self: *Pe) ?Digest {
        if (!self.has_import_dir or self.import_rva == 0) return null;
        var md5 = std.crypto.hash.Md5.init(.{});
        var any_entry = false;
        var first_string = true;
        var error_count: u32 = 0;
        var rva = self.import_rva;
        while (true) {
            const desc = self.getData(rva, 20) catch break;
            if (desc.len < 20) break;
            if (std.mem.allEqual(u8, desc, 0)) break;
            const desc_offset = self.sliceOffset(desc);
            const oft: u64 = std.mem.readInt(u32, desc[0..4], .little);
            const name_rva: u64 = std.mem.readInt(u32, desc[12..16], .little);
            const ft: u64 = std.mem.readInt(u32, desc[16..20], .little);
            rva += 20;

            var max_len = self.len - desc_offset;
            if (rva > oft or rva > ft) {
                const a: i64 = @as(i64, @intCast(rva)) - @as(i64, @intCast(oft));
                const b: i64 = @as(i64, @intCast(rva)) - @as(i64, @intCast(ft));
                max_len = @intCast(@max(a, b));
            }

            const symbols: Table = self.parseImports(oft, ft, max_len) catch .{ .start = 0, .len = 0 };
            if (error_count > 5) break;
            if (symbols.len == 0) {
                error_count += 1;
                continue;
            }

            var dll = self.getString(name_rva, max_dll_length);
            if (!validDosFilename(dll)) dll = "*invalid*";
            if (dll.len == 0) continue;
            any_entry = true;

            var lower_buf: [max_dll_length]u8 = undefined;
            const dll_lower = std.ascii.lowerString(&lower_buf, dll);
            var lib = dll_lower;
            if (std.mem.lastIndexOfScalar(u8, lib, '.')) |dot| {
                const ext = lib[dot + 1 ..];
                if (std.mem.eql(u8, ext, "dll") or std.mem.eql(u8, ext, "ocx") or std.mem.eql(u8, ext, "sys")) lib = lib[0..dot];
            }
            const table = ordinalTable(dll_lower);

            for (self.ws.values[symbols.start..][0..symbols.len]) |sym| {
                if (!first_string) md5.update(",");
                first_string = false;
                md5.update(lib);
                md5.update(".");
                if (sym & sym_ordinal != 0) {
                    const ord: u16 = @intCast(sym & 0xFFFF);
                    if (table) |t| if (lookupOrdinal(t, ord)) |n| {
                        updateLower(&md5, n);
                        continue;
                    };
                    var num: [8]u8 = undefined;
                    md5.update("ord");
                    md5.update(std.fmt.bufPrint(&num, "{d}", .{ord}) catch unreachable);
                } else {
                    const off = sym >> len_bits;
                    const len = sym & ((1 << len_bits) - 1);
                    updateLower(&md5, self.data[@intCast(off)..][0..@intCast(len)]);
                }
            }
        }
        if (!any_entry) return null;
        var digest: Digest = undefined;
        md5.final(&digest);
        return digest;
    }
};

fn updateLower(md5: *std.crypto.hash.Md5, s: []const u8) void {
    var buf: [64]u8 = undefined;
    var rest = s;
    while (rest.len > 0) {
        const n = @min(rest.len, buf.len);
        md5.update(std.ascii.lowerString(buf[0..n], rest[0..n]));
        rest = rest[n..];
    }
}

fn ordinalTable(dll_lower: []const u8) ?[]const ordinals.Entry {
    if (std.mem.eql(u8, dll_lower, "oleaut32.dll")) return &ordinals.oleaut32;
    if (std.mem.eql(u8, dll_lower, "ws2_32.dll")) return &ordinals.ws2_32;
    if (std.mem.eql(u8, dll_lower, "wsock32.dll")) return &ordinals.wsock32;
    return null;
}

fn lookupOrdinal(table: []const ordinals.Entry, ordinal: u16) ?[]const u8 {
    var lo: usize = 0;
    var hi: usize = table.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (table[mid].ordinal == ordinal) return table[mid].name;
        if (table[mid].ordinal < ordinal) lo = mid + 1 else hi = mid;
    }
    return null;
}

/// pefile `is_valid_dos_filename`: 8.3 file name characters plus path separators.
fn validDosFilename(s: []const u8) bool {
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c)) continue;
        if (std.mem.indexOfScalar(u8, "!#$%&'()-@^_`{}~+,.;=[]:\\/", c) == null) return false;
    }
    return true;
}

/// pefile `is_valid_function_name`.
fn validFunctionName(s: []const u8) bool {
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c)) continue;
        if (std.mem.indexOfScalar(u8, "._?@$()<>", c) == null) return false;
    }
    return true;
}

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

/// Builds a small PE32 or PE32+ image with one section holding the import
/// directory. Imports are given as (dll, names), where a name of the form
/// "#N" imports ordinal N.
fn buildPe(buf: []u8, pe64: bool, imports: []const struct { dll: []const u8, names: []const []const u8 }) []u8 {
    @memset(buf, 0);
    const file_align: u32 = 0x200;
    const sect_rva: u32 = 0x1000;
    const sect_off: u32 = 0x200;
    buf[0] = 'M';
    buf[1] = 'Z';
    std.mem.writeInt(u32, buf[0x3c..0x40], 0x40, .little);
    @memcpy(buf[0x40..0x44], "PE\x00\x00");
    const fh = 0x44;
    std.mem.writeInt(u16, buf[fh..][0..2], if (pe64) 0x8664 else 0x14c, .little);
    std.mem.writeInt(u16, buf[fh + 2 ..][0..2], 1, .little);
    const opt_size: u16 = if (pe64) 240 else 224;
    std.mem.writeInt(u16, buf[fh + 16 ..][0..2], opt_size, .little);
    const opt = fh + 20;
    std.mem.writeInt(u16, buf[opt..][0..2], if (pe64) 0x20b else 0x10b, .little);
    std.mem.writeInt(u32, buf[opt + 16 ..][0..4], sect_rva, .little);
    std.mem.writeInt(u32, buf[opt + 32 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, buf[opt + 36 ..][0..4], file_align, .little);
    std.mem.writeInt(u32, buf[opt + 60 ..][0..4], 0x200, .little);
    const base: usize = if (pe64) 112 else 96;
    std.mem.writeInt(u32, buf[opt + base - 4 ..][0..4], 16, .little);
    std.mem.writeInt(u32, buf[opt + base + 8 ..][0..4], sect_rva, .little);
    std.mem.writeInt(u32, buf[opt + base + 12 ..][0..4], 40, .little);

    // Section data layout: descriptors, then thunks, then names.
    const data = buf[sect_off..];
    var desc: usize = 0;
    var cursor: usize = 20 * (imports.len + 1);
    const thunk_size: usize = if (pe64) 8 else 4;
    for (imports) |imp| {
        const ilt = cursor;
        cursor += thunk_size * (imp.names.len + 1);
        for (imp.names, 0..) |name, i| {
            const slot = data[ilt + i * thunk_size ..];
            var value: u64 = undefined;
            if (name[0] == '#') {
                const ord = std.fmt.parseInt(u16, name[1..], 10) catch 0;
                value = (if (pe64) @as(u64, 1) << 63 else @as(u64, 1) << 31) | ord;
            } else {
                value = sect_rva + cursor;
                @memcpy(data[cursor + 2 ..][0..name.len], name);
                cursor += 2 + name.len + 1;
            }
            if (pe64) std.mem.writeInt(u64, slot[0..8], value, .little) else std.mem.writeInt(u32, slot[0..4], @intCast(value), .little);
        }
        const dll_rva = sect_rva + cursor;
        @memcpy(data[cursor..][0..imp.dll.len], imp.dll);
        cursor += imp.dll.len + 1;
        std.mem.writeInt(u32, data[desc..][0..4], @intCast(sect_rva + ilt), .little);
        std.mem.writeInt(u32, data[desc + 12 ..][0..4], @intCast(dll_rva), .little);
        std.mem.writeInt(u32, data[desc + 16 ..][0..4], @intCast(sect_rva + ilt), .little);
        desc += 20;
    }
    const raw = std.mem.alignForward(usize, cursor, file_align);
    const sh = opt + opt_size;
    @memcpy(buf[sh..][0..5], ".data");
    std.mem.writeInt(u32, buf[sh + 8 ..][0..4], @intCast(raw), .little);
    std.mem.writeInt(u32, buf[sh + 12 ..][0..4], sect_rva, .little);
    std.mem.writeInt(u32, buf[sh + 16 ..][0..4], @intCast(raw), .little);
    std.mem.writeInt(u32, buf[sh + 20 ..][0..4], sect_off, .little);
    return buf[0 .. sect_off + raw];
}

fn expectHex(expected: []const u8, pe: []const u8) !void {
    const S = struct {
        var ws: Workspace = .{};
    };
    const got = (try hash(&S.ws, pe)) orelse return error.TestExpectedHash;
    var hex: [hex_length]u8 = undefined;
    try testing.expectEqualStrings(expected, toHex(got, &hex));
}

test "imphash of named imports matches pefile" {
    var buf: [4096]u8 = undefined;
    // md5("kernel32.getprocaddress,kernel32.loadlibrarya,user32.messageboxw")
    const pe = buildPe(&buf, false, &.{
        .{ .dll = "KERNEL32.dll", .names = &.{ "GetProcAddress", "LoadLibraryA" } },
        .{ .dll = "USER32.dll", .names = &.{"MessageBoxW"} },
    });
    // pefile: md5 of "kernel32.getprocaddress,kernel32.loadlibrarya,user32.messageboxw"
    try expectHex("fcd11f719155dd55447a1f2dd8254800", pe);
}

test "ordinals are named from the tables or as ordN" {
    var buf: [4096]u8 = undefined;
    const pe = buildPe(&buf, true, &.{
        .{ .dll = "WS2_32.dll", .names = &.{ "#3", "#115", "#60000" } },
        .{ .dll = "oleaut32.DLL", .names = &.{"#2"} },
        .{ .dll = "custom.ocx", .names = &.{"#7"} },
        .{ .dll = "drv.sys.bak", .names = &.{"Init"} },
    });
    // pefile: md5 of "ws2_32.closesocket,ws2_32.wsastartup,ws2_32.ord60000,
    // oleaut32.sysallocstring,custom.ord7,drv.sys.bak.init"
    try expectHex("432a2f2631ac0d530ebd87983d595dfd", pe);
}

test "files that are not PE are rejected, PE files without imports give null" {
    var ws: Workspace = .{};
    try testing.expectError(error.InvalidPe, hash(&ws, ""));
    try testing.expectError(error.InvalidPe, hash(&ws, "MZ" ++ @as([100]u8, @splat(0))));
    var buf: [4096]u8 = undefined;
    const pe = buildPe(&buf, false, &.{});
    try testing.expect((try hash(&ws, pe)) == null);
}

test "toHex" {
    var hex: [hex_length]u8 = undefined;
    var d: Digest = undefined;
    std.crypto.hash.Md5.hash("", &d, .{});
    try testing.expectEqualStrings("d41d8cd98f00b204e9800998ecf8427e", toHex(d, &hex));
}

test "no panic on truncated or corrupted copies of a valid file" {
    var buf: [4096]u8 = undefined;
    const pe = buildPe(&buf, false, &.{
        .{ .dll = "KERNEL32.dll", .names = &.{ "GetProcAddress", "LoadLibraryA", "#5" } },
    });
    var ws: Workspace = .{};
    var copy: [4096]u8 = undefined;
    for (0..pe.len) |n| _ = hash(&ws, pe[0..n]) catch {};
    var prng = std.Random.DefaultPrng.init(1);
    const r = prng.random();
    for (0..2000) |_| {
        @memcpy(copy[0..pe.len], pe);
        for (0..1 + r.uintLessThan(usize, 8)) |_| copy[r.uintLessThan(usize, pe.len)] = r.int(u8);
        _ = hash(&ws, copy[0..pe.len]) catch {};
    }
}
