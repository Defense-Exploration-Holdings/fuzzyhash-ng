// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//! Perceptual image hashes compatible with ImageHash 4.3.2: `average`
//! (aHash), `difference` (dHash) and `perceptual` (pHash).
//!
//! ImageHash converts the image to Pillow's "L" mode, resizes it with
//! Pillow's LANCZOS filter and compares pixels (aHash, dHash) or DCT
//! coefficients (pHash). This module reproduces Pillow 13.0's luma
//! conversion and resampling (integer coefficients, two passes, the same
//! pass order) and scipy 1.18's DCT. pHash results on flat or symmetric
//! images depend on the DCT's rounding, which depends on the platform's
//! sin and cos; the values reproduced are those of x86-64 Linux (glibc).
//!
//! Images are passed decoded, as tightly packed 8-bit rows. Working memory
//! is caller-provided: see `scratchSize`.

const std = @import("std");
const dct = @import("imagehash/dct.zig");
const trig = @import("imagehash/trig.zig");

pub const Format = enum {
    /// One byte per pixel (Pillow "L").
    gray,
    /// Luma then alpha (Pillow "LA"). Alpha is ignored.
    gray_alpha,
    /// Pillow "RGB".
    rgb,
    /// Pillow "RGBA". Alpha is ignored, as in `convert("L")`.
    rgba,

    pub fn bytesPerPixel(self: Format) usize {
        return switch (self) {
            .gray => 1,
            .gray_alpha => 2,
            .rgb => 3,
            .rgba => 4,
        };
    }
};

/// A decoded image: `height` rows of `width` pixels, no padding.
pub const Image = struct {
    width: u32,
    height: u32,
    format: Format,
    pixels: []const u8,

    /// Pillow's `convert("L")` of one pixel (ITU-R 601-2 luma, rounded).
    fn luma(self: *const Image, x: usize, y: usize) u8 {
        const bpp = self.format.bytesPerPixel();
        const p = self.pixels[(y * self.width + x) * bpp ..];
        return switch (self.format) {
            .gray, .gray_alpha => p[0],
            .rgb, .rgba => @intCast((@as(u32, p[0]) * 19595 + @as(u32, p[1]) * 38470 + @as(u32, p[2]) * 7471 + 0x8000) >> 16),
        };
    }
};

pub const Error = error{
    /// Width or height is zero.
    EmptyImage,
    /// `pixels` is not `width * height * bytesPerPixel` long.
    InvalidImage,
    /// Width or height is above `max_dimension`.
    ImageTooLarge,
    /// `scratch` is smaller than `scratchSize` asks for.
    ScratchTooSmall,
    /// pHash size (`hash_size * highfreq_factor`) is not supported.
    UnsupportedSize,
};

/// Largest width or height accepted.
pub const max_dimension = 1 << 20;

pub const Kind = enum { average, difference, perceptual };

// ---------------------------------------------------------------------------
// Pillow LANCZOS resampling (libImaging/Resample.c, 8 bits per channel).

const precision_bits = 32 - 8 - 2;

fn sinc(x0: f64) f64 {
    if (x0 == 0.0) return 1.0;
    const x = x0 * std.math.pi;
    return trig.sin(x) / x;
}

fn lanczos(x: f64) f64 {
    if (-3.0 <= x and x < 3.0) return sinc(x) * sinc(x / 3);
    return 0.0;
}

const Coeffs = struct {
    ksize: usize,
    bounds: []i32, // xmin, xmax pairs
    kk: []i32,
};

fn ksizeFor(in_size: usize, out_size: usize) usize {
    var filterscale = @as(f64, @floatFromInt(in_size)) / @as(f64, @floatFromInt(out_size));
    if (filterscale < 1.0) filterscale = 1.0;
    const support = 3.0 * filterscale;
    return @as(usize, @intFromFloat(@ceil(support))) * 2 + 1;
}

/// precompute_coeffs + normalize_coeffs_8bpc. `window` holds ksize f64.
fn precompute(in_size: usize, out_size: usize, c: Coeffs, window: []f64) void {
    const in1: f32 = @floatFromInt(in_size);
    const scale = @as(f64, in1) / @as(f64, @floatFromInt(out_size));
    var filterscale = scale;
    if (filterscale < 1.0) filterscale = 1.0;
    const support = 3.0 * filterscale;
    const inv_filterscale = 1.0 / filterscale;
    const in_i: i64 = @intCast(in_size);
    for (0..out_size) |xx| {
        const center = 0.0 + (@as(f64, @floatFromInt(xx)) + 0.5) * scale;
        var ww: f64 = 0.0;
        var xmin: i64 = @intFromFloat(center - support + 0.5);
        if (xmin < 0) xmin = 0;
        var xmax: i64 = @intFromFloat(center + support + 0.5);
        if (xmax > in_i) xmax = in_i;
        xmax -= xmin;
        const n: usize = @intCast(@max(xmax, 0));
        for (0..n) |x| {
            const pos: f64 = @floatFromInt(@as(i64, @intCast(x)) + xmin);
            const w = lanczos((pos - center + 0.5) * inv_filterscale);
            window[x] = w;
            ww += w;
        }
        if (ww != 0.0) {
            for (0..n) |x| window[x] /= ww;
        }
        const k = c.kk[xx * c.ksize ..][0..c.ksize];
        for (0..c.ksize) |x| {
            const v: f64 = if (x < n) window[x] else 0;
            k[x] = if (v < 0)
                @intFromFloat(-0.5 + v * (1 << precision_bits))
            else
                @intFromFloat(0.5 + v * (1 << precision_bits));
        }
        c.bounds[xx * 2] = @intCast(xmin);
        c.bounds[xx * 2 + 1] = @intCast(xmax);
    }
}

fn clip8(ss: i32) u8 {
    const v = ss >> precision_bits;
    return @intCast(std.math.clamp(v, 0, 255));
}

/// A grayscale plane, either the input image (read through `luma`) or an
/// intermediate buffer.
const Plane = struct {
    image: ?*const Image,
    data: []const u8,
    width: usize,

    inline fn at(self: Plane, x: usize, y: usize) u8 {
        if (self.image) |im| return im.luma(x, y);
        return self.data[y * self.width + x];
    }
};

fn horizontal(src: Plane, row_offset: usize, out: []u8, out_w: usize, out_h: usize, c: Coeffs) void {
    for (0..out_h) |yy| {
        for (0..out_w) |xx| {
            const xmin: usize = @intCast(c.bounds[xx * 2]);
            const xmax: usize = @intCast(c.bounds[xx * 2 + 1]);
            const k = c.kk[xx * c.ksize ..];
            var ss: i32 = 1 << (precision_bits - 1);
            for (0..xmax) |x| ss +%= @as(i32, src.at(x + xmin, yy + row_offset)) *% k[x];
            out[yy * out_w + xx] = clip8(ss);
        }
    }
}

fn vertical(src: Plane, out: []u8, out_w: usize, out_h: usize, c: Coeffs) void {
    for (0..out_h) |yy| {
        const k = c.kk[yy * c.ksize ..];
        const ymin: usize = @intCast(c.bounds[yy * 2]);
        const ymax: usize = @intCast(c.bounds[yy * 2 + 1]);
        for (0..out_w) |xx| {
            var ss: i32 = 1 << (precision_bits - 1);
            for (0..ymax) |y| ss +%= @as(i32, src.at(xx, y + ymin)) *% k[y];
            out[yy * out_w + xx] = clip8(ss);
        }
    }
}

const Layout = struct {
    kh: usize,
    kv: usize,
    temp: usize,
    total: usize,
};

fn horizontalFirst(in_w: usize, in_h: usize, out_w: usize, out_h: usize) bool {
    const dy = @as(i64, @intCast(in_h)) - @as(i64, @intCast(out_h));
    const dx = @as(i64, @intCast(in_w)) - @as(i64, @intCast(out_w));
    return !(dy > 0 and dy > dx * 2);
}

fn resizeLayout(in_w: usize, in_h: usize, out_w: usize, out_h: usize) Layout {
    const kh = ksizeFor(in_w, out_w);
    const kv = ksizeFor(in_h, out_h);
    // The temporary image is at most out_w * in_h (horizontal first) or
    // in_w * out_h (vertical first).
    const temp = if (horizontalFirst(in_w, in_h, out_w, out_h)) out_w * in_h else in_w * out_h;
    const ints = (out_w * kh + out_h * kv + 2 * (out_w + out_h)) * @sizeOf(i32);
    const window = @max(kh, kv) * @sizeOf(f64);
    return .{ .kh = kh, .kv = kv, .temp = temp, .total = window + ints + temp + 16 };
}

const Arena = struct {
    buf: []u8,
    used: usize = 0,

    fn take(self: *Arena, comptime T: type, n: usize) []T {
        const start = std.mem.alignForward(usize, @intFromPtr(self.buf.ptr) + self.used, @alignOf(T)) - @intFromPtr(self.buf.ptr);
        const end = start + n * @sizeOf(T);
        std.debug.assert(end <= self.buf.len);
        self.used = end;
        const p: [*]T = @ptrCast(@alignCast(self.buf.ptr + start));
        return p[0..n];
    }
};

/// Pillow `image.convert("L").resize((out_w, out_h), LANCZOS)`.
fn resize(image: *const Image, out: []u8, out_w: usize, out_h: usize, arena: *Arena) void {
    const in_w: usize = image.width;
    const in_h: usize = image.height;
    const src: Plane = .{ .image = image, .data = &.{}, .width = in_w };
    const need_h = out_w != in_w;
    const need_v = out_h != in_h;
    if (!need_h and !need_v) {
        for (0..out_h) |y| for (0..out_w) |x| {
            out[y * out_w + x] = image.luma(x, y);
        };
        return;
    }
    const lay = resizeLayout(in_w, in_h, out_w, out_h);
    const window = arena.take(f64, @max(lay.kh, lay.kv));
    const h_first = horizontalFirst(in_w, in_h, out_w, out_h);
    var cv: Coeffs = undefined;
    var ch: Coeffs = undefined;
    if ((need_h and h_first) or need_v) {
        cv = .{ .ksize = lay.kv, .bounds = arena.take(i32, 2 * out_h), .kk = arena.take(i32, out_h * lay.kv) };
        precompute(in_h, out_h, cv, window);
    }
    var ybox_first: usize = 0;
    var ybox_last: usize = 0;
    if (need_h) {
        if (h_first) {
            ybox_first = @intCast(cv.bounds[0]);
            ybox_last = @intCast(cv.bounds[out_h * 2 - 2] + cv.bounds[out_h * 2 - 1]);
            for (0..out_h) |i| cv.bounds[i * 2] -= @intCast(ybox_first);
        }
        ch = .{ .ksize = lay.kh, .bounds = arena.take(i32, 2 * out_w), .kk = arena.take(i32, out_w * lay.kh) };
        precompute(in_w, out_w, ch, window);
    }
    if (h_first) {
        if (need_h and need_v) {
            const rows = ybox_last - ybox_first;
            const temp = arena.take(u8, out_w * rows);
            horizontal(src, ybox_first, temp, out_w, rows, ch);
            vertical(.{ .image = null, .data = temp, .width = out_w }, out, out_w, out_h, cv);
        } else if (need_h) {
            // ybox spans every row when the height is unchanged.
            horizontal(src, ybox_first, out, out_w, ybox_last - ybox_first, ch);
        } else {
            vertical(src, out, out_w, out_h, cv);
        }
    } else {
        if (need_h) {
            const temp = arena.take(u8, in_w * out_h);
            vertical(src, temp, in_w, out_h, cv);
            horizontal(.{ .image = null, .data = temp, .width = in_w }, 0, out, out_w, out_h, ch);
        } else {
            vertical(src, out, out_w, out_h, cv);
        }
    }
}

// ---------------------------------------------------------------------------

/// Hashes with `hash_size * hash_size` bits, as ImageHash's `hash_size`.
pub fn ImageHash(comptime hash_size: u16) type {
    if (hash_size < 2) @compileError("hash_size must be at least 2");
    return struct {
        const Self = @This();

        pub const bit_count: usize = @as(usize, hash_size) * hash_size;
        pub const hex_length: usize = (bit_count + 3) / 4;

        /// Bits in ImageHash's order (row-major), most significant first.
        bytes: [(bit_count + 7) / 8]u8,

        fn setBit(self: *Self, i: usize) void {
            self.bytes[i / 8] |= @as(u8, 0x80) >> @intCast(i % 8);
        }

        pub fn bit(self: Self, i: usize) bool {
            return self.bytes[i / 8] & (@as(u8, 0x80) >> @intCast(i % 8)) != 0;
        }

        /// Bytes of `scratch` needed to hash an image of this size. The
        /// pHash figure is for `highfreq_factor`.
        pub fn scratchSize(kind: Kind, width: u32, height: u32, highfreq_factor: u16) usize {
            if (width == 0 or height == 0) return 0;
            const out_w: usize, const out_h: usize = switch (kind) {
                .average => .{ hash_size, hash_size },
                .difference => .{ hash_size + 1, hash_size },
                .perceptual => .{ @as(usize, hash_size) * highfreq_factor, @as(usize, hash_size) * highfreq_factor },
            };
            var total = resizeLayout(width, height, out_w, out_h).total + out_w * out_h + 16;
            if (kind == .perceptual) total += (out_w * out_h + 2 * out_w + bit_count) * @sizeOf(f64);
            return total;
        }

        fn check(image: Image) Error!void {
            if (image.width == 0 or image.height == 0) return error.EmptyImage;
            if (image.width > max_dimension or image.height > max_dimension) return error.ImageTooLarge;
            const want = @as(usize, image.width) * image.height * image.format.bytesPerPixel();
            if (image.pixels.len != want) return error.InvalidImage;
        }

        /// `imagehash.average_hash(image, hash_size)`.
        pub fn average(image: Image, scratch: []u8) Error!Self {
            try check(image);
            if (scratch.len < scratchSize(.average, image.width, image.height, 4)) return error.ScratchTooSmall;
            var arena: Arena = .{ .buf = scratch };
            const px = arena.take(u8, bit_count);
            resize(&image, px, hash_size, hash_size, &arena);
            var sum: u64 = 0;
            for (px) |p| sum += p;
            var self: Self = .{ .bytes = @splat(0) };
            // p > sum / n, exactly as numpy compares against the float mean.
            for (px, 0..) |p, i| if (@as(u64, p) * bit_count > sum) self.setBit(i);
            return self;
        }

        /// `imagehash.dhash(image, hash_size)`: each pixel against its left
        /// neighbour, on a (hash_size + 1) x hash_size thumbnail.
        pub fn difference(image: Image, scratch: []u8) Error!Self {
            try check(image);
            if (scratch.len < scratchSize(.difference, image.width, image.height, 4)) return error.ScratchTooSmall;
            var arena: Arena = .{ .buf = scratch };
            const w = hash_size + 1;
            const px = arena.take(u8, w * hash_size);
            resize(&image, px, w, hash_size, &arena);
            var self: Self = .{ .bytes = @splat(0) };
            for (0..hash_size) |y| for (0..hash_size) |x| {
                if (px[y * w + x + 1] > px[y * w + x]) self.setBit(y * hash_size + x);
            };
            return self;
        }

        /// `imagehash.phash(image, hash_size, highfreq_factor)`.
        pub fn perceptual(image: Image, highfreq_factor: u16, scratch: []u8) Error!Self {
            try check(image);
            const n = @as(usize, hash_size) * highfreq_factor;
            if (highfreq_factor == 0 or !dct.supported(n)) return error.UnsupportedSize;
            if (scratch.len < scratchSize(.perceptual, image.width, image.height, highfreq_factor)) return error.ScratchTooSmall;
            var arena: Arena = .{ .buf = scratch };
            const m = arena.take(f64, n * n);
            const line = arena.take(f64, n);
            const buf = arena.take(f64, n);
            const low = arena.take(f64, bit_count);
            const px = arena.take(u8, n * n);
            resize(&image, px, n, n, &arena);
            for (px, m) |p, *v| v.* = @floatFromInt(p);
            const plan = dct.Plan.init(n);
            // scipy.fftpack.dct(pixels, axis=0): along columns.
            for (0..n) |x| {
                for (0..n) |y| line[y] = m[y * n + x];
                plan.dct2(line, buf);
                for (0..n) |y| m[y * n + x] = line[y];
            }
            // Then axis=1, only the rows that are kept.
            for (0..hash_size) |y| {
                const row = m[y * n ..][0..n];
                plan.dct2(row, buf);
                @memcpy(low[y * hash_size ..][0..hash_size], row[0..hash_size]);
            }
            const med = median(low, m[0..bit_count]);
            var self: Self = .{ .bytes = @splat(0) };
            for (low, 0..) |v, i| if (v > med) self.setBit(i);
            return self;
        }

        fn median(values: []const f64, work: []f64) f64 {
            @memcpy(work, values);
            std.mem.sort(f64, work, {}, std.sort.asc(f64));
            const h = work.len / 2;
            if (work.len % 2 == 1) return work[h];
            return (work[h - 1] + work[h]) / 2.0;
        }

        /// Lowercase hex as `str(ImageHash)`.
        pub fn toHex(self: Self, out: *[hex_length]u8) []const u8 {
            const pad = hex_length * 4 - bit_count;
            for (0..hex_length) |j| {
                var nib: u8 = 0;
                for (0..4) |b| {
                    const q = j * 4 + b;
                    nib <<= 1;
                    if (q >= pad and self.bit(q - pad)) nib |= 1;
                }
                out[j] = "0123456789abcdef"[nib];
            }
            return out;
        }

        pub const ParseError = error{ InvalidLength, InvalidCharacter, Overflow };

        /// Parses `hex_length` hex digits, either case.
        pub fn parseHex(s: []const u8) ParseError!Self {
            if (s.len != hex_length) return error.InvalidLength;
            const pad = hex_length * 4 - bit_count;
            var self: Self = .{ .bytes = @splat(0) };
            for (s, 0..) |c, j| {
                const nib = std.fmt.charToDigit(c, 16) catch return error.InvalidCharacter;
                for (0..4) |b| {
                    const q = j * 4 + b;
                    const on = nib & (@as(u8, 8) >> @intCast(b)) != 0;
                    if (q < pad) {
                        if (on) return error.Overflow;
                    } else if (on) self.setBit(q - pad);
                }
            }
            return self;
        }

        /// Number of differing bits (`hash1 - hash2` in ImageHash).
        pub fn distance(a: Self, b: Self) u32 {
            var d: u32 = 0;
            for (a.bytes, b.bytes) |x, y| d += @popCount(x ^ y);
            return d;
        }
    };
}

/// The default 8x8 (64-bit) hashes.
pub const Hash = ImageHash(8);

test {
    _ = dct;
    _ = trig;
}

const testing = std.testing;

fn testRgb(buf: []u8, w: usize, h: usize) Image {
    for (0..h) |y| for (0..w) |x| {
        const p = buf[(y * w + x) * 3 ..];
        p[0] = @truncate(x * 7 + y * 3);
        p[1] = @truncate(x * y);
        p[2] = @truncate((x + 2 * y) * 5);
    };
    return .{ .width = @intCast(w), .height = @intCast(h), .format = .rgb, .pixels = buf[0 .. w * h * 3] };
}

fn expectHashes(comptime H: type, image: Image, a: []const u8, d: []const u8, p: []const u8) !void {
    const scratch = try testing.allocator.alloc(u8, @max(
        H.scratchSize(.average, image.width, image.height, 4),
        H.scratchSize(.difference, image.width, image.height, 4),
        H.scratchSize(.perceptual, image.width, image.height, 4),
    ));
    defer testing.allocator.free(scratch);
    var hex: [H.hex_length]u8 = undefined;
    try testing.expectEqualStrings(a, (try H.average(image, scratch)).toHex(&hex));
    try testing.expectEqualStrings(d, (try H.difference(image, scratch)).toHex(&hex));
    try testing.expectEqualStrings(p, (try H.perceptual(image, 4, scratch)).toHex(&hex));
}

test "hashes match ImageHash 4.3.2" {
    var buf: [640 * 480 * 3]u8 = undefined;
    try expectHashes(Hash, testRgb(&buf, 37, 23), "00071f3e3f366c6d", "fffefef8f2e4cdd9", "833d63665956a5aa");
    try expectHashes(Hash, testRgb(&buf, 640, 480), "01d965a400d94165", "8513494891134148", "aa08f7287757d702");

    // A flat image: every AC coefficient is zero, so only the DC bit is set.
    const flat: [100]u8 = @splat(128);
    const flat_img: Image = .{ .width = 10, .height = 10, .format = .gray, .pixels = &flat };
    try expectHashes(Hash, flat_img, "0000000000000000", "0000000000000000", "8000000000000000");

    var grad: [64 * 48]u8 = undefined;
    for (0..48) |y| for (0..64) |x| {
        grad[y * 64 + x] = @truncate(x * 255 / 63 + y);
    };
    const grad_img: Image = .{ .width = 64, .height = 48, .format = .gray, .pixels = &grad };
    try expectHashes(Hash, grad_img, "0f0f0f1e1e1e1e1e", "fefefefefefcfcfc", "95a92aae6aac6a35");
}

test "other hash sizes print ImageHash's hex width" {
    var buf: [37 * 23 * 3]u8 = undefined;
    const img = testRgb(&buf, 37, 23);
    var scratch: [64 * 1024]u8 = undefined;
    var hex5: [ImageHash(5).hex_length]u8 = undefined;
    try testing.expectEqualStrings("103b1ab", (try ImageHash(5).perceptual(img, 4, &scratch)).toHex(&hex5));
    var hex3: [ImageHash(3).hex_length]u8 = undefined;
    try testing.expectEqualStrings("05e", (try ImageHash(3).average(img, &scratch)).toHex(&hex3));
}

test "parseHex, toHex and distance" {
    const a = try Hash.parseHex("833d63665956a5aa");
    const b = try Hash.parseHex("833D63665956A5AB");
    var hex: [16]u8 = undefined;
    try testing.expectEqualStrings("833d63665956a5aa", a.toHex(&hex));
    try testing.expectEqual(@as(u32, 1), Hash.distance(a, b));
    try testing.expectError(error.InvalidLength, Hash.parseHex("833d"));
    try testing.expectError(error.InvalidCharacter, Hash.parseHex("833d63665956a5ag"));
    try testing.expectError(error.Overflow, ImageHash(3).parseHex("25e"));
    const c = try ImageHash(3).parseHex("05e");
    var hex3: [3]u8 = undefined;
    try testing.expectEqualStrings("05e", c.toHex(&hex3));
}

test "invalid input" {
    var scratch: [1024]u8 = undefined;
    const px: [12]u8 = @splat(0);
    try testing.expectError(error.EmptyImage, Hash.average(.{ .width = 0, .height = 3, .format = .gray, .pixels = &.{} }, &scratch));
    try testing.expectError(error.InvalidImage, Hash.average(.{ .width = 2, .height = 2, .format = .rgb, .pixels = px[0..11] }, &scratch));
    try testing.expectError(error.ScratchTooSmall, Hash.average(.{ .width = 2, .height = 2, .format = .rgb, .pixels = &px }, scratch[0..10]));
    try testing.expectError(error.UnsupportedSize, Hash.perceptual(.{ .width = 2, .height = 2, .format = .rgb, .pixels = &px }, 137, &scratch));
}
