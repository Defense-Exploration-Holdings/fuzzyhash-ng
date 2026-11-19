// SPDX-License-Identifier: MIT-CMU
// Copyright (c) 1997-2011 by Secret Labs AB
// Copyright (c) 1995-2011 by Fredrik Lundh and contributors
// Copyright (c) 2010 by Jeffrey 'Alex' Clark and contributors
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//
// Ported from Pillow 13.0 (libImaging/Resample.c), MIT-CMU License; see
// LICENSES/Pillow-LICENSE. Changes: rewritten in Zig for 8-bit grayscale
// only, with caller-provided working memory.
//! Pillow `image.convert("L").resize(size, LANCZOS)`: the same integer
//! coefficients, the same two passes in the same order.

const std = @import("std");
const trig = @import("trig.zig");
const Image = @import("../imagehash.zig").Image;

/// Pillow's `convert("L")` of one pixel (ITU-R 601-2 luma, rounded).
fn luma(image: *const Image, x: usize, y: usize) u8 {
    const bpp = image.format.bytesPerPixel();
    const p = image.pixels[(y * image.width + x) * bpp ..];
    return switch (image.format) {
        .gray, .gray_alpha => p[0],
        .rgb, .rgba => @intCast((@as(u32, p[0]) * 19595 + @as(u32, p[1]) * 38470 + @as(u32, p[2]) * 7471 + 0x8000) >> 16),
    };
}

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
        if (self.image) |im| return luma(im, x, y);
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

pub const Layout = struct {
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

pub fn resizeLayout(in_w: usize, in_h: usize, out_w: usize, out_h: usize) Layout {
    const kh = ksizeFor(in_w, out_w);
    const kv = ksizeFor(in_h, out_h);
    // The temporary image is at most out_w * in_h (horizontal first) or
    // in_w * out_h (vertical first).
    const temp = if (horizontalFirst(in_w, in_h, out_w, out_h)) out_w * in_h else in_w * out_h;
    const ints = (out_w * kh + out_h * kv + 2 * (out_w + out_h)) * @sizeOf(i32);
    const window = @max(kh, kv) * @sizeOf(f64);
    return .{ .kh = kh, .kv = kv, .temp = temp, .total = window + ints + temp + 16 };
}

pub const Arena = struct {
    buf: []u8,
    used: usize = 0,

    pub fn take(self: *Arena, comptime T: type, n: usize) []T {
        const start = std.mem.alignForward(usize, @intFromPtr(self.buf.ptr) + self.used, @alignOf(T)) - @intFromPtr(self.buf.ptr);
        const end = start + n * @sizeOf(T);
        std.debug.assert(end <= self.buf.len);
        self.used = end;
        const p: [*]T = @ptrCast(@alignCast(self.buf.ptr + start));
        return p[0..n];
    }
};

/// Pillow `image.convert("L").resize((out_w, out_h), LANCZOS)`.
pub fn resize(image: *const Image, out: []u8, out_w: usize, out_h: usize, arena: *Arena) void {
    const in_w: usize = image.width;
    const in_h: usize = image.height;
    const src: Plane = .{ .image = image, .data = &.{}, .width = in_w };
    const need_h = out_w != in_w;
    const need_v = out_h != in_h;
    if (!need_h and !need_v) {
        for (0..out_h) |y| for (0..out_w) |x| {
            out[y * out_w + x] = luma(image, x, y);
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
