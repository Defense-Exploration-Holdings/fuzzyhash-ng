// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2010-2019 Max-Planck-Society
// Copyright (c) 2026 Defense Exploration Holdings, LLC
//
// Ported from the ducc0 real FFT used by scipy 1.18's `scipy.fftpack.dct`,
// BSD 3-Clause License; see LICENSES/ducc0-LICENSE. Changes: rewritten in
// Zig for the real-input lengths pHash uses.
//! Unnormalized type-II DCT, computed with the same floating-point
//! operations, in the same order, as scipy 1.18's `scipy.fftpack.dct`.
//! pHash compares DCT values against their median, so on flat or symmetric
//! images the rounding noise decides bits; it has to be the same noise.
//!
//! Supported lengths: 1 to 1000 with every prime factor below 135. Longer
//! lengths and larger prime factors take other code paths in ducc0
//! (complex FFT, Bluestein) that are not ported.

const std = @import("std");
const trig = @import("trig.zig");

pub const max_length = 1000;

/// Whether `n` is a length this module computes.
pub fn supported(n: usize) bool {
    if (n == 0 or n > max_length) return false;
    var f: Factors = .{};
    f.init(n);
    for (f.slice()) |p| if (p >= 135) return false;
    return true;
}

fn ld(comptime v: comptime_float) f64 {
    // C++ `Tfs(<long double literal>)`: rounded to x87 extended first.
    return @floatCast(@as(f80, v));
}

const Cmplx = struct { r: f64, i: f64 };

/// ducc0's UnityRoots: the n-th roots of unity, from two small tables.
const Roots = struct {
    n: usize,
    shift: std.math.Log2Int(usize),
    mask: usize,
    v1: [64]Cmplx = undefined,
    v2: [64]Cmplx = undefined,

    fn calc(x0: usize, n: usize, ang: f64) Cmplx {
        const S = trig.glibcSin;
        const C = trig.glibcCos;
        var x = x0 << 3;
        if (x < 4 * n) {
            if (x < 2 * n) {
                if (x < n) return .{ .r = C(fl(x) * ang), .i = S(fl(x) * ang) };
                return .{ .r = S(fl(2 * n - x) * ang), .i = C(fl(2 * n - x) * ang) };
            } else {
                x -= 2 * n;
                if (x < n) return .{ .r = -S(fl(x) * ang), .i = C(fl(x) * ang) };
                return .{ .r = -C(fl(2 * n - x) * ang), .i = S(fl(2 * n - x) * ang) };
            }
        } else {
            x = 8 * n - x;
            if (x < 2 * n) {
                if (x < n) return .{ .r = C(fl(x) * ang), .i = -S(fl(x) * ang) };
                return .{ .r = S(fl(2 * n - x) * ang), .i = -C(fl(2 * n - x) * ang) };
            } else {
                x -= 2 * n;
                if (x < n) return .{ .r = -S(fl(x) * ang), .i = -C(fl(x) * ang) };
                return .{ .r = -C(fl(2 * n - x) * ang), .i = -S(fl(2 * n - x) * ang) };
            }
        }
    }

    fn init(n: usize) Roots {
        const pi: f80 = 3.141592653589793238462643383279502884197;
        const ang: f64 = @floatCast(@as(f80, 0.25) * pi / @as(f80, @floatFromInt(n)));
        const nval = (n + 2) / 2;
        var shift: std.math.Log2Int(usize) = 1;
        while ((@as(usize, 1) << shift) * (@as(usize, 1) << shift) < nval) shift += 1;
        const mask = (@as(usize, 1) << shift) - 1;
        var self: Roots = .{ .n = n, .shift = shift, .mask = mask };
        self.v1[0] = .{ .r = 1, .i = 0 };
        for (1..mask + 1) |i| self.v1[i] = calc(i, n, ang);
        const n2 = (nval + mask) / (mask + 1);
        self.v2[0] = .{ .r = 1, .i = 0 };
        for (1..n2) |i| self.v2[i] = calc(i * (mask + 1), n, ang);
        return self;
    }

    fn get(self: *const Roots, idx0: usize) Cmplx {
        if (2 * idx0 <= self.n) {
            const x1 = self.v1[idx0 & self.mask];
            const x2 = self.v2[idx0 >> self.shift];
            return .{ .r = x1.r * x2.r - x1.i * x2.i, .i = x1.r * x2.i + x1.i * x2.r };
        }
        const idx = self.n - idx0;
        const x1 = self.v1[idx & self.mask];
        const x2 = self.v2[idx >> self.shift];
        return .{ .r = x1.r * x2.r - x1.i * x2.i, .i = -(x1.r * x2.i + x1.i * x2.r) };
    }
};

fn fl(x: usize) f64 {
    return @floatFromInt(x);
}

const Factors = struct {
    v: [16]usize = undefined,
    len: usize = 0,

    fn push(self: *Factors, x: usize) void {
        self.v[self.len] = x;
        self.len += 1;
    }

    // ducc0 rfftpass::factorize
    fn init(self: *Factors, n0: usize) void {
        var n = n0;
        while (n & 3 == 0) {
            self.push(4);
            n >>= 2;
        }
        if (n & 1 == 0) {
            n >>= 1;
            self.push(2);
            std.mem.swap(usize, &self.v[0], &self.v[self.len - 1]);
        }
        var d: usize = 3;
        while (d * d <= n) : (d += 2) {
            while (n % d == 0) {
                self.push(d);
                n /= d;
            }
        }
        if (n > 1) self.push(n);
    }

    fn slice(self: *const Factors) []const usize {
        return self.v[0..self.len];
    }
};

const Pass = struct {
    l1: usize,
    ido: usize,
    roots: *const Roots,

    // WA(x, i-2) and WA(x, i-1) for even i: root (x+1)*l1*(i/2).
    fn wa(self: Pass, x: usize, i: usize) Cmplx {
        return self.roots.get((x + 1) * self.l1 * (i / 2));
    }
};

inline fn mulpm(a: *f64, b: *f64, c: f64, d: f64, e: f64, f: f64) void {
    a.* = c * e + d * f;
    b.* = c * f - d * e;
}

const Acc = struct {
    // Backward passes read CC(a,b,c) = cc[a+ido*(b+ip*c)] and write
    // CH(a,b,c) = ch[a+ido*(b+l1*c)].
    cc: []const f64,
    ch: []f64,
    ido: usize,
    l1: usize,
    ip: usize,

    inline fn CC(s: Acc, a: usize, b: usize, c: usize) f64 {
        return s.cc[a + s.ido * (b + s.ip * c)];
    }
    inline fn CH(s: Acc, a: usize, b: usize, c: usize) *f64 {
        return &s.ch[a + s.ido * (b + s.l1 * c)];
    }
};

inline fn pm(a: *f64, b: *f64, c: f64, d: f64) void {
    a.* = c + d;
    b.* = c - d;
}

fn radb2(p: Pass, cc: []const f64, ch: []f64) void {
    const l1 = p.l1;
    const ido = p.ido;
    const s: Acc = .{ .cc = cc, .ch = ch, .ido = ido, .l1 = l1, .ip = 2 };
    for (0..l1) |k| pm(s.CH(0, k, 0), s.CH(0, k, 1), s.CC(0, 0, k), s.CC(ido - 1, 1, k));
    if (ido & 1 == 0) {
        for (0..l1) |k| {
            s.CH(ido - 1, k, 0).* = 2.0 * s.CC(ido - 1, 0, k);
            s.CH(ido - 1, k, 1).* = -2.0 * s.CC(0, 1, k);
        }
    }
    if (ido <= 2) return;
    for (0..l1) |k| {
        var i: usize = 2;
        while (i < ido) : (i += 2) {
            const ic = ido - i;
            var ti2: f64 = undefined;
            var tr2: f64 = undefined;
            pm(s.CH(i - 1, k, 0), &tr2, s.CC(i - 1, 0, k), s.CC(ic - 1, 1, k));
            pm(&ti2, s.CH(i, k, 0), s.CC(i, 0, k), s.CC(ic, 1, k));
            const w = p.wa(0, i);
            mulpm(s.CH(i, k, 1), s.CH(i - 1, k, 1), w.r, w.i, ti2, tr2);
        }
    }
}

fn radb3(p: Pass, cc: []const f64, ch: []f64) void {
    const l1 = p.l1;
    const ido = p.ido;
    const taur: f64 = -0.5;
    const taui = comptime ld(0.8660254037844386467637231707529362);
    const s: Acc = .{ .cc = cc, .ch = ch, .ido = ido, .l1 = l1, .ip = 3 };
    for (0..l1) |k| {
        const tr2 = 2.0 * s.CC(ido - 1, 1, k);
        const cr2 = s.CC(0, 0, k) + taur * tr2;
        s.CH(0, k, 0).* = s.CC(0, 0, k) + tr2;
        const ci3 = 2.0 * taui * s.CC(0, 2, k);
        pm(s.CH(0, k, 2), s.CH(0, k, 1), cr2, ci3);
    }
    if (ido == 1) return;
    for (0..l1) |k| {
        var i: usize = 2;
        while (i < ido) : (i += 2) {
            const ic = ido - i;
            const tr2 = s.CC(i - 1, 2, k) + s.CC(ic - 1, 1, k);
            const ti2 = s.CC(i, 2, k) - s.CC(ic, 1, k);
            const cr2 = s.CC(i - 1, 0, k) + taur * tr2;
            const ci2 = s.CC(i, 0, k) + taur * ti2;
            s.CH(i - 1, k, 0).* = s.CC(i - 1, 0, k) + tr2;
            s.CH(i, k, 0).* = s.CC(i, 0, k) + ti2;
            const cr3 = taui * (s.CC(i - 1, 2, k) - s.CC(ic - 1, 1, k));
            const ci3 = taui * (s.CC(i, 2, k) + s.CC(ic, 1, k));
            var dr2: f64 = undefined;
            var dr3: f64 = undefined;
            var di2: f64 = undefined;
            var di3: f64 = undefined;
            pm(&dr3, &dr2, cr2, ci3);
            pm(&di2, &di3, ci2, cr3);
            const w0 = p.wa(0, i);
            const w1 = p.wa(1, i);
            mulpm(s.CH(i, k, 1), s.CH(i - 1, k, 1), w0.r, w0.i, di2, dr2);
            mulpm(s.CH(i, k, 2), s.CH(i - 1, k, 2), w1.r, w1.i, di3, dr3);
        }
    }
}

fn radb4(p: Pass, cc: []const f64, ch: []f64) void {
    const l1 = p.l1;
    const ido = p.ido;
    const sqrt2 = comptime ld(1.414213562373095048801688724209698);
    const s: Acc = .{ .cc = cc, .ch = ch, .ido = ido, .l1 = l1, .ip = 4 };
    for (0..l1) |k| {
        var tr1: f64 = undefined;
        var tr2: f64 = undefined;
        pm(&tr2, &tr1, s.CC(0, 0, k), s.CC(ido - 1, 3, k));
        const tr3 = 2.0 * s.CC(ido - 1, 1, k);
        const tr4 = 2.0 * s.CC(0, 2, k);
        pm(s.CH(0, k, 0), s.CH(0, k, 2), tr2, tr3);
        pm(s.CH(0, k, 3), s.CH(0, k, 1), tr1, tr4);
    }
    if (ido & 1 == 0) {
        for (0..l1) |k| {
            var tr1: f64 = undefined;
            var tr2: f64 = undefined;
            var ti1: f64 = undefined;
            var ti2: f64 = undefined;
            pm(&ti1, &ti2, s.CC(0, 3, k), s.CC(0, 1, k));
            pm(&tr2, &tr1, s.CC(ido - 1, 0, k), s.CC(ido - 1, 2, k));
            s.CH(ido - 1, k, 0).* = tr2 + tr2;
            s.CH(ido - 1, k, 1).* = sqrt2 * (tr1 - ti1);
            s.CH(ido - 1, k, 2).* = ti2 + ti2;
            s.CH(ido - 1, k, 3).* = -sqrt2 * (tr1 + ti1);
        }
    }
    if (ido <= 2) return;
    for (0..l1) |k| {
        var i: usize = 2;
        while (i < ido) : (i += 2) {
            const ic = ido - i;
            var ci2: f64 = undefined;
            var ci3: f64 = undefined;
            var ci4: f64 = undefined;
            var cr2: f64 = undefined;
            var cr3: f64 = undefined;
            var cr4: f64 = undefined;
            var ti1: f64 = undefined;
            var ti2: f64 = undefined;
            var ti3: f64 = undefined;
            var ti4: f64 = undefined;
            var tr1: f64 = undefined;
            var tr2: f64 = undefined;
            var tr3: f64 = undefined;
            var tr4: f64 = undefined;
            pm(&tr2, &tr1, s.CC(i - 1, 0, k), s.CC(ic - 1, 3, k));
            pm(&ti1, &ti2, s.CC(i, 0, k), s.CC(ic, 3, k));
            pm(&tr4, &ti3, s.CC(i, 2, k), s.CC(ic, 1, k));
            pm(&tr3, &ti4, s.CC(i - 1, 2, k), s.CC(ic - 1, 1, k));
            pm(s.CH(i - 1, k, 0), &cr3, tr2, tr3);
            pm(s.CH(i, k, 0), &ci3, ti2, ti3);
            pm(&cr4, &cr2, tr1, tr4);
            pm(&ci2, &ci4, ti1, ti4);
            const w0 = p.wa(0, i);
            const w1 = p.wa(1, i);
            const w2 = p.wa(2, i);
            mulpm(s.CH(i, k, 1), s.CH(i - 1, k, 1), w0.r, w0.i, ci2, cr2);
            mulpm(s.CH(i, k, 2), s.CH(i - 1, k, 2), w1.r, w1.i, ci3, cr3);
            mulpm(s.CH(i, k, 3), s.CH(i - 1, k, 3), w2.r, w2.i, ci4, cr4);
        }
    }
}

fn radb5(p: Pass, cc: []const f64, ch: []f64) void {
    const l1 = p.l1;
    const ido = p.ido;
    const tr11 = comptime ld(0.3090169943749474241022934171828191);
    const ti11 = comptime ld(0.9510565162951535721164393333793821);
    const tr12 = comptime ld(-0.8090169943749474241022934171828191);
    const ti12 = comptime ld(0.5877852522924731291687059546390728);
    const s: Acc = .{ .cc = cc, .ch = ch, .ido = ido, .l1 = l1, .ip = 5 };
    for (0..l1) |k| {
        const ti5 = s.CC(0, 2, k) + s.CC(0, 2, k);
        const ti4 = s.CC(0, 4, k) + s.CC(0, 4, k);
        const tr2 = s.CC(ido - 1, 1, k) + s.CC(ido - 1, 1, k);
        const tr3 = s.CC(ido - 1, 3, k) + s.CC(ido - 1, 3, k);
        s.CH(0, k, 0).* = s.CC(0, 0, k) + tr2 + tr3;
        const cr2 = s.CC(0, 0, k) + tr11 * tr2 + tr12 * tr3;
        const cr3 = s.CC(0, 0, k) + tr12 * tr2 + tr11 * tr3;
        var ci4: f64 = undefined;
        var ci5: f64 = undefined;
        mulpm(&ci5, &ci4, ti5, ti4, ti11, ti12);
        pm(s.CH(0, k, 4), s.CH(0, k, 1), cr2, ci5);
        pm(s.CH(0, k, 3), s.CH(0, k, 2), cr3, ci4);
    }
    if (ido == 1) return;
    for (0..l1) |k| {
        var i: usize = 2;
        while (i < ido) : (i += 2) {
            const ic = ido - i;
            var tr2: f64 = undefined;
            var tr3: f64 = undefined;
            var tr4: f64 = undefined;
            var tr5: f64 = undefined;
            var ti2: f64 = undefined;
            var ti3: f64 = undefined;
            var ti4: f64 = undefined;
            var ti5: f64 = undefined;
            pm(&tr2, &tr5, s.CC(i - 1, 2, k), s.CC(ic - 1, 1, k));
            pm(&ti5, &ti2, s.CC(i, 2, k), s.CC(ic, 1, k));
            pm(&tr3, &tr4, s.CC(i - 1, 4, k), s.CC(ic - 1, 3, k));
            pm(&ti4, &ti3, s.CC(i, 4, k), s.CC(ic, 3, k));
            s.CH(i - 1, k, 0).* = s.CC(i - 1, 0, k) + tr2 + tr3;
            s.CH(i, k, 0).* = s.CC(i, 0, k) + ti2 + ti3;
            const cr2 = s.CC(i - 1, 0, k) + tr11 * tr2 + tr12 * tr3;
            const ci2 = s.CC(i, 0, k) + tr11 * ti2 + tr12 * ti3;
            const cr3 = s.CC(i - 1, 0, k) + tr12 * tr2 + tr11 * tr3;
            const ci3 = s.CC(i, 0, k) + tr12 * ti2 + tr11 * ti3;
            var ci4: f64 = undefined;
            var ci5: f64 = undefined;
            var cr5: f64 = undefined;
            var cr4: f64 = undefined;
            mulpm(&cr5, &cr4, tr5, tr4, ti11, ti12);
            mulpm(&ci5, &ci4, ti5, ti4, ti11, ti12);
            var dr2: f64 = undefined;
            var dr3: f64 = undefined;
            var dr4: f64 = undefined;
            var dr5: f64 = undefined;
            var di2: f64 = undefined;
            var di3: f64 = undefined;
            var di4: f64 = undefined;
            var di5: f64 = undefined;
            pm(&dr4, &dr3, cr3, ci4);
            pm(&di3, &di4, ci3, cr4);
            pm(&dr5, &dr2, cr2, ci5);
            pm(&di2, &di5, ci2, cr5);
            const w0 = p.wa(0, i);
            const w1 = p.wa(1, i);
            const w2 = p.wa(2, i);
            const w3 = p.wa(3, i);
            mulpm(s.CH(i, k, 1), s.CH(i - 1, k, 1), w0.r, w0.i, di2, dr2);
            mulpm(s.CH(i, k, 2), s.CH(i - 1, k, 2), w1.r, w1.i, di3, dr3);
            mulpm(s.CH(i, k, 3), s.CH(i - 1, k, 3), w2.r, w2.i, di4, dr4);
            mulpm(s.CH(i, k, 4), s.CH(i - 1, k, 4), w3.r, w3.i, di5, dr5);
        }
    }
}

/// Generic odd prime radix backward pass. Uses cc as scratch; the result
/// is in ch.
fn radbg(p: Pass, ip: usize, cc: []f64, ch: []f64) void {
    const l1 = p.l1;
    const ido = p.ido;
    const n = p.roots.n;
    const ipph = (ip + 1) / 2;
    const idl1 = ido * l1;

    var csarr: [2 * 134]f64 = undefined;
    csarr[0] = 1;
    csarr[1] = 0;
    {
        var i: usize = 2;
        var ic: usize = 2 * ip - 2;
        while (i <= ic) : ({
            i += 2;
            ic -= 2;
        }) {
            const v = p.roots.get(i / 2 * (n / ip));
            csarr[i] = v.r;
            csarr[i + 1] = v.i;
            csarr[ic] = v.r;
            csarr[ic + 1] = -v.i;
        }
    }
    const S = struct {
        cc: []f64,
        ch: []f64,
        ido: usize,
        l1: usize,
        ip: usize,
        idl1: usize,
        inline fn CC(s: @This(), a: usize, b: usize, c: usize) f64 {
            return s.cc[a + s.ido * (b + s.ip * c)];
        }
        inline fn CH(s: @This(), a: usize, b: usize, c: usize) *f64 {
            return &s.ch[a + s.ido * (b + s.l1 * c)];
        }
        inline fn C1(s: @This(), a: usize, b: usize, c: usize) *f64 {
            return &s.cc[a + s.ido * (b + s.l1 * c)];
        }
        inline fn C2(s: @This(), a: usize, b: usize) *f64 {
            return &s.cc[a + s.idl1 * b];
        }
        inline fn CH2(s: @This(), a: usize, b: usize) *f64 {
            return &s.ch[a + s.idl1 * b];
        }
    };
    const s: S = .{ .cc = cc, .ch = ch, .ido = ido, .l1 = l1, .ip = ip, .idl1 = idl1 };

    for (0..l1) |k| {
        for (0..ido) |i| s.CH(i, k, 0).* = s.CC(i, 0, k);
    }
    {
        var j: usize = 1;
        var jc: usize = ip - 1;
        while (j < ipph) : ({
            j += 1;
            jc -= 1;
        }) {
            const j2 = 2 * j - 1;
            for (0..l1) |k| {
                s.CH(0, k, j).* = 2.0 * s.CC(ido - 1, j2, k);
                s.CH(0, k, jc).* = 2.0 * s.CC(0, j2 + 1, k);
            }
        }
    }
    if (ido != 1) {
        var j: usize = 1;
        var jc: usize = ip - 1;
        while (j < ipph) : ({
            j += 1;
            jc -= 1;
        }) {
            const j2 = 2 * j - 1;
            for (0..l1) |k| {
                var i: usize = 1;
                while (i <= ido - 2) : (i += 2) {
                    const ic = ido - i - 2;
                    s.CH(i, k, j).* = s.CC(i, j2 + 1, k) + s.CC(ic, j2, k);
                    s.CH(i, k, jc).* = s.CC(i, j2 + 1, k) - s.CC(ic, j2, k);
                    s.CH(i + 1, k, j).* = s.CC(i + 1, j2 + 1, k) - s.CC(ic + 1, j2, k);
                    s.CH(i + 1, k, jc).* = s.CC(i + 1, j2 + 1, k) + s.CC(ic + 1, j2, k);
                }
            }
        }
    }
    {
        var l: usize = 1;
        var lc: usize = ip - 1;
        while (l < ipph) : ({
            l += 1;
            lc -= 1;
        }) {
            for (0..idl1) |ik| {
                s.C2(ik, l).* = s.CH2(ik, 0).* + csarr[2 * l] * s.CH2(ik, 1).* + csarr[4 * l] * s.CH2(ik, 2).*;
                s.C2(ik, lc).* = csarr[2 * l + 1] * s.CH2(ik, ip - 1).* + csarr[4 * l + 1] * s.CH2(ik, ip - 2).*;
            }
            var iang: usize = 2 * l;
            var j: usize = 3;
            var jc: usize = ip - 3;
            while (j + 3 < ipph) : ({
                j += 4;
                jc -= 4;
            }) {
                iang += l;
                if (iang > ip) iang -= ip;
                const ar1 = csarr[2 * iang];
                const ai1 = csarr[2 * iang + 1];
                iang += l;
                if (iang > ip) iang -= ip;
                const ar2 = csarr[2 * iang];
                const ai2 = csarr[2 * iang + 1];
                iang += l;
                if (iang > ip) iang -= ip;
                const ar3 = csarr[2 * iang];
                const ai3 = csarr[2 * iang + 1];
                iang += l;
                if (iang > ip) iang -= ip;
                const ar4 = csarr[2 * iang];
                const ai4 = csarr[2 * iang + 1];
                for (0..idl1) |ik| {
                    s.C2(ik, l).* += ar1 * s.CH2(ik, j).* + ar2 * s.CH2(ik, j + 1).* +
                        ar3 * s.CH2(ik, j + 2).* + ar4 * s.CH2(ik, j + 3).*;
                    s.C2(ik, lc).* += ai1 * s.CH2(ik, jc).* + ai2 * s.CH2(ik, jc - 1).* +
                        ai3 * s.CH2(ik, jc - 2).* + ai4 * s.CH2(ik, jc - 3).*;
                }
            }
            while (j + 1 < ipph) : ({
                j += 2;
                jc -= 2;
            }) {
                iang += l;
                if (iang > ip) iang -= ip;
                const ar1 = csarr[2 * iang];
                const ai1 = csarr[2 * iang + 1];
                iang += l;
                if (iang > ip) iang -= ip;
                const ar2 = csarr[2 * iang];
                const ai2 = csarr[2 * iang + 1];
                for (0..idl1) |ik| {
                    s.C2(ik, l).* += ar1 * s.CH2(ik, j).* + ar2 * s.CH2(ik, j + 1).*;
                    s.C2(ik, lc).* += ai1 * s.CH2(ik, jc).* + ai2 * s.CH2(ik, jc - 1).*;
                }
            }
            while (j < ipph) : ({
                j += 1;
                jc -= 1;
            }) {
                iang += l;
                if (iang > ip) iang -= ip;
                const war = csarr[2 * iang];
                const wai = csarr[2 * iang + 1];
                for (0..idl1) |ik| {
                    s.C2(ik, l).* += war * s.CH2(ik, j).*;
                    s.C2(ik, lc).* += wai * s.CH2(ik, jc).*;
                }
            }
        }
    }
    for (1..ipph) |j| {
        for (0..idl1) |ik| s.CH2(ik, 0).* += s.CH2(ik, j).*;
    }
    {
        var j: usize = 1;
        var jc: usize = ip - 1;
        while (j < ipph) : ({
            j += 1;
            jc -= 1;
        }) {
            for (0..l1) |k| pm(s.CH(0, k, jc), s.CH(0, k, j), s.C1(0, k, j).*, s.C1(0, k, jc).*);
        }
    }
    if (ido == 1) return;
    {
        var j: usize = 1;
        var jc: usize = ip - 1;
        while (j < ipph) : ({
            j += 1;
            jc -= 1;
        }) {
            for (0..l1) |k| {
                var i: usize = 1;
                while (i <= ido - 2) : (i += 2) {
                    s.CH(i, k, j).* = s.C1(i, k, j).* - s.C1(i + 1, k, jc).*;
                    s.CH(i, k, jc).* = s.C1(i, k, j).* + s.C1(i + 1, k, jc).*;
                    s.CH(i + 1, k, j).* = s.C1(i + 1, k, j).* + s.C1(i, k, jc).*;
                    s.CH(i + 1, k, jc).* = s.C1(i + 1, k, j).* - s.C1(i, k, jc).*;
                }
            }
        }
    }
    for (1..ip) |j| {
        for (0..l1) |k| {
            var i: usize = 1;
            while (i <= ido - 2) : (i += 2) {
                const w = p.roots.get(j * l1 * ((i + 1) / 2));
                const t1 = s.CH(i, k, j).*;
                const t2 = s.CH(i + 1, k, j).*;
                s.CH(i, k, j).* = w.r * t1 - w.i * t2;
                s.CH(i + 1, k, j).* = w.r * t2 + w.i * t1;
            }
        }
    }
}

/// Backward real FFT (ducc0 `pocketfft_r::exec` with fwd=false), input in
/// FFTPACK half-complex order. `a` holds the input; `b` is scratch of the
/// same length. Returns the slice holding the result.
fn rfftBackward(roots: *const Roots, a: []f64, b: []f64) []f64 {
    const n = a.len;
    var f: Factors = .{};
    f.init(n);
    var p1 = a;
    var p2 = b;
    var l1: usize = 1;
    for (f.slice()) |ip| {
        const pass: Pass = .{ .l1 = l1, .ido = n / (l1 * ip), .roots = roots };
        switch (ip) {
            2 => radb2(pass, p1, p2),
            3 => radb3(pass, p1, p2),
            4 => radb4(pass, p1, p2),
            5 => radb5(pass, p1, p2),
            else => radbg(pass, ip, p1, p2),
        }
        std.mem.swap([]f64, &p1, &p2);
        l1 *= ip;
    }
    return p1;
}

/// Plan for one DCT length: the FFT roots and the DCT twiddles.
pub const Plan = struct {
    n: usize,
    fft_roots: Roots,
    tw_roots: Roots,

    pub fn init(n: usize) Plan {
        std.debug.assert(supported(n));
        return .{ .n = n, .fft_roots = Roots.init(n), .tw_roots = Roots.init(4 * n) };
    }

    fn twiddle(self: *const Plan, i: usize) f64 {
        return self.tw_roots.get(i + 1).r;
    }

    /// In-place type-II DCT of `c` (length n), unnormalized, as
    /// `scipy.fftpack.dct(x)`. `buf` is scratch of length n.
    pub fn dct2(self: *const Plan, c: []f64, buf: []f64) void {
        const n = self.n;
        const ns2 = (n + 1) / 2;
        c[0] *= 2;
        if (n & 1 == 0) c[n - 1] *= 2;
        {
            var k: usize = 1;
            while (k + 1 < n) : (k += 2) {
                const t = c[k + 1];
                c[k + 1] -= c[k];
                c[k] = t + c[k];
            }
        }
        const res = rfftBackward(&self.fft_roots, c, buf[0..n]);
        c[0] = res[0];
        {
            var k: usize = 1;
            var kc: usize = n - 1;
            while (k < ns2) : ({
                k += 1;
                kc -= 1;
            }) {
                const t1 = self.twiddle(k - 1) * res[kc] + self.twiddle(kc - 1) * res[k];
                const t2 = self.twiddle(k - 1) * res[k] - self.twiddle(kc - 1) * res[kc];
                c[k] = 0.5 * (t1 + t2);
                c[kc] = 0.5 * (t1 - t2);
            }
        }
        if (n & 1 == 0) c[ns2] = res[ns2] * self.twiddle(ns2 - 1);
    }
};

test "dct of small vectors matches the definition" {
    // y[k] = 2 * sum x[i] cos(pi k (2i+1) / 2n)
    for ([_]usize{ 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 30, 32, 49, 64, 77 }) |n| {
        var x: [77]f64 = undefined;
        var y: [77]f64 = undefined;
        var buf: [77]f64 = undefined;
        for (0..n) |i| x[i] = @floatFromInt((i * 37 + 11) % 23);
        @memcpy(y[0..n], x[0..n]);
        const plan = Plan.init(n);
        plan.dct2(y[0..n], buf[0..n]);
        for (0..n) |k| {
            var want: f64 = 0;
            for (0..n) |i| want += 2 * x[i] * @cos(std.math.pi * @as(f64, @floatFromInt(k * (2 * i + 1))) / @as(f64, @floatFromInt(2 * n)));
            try std.testing.expectApproxEqAbs(want, y[k], 1e-9);
        }
    }
}
