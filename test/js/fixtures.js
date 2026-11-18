// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Small PE and ELF files built in memory, for the imphash and telfhash tests.

/**
 * A PE32 or PE32+ image with one section holding the import directory.
 * `imports` is a list of [dll, names]; a name of the form "#N" imports
 * ordinal N.
 */
export function buildPe(pe64, imports) {
  const buf = new Uint8Array(4096);
  const dv = new DataView(buf.buffer);
  const fileAlign = 0x200;
  const sectRva = 0x1000;
  const sectOff = 0x200;
  buf[0] = 0x4d;
  buf[1] = 0x5a;
  dv.setUint32(0x3c, 0x40, true);
  buf.set([0x50, 0x45, 0, 0], 0x40);
  const fh = 0x44;
  dv.setUint16(fh, pe64 ? 0x8664 : 0x14c, true);
  dv.setUint16(fh + 2, 1, true);
  const optSize = pe64 ? 240 : 224;
  dv.setUint16(fh + 16, optSize, true);
  const opt = fh + 20;
  dv.setUint16(opt, pe64 ? 0x20b : 0x10b, true);
  dv.setUint32(opt + 16, sectRva, true);
  dv.setUint32(opt + 32, 0x1000, true);
  dv.setUint32(opt + 36, fileAlign, true);
  dv.setUint32(opt + 60, 0x200, true);
  const base = pe64 ? 112 : 96;
  dv.setUint32(opt + base - 4, 16, true);
  dv.setUint32(opt + base + 8, sectRva, true);
  dv.setUint32(opt + base + 12, 40, true);

  const thunk = pe64 ? 8 : 4;
  let desc = 0;
  let cursor = 20 * (imports.length + 1);
  const ascii = (s, at) => {
    for (let i = 0; i < s.length; i++) buf[sectOff + at + i] = s.charCodeAt(i);
  };
  for (const [dll, names] of imports) {
    const ilt = cursor;
    cursor += thunk * (names.length + 1);
    names.forEach((name, i) => {
      const slot = sectOff + ilt + i * thunk;
      let value;
      if (name[0] === '#') {
        value = (pe64 ? 1n << 63n : 1n << 31n) | BigInt(Number(name.slice(1)));
      } else {
        value = BigInt(sectRva + cursor);
        ascii(name, cursor + 2);
        cursor += 2 + name.length + 1;
      }
      if (pe64) dv.setBigUint64(slot, value, true);
      else dv.setUint32(slot, Number(value), true);
    });
    const dllRva = sectRva + cursor;
    ascii(dll, cursor);
    cursor += dll.length + 1;
    dv.setUint32(sectOff + desc, sectRva + ilt, true);
    dv.setUint32(sectOff + desc + 12, dllRva, true);
    dv.setUint32(sectOff + desc + 16, sectRva + ilt, true);
    desc += 20;
  }
  const raw = Math.ceil(cursor / fileAlign) * fileAlign;
  const sh = opt + optSize;
  ascii('.data', sh - sectOff);
  dv.setUint32(sh + 8, raw, true);
  dv.setUint32(sh + 12, sectRva, true);
  dv.setUint32(sh + 16, raw, true);
  dv.setUint32(sh + 20, sectOff, true);
  return buf.slice(0, sectOff + raw);
}

/** An ELF64 little-endian x86-64 file with sections NULL, .dynstr, .dynsym and .shstrtab. */
export function buildElf(names) {
  const buf = new Uint8Array(4096);
  const dv = new DataView(buf.buffer);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  dv.setUint16(16, 3, true); // ET_DYN
  dv.setUint16(18, 62, true); // x86-64
  const strOff = 0x100;
  let p = strOff + 1;
  const offs = [];
  for (const n of names) {
    offs.push(p - strOff);
    for (let i = 0; i < n.length; i++) buf[p + i] = n.charCodeAt(i);
    p += n.length + 1;
  }
  const symOff = 0x400;
  names.forEach((_, i) => {
    const e = symOff + 24 * (i + 1);
    dv.setUint32(e, offs[i], true);
    buf[e + 4] = (1 << 4) | 2; // GLOBAL FUNC
  });
  const shstr = '\0.dynstr\0.dynsym\0.shstrtab\0';
  for (let i = 0; i < shstr.length; i++) buf[0x800 + i] = shstr.charCodeAt(i);
  const sh = 0x900;
  dv.setBigUint64(40, BigInt(sh), true);
  dv.setUint16(52, 64, true);
  dv.setUint16(58, 64, true);
  dv.setUint16(60, 4, true);
  dv.setUint16(62, 3, true);
  const secs = [
    [0, 0, 0, 0, 0, 0],
    [1, 3, strOff, p - strOff, 0, 0],
    [9, 11, symOff, 24 * (names.length + 1), 1, 24],
    [17, 3, 0x800, shstr.length, 0, 0],
  ];
  secs.forEach(([name, type, off, size, link, entsize], i) => {
    const e = sh + 64 * i;
    dv.setUint32(e, name, true);
    dv.setUint32(e + 4, type, true);
    dv.setBigUint64(e + 24, BigInt(off), true);
    dv.setBigUint64(e + 32, BigInt(size), true);
    dv.setUint32(e + 40, link, true);
    dv.setBigUint64(e + 56, BigInt(entsize), true);
  });
  return buf.slice(0, sh + 64 * secs.length);
}
