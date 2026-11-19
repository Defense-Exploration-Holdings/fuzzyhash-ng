#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Writes test/reference/vectors.zig: ssdeep 2.14.1 and TLSH 5.0.2 results for a generated
// corpus, taken from the reference programs that scripts/fetch-oracles.sh builds.
//
//   scripts/fetch-oracles.sh .oracles
//   node scripts/reference-vectors.mjs .oracles > test/reference/vectors.zig
//
// The corpus is not stored. Each input is generated from (kind, length, seed) and optionally
// mutated, by the same code as in test/reference/corpus.zig, which the Zig tests use to
// regenerate the inputs and check them against the saved results. The two must stay in step.
//
// The reference programs are run as programs only, on temporary files.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// ---- corpus (keep in step with test/reference/corpus.zig) -------------------------------

const KINDS = ['random', 'text', 'runs'];

const WORDS = [
  'the', 'of', 'and', 'to', 'in', 'is', 'that', 'for', 'it', 'as', 'was', 'with', 'be', 'by',
  'on', 'not', 'he', 'this', 'are', 'or', 'his', 'from', 'at', 'which', 'but', 'have', 'an',
  'had', 'they', 'you', 'were', 'their', 'one', 'all', 'we', 'can', 'her', 'has', 'there',
  'been', 'if', 'more', 'when', 'will', 'would', 'who', 'so', 'no', 'file', 'hash', 'block',
  'digest', 'sample', 'packet', 'header', 'section', 'import', 'export', 'string', 'buffer',
  'kernel', 'module', 'driver', 'signature',
];

/** xorshift32. `seed` must not be 0. */
function rng(seed) {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x;
  };
}

export function generate(kind, len, seed) {
  const next = rng(seed);
  const out = new Uint8Array(len);
  let i = 0;
  if (kind === 'random') {
    while (i < len) out[i++] = next() >>> 24;
  } else if (kind === 'text') {
    while (i < len) {
      const w = WORDS[next() % WORDS.length];
      for (let k = 0; k < w.length && i < len; k++) out[i++] = w.charCodeAt(k);
      if (i < len) out[i++] = next() % 8 === 0 ? 0x0a : 0x20;
    }
  } else if (kind === 'runs') {
    const alphabet = [0x41, 0x43, 0x47, 0x54];
    while (i < len) {
      const b = alphabet[next() % 4];
      let run = 1 + (next() % 32);
      while (run-- > 0 && i < len) out[i++] = b;
    }
  } else {
    throw new Error(`unknown kind ${kind}`);
  }
  return out;
}

/** Applies `count` single-byte edits (replace, insert or delete). */
export function mutate(input, seed, count) {
  const next = rng(seed);
  let buf = Array.from(input);
  for (let n = 0; n < count; n++) {
    const op = next() % 3;
    if (buf.length === 0 && op !== 1) continue;
    const pos = next() % (buf.length + (op === 1 ? 1 : 0));
    if (op === 0) buf[pos] = next() >>> 24;
    else if (op === 1) buf.splice(pos, 0, next() >>> 24);
    else buf.splice(pos, 1);
  }
  return Uint8Array.from(buf);
}

const LENGTHS = [
  0, 1, 2, 3, 7, 32, 49, 50, 51, 64, 100, 255, 256, 257, 500, 1000, 2048, 4095, 4096, 4097, 6000,
  10000, 30000, 65536, 100000, 262144,
];
const LARGE = [1048576];
const PAIR_LENGTHS = [64, 300, 1000, 5000, 20000, 100000];
const PAIR_EDITS = [1, 10, 100];

/** Every input: { kind, len, seed, mutateSeed, edits }. */
export function corpus() {
  const cases = [];
  const pairs = [];
  for (const [k, kind] of KINDS.entries()) {
    for (const len of [...LENGTHS, ...LARGE]) cases.push({ kind, len, seed: 1 + k * 1000 + (len % 997), mutateSeed: 0, edits: 0 });
    for (const len of PAIR_LENGTHS) {
      const seed = 7 + k * 1000 + (len % 991);
      const a = cases.length;
      cases.push({ kind, len, seed, mutateSeed: 0, edits: 0 });
      for (const edits of PAIR_EDITS) {
        pairs.push({ a, b: cases.length });
        cases.push({ kind, len, seed, mutateSeed: seed * 31 + edits, edits });
      }
      // The same generator run twice as long: the first half is identical, the length differs.
      pairs.push({ a, b: cases.length });
      cases.push({ kind, len: len * 2, seed, mutateSeed: 0, edits: 0 });
    }
  }
  return { cases, pairs };
}

export function bytesOf(c) {
  const base = generate(c.kind, c.len, c.seed);
  return c.edits === 0 ? base : mutate(base, c.mutateSeed, c.edits);
}

// ---- reference programs ---------------------------------------------------------------

const VARIANTS = ['128-1', '128-3', '256-1', '256-3'];

function run(bin, args) {
  return execFileSync(bin, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function main() {
  const oracles = resolve(process.argv[2] ?? '.oracles');
  const ssdeepBin = join(oracles, 'ssdeep', 'bin', 'ssdeep');
  const tlshBin = (v) => join(oracles, `tlsh-${v}`, 'bin', 'tlsh_unittest');
  const work = mkdtempSync(join(tmpdir(), 'fuzzyhash-vectors-'));
  try {
    const { cases, pairs } = corpus();
    const results = cases.map((c, i) => {
      const file = join(work, `${i}.bin`);
      writeFileSync(file, bytesOf(c));
      const ss = run(ssdeepBin, ['-s', '-b', file]).split('\n')[1];
      const ssdeep = ss.slice(0, ss.indexOf(',"'));
      const tlsh = VARIANTS.map((v) => {
        // No digest (too short or too uniform): a message on standard error, nothing on standard output.
        const digest = run(tlshBin(v), ['-f', file]).trim().split('\t')[0];
        return /^[0-9A-Z]+$/.test(digest) ? digest : null;
      });
      return { file, ssdeep, tlsh };
    });

    const pairResults = pairs.map(({ a, b }) => {
      const known = join(work, `known-${a}.txt`);
      writeFileSync(known, run(ssdeepBin, ['-s', '-b', results[a].file]));
      const m = /\((\d+)\)\s*$/.exec(run(ssdeepBin, ['-a', '-s', '-b', '-m', known, results[b].file]).trim());
      if (!m) throw new Error(`no ssdeep score for pair ${a} ${b}`);
      const diff = (xlen) =>
        VARIANTS.map((v, k) => {
          const da = results[a].tlsh[k];
          const db = results[b].tlsh[k];
          if (da === null || db === null) return null;
          // By file: the 3-byte checksum builds do not read digests with the T1 prefix.
          const out = run(tlshBin(v), ['-c', results[a].file, '-f', results[b].file, ...(xlen ? ['-xlen'] : [])]);
          return Number(out.trim().split(/\s+/)[0]);
        });
      return { a, b, ssdeep: Number(m[1]), diff: diff(false), diffXlen: diff(true) };
    });

    const ssdeepVersion = run(ssdeepBin, ['-V']).trim();
    const str = (s) => (s === null ? 'null' : JSON.stringify(s));
    const num = (n) => (n === null ? 'null' : String(n));
    const lines = [];
    lines.push('// SPDX-License-Identifier: MIT');
    lines.push('// Copyright (c) 2026 Defense Exploration Holdings, LLC');
    lines.push('// Generated by scripts/reference-vectors.mjs from the reference programs built by');
    lines.push(`// scripts/fetch-oracles.sh (ssdeep ${ssdeepVersion}, TLSH 5.0.2). Do not edit.`);
    lines.push('');
    lines.push('const corpus = @import("corpus.zig");');
    lines.push('');
    lines.push('/// TLSH builds, in the order of `Case.tlsh` and `Pair.tlsh_diff`.');
    lines.push('pub const tlsh_variants = [_][]const u8{ ' + VARIANTS.map((v) => JSON.stringify(v)).join(', ') + ' };');
    lines.push('');
    lines.push('pub const Case = struct {');
    lines.push('    input: corpus.Input,');
    lines.push('    ssdeep: []const u8,');
    lines.push('    /// null where TLSH gives no digest (input too short or too uniform).');
    lines.push('    tlsh: [4]?[]const u8,');
    lines.push('};');
    lines.push('');
    lines.push('pub const Pair = struct {');
    lines.push('    a: usize,');
    lines.push('    b: usize,');
    lines.push('    ssdeep: u8,');
    lines.push('    tlsh_diff: [4]?u32,');
    lines.push('    tlsh_diff_xlen: [4]?u32,');
    lines.push('};');
    lines.push('');
    lines.push('pub const cases = [_]Case{');
    cases.forEach((c, i) => {
      const r = results[i];
      lines.push(
        `    .{ .input = .{ .kind = .${c.kind}, .len = ${c.len}, .seed = ${c.seed}, .mutate_seed = ${c.mutateSeed}, .edits = ${c.edits} }, ` +
          `.ssdeep = ${str(r.ssdeep)}, .tlsh = .{ ${r.tlsh.map(str).join(', ')} } },`,
      );
    });
    lines.push('};');
    lines.push('');
    lines.push('pub const pairs = [_]Pair{');
    for (const p of pairResults) {
      lines.push(
        `    .{ .a = ${p.a}, .b = ${p.b}, .ssdeep = ${p.ssdeep}, .tlsh_diff = .{ ${p.diff.map(num).join(', ')} }, ` +
          `.tlsh_diff_xlen = .{ ${p.diffXlen.map(num).join(', ')} } },`,
      );
    }
    lines.push('};');
    process.stdout.write(lines.join('\n') + '\n');
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

main();
