// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Licence check for the shipped tree.
//
//   node scripts/check-licenses.mjs [root]
//
// Fails (exit 1) when
//   - a source file under src/ or packages/fuzzyhash-ng/src/ (or build.zig) has no
//     SPDX-License-Identifier line near the top, or names a licence not in ALLOWED;
//   - any file that ships (the Zig package paths and the npm package files) contains a
//     GPL licence identifier or the GPL licence text.
//
// Ported code keeps its upstream licence: telfhash (Apache-2.0), capstone's
// disassembler code and tables (BSD-3-Clause, and NCSA for its LLVM-derived x86
// decoder), Pillow's resampler (MIT-CMU), ImageHash (BSD-2-Clause) and the ducc0
// FFT (BSD-3-Clause), and SimHash's tables keep the Unicode data licence
// (Unicode-3.0). Those are allowed next to MIT.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ALLOWED = new Set(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'MIT-CMU', 'NCSA', 'Unicode-3.0']);

/** Directories and files whose source files need an SPDX header. */
export const HEADER_ROOTS = ['build.zig', 'src', 'packages/fuzzyhash-ng/src', 'packages/fuzzyhash-ng/wasm'];

/** Everything that ships: build.zig.zon `.paths` and the npm package `files`. */
export const SHIPPED_ROOTS = [
  'build.zig',
  'build.zig.zon',
  'src',
  'LICENSE',
  'LICENSES',
  'README.md',
  'packages/fuzzyhash-ng',
];

const SOURCE_EXT = /\.(zig|mjs|js|cjs|mts|ts)$/;
const SKIP_DIRS = new Set(['node_modules', '.zig-cache', 'zig-out', '.git']);
const HEADER_LINES = 5;

const GPL_PATTERNS = [
  /\b(?:L|A)?GPL-?[123](?:\.[01])?(?:-only|-or-later|\+)?\b/,
  /GNU (?:Lesser |Library |Affero )?General Public License/i,
];

function walk(root, rel, out) {
  const abs = join(root, rel);
  let st;
  try {
    st = statSync(abs);
  } catch {
    return;
  }
  if (st.isDirectory()) {
    for (const name of readdirSync(abs).sort()) {
      if (SKIP_DIRS.has(name)) continue;
      walk(root, rel ? join(rel, name) : name, out);
    }
  } else if (st.isFile()) {
    out.push(rel.split(sep).join('/'));
  }
}

function filesUnder(root, roots) {
  const out = [];
  for (const r of roots) walk(root, r, out);
  return out;
}

/** The SPDX expression in the first lines of `text`, or null. */
export function spdxOf(text) {
  const head = text.split('\n', HEADER_LINES).join('\n');
  const m = /SPDX-License-Identifier:\s*([^\n*]+?)\s*(?:\*\/)?\s*$/m.exec(head);
  return m ? m[1] : null;
}

/** True when every licence named in the SPDX expression is allowed. */
export function expressionAllowed(expr) {
  const ids = expr.replace(/[()]/g, ' ').split(/\s+(?:AND|OR|WITH)\s+|\s+/).filter(Boolean);
  return ids.length > 0 && ids.every((id) => ALLOWED.has(id));
}

/** Check the tree at `root`. Returns a list of problems, empty when it passes. */
export function check(root) {
  const problems = [];

  for (const file of filesUnder(root, HEADER_ROOTS)) {
    if (!SOURCE_EXT.test(file)) continue;
    const expr = spdxOf(readFileSync(join(root, file), 'utf8'));
    if (expr === null) problems.push(`${file}: no SPDX-License-Identifier in the first ${HEADER_LINES} lines`);
    else if (!expressionAllowed(expr)) problems.push(`${file}: licence "${expr}" is not allowed`);
  }

  for (const file of filesUnder(root, SHIPPED_ROOTS)) {
    const buf = readFileSync(join(root, file));
    if (buf.includes(0)) continue; // binary
    const text = buf.toString('utf8');
    for (const re of GPL_PATTERNS) {
      const m = re.exec(text);
      if (m) {
        const line = text.slice(0, m.index).split('\n').length;
        problems.push(`${file}:${line}: GPL reference "${m[0]}" in a shipped file`);
        break;
      }
    }
  }

  return problems;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const root = process.argv[2] ?? fileURLToPath(new URL('..', import.meta.url));
  const problems = check(root);
  for (const p of problems) console.error(p);
  if (problems.length > 0) {
    console.error(`check-licenses: ${problems.length} problem(s) in ${relative(process.cwd(), root) || '.'}`);
    process.exit(1);
  }
  console.log('check-licenses: ok');
}
