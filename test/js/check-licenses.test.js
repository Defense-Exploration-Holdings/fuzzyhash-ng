// SPDX-License-Identifier: MIT
// scripts/check-licenses.mjs on small trees built for each case.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { check, expressionAllowed, spdxOf } from '../../scripts/check-licenses.mjs';

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), 'fuzzyhash-licenses-'));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return root;
}

function withTree(files, fn) {
  const root = tree(files);
  try {
    return fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('spdxOf reads line and block comment headers, after a shebang', () => {
  assert.equal(spdxOf('// SPDX-License-Identifier: MIT\nconst x = 1;\n'), 'MIT');
  assert.equal(spdxOf('/* SPDX-License-Identifier: Apache-2.0 */\n'), 'Apache-2.0');
  assert.equal(spdxOf('#!/usr/bin/env node\n// SPDX-License-Identifier: MIT\n'), 'MIT');
  assert.equal(spdxOf('a\nb\nc\nd\ne\n// SPDX-License-Identifier: MIT\n'), null);
  assert.equal(spdxOf('const x = 1;\n'), null);
});

test('expressionAllowed accepts MIT, Apache-2.0, BSD-3-Clause, NCSA and combinations of them only', () => {
  assert.equal(expressionAllowed('MIT'), true);
  assert.equal(expressionAllowed('Apache-2.0'), true);
  assert.equal(expressionAllowed('MIT AND Apache-2.0'), true);
  assert.equal(expressionAllowed('(MIT OR Apache-2.0)'), true);
  assert.equal(expressionAllowed('GPL-2.0-only'), false);
  assert.equal(expressionAllowed('BSD-3-Clause'), true);
  assert.equal(expressionAllowed('NCSA AND BSD-3-Clause'), true);
  assert.equal(expressionAllowed('MIT AND MPL-2.0'), false);
  assert.equal(expressionAllowed(''), false);
});

test('a clean tree passes', () => {
  withTree(
    {
      'build.zig': '// SPDX-License-Identifier: MIT\n',
      'src/root.zig': '// SPDX-License-Identifier: MIT\n',
      'src/tlsh.zig': '// SPDX-License-Identifier: Apache-2.0\n',
      'packages/fuzzyhash-ng/src/index.mjs': '// SPDX-License-Identifier: MIT\n',
      'packages/fuzzyhash-ng/README.md': 'Licensed under MIT.\n',
      'README.md': '# fuzzyhash-ng\n',
    },
    (root) => assert.deepEqual(check(root), []),
  );
});

test('a source file without a header is reported', () => {
  withTree({ 'src/a.zig': 'const std = @import("std");\n' }, (root) => {
    const problems = check(root);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /^src\/a\.zig: no SPDX-License-Identifier/);
  });
});

test('a source file under a licence that is not allowed is reported', () => {
  withTree({ 'packages/fuzzyhash-ng/src/x.mjs': '// SPDX-License-Identifier: MPL-2.0\n' }, (root) => {
    assert.match(check(root)[0], /licence "MPL-2.0" is not allowed/);
  });
});

test('files outside the header roots need no header', () => {
  withTree({ 'test/js/a.test.js': 'test();\n', 'scripts/x.mjs': 'x();\n' }, (root) => {
    assert.deepEqual(check(root), []);
  });
});

test('a GPL identifier or licence text in a shipped file is reported with its line', () => {
  withTree(
    {
      'README.md': 'line one\nThis is GPL-2.0-or-later code.\n',
      'LICENSES/OTHER': 'GNU General Public License, version 2\n',
    },
    (root) => {
      const problems = check(root).sort();
      assert.equal(problems.length, 2);
      assert.match(problems[0], /^LICENSES\/OTHER:1: GPL reference/);
      assert.match(problems[1], /^README\.md:2: GPL reference "GPL-2\.0-or-later"/);
    },
  );
});

test('GPL references outside the shipped tree are allowed', () => {
  withTree({ 'CONTRIBUTING.md': 'ssdeep is GPL-2.0, so do not read its source.\n' }, (root) => {
    assert.deepEqual(check(root), []);
  });
});

test('build output and dependencies are skipped', () => {
  withTree(
    {
      'src/.zig-cache/x.zig': 'no header\n',
      'packages/fuzzyhash-ng/node_modules/dep/index.js': 'GPL-3.0\n',
    },
    (root) => assert.deepEqual(check(root), []),
  );
});
