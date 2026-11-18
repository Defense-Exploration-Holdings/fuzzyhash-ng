#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Defense Exploration Holdings, LLC
// Stages the JSR (jsr.io) package from packages/fuzzyhash-ng.
//
//   node scripts/build-jsr.mjs --sync        rewrite jsr.json (version, license, exports) from package.json
//   node scripts/build-jsr.mjs --check       fail when jsr.json disagrees with package.json
//   node scripts/build-jsr.mjs --out <dir>   stage the package into <dir> (created, must be empty or missing)
//
// package.json is the source of truth for the version, the licence and the entry points. Each npm
// entry point `./<name>` becomes the JSR export `./<name>` with its `default` file.
//
// Staging copies the files JSR needs into a directory outside the repository, so that the generated
// wasm/ modules (ignored by git) are included. It puts `// @ts-self-types="./x.d.mts"` on the first
// line of every module that has a declaration file next to it, because JSR does not look for .d.mts
// files by itself, and points the declaration files at each other by their .d.mts names, because
// Deno does not map `./x.mjs` to `./x.d.mts`. The files in the repository are not changed.
//
// Prerequisite: `zig build js --release=small`. Nothing here publishes; `deno publish` in the
// staged directory does, in .github/workflows/publish-jsr.yml.
import { readFileSync, writeFileSync, mkdirSync, cpSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PKG_ROOT = join(ROOT, 'packages', 'fuzzyhash-ng');
const JSR_JSON = join(PKG_ROOT, 'jsr.json');
const NAME = /^@[a-z0-9-]+\/[a-z0-9-]+$/;

function readJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

/** JSR exports derived from the npm `exports` map. */
export function jsrExports(pkg) {
  const out = {};
  for (const [key, value] of Object.entries(pkg.exports)) {
    if (key === './package.json') continue;
    out[key] = value.default;
  }
  return out;
}

export function derived(pkg, current) {
  return { ...current, version: pkg.version, license: pkg.license, exports: jsrExports(pkg) };
}

export function checkConfig(pkgRoot = PKG_ROOT) {
  const pkg = readJson(join(pkgRoot, 'package.json'));
  const jsr = readJson(join(pkgRoot, 'jsr.json'));
  const want = derived(pkg, jsr);
  const problems = [];
  if (jsr.version !== want.version) problems.push(`version ${jsr.version} in jsr.json, ${want.version} in package.json`);
  if (jsr.license !== want.license) problems.push(`license ${jsr.license} in jsr.json, ${want.license} in package.json`);
  if (JSON.stringify(jsr.exports) !== JSON.stringify(want.exports)) problems.push('exports in jsr.json differ from the npm exports map');
  if (!NAME.test(jsr.name || '')) problems.push(`jsr.json name ${jsr.name} is not @scope/name`);
  for (const [key, file] of Object.entries(jsr.exports)) {
    if (!existsSync(join(pkgRoot, file))) problems.push(`${key}: ${file} does not exist`);
    if (!existsSync(join(pkgRoot, file.replace(/\.mjs$/, '.d.mts')))) problems.push(`${key}: ${file} has no declaration file`);
  }
  return problems;
}

export function sync() {
  const pkg = readJson(join(PKG_ROOT, 'package.json'));
  writeFileSync(JSR_JSON, JSON.stringify(derived(pkg, readJson(JSR_JSON)), null, 2) + '\n');
}

function walk(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, e.name);
    if (e.isDirectory()) walk(path, out);
    else out.push(path);
  }
  return out;
}

/** Stages the package into `out` and returns the staged jsr.json. */
export function stage(out, pkgRoot = PKG_ROOT) {
  const problems = checkConfig(pkgRoot);
  if (problems.length) throw new Error(problems.join('\n'));
  const jsr = readJson(join(pkgRoot, 'jsr.json'));
  if (existsSync(out) && readdirSync(out).length) throw new Error(`${out} is not empty`);
  for (const entry of jsr.publish.include) {
    if (!existsSync(join(pkgRoot, entry))) throw new Error(`missing ${entry} in ${pkgRoot} (run: zig build js --release=small)`);
  }
  mkdirSync(out, { recursive: true });
  for (const entry of jsr.publish.include) cpSync(join(pkgRoot, entry), join(out, entry), { recursive: true });
  writeFileSync(join(out, 'jsr.json'), JSON.stringify(jsr, null, 2) + '\n');

  const files = walk(join(out, 'src'));
  for (const decl of files.filter((f) => f.endsWith('.d.mts'))) {
    const text = readFileSync(decl, 'utf8');
    const rewritten = text.replace(/from '\.\/([a-z0-9-]+)\.mjs'/g, (m, name) =>
      existsSync(join(dirname(decl), `${name}.d.mts`)) ? `from './${name}.d.mts'` : m,
    );
    if (rewritten !== text) writeFileSync(decl, rewritten);
    const source = decl.replace(/\.d\.mts$/, '.mjs');
    if (existsSync(source)) {
      const name = decl.slice(dirname(decl).length + 1);
      writeFileSync(source, `// @ts-self-types="./${name}"\n${readFileSync(source, 'utf8')}`);
    }
  }
  for (const file of Object.values(jsr.exports)) {
    if (!readFileSync(join(out, file), 'utf8').startsWith('// @ts-self-types=')) throw new Error(`${file} has no declaration file next to it`);
  }
  return jsr;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cmd, arg] = process.argv.slice(2);
  if (cmd === '--sync') {
    sync();
    console.log('jsr.json updated');
  } else if (cmd === '--check') {
    const problems = checkConfig();
    if (problems.length) {
      console.error(problems.join('\n'));
      process.exit(1);
    }
    console.log('jsr.json matches package.json');
  } else if (cmd === '--out' && arg) {
    const jsr = stage(resolve(arg));
    console.log(`staged ${jsr.name}@${jsr.version} in ${resolve(arg)}`);
  } else {
    console.error('usage: build-jsr.mjs --sync | --check | --out <dir>');
    process.exit(2);
  }
}
