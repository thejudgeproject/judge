#!/usr/bin/env node
/**
 * Lint: syntax, encoding, whitespace, and the rules specific to what this repository promises
 * about itself: no printing from library code, no unfinished markers, no dependencies, and no
 * counts in the README that have drifted from the code.
 *
 * Dependency-free, for the same reason `reference/` is.
 *
 *   node scripts/lint.mjs
 *   node scripts/lint.mjs --fix     # whitespace and line endings only; never logic
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIX = process.argv.includes('--fix');
const MAX_LINE = 120;

const SKIP = new Set(['node_modules', '.git', 'coverage', 'dist', 'build']);
/* This file contains the words it searches for. Exempting it from its own content rules is
   the alternative to obfuscating them, and an obfuscated rule is a rule nobody can review. */
const SELF = path.join('scripts', 'lint.mjs');
const CODE = /\.(mjs|js|cjs)$/;
const TEXT = /\.(mjs|js|cjs|json|md|ya?ml)$/;

const problems = [];
const note = (file, line, rule, detail) =>
  problems.push({ file: path.relative(ROOT, file), line, rule, detail });

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (TEXT.test(e.name)) out.push(full);
  }
  return out;
}

const files = walk(ROOT).sort();

for (const file of files) {
  const raw = fs.readFileSync(file, 'utf8');
  let text = raw;

  /* ---- encoding and line endings ---------------------------------------------------- */
  if (text.includes('\r')) {
    if (FIX) text = text.replace(/\r\n?/g, '\n');
    else note(file, 0, 'line endings', 'CRLF found; this repository is LF only');
  }
  if (text.charCodeAt(0) === 0xfeff) {
    if (FIX) text = text.slice(1);
    else note(file, 1, 'byte order mark', 'remove it');
  }

  /* ---- trailing whitespace and final newline ---------------------------------------- */
  const lines = text.split('\n');
  lines.forEach((l, i) => {
    if (/[ \t]+$/.test(l)) {
      if (!FIX) note(file, i + 1, 'trailing whitespace', '');
    }
    if (/\t/.test(l) && !file.endsWith('.md')) {
      if (!FIX) note(file, i + 1, 'tab', 'indent with spaces');
    }
  });
  if (FIX) text = lines.map((l) => l.replace(/[ \t]+$/, '')).join('\n').replace(/\n*$/, '\n');
  else if (text.length && !text.endsWith('\n')) note(file, lines.length, 'final newline', 'missing');
  else if (/\n\n$/.test(text)) note(file, lines.length, 'final newline', 'more than one');

  const isSelf = path.relative(ROOT, file) === SELF;

  /* ---- line length ------------------------------------------------------------------- */
  /* JSON is data. A canonical string is exactly as long as the record it seals, and wrapping
     it would change the bytes, which is the one thing a fixture must never do. */
  if (!file.endsWith('.json')) {
    text.split('\n').forEach((l, i) => {
      /* A long URL, or a table row, is not a style problem. */
      if (l.length > MAX_LINE && !/^\s*(https?:\/\/|\|)/.test(l) && !/\bhttps?:\/\/\S{40,}/.test(l)) {
        note(file, i + 1, 'line length', `${l.length} > ${MAX_LINE}`);
      }
    });
  }

  /* ---- house punctuation ------------------------------------------------------------- */
  /* House style: no em dashes. A comma, a colon or a full stop covers every use. */
  text.split('\n').forEach((l, i) => {
    if (isSelf) return;
    if (l.includes('\u2014')) note(file, i + 1, 'em dash', 'use a comma, a colon or a full stop');
  });

  /* ---- per-type checks --------------------------------------------------------------- */
  if (file.endsWith('.json')) {
    try { JSON.parse(text); } catch (e) { note(file, 0, 'json', e.message); }
  }

  if (CODE.test(file)) {
    try {
      execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
    } catch (e) {
      note(file, 0, 'syntax', String(e.stderr || e.message).split('\n')[0]);
    }
    text.split('\n').forEach((l, i) => {
      if (isSelf) return;
      if (/\bdebugger\b/.test(l)) note(file, i + 1, 'debugger', 'left in');
      if (/\b(TODO|FIXME|XXX|HACK)\b/.test(l)) {
        note(file, i + 1, 'marker', 'finish it or open an issue; do not ship the marker');
      }
      /* The reference implementation is a library. A library that prints is a library that
         cannot be embedded quietly. bin/ and scripts/ are allowed to speak. */
      if (/^reference\//.test(path.relative(ROOT, file)) && /\bconsole\.(log|warn|error)\b/.test(l)) {
        note(file, i + 1, 'console in library code', 'return a value instead');
      }
    });
  }

  if (file.endsWith('.md')) {
    text.split('\n').forEach((l, i) => {
      if (/\b(TODO|FIXME|TBD|coming soon|lorem ipsum)\b/i.test(l)) {
        note(file, i + 1, 'placeholder', 'say what is true now, or say nothing');
      }
    });
  }

  if (FIX && text !== raw) fs.writeFileSync(file, text);
}

/* ---- repository-level checks --------------------------------------------------------- */
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
for (const [name, rel] of Object.entries({ main: pkg.main, ...(pkg.bin || {}) })) {
  if (rel && !fs.existsSync(path.join(ROOT, rel))) {
    note(path.join(ROOT, 'package.json'), 0, 'package.json', `${name} points at a missing file: ${rel}`);
  }
}
if (pkg.dependencies && Object.keys(pkg.dependencies).length) {
  note(path.join(ROOT, 'package.json'), 0, 'dependencies',
    'this package is dependency-free by design; adding one needs a decision, not a commit');
}

/* The README states how many tests there are. A number in documentation rots the moment
   someone adds a case, so it is checked rather than trusted. */
const testDir = path.join(ROOT, 'test');
const actualTests = fs.existsSync(testDir)
  ? fs.readdirSync(testDir)
    .filter((f) => f.endsWith('.test.mjs'))
    .reduce((n, f) => n + (fs.readFileSync(path.join(testDir, f), 'utf8')
      .match(/^test\(/gm) || []).length, 0)
  : 0;
const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const claimed = readme.match(/(\d+)\s+tests\b/);
if (claimed && Number(claimed[1]) !== actualTests) {
  note(path.join(ROOT, 'README.md'), 0, 'stale count',
    `README says ${claimed[1]} tests; there are ${actualTests}`);
}

if (!problems.length) {
  process.stdout.write(`\n  lint: clean  (${files.length} files)\n\n`);
  process.exit(0);
}
process.stderr.write(`\n  lint: ${problems.length} problem(s)\n\n`);
for (const p of problems) {
  process.stderr.write(`  ${p.file}:${p.line}  [${p.rule}]${p.detail ? `  ${p.detail}` : ''}\n`);
}
process.stderr.write(FIX ? '\n' : '\n  Whitespace and line endings: node scripts/lint.mjs --fix\n\n');
process.exit(1);
