#!/usr/bin/env node
/**
 * Every relative link and every in-page anchor in the documentation must resolve, and every
 * file the documentation promises must exist. Runs in CI, so a renamed file breaks the build
 * rather than the reader.
 *
 * External links are checked for shape only and never fetched: a check that fails because
 * someone else's server is slow gets ignored rather than fixed.
 *
 *   node scripts/check-links.mjs
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP = new Set(['node_modules', '.git', 'coverage', 'dist', 'build']);

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (e.name.endsWith('.md')) out.push(full);
  }
  return out;
}

/** GitHub's slug rule, near enough for our own headings: lowercase, strip punctuation, dash spaces. */
function slug(heading) {
  return heading.trim().toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-');
}

const docs = walk(ROOT).sort();

/* Anchors available in each document, by absolute path. */
const anchors = new Map();
for (const file of docs) {
  const set = new Set();
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = line.match(/^#{1,6}\s+(.*?)\s*$/);
    if (m) set.add(slug(m[1]));
  }
  anchors.set(file, set);
}

const problems = [];
let checked = 0;

for (const file of docs) {
  const text = fs.readFileSync(file, 'utf8');
  const lines = text.split('\n');

  /* Ignore fenced code blocks: a path inside an example command is illustration, not a link. */
  let fenced = false;
  lines.forEach((line, i) => {
    if (/^\s*```/.test(line)) { fenced = !fenced; return; }
    if (fenced) return;

    for (const m of line.matchAll(/\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
      const target = m[1];
      checked += 1;

      if (/^(https?:|mailto:)/.test(target)) {
        if (/^https?:\/\/[^/]*\s/.test(target)) {
          problems.push({ file, line: i + 1, target, why: 'malformed URL' });
        }
        continue;
      }

      const [rel, frag] = target.split('#');
      const resolved = rel
        ? path.resolve(path.dirname(file), rel)
        : file;

      if (rel && !fs.existsSync(resolved)) {
        problems.push({ file, line: i + 1, target, why: 'no such file' });
        continue;
      }
      if (frag) {
        const have = anchors.get(resolved);
        if (!have) {
          problems.push({ file, line: i + 1, target, why: 'anchor in a non-markdown file' });
        } else if (!have.has(frag.toLowerCase())) {
          problems.push({ file, line: i + 1, target, why: 'no such heading' });
        }
      }
    }
  });
}

/* Files the documentation promises exist. */
const PROMISED = [
  'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'LICENSE', 'CHANGELOG.md', '.env.example',
  'docs/SPEC.md', 'docs/ARCHITECTURE.md', 'docs/THREAT-MODEL.md',
  'reference/judge.mjs', 'reference/receipt.mjs', 'bin/judge-verify.mjs',
  'examples/receipt.example.json', 'examples/receipt.tampered.json',
];
for (const rel of PROMISED) {
  if (!fs.existsSync(path.join(ROOT, rel))) {
    problems.push({ file: path.join(ROOT, 'scripts/check-links.mjs'), line: 0, target: rel,
      why: 'listed as required but missing' });
  }
}

if (!problems.length) {
  process.stdout.write(`\n  links: clean  (${checked} checked across ${docs.length} documents)\n\n`);
  process.exit(0);
}
process.stderr.write(`\n  links: ${problems.length} broken\n\n`);
for (const p of problems) {
  process.stderr.write(`  ${path.relative(ROOT, p.file)}:${p.line}  ${p.target}  -  ${p.why}\n`);
}
process.stderr.write('\n');
process.exit(1);
