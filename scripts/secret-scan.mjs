#!/usr/bin/env node
/**
 * Refuses to let a secret, a credential or an identifying detail reach this repository.
 *
 * Runs in CI on every push and pull request, and can be wired to a pre-commit hook. It walks
 * the working tree and, in CI, the full history, a secret removed in the latest commit is
 * still a secret if it is sitting in an earlier one.
 *
 *   node scripts/secret-scan.mjs            # working tree
 *   node scripts/secret-scan.mjs --history  # every commit, every file
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

/* fileURLToPath, not URL.pathname: on Windows the latter yields "/C:/..." and every
   subsequent path operation is then quietly wrong. */
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HISTORY = process.argv.includes('--history');

/* Extra literals to refuse, supplied by the operator at run time and never committed:
   a value you are checking for must not be written down in the thing you are checking.

     SCAN_FORBIDDEN="one,two" node scripts/secret-scan.mjs                                  */
const FORBIDDEN = (process.env.SCAN_FORBIDDEN || '')
  .split(',').map((s) => s.trim()).filter((s) => s.length >= 3);

/* Each rule is [name, pattern]. They are deliberately broad: a false positive costs someone a
   minute, and a false negative costs a credential. */
const RULES = [
  ['private key block',      /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
  ['solana keypair array',   /\[\s*(?:\d{1,3}\s*,\s*){60,}\d{1,3}\s*\]/],
  ['seed phrase',            /\b(?:abandon|ability|able|about|above)\b(?:\s+\w+){10,}/i],
  ['aws access key',         /\bAKIA[0-9A-Z]{16}\b/],
  ['github token',           /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['slack token',            /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ['stripe key',             /\bsk_(live|test)_[A-Za-z0-9]{16,}\b/],
  ['generic bearer token',   /\b(authorization|bearer)\s*[:=]\s*['"][A-Za-z0-9._\-]{20,}['"]/i],
  ['assigned secret',        new RegExp(String.raw`\b(api[_-]?key|secret|passcode|password`
                             + String.raw`|passwd|admin[_-]?key|token)\s*[:=]\s*['"][^'"\s]{6,}['"]`, 'i')],
  /* Any shouty name that sounds like a secret, with something assigned to it. Naming the
     specific variables an application happens to use would both narrow the rule and publish
     the variable names, so this matches the shape instead. */
  ['assigned env secret',    new RegExp(String.raw`^\s*[A-Z0-9_]*`
                             + String.raw`(KEY|SECRET|TOKEN|PASSCODE|PASSWORD|SALT|SEED|MNEMONIC)`
                             + String.raw`[A-Z0-9_]*\s*=\s*\S`, 'm')],
  ['windows user path',      /[A-Za-z]:\\+Users\\+[^\\\s"']+/],
  /* A home directory in a committed file names whoever it belongs to. `runner` is the
     GitHub Actions working directory and appears in CI output, not in anybody's tree. */
  ['unix home path',         /\/(?:home|Users)\/(?!runner\b)[A-Za-z0-9._-]+\//],
  ['personal email',         /\b[A-Za-z0-9._%+-]+@(?!example\.(?:com|org)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/],
  ['ssh public key',         /\bssh-(rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/]{20,}/],
  ['json web token',         /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ['discord webhook',        /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\//],
  ['telegram bot token',     /\b\d{8,12}:[A-Za-z0-9_-]{30,}\b/],
  /* A 64-byte base58 blob is a transaction signature and a secret key alike, the shapes are
     identical, so this matches on how the value is used, not on what it looks like. */
  ['solana secret base58',   /\b(secret|private|keypair|signer)[_-]?key\b\s*[:=]\s*['"][1-9A-HJ-NP-Za-km-z]{80,}['"]/i],
  ['internal worker host',   /\b[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev\b/],
  ['device or share path',   /(?:^|[\s"'(])\\\\[A-Za-z0-9._-]+\\/],
  /* Routable IPv4 only. Loopback, RFC 1918 and the documentation ranges are not identifying,
     and flagging them would train people to ignore this scanner. */
  ['ip address',             new RegExp(String.raw`(?<![\w.])(?!0\.|10\.|127\.|169\.254\.|192\.168\.`
                             + String.raw`|172\.(?:1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.`
                             + String.raw`|203\.0\.113\.|255\.)(?:\d{1,3}\.){3}\d{1,3}(?![\w.])`)],
  ['passcode near digits',   /\bpass(?:code|word)\b[^\n]{0,20}\b\d{4,}\b/i],
];

/* Placeholders and fixtures that are supposed to look like the real thing. Anything listed
   here must be demonstrably inert. */
const ALLOW = [
  /judge-anchor\/1 root=/,                       // the memo format itself
  /MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr/, // a public Solana program id
  /security@|noreply@|example\.com/,             // documentation addresses
];

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);

/* An allowlist of text extensions misses exactly the files worth checking: .env, .env.local,
   a credential pasted into notes.bak. So everything is scanned except what is definitely
   binary, and anything with a NUL byte in it is treated as binary regardless of its name. */
const BINARY = new RegExp(String.raw`\.(png|jpe?g|gif|webp|avif|ico|pdf|zip|g?z|tar|7z|rar`
  + String.raw`|woff2?|ttf|otf|eot|mp[34]|mov|webm|wasm|bin|exe|dll|so|dylib|class|jar)$`, 'i');

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (!BINARY.test(e.name)) out.push(full);
  }
  return out;
}

const looksBinary = (text) => text.slice(0, 8192).includes('\u0000');

const findings = [];
function scan(label, text) {
  text.split('\n').forEach((line, i) => {
    if (ALLOW.some((a) => a.test(line))) return;
    for (const [name, re] of RULES) {
      if (re.test(line)) {
        findings.push({ label, line: i + 1, rule: name, excerpt: line.trim().slice(0, 110) });
      }
    }
    for (const literal of FORBIDDEN) {
      if (line.includes(literal)) {
        findings.push({ label, line: i + 1, rule: 'forbidden literal',
          excerpt: '(withheld; the value is one you asked this scan to refuse)' });
      }
    }
  });
}

for (const f of walk(ROOT)) {
  let text; try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
  if (looksBinary(text)) continue;
  scan(path.relative(ROOT, f), text);
}

if (HISTORY) {
  let commits = [];
  try { commits = execSync('git rev-list --all', { cwd: ROOT }).toString().trim().split('\n').filter(Boolean); }
  catch { commits = []; }
  for (const c of commits) {
    let files = [];
    try { files = execSync(`git ls-tree -r --name-only ${c}`, { cwd: ROOT }).toString().trim().split('\n'); }
    catch { continue; }
    for (const f of files) {
      if (BINARY.test(f)) continue;
      try {
        const blob = execSync(`git show ${c}:${f}`, { cwd: ROOT, maxBuffer: 1 << 26 }).toString();
        scan(`${c.slice(0, 8)}:${f}`, blob);
      }
      catch { /* binary or removed */ }
    }
  }
  /* Commit metadata identifies a person as directly as file content, so it is scanned too. */
  try {
    const who = execSync('git log --all --format="%an <%ae>|%cn <%ce>"', { cwd: ROOT }).toString();
    for (const line of new Set(who.trim().split('\n').filter(Boolean))) {
      if (!/^JUDGE Project <[^>]+@users\.noreply\.github\.com>\|/.test(line)) {
        findings.push({ label: 'git author metadata', line: 0, rule: 'identity in commit metadata', excerpt: line });
      }
    }
  } catch { /* no history yet */ }
}

if (!findings.length) {
  console.log(`\n  secret scan: clean  (${HISTORY ? 'working tree and full history' : 'working tree'})\n`);
  process.exit(0);
}
console.error(`\n  secret scan: ${findings.length} finding(s)\n`);
for (const f of findings) console.error(`  ${f.label}:${f.line}  [${f.rule}]\n      ${f.excerpt}`);
console.error('\n  Nothing is published until these are gone. If one is a false positive, add it\n'
  + '  to ALLOW in this file with a comment saying why it is inert.\n');
process.exit(1);
