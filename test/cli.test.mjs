/**
 * The command-line verifier, exercised the way a user runs it.
 *
 * Exit codes are the interface here, a script checking a batch of receipts reads the status,
 * not the prose, so they are asserted rather than assumed.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');
const CLI = path.join(ROOT, 'bin', 'judge-verify.mjs');
const example = (name) => path.join(ROOT, 'examples', name);

function run(args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [CLI, ...args], { cwd: ROOT, env: { ...process.env, ...env } },
      (err, stdout, stderr) => resolve({ code: err ? err.code ?? 1 : 0, stdout, stderr }));
  });
}

test('a valid unanchored receipt exits 2 and says PENDING', async () => {
  const r = await run([example('receipt.example.json')]);
  assert.equal(r.code, 2);
  assert.match(r.stdout, /PENDING/);
  assert.doesNotMatch(r.stdout, /VERIFIED/);
});

test('a tampered receipt exits 1 and says ALTERED', async () => {
  const r = await run([example('receipt.tampered.json')]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /ALTERED/);
  assert.match(r.stdout, /FAIL/);
});

test('--json emits parseable output carrying every check', async () => {
  const r = await run([example('receipt.example.json'), '--json']);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.result, 'PENDING');
  assert.ok(Array.isArray(parsed.checks) && parsed.checks.length > 0);
  assert.ok(parsed.checks.every((c) => typeof c.ok === 'boolean'));
});

test('no arguments is a usage error, not a pass', async () => {
  const r = await run([]);
  assert.equal(r.code, 3);
});

test('--version prints the package version and exits 0', async () => {
  const pkg = JSON.parse(
    (await import('node:fs')).readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const r = await run(['--version']);
  assert.equal(r.code, 0);
  assert.equal(r.stdout.trim(), `judge-verify ${pkg.version}`);
});

test('--help exits 0', async () => {
  const r = await run(['--help']);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /judge-verify/);
});

test('a missing file is reported, and is never treated as a passing check', async () => {
  const r = await run([path.join(ROOT, 'examples', 'does-not-exist.json')]);
  assert.equal(r.code, 3);
  assert.match(r.stderr, /could not read/);
});

test('a file that is not JSON is refused rather than half-read', async () => {
  const r = await run([path.join(ROOT, 'README.md')]);
  assert.equal(r.code, 3);
});

test('a flag missing its value is refused', async () => {
  const r = await run([example('receipt.example.json'), '--rpc']);
  assert.equal(r.code, 3);
  assert.match(r.stderr, /needs a value/);
});

test('an RPC endpoint that is not an http URL is refused', async () => {
  const r = await run([example('receipt.example.json'), '--rpc', 'ftp://example.com']);
  assert.equal(r.code, 3);
});

test('an unknown option is refused rather than ignored', async () => {
  const r = await run([example('receipt.example.json'), '--verify-harder']);
  assert.equal(r.code, 3);
  assert.match(r.stderr, /Unknown option/);
});

test('two receipts at once is refused rather than silently checking one', async () => {
  const r = await run([example('receipt.example.json'), example('receipt.tampered.json')]);
  assert.equal(r.code, 3);
});

test('an unreachable RPC endpoint is an error, never a pass or a verdict on the record',
  async () => {
    /* 127.0.0.1 with nothing listening: the request fails rather than answering. */
    const r = await run([example('receipt.example.json'), '--rpc', 'http://127.0.0.1:9', '--json']);
    assert.notEqual(r.code, 0);
    assert.doesNotMatch(r.stdout + r.stderr, /VERIFIED/);
  });

test('JUDGE_RPC_URL is read from the environment when --rpc is absent', async () => {
  const r = await run([example('receipt.example.json')], { JUDGE_RPC_URL: 'http://127.0.0.1:9' });
  /* The example names no anchoring transaction, so the endpoint is never contacted and the
     answer stays PENDING, but the header must show that an endpoint was configured. */
  assert.match(r.stdout, /read from http:\/\/127\.0\.0\.1:9/);
  assert.equal(r.code, 2);
});

test('an unknown commitment level is refused', async () => {
  const r = await run([example('receipt.example.json'), '--commitment', 'eventually']);
  assert.equal(r.code, 3);
});
