#!/usr/bin/env node
/**
 * judge-verify: check a JUDGE receipt.
 *
 *   judge-verify <receipt.json>
 *   judge-verify <receipt.json> --rpc https://api.mainnet-beta.solana.com
 *   judge-verify <receipt.json> --rpc <url> --publisher <base58> --commitment finalized
 *   judge-verify <receipt.json> --json
 *
 * Without an RPC endpoint it runs every check that needs no network: the content fingerprint,
 * the chain link, each response, the merkle path and the attestation signature. With one it
 * also reads the anchoring transaction and compares the root recorded on chain.
 *
 * Defaults come from the environment when the flags are absent: JUDGE_RPC_URL,
 * JUDGE_PUBLISHER_KEY, JUDGE_COMMITMENT. See .env.example.
 *
 * Exit codes:  0 verified · 1 altered or not anchored · 2 pending or redacted · 3 usage error
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyReceipt, rpcReader } from '../reference/receipt.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/* Read rather than imported: JSON import attributes are not available on Node 18, which this
   still supports. A verifier that cannot state its own version is hard to file a bug against. */
function version() {
  try {
    return JSON.parse(fs.readFileSync(path.join(HERE, '..', 'package.json'), 'utf8')).version;
  } catch {
    return 'unknown';
  }
}

const USAGE = `
  judge-verify: check a JUDGE receipt

    judge-verify <receipt.json> [--rpc <url>] [--publisher <key>]
                                [--commitment confirmed|finalized] [--json]

    --rpc         also read the anchoring transaction from this Solana RPC endpoint
    --publisher   the key the anchor must be signed by; defaults to the one in the receipt
    --commitment  how settled the transaction must be (default: confirmed)
    --json        machine-readable output
    --version     print the version and exit

  Environment: JUDGE_RPC_URL, JUDGE_PUBLISHER_KEY, JUDGE_COMMITMENT (flags win).

  Exit codes: 0 verified · 1 altered or not anchored · 2 pending · 3 usage error
`;

const EXIT = { VERIFIED: 0, ALTERED: 1, NOT_ANCHORED: 1, PENDING: 2, REDACTED: 2 };
const TAKES_VALUE = new Set(['--rpc', '--publisher', '--commitment']);
const FLAGS = new Set(['--json', '--help', '-h', '--version', '-V']);

function fail(message) {
  process.stderr.write(`\n  ${message}\n${USAGE}`);
  process.exit(3);
}

/** Parsed positionally rather than by index arithmetic, so a repeated or stray flag is an
 *  error the user sees rather than a value silently read as a filename. */
function parseArgs(argv) {
  const out = { file: null, rpc: null, publisher: null, commitment: null,
    json: false, help: false, version: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (TAKES_VALUE.has(arg)) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) fail(`${arg} needs a value.`);
      const key = arg.slice(2);
      if (out[key] !== null) fail(`${arg} was given more than once.`);
      out[key] = value;
      i += 1;
    } else if (FLAGS.has(arg)) {
      if (arg === '--json') out.json = true;
      else if (arg === '--version' || arg === '-V') out.version = true;
      else out.help = true;
    } else if (arg.startsWith('-')) {
      fail(`Unknown option: ${arg}`);
    } else if (out.file === null) {
      out.file = arg;
    } else {
      fail('More than one receipt was given; this checks one at a time.');
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));

if (args.version) {
  process.stdout.write(`judge-verify ${version()}\n`);
  process.exit(0);
}

if (args.help || !args.file) {
  process.stdout.write(USAGE);
  process.exit(args.help ? 0 : 3);
}

const rpc = args.rpc || process.env.JUDGE_RPC_URL || null;
const publisherKey = args.publisher || process.env.JUDGE_PUBLISHER_KEY || null;
const commitment = args.commitment || process.env.JUDGE_COMMITMENT || 'confirmed';

if (rpc && !/^https?:\/\//.test(rpc)) fail('The RPC endpoint must be an http or https URL.');
if (!['confirmed', 'finalized', 'processed'].includes(commitment)) {
  fail(`Unknown commitment: ${commitment}`);
}

let receipt;
try {
  receipt = JSON.parse(fs.readFileSync(path.resolve(args.file), 'utf8'));
} catch (err) {
  process.stderr.write(`\n  could not read ${args.file}: ${err.message}\n\n`);
  process.exit(3);
}

let outcome;
try {
  outcome = await verifyReceipt(receipt, {
    fetchTransaction: rpc ? rpcReader(rpc, { commitment }) : null,
    publisherKey,
  });
} catch (err) {
  /* A transport failure is not a verdict on the record. Exit 3 (usage/environment) rather
     than 0 or 1, so callers do not read it as either outcome. */
  process.stderr.write(`\n  the check could not be completed: ${err.message}\n\n`);
  process.exit(3);
}

if (args.json) {
  process.stdout.write(`${JSON.stringify(outcome, null, 2)}\n`);
} else {
  const report = receipt.report || {};
  const lines = [
    '',
    `  receipt   ${report.publicId || report.number || '(unidentified)'}`,
    `  filed     ${report.filedAt || '(unstated)'}`,
    rpc ? `  anchor    read from ${rpc} at ${commitment}`
      : '  anchor    not checked (pass --rpc to read it from the chain)',
    '',
    ...outcome.checks.map((c) =>
      `  [${c.ok ? '  ok  ' : ' FAIL '}] ${c.name}${c.detail ? `  -  ${c.detail}` : ''}`),
    '',
    `  ${outcome.result}${outcome.reason ? `  -  ${outcome.reason}` : ''}`,
    '',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

process.exit(EXIT[outcome.result] ?? 1);
