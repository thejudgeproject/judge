/**
 * Tests for receipt verification.
 *
 * The fixtures in examples/ are not decoration. They are the committed known-answer vectors
 * for this module. If a change to the hashing or the merkle construction ever alters them,
 * these tests fail, which is the point.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyReceipt, attestationString, verifyAttestation, RECEIPT_FORMAT }
  from '../reference/receipt.mjs';
import { RESULT, subtle } from '../reference/judge.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(fs.readFileSync(path.join(HERE, '..', 'examples', name), 'utf8'));
const clone = (o) => JSON.parse(JSON.stringify(o));

const GOOD = load('receipt.example.json');
const TAMPERED = load('receipt.tampered.json');

test('the example receipt passes every offline check', async () => {
  const out = await verifyReceipt(GOOD);
  const failed = out.checks.filter((c) => !c.ok);
  assert.deepEqual(failed, [], 'no check should fail');
  assert.equal(out.result, RESULT.PENDING, 'no anchor and no network: PENDING is the only supportable result');
});

test('a receipt with no anchoring transaction is PENDING, never VERIFIED', async () => {
  assert.equal(GOOD.batch.recordingTransaction, null);
  const out = await verifyReceipt(GOOD);
  assert.notEqual(out.result, RESULT.VERIFIED);
});

test('one word changed in the sealed text is caught', async () => {
  const out = await verifyReceipt(TAMPERED);
  assert.equal(out.result, RESULT.ALTERED);
  assert.match(out.reason, /content fingerprint/);
});

test('a stored hash edited to match tampered text still fails at the chain link', async () => {
  const r = clone(GOOD);
  r.canonicalString = r.canonicalString.replace('single transaction', 'single transactionx');
  /* recompute the content hash the way a forger would, and leave the chain hash alone */
  const { createHash } = await import('node:crypto');
  r.fingerprint.contentHash = createHash('sha256').update(r.canonicalString, 'utf8').digest('hex');
  const out = await verifyReceipt(r);
  assert.equal(out.result, RESULT.ALTERED);
  assert.match(out.reason, /chain fingerprint/);
});

test('a forged merkle path is rejected', async () => {
  const r = clone(GOOD);
  r.merkleProof.path[0].hash = 'f'.repeat(64);
  const out = await verifyReceipt(r);
  assert.equal(out.result, RESULT.ALTERED);
  assert.match(out.reason, /merkle path/);
});

test('a truncated merkle path is rejected', async () => {
  const r = clone(GOOD);
  r.merkleProof.path = r.merkleProof.path.slice(0, -1);
  const out = await verifyReceipt(r);
  assert.equal(out.result, RESULT.ALTERED);
});

test('a receipt sealing a different field set is rejected', async () => {
  const r = clone(GOOD);
  r.canonicalFields = r.canonicalFields.slice(0, -1);
  const out = await verifyReceipt(r);
  assert.equal(out.result, RESULT.ALTERED);
  assert.match(out.reason, /field/);
});

test('an unknown receipt format is refused rather than guessed at', async () => {
  const r = clone(GOOD);
  r.format = 'judge-report-proof/2';
  const out = await verifyReceipt(r);
  assert.equal(out.result, RESULT.ALTERED);
  assert.match(out.reason, /format/);
});

test('a redacted receipt is REDACTED, not verified and not altered', async () => {
  const r = clone(GOOD);
  r.report.redacted = true;
  r.canonicalString = null;
  const out = await verifyReceipt(r);
  assert.equal(out.result, RESULT.REDACTED);
});

test('the attestation signature verifies, and does not verify over other bytes', async () => {
  const a = GOOD.attestation;
  assert.equal(await verifyAttestation(a.statement, a.signature, a.publicKey), true);
  assert.equal(await verifyAttestation(a.statement + ' ', a.signature, a.publicKey), false);
});

test('an attestation whose statement does not describe the record is rejected', async () => {
  const r = clone(GOOD);
  r.attestation.statement = attestationString({
    publicNo: 999, filedAt: r.report.filedAt, prevHash: r.fingerprint.previousChainHash,
    contentHash: r.fingerprint.contentHash, chainHash: r.fingerprint.chainHash,
  });
  const out = await verifyReceipt(r);
  assert.equal(out.result, RESULT.ALTERED);
  assert.match(out.reason, /signed statement/);
});

test('a re-signed statement from the wrong key is rejected', async () => {
  const r = clone(GOOD);
  const kp = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const sig = new Uint8Array(await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey,
    new TextEncoder().encode(r.attestation.statement)));
  r.attestation.signature = Buffer.from(sig).toString('base64url');
  const out = await verifyReceipt(r);
  assert.equal(out.result, RESULT.ALTERED);
  assert.match(out.reason, /signature/);
});

/* ------------------------------------------------------------------ the anchor step */

const anchorTx = (memo, signer, err = null) => ({
  slot: 301_455_912,
  meta: { err, logMessages: [] },
  transaction: {
    message: {
      accountKeys: [{ pubkey: signer, signer: true }],
      instructions: [{ programId: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', parsed: memo }],
    },
  },
});

const PUBLISHER = 'ExamplePublisherKey11111111111111111111111';

function anchored(root, { signer = PUBLISHER, memo = null, err = null } = {}) {
  const r = clone(GOOD);
  r.batch.recordingTransaction = 'ExampleAnchorSignature1111111111111111111111'
    + '111111111111111111111111111111111111111111';
  r.batch.signer = PUBLISHER;
  const text = memo ?? `judge-anchor/1 root=${root} n=5 first=1 last=5`;
  return { receipt: r, fetchTransaction: async () => anchorTx(text, signer, err) };
}

test('an anchor signed by the publisher, carrying the right root, verifies', async () => {
  const { receipt, fetchTransaction } = anchored(GOOD.merkleProof.root);
  const out = await verifyReceipt(receipt, { fetchTransaction });
  assert.equal(out.result, RESULT.VERIFIED);
  assert.equal(out.slot, 301_455_912);
});

test('the same memo signed by any other key is refused', async () => {
  const { receipt, fetchTransaction } =
    anchored(GOOD.merkleProof.root, { signer: 'SomeoneElse1111111111111111111111111111111' });
  const out = await verifyReceipt(receipt, { fetchTransaction });
  assert.equal(out.result, RESULT.NOT_ANCHORED);
  assert.match(out.reason, /publisher key/);
});

test('an anchored root that differs from the receipt root is ALTERED', async () => {
  const { receipt, fetchTransaction } = anchored('a'.repeat(64));
  const out = await verifyReceipt(receipt, { fetchTransaction });
  assert.equal(out.result, RESULT.ALTERED);
  assert.match(out.reason, /differs/);
});

test('a failed transaction is NOT_ANCHORED, not PENDING', async () => {
  const { receipt, fetchTransaction } = anchored(GOOD.merkleProof.root, { err: { InstructionError: [0, 'Custom'] } });
  const out = await verifyReceipt(receipt, { fetchTransaction });
  assert.equal(out.result, RESULT.NOT_ANCHORED);
});

test('a transaction that cannot be found is PENDING, not a failure', async () => {
  const { receipt } = anchored(GOOD.merkleProof.root);
  const out = await verifyReceipt(receipt, { fetchTransaction: async () => null });
  assert.equal(out.result, RESULT.PENDING);
});

test('a transaction with no anchor memo is NOT_ANCHORED', async () => {
  const { receipt, fetchTransaction } = anchored(GOOD.merkleProof.root, { memo: 'gm' });
  const out = await verifyReceipt(receipt, { fetchTransaction });
  assert.equal(out.result, RESULT.NOT_ANCHORED);
  assert.match(out.reason, /no anchor memo/);
});

test('naming an anchor without supplying an RPC reader stays PENDING rather than claiming more', async () => {
  const { receipt } = anchored(GOOD.merkleProof.root);
  const out = await verifyReceipt(receipt);
  assert.equal(out.result, RESULT.PENDING);
});

test('the receipt format constant matches the fixtures', () => {
  assert.equal(GOOD.format, RECEIPT_FORMAT);
});
