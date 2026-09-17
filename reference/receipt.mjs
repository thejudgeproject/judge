/**
 * JUDGE receipt verification (`judge-report-proof/1`).
 *
 * A receipt is the file a reader can download beside any report. It carries the exact bytes
 * that were hashed, the hashes themselves, the batch and merkle path if one exists, and the
 * attestation signature made at filing time. Everything needed to check the record is in it,
 * which is the point: a saved receipt stays checkable after the archive is gone.
 *
 * This module verifies one without contacting JUDGE. The only optional network call is to a
 * Solana RPC endpoint the caller chooses, to read the anchoring transaction.
 *
 * No dependencies. Node 18+, or any browser with Web Crypto.
 */

import {
  subtle, sha256Hex, chainHash, merkleVerify,
  parseAnchorMemo, memosFrom, signersOf, RESULT, SEALED_FIELDS,
} from './judge.mjs';

export const RECEIPT_FORMAT = 'judge-report-proof/1';
export const ATTESTATION_FORMAT = 'judge-attestation/1';

const SUBTLE = subtle;
const enc = new TextEncoder();

function b64urlToBytes(s) {
  const pad = '='.repeat((4 - (String(s).length % 4)) % 4);
  const b64 = String(s).replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = typeof atob === 'function'
    ? atob(b64)
    : Buffer.from(b64, 'base64').toString('binary');
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/* ------------------------------------------------------------------ SPEC §9: attestation */

/**
 * The exact bytes JUDGE signs at filing time. Order and spelling are part of the contract:
 * a verifier rebuilds this string from the receipt rather than trusting a copy of it.
 */
export function attestationString({ publicNo, filedAt, prevHash, contentHash: ch, chainHash: hh }) {
  return [
    ATTESTATION_FORMAT,
    `public_no=${publicNo}`,
    `filed_at=${filedAt}`,
    `prev_hash=${prevHash || ''}`,
    `content_hash=${ch}`,
    `chain_hash=${hh}`,
  ].join('\n');
}

/**
 * ECDSA P-256 over SHA-256, signature as base64url of the raw r‖s pair.
 *
 * What this is worth, precisely: it does not make rewriting impossible, it makes rewriting
 * provable by whoever was rewritten. A stolen key can sign new statements from that moment
 * on; it cannot reach back and unsign one already downloaded.
 */
export async function verifyAttestation(statement, signatureB64url, publicKeyJwk) {
  if (!statement || !signatureB64url || !publicKeyJwk) return false;
  try {
    const key = await SUBTLE.importKey(
      'jwk', publicKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    );
    return await SUBTLE.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key,
      b64urlToBytes(signatureB64url), enc.encode(statement),
    );
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ receipt verification */

/**
 * Verify a parsed receipt object.
 *
 * `fetchTransaction(signature)` is optional. Omit it and the anchor step is skipped and
 * reported as such; supply one and step 5 runs against whichever RPC endpoint you trust.
 *
 * Returns { result, checks[], reason? } where every check carries its own pass/fail so a
 * failure says which step failed rather than only that something did.
 */
export async function verifyReceipt(receipt, { fetchTransaction = null, publisherKey = null } = {}) {
  const checks = [];
  const add = (name, ok, detail) => { checks.push({ name, ok, detail }); return ok; };
  const done = (result, reason) => ({ result, reason, checks });

  if (!receipt || typeof receipt !== 'object') return done(RESULT.ALTERED, 'not a receipt');
  if (receipt.format !== RECEIPT_FORMAT) {
    return done(RESULT.ALTERED, `unknown receipt format: ${receipt.format ?? '(none)'}`);
  }

  const fp = receipt.fingerprint || {};
  const rep = receipt.report || {};

  if (rep.redacted || receipt.canonicalString === null) {
    add('redacted', true, 'content withheld; position and hashes retained');
    return done(RESULT.REDACTED, 'the content of this record is unavailable');
  }

  /* --- step 1: the content hash, over the bytes the receipt itself carries --------------- */
  const computedContent = await sha256Hex(receipt.canonicalString);
  if (!add('content hash', computedContent === String(fp.contentHash || '').toLowerCase(),
    `computed ${computedContent}`)) {
    return done(RESULT.ALTERED, 'the content fingerprint does not match the sealed bytes');
  }

  /* The field list is part of the seal. A receipt whose canonical string was built over a
     different set of fields would hash consistently and still describe a different record. */
  if (Array.isArray(receipt.canonicalFields)) {
    const same = receipt.canonicalFields.length === SEALED_FIELDS.length
      && receipt.canonicalFields.every((f, i) => f === SEALED_FIELDS[i]);
    if (!add('sealed field set', same, `${receipt.canonicalFields.length} fields`)) {
      return done(RESULT.ALTERED, 'the receipt seals a different set of fields than the specification');
    }
  }

  /* --- step 2: the chain hash, advancing on the RECOMPUTED content hash ------------------ */
  const prev = fp.previousChainHash == null ? '' : String(fp.previousChainHash);
  const computedChain = await chainHash(prev, computedContent);
  if (!add('chain hash', computedChain === String(fp.chainHash || '').toLowerCase(),
    `computed ${computedChain}`)) {
    return done(RESULT.ALTERED, 'the chain fingerprint does not link');
  }

  /* --- step 3: each response chains from the report and then from its predecessor -------- */
  for (const [i, r] of (receipt.responses || []).entries()) {
    if (r.canonicalString == null) { add(`response ${i + 1}`, true, 'redacted'); continue; }
    const rc = await sha256Hex(r.canonicalString);
    if (!add(`response ${i + 1} content hash`, rc === String(r.contentHash || '').toLowerCase(), rc)) {
      return done(RESULT.ALTERED, `response ${i + 1} has been changed`);
    }
    const rch = await chainHash(r.previousHash == null ? '' : String(r.previousHash), rc);
    if (!add(`response ${i + 1} chain hash`, rch === String(r.chainHash || '').toLowerCase(), rch)) {
      return done(RESULT.ALTERED, `response ${i + 1} does not link`);
    }
  }

  /* --- step 4: the merkle path to the batch root ----------------------------------------- */
  const proof = receipt.merkleProof || null;
  if (proof && Array.isArray(proof.path) && proof.root) {
    const path = proof.path.map((s) => ({
      side: (s.side === 'L' || s.side === 'R') ? s.side : (s.right ? 'R' : 'L'),
      hash: s.hash,
    }));
    if (!add('merkle path', await merkleVerify(computedChain, path, proof.root),
      `${path.length} step(s) to ${String(proof.root).slice(0, 16)}…`)) {
      return done(RESULT.ALTERED, 'the merkle path does not reach the batch root');
    }
  } else {
    add('merkle path', true, 'not in a batch yet');
  }

  /* --- step 6 (run before 5, because it needs no network) -------------------------------- */
  const att = receipt.attestation || null;
  if (att) {
    const rebuilt = attestationString({
      publicNo: rep.number, filedAt: rep.filedAt,
      prevHash: prev, contentHash: computedContent, chainHash: computedChain,
    });
    if (!add('attestation statement', rebuilt === att.statement,
      'rebuilt from the receipt, compared to the signed copy')) {
      return done(RESULT.ALTERED, 'the signed statement does not describe this record');
    }
    if (!add('attestation signature',
      await verifyAttestation(rebuilt, att.signature, att.publicKey), 'ECDSA P-256')) {
      return done(RESULT.ALTERED, 'the attestation signature does not verify');
    }
  } else {
    add('attestation', true, 'none in this receipt');
  }

  /* --- step 5: the anchor. The only step that does not depend on JUDGE ------------------- */
  const batch = receipt.batch || null;
  const sig = batch?.recordingTransaction || null;
  if (!sig) {
    return done(RESULT.PENDING, 'sealed and chained; this batch has not been anchored yet');
  }
  if (!fetchTransaction) {
    return done(RESULT.PENDING,
      'an anchoring transaction is named but was not read. Supply an RPC endpoint to check it');
  }

  const tx = await fetchTransaction(sig);
  if (!tx) return done(RESULT.PENDING, 'the anchoring transaction was not found at this commitment');
  if (tx.meta?.err) return done(RESULT.NOT_ANCHORED, 'the anchoring transaction failed on chain');

  const signers = signersOf(tx);
  const expected = publisherKey || batch.signer || null;
  if (!expected) {
    return done(RESULT.NOT_ANCHORED,
      'no publisher key to compare the signer against. Pass one explicitly');
  }
  if (!add('anchor signer', signers.includes(String(expected)), String(expected))) {
    return done(RESULT.NOT_ANCHORED, 'the transaction was not signed by the publisher key');
  }

  for (const memo of memosFrom(tx)) {
    const parsed = parseAnchorMemo(memo);
    if (!parsed) continue;
    const root = String(proof?.root || batch.merkleRoot || '').toLowerCase();
    if (!add('anchored root', parsed.root === root, parsed.root)) {
      return done(RESULT.ALTERED, 'the root on chain differs from the root in this receipt');
    }
    return { result: RESULT.VERIFIED, reason: 'the root in this receipt is the root on chain',
      slot: tx.slot ?? null, checks };
  }
  return done(RESULT.NOT_ANCHORED, 'that transaction carries no anchor memo');
}

/**
 * A minimal Solana RPC reader. Injected rather than built in, so the endpoint is the caller's
 * choice and the verification logic stays testable without a network.
 */
export function rpcReader(endpoint, { commitment = 'confirmed', timeoutMs = 15000 } = {}) {
  return async function fetchTransaction(signature) {
    const cancel = AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: cancel,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getTransaction',
        params: [signature, { encoding: 'jsonParsed', commitment, maxSupportedTransactionVersion: 0 }],
      }),
    });
    if (!res.ok) throw new Error(`the RPC endpoint returned ${res.status}`);
    const body = await res.json();
    if (body.error) throw new Error(`the RPC endpoint reported: ${body.error.message || 'an error'}`);
    /* A null result means "no such transaction at this commitment", which is a legitimate
       answer and is not the same as a failed request. The caller distinguishes them. */
    return body.result || null;
  };
}
