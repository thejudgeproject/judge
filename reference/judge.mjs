/**
 * JUDGE reference implementation of the record format and verification procedure.
 *
 * Written from docs/SPEC.md rather than extracted from the JUDGE application. If this and the
 * production implementation agree, they agree because the specification is unambiguous, which
 * indicates the specification is unambiguous.
 *
 * No dependencies. Runs on Node 18+ and in any browser with Web Crypto.
 */

/**
 * Web Crypto, wherever it lives.
 *
 * Browsers and Node 19+ expose it on `globalThis.crypto`. Node 18 ships the same
 * implementation but does not put it on the global, so it is fetched from `node:crypto`
 * instead. The dynamic import is only reached when the global is absent, so a browser bundle
 * never resolves it.
 */
async function resolveSubtle() {
  if (globalThis.crypto?.subtle) return globalThis.crypto.subtle;
  try {
    const { webcrypto } = await import('node:crypto');
    if (webcrypto?.subtle) return webcrypto.subtle;
  } catch {
    /* not a Node runtime */
  }
  throw new Error('Web Crypto is required: Node 18 or newer, or any modern browser.');
}

export const subtle = await resolveSubtle();
const SUBTLE = subtle;

const enc = new TextEncoder();
const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => {
  if (!/^[0-9a-f]*$/i.test(s) || s.length % 2) throw new Error('not hex: ' + s);
  return new Uint8Array(s.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);
};
const sha256 = async (bytes) => new Uint8Array(await SUBTLE.digest('SHA-256', bytes));

/** SHA-256 of a UTF-8 string, lowercase hex. The one hashing primitive everything else uses. */
export async function sha256Hex(text) {
  return hex(await sha256(enc.encode(String(text))));
}
const concat = (...arrays) => {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let at = 0;
  for (const a of arrays) { out.set(a, at); at += a.length; }
  return out;
};

/* ---------------------------------------------------------------- SPEC §1: sealed fields */

export const SEALED_FIELDS = Object.freeze([
  'public_no', 'filed_at', 'subject_raw', 'subject_type', 'address', 'project', 'twitter',
  'telegram', 'associated', 'title', 'facts', 'incident_type', 'vector', 'hindsight',
  'amount_sol', 'incident_date', 'tx_sig', 'still_active',
]);

export const RESPONSE_FIELDS = Object.freeze([
  'report', 'platform', 'username', 'body', 'stance', 'settled', 'evidence', 'created_at',
]);

/* ---------------------------------------------------------------- SPEC §2: canonical form */

function sealedValue(field, value) {
  if (value === null || value === undefined) return '';        // NULL and empty are the same
  if (field === 'still_active') {
    return (value === true || value === 1 || value === '1') ? '1' : '0';
  }
  if (field === 'hindsight') {
    if (typeof value === 'string') return value || '[]';
    return JSON.stringify(Array.isArray(value) ? value : []);
  }
  return String(value);
}

/** SPEC §2. `field=value` lines, LF-joined, no trailing newline, no escaping. */
export function canonical(record, fields = SEALED_FIELDS) {
  return fields.map((f) => `${f}=${sealedValue(f, record[f])}`).join('\n');
}

/* ---------------------------------------------------------------- SPEC §3–§4: hashes */

export async function contentHash(record, fields = SEALED_FIELDS) {
  return sha256Hex(canonical(record, fields));
}

/** SPEC §4. Concatenation is over the hex STRINGS. Genesis prev is the empty string. */
export async function chainHash(prevChainHash, contentHashHex) {
  return sha256Hex(String(prevChainHash || '') + contentHashHex);
}

/* ---------------------------------------------------------------- SPEC §6: merkle */

const leafHash = async (chainHashHex) => await sha256(concat(new Uint8Array([0x00]), unhex(chainHashHex)));
const nodeHash = async (l, r) => await sha256(concat(new Uint8Array([0x01]), l, r));

/** SPEC §6. Odd node is PROMOTED, never duplicated (CVE-2012-2459). */
export async function merkleRoot(chainHashes) {
  if (!chainHashes.length) throw new Error('a batch cannot be empty');
  let level = await Promise.all(chainHashes.map(leafHash));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? await nodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return hex(level[0]);
}

/** The sibling path from one leaf to the root, as [{side, hash}] with side 'L' | 'R'. */
export async function merklePath(chainHashes, index) {
  if (index < 0 || index >= chainHashes.length) throw new Error('index outside the batch');
  let level = await Promise.all(chainHashes.map(leafHash));
  let at = index;
  const path = [];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const has = i + 1 < level.length;
      if (i === at || i + 1 === at) {
        if (has) {
          const meLeft = (at === i);
          path.push({ side: meLeft ? 'R' : 'L', hash: hex(level[meLeft ? i + 1 : i]) });
        }
        at = next.length;                       // promoted, or the parent's position
      }
      next.push(has ? await nodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return path;
}

export async function merkleVerify(chainHashHex, path, expectedRootHex) {
  let acc = await leafHash(chainHashHex);
  for (const step of path) {
    if (step.side !== 'L' && step.side !== 'R') throw new Error('bad path step');
    const sib = unhex(step.hash);
    acc = step.side === 'R' ? await nodeHash(acc, sib) : await nodeHash(sib, acc);
  }
  return hex(acc) === String(expectedRootHex).toLowerCase();
}

/* ---------------------------------------------------------------- SPEC §7: the anchor memo */

export const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
export const MEMO_FORMAT = 'judge-anchor/1';

/** SPEC §7. Parsed, not pattern-matched: text that merely contains hex is not an anchor. */
export function parseAnchorMemo(memo) {
  const text = String(memo || '').trim();
  if (text.indexOf(MEMO_FORMAT) !== 0) return null;
  const root = text.match(/(?:^|\s)root=([0-9a-fA-F]{64})(?:\s|$)/);
  if (!root) return null;
  const num = (k) => {
    const m = text.match(new RegExp(`(?:^|\\s)${k}=(\\d+)(?:\\s|$)`));
    return m ? Number(m[1]) : null;
  };
  return { root: root[1].toLowerCase(), count: num('n'), first: num('first'), last: num('last') };
}

/** Every memo in a jsonParsed transaction, from the instruction and from the log line. */
export function memosFrom(tx) {
  const out = [];
  const ix = tx?.transaction?.message?.instructions || [];
  for (const one of ix) {
    if (one?.programId !== MEMO_PROGRAM_ID) continue;
    if (typeof one.parsed === 'string') out.push(one.parsed);
    else if (typeof one.parsed?.info === 'string') out.push(one.parsed.info);
  }
  for (const line of tx?.meta?.logMessages || []) {
    const m = String(line).match(/Program log: Memo \(len \d+\): "([\s\S]*)"$/);
    if (m) out.push(m[1]);
  }
  return out;
}

/** Accounts that signed. Handles both jsonParsed and legacy string account keys. */
export function signersOf(tx) {
  const msg = tx?.transaction?.message || {};
  const keys = msg.accountKeys || [];
  const required = Number(msg.header?.numRequiredSignatures || 0);
  const out = [];
  keys.forEach((k, i) => {
    if (k && typeof k === 'object') { if (k.signer) out.push(String(k.pubkey)); }
    else if (typeof k === 'string' && i < required) out.push(k);
  });
  return out;
}

/* ---------------------------------------------------------------- SPEC §8: verification */

export const RESULT = Object.freeze({
  VERIFIED: 'VERIFIED',
  ALTERED: 'ALTERED',
  PENDING: 'PENDING',
  NOT_ANCHORED: 'NOT_ANCHORED',
  REDACTED: 'REDACTED',
});

/**
 * SPEC §8. `fetchTransaction(signature)` returns the jsonParsed transaction or null.
 * Injected rather than built in, so this is testable without a network and usable against
 * whichever RPC endpoint the caller trusts.
 */
export async function verifyReport({
  record, storedContentHash, storedChainHash, prevChainHash,
  batchRoot, merklePath: path, anchorSignature, publisherKey,
  fetchTransaction, redacted = false,
}) {
  if (redacted) return { result: RESULT.REDACTED, reason: 'content unavailable' };

  const computedContent = await contentHash(record);
  if (computedContent !== String(storedContentHash).toLowerCase()) {
    return { result: RESULT.ALTERED, reason: 'content hash', computedContent };
  }

  /* Deliberately advances on the RECOMPUTED content hash. Using the stored one would let an
     edited record with an untouched hash string still appear to link. SPEC §8 step 3. */
  const computedChain = await chainHash(prevChainHash, computedContent);
  if (computedChain !== String(storedChainHash).toLowerCase()) {
    return { result: RESULT.ALTERED, reason: 'chain hash', computedChain };
  }

  if (batchRoot && path) {
    if (!await merkleVerify(computedChain, path, batchRoot)) {
      return { result: RESULT.ALTERED, reason: 'merkle path' };
    }
  }

  if (!anchorSignature || !fetchTransaction) {
    return { result: RESULT.PENDING, reason: 'not anchored yet', computedChain };
  }

  const tx = await fetchTransaction(anchorSignature);
  if (!tx) return { result: RESULT.PENDING, reason: 'transaction not found at this commitment' };
  if (tx.meta?.err) return { result: RESULT.NOT_ANCHORED, reason: 'transaction failed on chain' };

  if (!signersOf(tx).includes(String(publisherKey))) {
    return { result: RESULT.NOT_ANCHORED, reason: 'not signed by the publisher key' };
  }

  for (const memo of memosFrom(tx)) {
    const parsed = parseAnchorMemo(memo);
    if (!parsed) continue;
    if (parsed.root !== String(batchRoot).toLowerCase()) {
      return { result: RESULT.ALTERED, reason: 'anchored root differs from the batch root' };
    }
    return { result: RESULT.VERIFIED, slot: tx.slot ?? null, root: parsed.root };
  }
  return { result: RESULT.NOT_ANCHORED, reason: 'no anchor memo in this transaction' };
}

/** Recompute a whole chain and report the first record that does not link. */
export async function verifyChain(records) {
  let prev = '';
  for (const r of records) {
    const c = await contentHash(r.record ?? r);
    const ch = await chainHash(prev, c);
    if (r.chain_hash && ch !== String(r.chain_hash).toLowerCase()) {
      return { ok: false, brokenAt: r.record?.public_no ?? r.public_no, expected: ch, stored: r.chain_hash };
    }
    prev = r.chain_hash || ch;
  }
  return { ok: true, head: prev };
}
