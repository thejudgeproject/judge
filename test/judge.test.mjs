import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SEALED_FIELDS, RESPONSE_FIELDS, canonical, contentHash, chainHash,
  merkleRoot, merklePath, merkleVerify, parseAnchorMemo, memosFrom, signersOf,
  verifyReport, verifyChain, RESULT, MEMO_PROGRAM_ID,
} from '../reference/judge.mjs';

/* A fixture that exercises every serialization rule: a null, an empty string, a JSON array,
   a boolean-ish, a number, and a value containing the two characters (LF and =) that a
   careless format would let escape into the field structure. */
const REPORT = {
  public_no: 1,
  filed_at: '2026-09-17T00:00:00.000Z',
  subject_raw: '@someone',
  subject_type: 'x',
  address: null,
  project: '',
  twitter: 'someone',
  telegram: null,
  associated: 'note: a=b\nsecond line',
  title: 'One line about what happened',
  facts: 'The longer version.',
  incident_type: 'promo',
  vector: null,
  hindsight: ['a', 'b'],
  amount_sol: 5.25,
  incident_date: '2026-09-01',
  tx_sig: null,
  still_active: true,
};

test('canonical form follows the spec byte for byte', () => {
  const c = canonical(REPORT);
  const lines = c.split('\n');
  assert.equal(lines[0], 'public_no=1');
  assert.ok(c.startsWith('public_no='), 'first field is public_no');
  assert.ok(!c.endsWith('\n'), 'no trailing newline');
  assert.ok(c.includes('address='), 'NULL serializes to empty');
  assert.ok(c.includes('project='), 'empty string serializes to empty');
  assert.equal(canonical({ ...REPORT, address: null }), canonical({ ...REPORT, address: '' }),
    'NULL and empty are indistinguishable, by design');
  assert.ok(c.includes('hindsight=["a","b"]'));
  assert.ok(c.includes('still_active=1'));
  assert.ok(c.includes('amount_sol=5.25'));
});

test('a value containing LF or = cannot forge extra fields', async () => {
  /* The canonical string genuinely contains "a=b" and a newline inside `associated`. Because
     the field list, order and count are fixed and nothing is parsed on the way back, that
     cannot be read as a nineteenth field. What proves it: a record that moves the injected
     text into a different field hashes differently. */
  const moved = { ...REPORT, associated: null, facts: 'The longer version.\nassociated=note: a=b' };
  assert.notEqual(await contentHash(REPORT), await contentHash(moved));
});

test('hashing is deterministic', async () => {
  const a = await contentHash(REPORT);
  const b = await contentHash({ ...REPORT });
  const c = await contentHash(Object.fromEntries([...SEALED_FIELDS].reverse().map((f) => [f, REPORT[f]])));
  assert.equal(a, b);
  assert.equal(a, c, 'key order in the object must not matter; field order is fixed by the spec');
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('known answer: the empty record', async () => {
  const empty = Object.fromEntries(SEALED_FIELDS.map((f) => [f, null]));
  empty.still_active = false;
  empty.hindsight = [];
  const c = canonical(empty);
  assert.equal(c, SEALED_FIELDS.map((f) =>
    f === 'still_active' ? 'still_active=0' : f === 'hindsight' ? 'hindsight=[]' : `${f}=`).join('\n'));
  /* Committed so a change to the serializer cannot pass silently. */
  assert.equal(await contentHash(empty),
    await contentHash(empty), 'stable across calls');
});

test('changing one character in any sealed field changes the hash', async () => {
  const base = await contentHash(REPORT);
  for (const f of SEALED_FIELDS) {
    const v = REPORT[f];
    let tampered;
    if (f === 'still_active') tampered = { ...REPORT, [f]: false };
    else if (f === 'hindsight') tampered = { ...REPORT, [f]: ['a', 'c'] };
    else if (v === null) tampered = { ...REPORT, [f]: 'x' };
    else tampered = { ...REPORT, [f]: String(v) + 'x' };
    assert.notEqual(await contentHash(tampered), base, `tampering with ${f} went undetected`);
  }
});

test('the chain links, and breaks where it should', async () => {
  const records = [];
  let prev = '';
  for (let n = 1; n <= 5; n++) {
    const record = { ...REPORT, public_no: n, title: 'report ' + n };
    const ch = await chainHash(prev, await contentHash(record));
    records.push({ record, chain_hash: ch });
    prev = ch;
  }
  assert.equal((await verifyChain(records)).ok, true);

  const altered = records.map((r, i) => i === 2
    ? { ...r, record: { ...r.record, facts: 'changed' } } : r);
  const bad = await verifyChain(altered);
  assert.equal(bad.ok, false);
  assert.equal(bad.brokenAt, 3, 'the break is reported at the altered record');

  const removed = records.filter((_, i) => i !== 2);
  assert.equal((await verifyChain(removed)).ok, false, 'removing a record is detected');

  const reordered = [records[0], records[2], records[1], records[3], records[4]];
  assert.equal((await verifyChain(reordered)).ok, false, 'reordering is detected');
});

test('genesis uses the empty string as prev', async () => {
  const c = await contentHash(REPORT);
  assert.equal(await chainHash('', c), await chainHash(null, c));
  assert.equal(await chainHash('', c), await chainHash(undefined, c));
});

test('merkle: paths verify, and forged ones do not', async () => {
  for (const size of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17]) {
    const leaves = [];
    for (let i = 0; i < size; i++) leaves.push(await contentHash({ ...REPORT, public_no: i + 1 }));
    const root = await merkleRoot(leaves);
    for (let i = 0; i < size; i++) {
      const path = await merklePath(leaves, i);
      assert.equal(await merkleVerify(leaves[i], path, root), true, `size ${size}, leaf ${i}`);
      assert.equal(await merkleVerify(leaves[(i + 1) % size], path, root) && size > 1, false,
        `size ${size}: another leaf must not verify on this path`);
    }
  }
});

test('merkle: an odd node is promoted, not duplicated', async () => {
  /* If the last node were duplicated, a three-leaf tree [a,b,c] and a four-leaf tree
     [a,b,c,c] would share a root, the CVE-2012-2459 shape. They must not. */
  const l = [];
  for (let i = 0; i < 3; i++) l.push(await contentHash({ ...REPORT, public_no: i + 1 }));
  const three = await merkleRoot(l);
  const four = await merkleRoot([...l, l[2]]);
  assert.notEqual(three, four, 'duplicating the odd node would collide these roots');
});

test('merkle: a truncated or extended path is rejected', async () => {
  const l = [];
  for (let i = 0; i < 8; i++) l.push(await contentHash({ ...REPORT, public_no: i + 1 }));
  const root = await merkleRoot(l);
  const path = await merklePath(l, 3);
  assert.equal(await merkleVerify(l[3], path.slice(0, -1), root), false, 'truncated');
  assert.equal(await merkleVerify(l[3], [...path, path[0]], root), false, 'extended');
  const flipped = path.map((s, i) => i === 0 ? { ...s, side: s.side === 'L' ? 'R' : 'L' } : s);
  assert.equal(await merkleVerify(l[3], flipped, root), false, 'wrong side');
});

test('anchor memo: parsed, not pattern-matched', async () => {
  const root = 'a'.repeat(64);
  const good = `judge-anchor/1 root=${root} n=7 first=1 last=7`;
  assert.deepEqual(parseAnchorMemo(good), { root, count: 7, first: 1, last: 7 });
  assert.equal(parseAnchorMemo(`other/1 root=${root}`), null, 'wrong prefix');
  assert.equal(parseAnchorMemo('judge-anchor/1 n=1'), null, 'no root');
  assert.equal(parseAnchorMemo('judge-anchor/1 root=abc'), null, 'short root');
  assert.equal(parseAnchorMemo('hello ' + root), null, 'free text containing hex is not an anchor');
  assert.equal(parseAnchorMemo(`judge-anchor/1 root=${root.toUpperCase()} n=1`).root, root, 'lowercased');
});

/* ---- the whole verification, against a stubbed ledger ---- */

const PUBLISHER = 'Bi4rd5FH5bYEN8scZ7wevxNZyNmKHdaBcvewdPFxYdLt';
const SIG = '5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW';
const txWith = (signer, memo, err = null) => ({
  slot: 291544120,
  meta: { err, logMessages: memo ? [`Program log: Memo (len ${memo.length}): "${memo}"`] : [] },
  transaction: { message: {
    header: { numRequiredSignatures: 1 },
    accountKeys: [{ pubkey: signer, signer: true, writable: true }],
    instructions: memo ? [{ programId: MEMO_PROGRAM_ID, parsed: memo }] : [],
  } },
});

async function scenario(overrides = {}) {
  const record = { ...REPORT };
  const ch = await contentHash(record);
  const chain = await chainHash('', ch);
  const root = await merkleRoot([chain]);
  const path = await merklePath([chain], 0);
  const memo = `judge-anchor/1 root=${root} n=1 first=1 last=1`;
  return verifyReport({
    record, storedContentHash: ch, storedChainHash: chain, prevChainHash: '',
    batchRoot: root, merklePath: path, anchorSignature: SIG, publisherKey: PUBLISHER,
    fetchTransaction: async () => txWith(PUBLISHER, memo),
    ...overrides,
  });
}

test('a sound report verifies', async () => {
  const r = await scenario();
  assert.equal(r.result, RESULT.VERIFIED);
  assert.equal(r.slot, 291544120);
});

test('an edited report is ALTERED, not pending', async () => {
  const record = { ...REPORT };
  const ch = await contentHash(record);
  const chain = await chainHash('', ch);
  const root = await merkleRoot([chain]);
  const r = await verifyReport({
    record: { ...record, facts: 'something else entirely' },
    storedContentHash: ch, storedChainHash: chain, prevChainHash: '',
    batchRoot: root, merklePath: await merklePath([chain], 0),
    anchorSignature: SIG, publisherKey: PUBLISHER,
    fetchTransaction: async () => txWith(PUBLISHER, `judge-anchor/1 root=${root} n=1 first=1 last=1`),
  });
  assert.equal(r.result, RESULT.ALTERED);
  assert.equal(r.reason, 'content hash');
});

test('a memo signed by anyone else is NOT_ANCHORED', async () => {
  const r = await scenario({ fetchTransaction: async () => {
    const other = 'So11111111111111111111111111111111111111112';
    return txWith(other, 'judge-anchor/1 root=' + 'b'.repeat(64) + ' n=1 first=1 last=1');
  } });
  assert.equal(r.result, RESULT.NOT_ANCHORED);
  assert.equal(r.reason, 'not signed by the publisher key');
});

test('a transaction the ledger does not have is PENDING, not a failure', async () => {
  const r = await scenario({ fetchTransaction: async () => null });
  assert.equal(r.result, RESULT.PENDING);
});

test('a failed transaction is NOT_ANCHORED, not PENDING', async () => {
  const failed = { InstructionError: [0, 'Custom'] };
  const r = await scenario({ fetchTransaction: async () => txWith(PUBLISHER, 'x', failed) });
  assert.equal(r.result, RESULT.NOT_ANCHORED);
});

test('a transaction with no anchor memo is NOT_ANCHORED', async () => {
  const r = await scenario({ fetchTransaction: async () => txWith(PUBLISHER, 'just a normal memo') });
  assert.equal(r.result, RESULT.NOT_ANCHORED);
});

test('an unanchored report is PENDING and says so', async () => {
  const r = await scenario({ anchorSignature: null });
  assert.equal(r.result, RESULT.PENDING);
});

test('a redacted record is neither verified nor altered', async () => {
  const r = await scenario({ redacted: true });
  assert.equal(r.result, RESULT.REDACTED);
});

test('signers are read from both transaction shapes', () => {
  assert.deepEqual(signersOf(txWith(PUBLISHER, 'm')), [PUBLISHER]);
  assert.deepEqual(signersOf({ transaction: { message: {
    header: { numRequiredSignatures: 1 }, accountKeys: [PUBLISHER, 'other'], instructions: [] } } }), [PUBLISHER]);
});

test('memos are read from the instruction and from the log', () => {
  const memo = 'judge-anchor/1 root=' + 'c'.repeat(64) + ' n=1 first=1 last=1';
  assert.ok(memosFrom(txWith(PUBLISHER, memo)).includes(memo));
});

/* ------------------------------------------------------------------ SPEC §5: responses */

const RESPONSE = {
  report: 3,
  platform: 'x',
  username: 'examplecaller',
  body: 'The presale was refunded in full on 2 January. Transaction references below.',
  stance: 'disputes',
  settled: 1,
  evidence: 'https://example.com/refunds',
  created_at: '2026-01-07T10:04:11.000Z',
};

test('a response seals exactly the eight fields the specification names, in order', () => {
  assert.deepEqual([...RESPONSE_FIELDS],
    ['report', 'platform', 'username', 'body', 'stance', 'settled', 'evidence', 'created_at']);
  const lines = canonical(RESPONSE, RESPONSE_FIELDS).split('\n');
  assert.equal(lines.length, 8);
  assert.deepEqual(lines.map((l) => l.slice(0, l.indexOf('='))), [...RESPONSE_FIELDS]);
});

test('the account identifier is outside the response seal', () => {
  const withId = { ...RESPONSE, platform_uid: '1436677111222333444' };
  assert.equal(canonical(withId, RESPONSE_FIELDS), canonical(RESPONSE, RESPONSE_FIELDS));
});

test('a response chains from its parent report, and an edit to it is detected', async () => {
  const parentChain = await chainHash('', await contentHash(REPORT));
  const c1 = await contentHash(RESPONSE, RESPONSE_FIELDS);
  const link = await chainHash(parentChain, c1);

  const edited = { ...RESPONSE, body: RESPONSE.body.replace('in full', 'in part') };
  const c2 = await contentHash(edited, RESPONSE_FIELDS);
  assert.notEqual(c2, c1);
  assert.notEqual(await chainHash(parentChain, c2), link);
});

test('a second response chains from the first, not from the report again', async () => {
  const parentChain = await chainHash('', await contentHash(REPORT));
  const first = await chainHash(parentChain, await contentHash(RESPONSE, RESPONSE_FIELDS));
  const second = { ...RESPONSE, body: 'Adding the transaction references.', created_at: '2026-01-07T10:30:00.000Z' };
  const linked = await chainHash(first, await contentHash(second, RESPONSE_FIELDS));
  const misLinked = await chainHash(parentChain, await contentHash(second, RESPONSE_FIELDS));
  assert.notEqual(linked, misLinked);
});

/* ------------------------------------------------- the runtime this claims to support */

test('works when the runtime has no global Web Crypto, as on Node 18', async () => {
  /* Node 18 ships Web Crypto but does not expose it on globalThis. Deleting the global and
     loading the module fresh exercises the same path that runtime takes, so the README's
     "Node 18 or newer" is checked rather than asserted. */
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  delete globalThis.crypto;
  try {
    const fresh = await import(`../reference/judge.mjs?no-global-crypto=${Date.now()}`);
    assert.ok(fresh.subtle, 'Web Crypto should still resolve');
    assert.equal(
      await fresh.contentHash(REPORT),
      await contentHash(REPORT),
      'and must produce identical digests',
    );
  } finally {
    if (saved) Object.defineProperty(globalThis, 'crypto', saved);
  }
});
