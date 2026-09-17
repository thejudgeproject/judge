# JUDGE record format and verification, v1

Normative. This document is complete enough to reimplement verification without reference to
any JUDGE source code. Where this document and an implementation disagree, this document is
wrong and should be corrected, the specification is the contract.

Key words follow RFC 2119.

---

## 1. Sealed fields

A report has exactly eighteen sealed fields, in this order:

```
public_no, filed_at, subject_raw, subject_type, address, project, twitter,
telegram, associated, title, facts, incident_type, vector, hindsight,
amount_sol, incident_date, tx_sig, still_active
```

Any other stored value (vote counts, search indexes, the batch identifier attached after
publication, the redaction flag) is outside the seal.

The rule is mechanical: **a value that can legitimately change after publication MUST NOT be
sealed.** If it were, every later verification of that record would fail, and a failure that
happens routinely tells a reader nothing.

## 2. Canonical serialization

Each sealed field is written as:

```
<name>=<value>
```

Lines are joined with a single LF (`0x0A`). There is **no trailing newline**.

Value encoding:

| type | serializes as |
|---|---|
| NULL | the empty string |
| string | itself, unmodified |
| `hindsight` | its JSON array, e.g. `["a","b"]`; empty is `[]` |
| `still_active` | `1` or `0` |
| number | its stored decimal representation |

No escaping is applied and none is required. Field names, field order and field count are all
fixed, so a value containing LF or `=` cannot be reinterpreted as a different set of fields.
There is no parser on the verification path, only a comparison of bytes.

An absent value and an empty value serialize identically. This is intentional: the two are not
distinguishable in the record and MUST NOT be made distinguishable by the serializer.

The result is encoded as UTF-8.

## 3. Content hash

```
content_hash = lowercase_hex( SHA-256( UTF8( canonical ) ) )
```

## 4. Chain hash

`public_no` is assigned in strictly increasing sequence at publication.

```
chain_hash = lowercase_hex( SHA-256( UTF8( prev_chain_hash ‖ content_hash ) ) )
```

`‖` is string concatenation over the **lowercase hex representations**, not over raw bytes.
For the first record, `prev_chain_hash` is the empty string.

Consequences a verifier MUST rely on:

- altering any sealed field changes `content_hash`, and therefore every `chain_hash` after it
- removing a record leaves its successor's `prev_hash` naming a hash that occurs nowhere
- inserting a record is indistinguishable from altering one, and is caught the same way

## 5. Responses

A response seals eight fields, in this order:

```
report, platform, username, body, stance, settled, evidence, created_at
```

Serialization and hashing are as in §2–§3. A response chains from its parent report's
`chain_hash`, and thereafter from the previous response to the same report.

The internal account identifier is excluded from the seal. A fingerprint that a reader cannot
reproduce proves nothing to that reader.

## 6. Merkle tree

Published records not yet in a batch are folded into one tree over their `chain_hash` values,
in ascending `public_no` order. The construction is RFC 6962 shaped:

```
leaf(h)          = SHA-256( 0x00 ‖ bytes(h) )
node(left,right) = SHA-256( 0x01 ‖ left ‖ right )
```

Here `‖` is **byte** concatenation, and `bytes(h)` is the 32 bytes the hex decodes to.

A level with an odd number of nodes promotes the final node to the next level unchanged. It
MUST NOT be duplicated. Duplication is the CVE-2012-2459 shape and permits two distinct trees
with the same root.

The batch records the root, the count, and the first and last `public_no` covered.

## 7. Anchoring

The root is written to Solana as an SPL Memo instruction
(`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`) in a transaction signed by the publisher key.

```
judge-anchor/1 root=<64 lowercase hex> n=<count> first=<public_no> last=<public_no>
```

Fields are separated by single spaces. The memo MUST begin with `judge-anchor/1`.

Nothing else is written on chain. Specifically not: report text, handles, addresses, evidence,
identifiers, or any metadata about a filer.

## 8. Verification

A verifier is given a report's field values, its hashes, its batch, its merkle path, the
publisher's public key and a Solana RPC endpoint.

1. Recompute the canonical form (§2) from the field values **as displayed**.
2. Recompute `content_hash` (§3). If it differs from the stored value → **ALTERED**.
3. Recompute `chain_hash` (§4) using the recomputed `content_hash`, never the stored one.
   Advancing on a stored hash would let an edited record with an untouched hash string appear
   to link. If it differs → **ALTERED**.
4. Walk the merkle path (§6) from this record's leaf. If it does not reach the batch root →
   **ALTERED**.
5. Fetch the anchoring transaction by signature at `confirmed` commitment or higher.
   - not found → **PENDING** (not a failure; it may not have landed yet)
   - `meta.err` non-null → **NOT ANCHORED**
6. Check the transaction's signers include the expected publisher key. If not →
   **NOT ANCHORED**. A memo in this format signed by any other key is a stranger's memo and
   carries no weight.
7. Parse the memo (§7). Absent or malformed → **NOT ANCHORED**.
8. Compare the memo's root to the batch root. Equal → **VERIFIED**. Otherwise → **ALTERED**.

An implementation MUST distinguish **PENDING** from **NOT ANCHORED**. Reporting a failure as
"pending" hides a real negative; reporting pending as a failure cries wolf on every batch that
has simply not been anchored yet. Every ambiguous outcome MUST resolve toward the smaller true
statement, never toward an unearned confirmation.

## 9. Attestation

At the moment a record is written, the archive signs a short statement about it. The signature
travels in the receipt (§8 of the receipt format), and it closes the window between publication
and the next batch: before a root exists on chain, a reader still holds something the archive
cannot take back.

The signed bytes are exactly:

```
judge-attestation/1
public_no=<n>
filed_at=<iso8601>
prev_hash=<64 hex, or empty for the first record>
content_hash=<64 hex>
chain_hash=<64 hex>
```

Lines are joined with a single LF, there is no trailing newline, and the order and spelling of
the keys are part of the contract. A verifier MUST rebuild this string from the values it is
checking rather than trusting the copy carried in the receipt. Otherwise a receipt could
present a signature over a statement describing some other record.

| | |
|---|---|
| algorithm | ECDSA on P-256, SHA-256 |
| signature encoding | base64url of the raw `r ‖ s` pair, 64 bytes, no DER wrapper |
| public key | JWK, published at the archive's public settings endpoint and repeated in each receipt |

**What this establishes.** It does not make rewriting impossible. It makes rewriting *provable
by whoever was rewritten*. A compromised key can sign new statements from the moment of
compromise onward; it cannot reach back and unsign a statement someone already downloaded. If a
record is later altered and re-anchored, the receipt in a reader's hands contradicts the chain,
and the contradiction is checkable without asking the archive anything.

**What it does not establish.** Nothing about whether the report is accurate, and nothing about
who filed it. An attestation is a statement by the archive about the archive's own record at a
point in time.

An implementation MUST NOT report a record as verified on the strength of an attestation alone.
The attestation is one check among those in §8; it is not a substitute for the anchor.

## 10. Redaction

Redaction blanks the content and identifier columns and sets `status='redacted'`. It leaves
`public_no`, `content_hash` and `chain_hash` untouched, so the record keeps its position and
the removal is visible rather than silent.

A verifier encountering a redacted record MUST report that the content is unavailable. It MUST
NOT report the record as verified, and MUST NOT report it as altered.

## 11. Trust assumptions

Verification removes the archive operator from the arithmetic. It does not remove everybody.
A reader using a verifier served by the archive still trusts:

- the verifier itself, as delivered
- the RPC endpoint queried, for the transaction it returns
- SHA-256 and ed25519
- the ledger's own history guarantees

The first is the residual risk and it is the reason downloadable receipts exist: a receipt
carries the canonical bytes, the hashes, the batch and the path, so the check can be repeated
with an implementation, such as the one in this repository, that did not come from the
archive. The second is why the RPC endpoint is configurable rather than fixed.

## 12. Known limits

A client-side check cannot detect **truncation by the party that publishes the head**: drop the
last N records and the head together, and the survivors still chain correctly. Only a root read
from the chain closes that, and only for the range that root covers.
