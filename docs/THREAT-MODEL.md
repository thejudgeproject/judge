# Threat model

What JUDGE is built to withstand, what it is not, and where the honest edges are.

## Assets

| | |
|---|---|
| the record | published reports and responses, and their order |
| the proof | that a record is unchanged since publication |
| the right of reply | a named party's ability to answer |
| filer safety | a filer's identity, which the system is built never to hold |

## Adversaries

### A1. The operator of JUDGE

The one this whole design exists for. Assume the operator is malicious, compromised, or under
legal or financial pressure to change the record.

| attempt | outcome |
|---|---|
| edit a published report | `content_hash` no longer matches; every `chain_hash` after it breaks |
| edit and recompute all hashes | the recomputed root no longer matches the anchored root |
| re-anchor a rewritten history | the original anchor is still on chain; two roots for one range is itself the evidence |
| delete a report from the middle | its successor's `prev_hash` names a hash that occurs nowhere |
| **truncate the head** | **not detected by a client-side check alone**. See Limits |
| refuse to publish a report | not prevented. Nothing forces publication |
| redact a report | permitted, and visible: hashes and position are retained, status becomes `redacted` |

### A2. A coordinated campaign

Many accounts filing similar reports to bury one person.

Handled before publication by an automated check that reads submission behaviour and never the
claim. Its design is deliberately not public (see README). What is public is its boundary: it
cannot edit a submission, and it cannot be probed, because held and refused submissions get
byte-identical wording. Its output never appears on any public endpoint.

It is a mitigation, not a guarantee. A patient, well-resourced and well-distributed campaign is
not defeated by any automated check.

### A3. An impostor responding as the reported party

Responses require proof of control of an X or Telegram account named in the report (OAuth 2.0
PKCE; Telegram Login Widget HMAC). The handle is taken from the resulting token, never from the
request body. A handle typed into a form is never treated as proof.

This proves control of an account. It does not prove the account belongs to the person the
report is about. That is the same limit every platform has.

### A4. A forged anchor

Anyone can write a transaction whose memo copies our format. Verification checks the
transaction's **signers**, so a memo from any other key is refused. Forging an anchor requires
the publisher's private key, which is never on the server.

### A5. Someone trying to identify a filer

Reports are anonymous. IP addresses, device and session data and abuse signals are never
exposed through any public endpoint, and never anchored, nothing but a 32-byte root per batch
reaches the chain.

Residual: a filer can identify themselves through the content they write, and a transaction
signature offered as evidence may link to a wallet that identifies them. The submission form
warns about the second before the field rather than after it. Neither is something the
architecture can solve for someone determined to be specific.

### A6. A network attacker between the reader and the RPC

Could return a fabricated transaction. Mitigated by the reader choosing the endpoint; the RPC
is configuration, not a constant. Not mitigated for a reader who uses the default and is fully
MITM'd. Recorded in SPEC §11.

## Limits

1. **Head truncation.** Drop the last N records and the head together and the survivors still
   chain. Only an on-chain root closes this, and only for the range it covers.
2. **The served verifier.** A reader running a verifier delivered by the archive is trusting
   that delivery. Receipts and this repository exist to remove that dependency.
3. **Anchoring is not truth.** It establishes integrity and ordering. Whether a report is
   accurate is outside what any of this can answer.
4. **Availability is not guaranteed.** Nothing here prevents the site going away. It ensures
   that a receipt saved beforehand remains checkable if it does.
5. **Pre-anchor window.** Between publication and the next batch, a record is sealed, chained
   and signed but not yet anchored. Verification says so rather than implying otherwise.

## Non-goals

- deciding whether reports are true
- preventing anyone from filing a false report
- anonymity against an adversary who compromises the reader's own device
- preventing an operator from declining to publish
