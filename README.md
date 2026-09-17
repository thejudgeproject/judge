# JUDGE

[![ci](https://github.com/thejudgeproject/judge/actions/workflows/ci.yml/badge.svg)](https://github.com/thejudgeproject/judge/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A518-informational.svg)](package.json)

**The backlog of bad behavior.**

JUDGE is a public record for crypto. Look up who you're dealing with, report your experience, or
respond publicly if you're named in a report.

Each report is screened for manipulation, sealed with a unique fingerprint, linked to the
record, anchored on-chain, and independently verified. This is the specification for that, a
dependency-free implementation of it, and the tests that hold both to it.

[thejudgeproject.com](https://thejudgeproject.com)

| | |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | **Normative.** Canonical form, hashing, merkle construction, memo format, attestation, verification |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, trust boundaries, the X and Telegram flows, the admission layer's boundary |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Adversaries, what each attempt runs into, and the limits |
| [reference/](reference/) | The implementation. No dependencies |
| [bin/judge-verify.mjs](bin/judge-verify.mjs) | Verify a receipt offline, or against an RPC endpoint you choose |
| [examples/](examples/) | A valid receipt and a tampered twin, with real digests |
| [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) | Disclosure process; what is worth contributing |

---

## Canonical form

Eighteen columns, fixed order, `field=value` lines joined with LF, no trailing newline:

```
public_no, filed_at, subject_raw, subject_type, address, project, twitter, telegram,
associated, title, facts, incident_type, vector, hindsight, amount_sol, incident_date,
tx_sig, still_active
```

NULL serializes to empty, `hindsight` to its JSON array, `still_active` to 1 or 0. No escaping:
names, order and count are fixed, so a value containing LF cannot be parsed as another field.
Mutable columns stay outside the seal.

## Fingerprint and chain

`public_no` is assigned in sequence at publication.

```
content_hash = SHA256(UTF8(canonical))
chain_hash   = SHA256(prev ‖ content_hash)
```

Concatenation is over lowercase hex, not raw bytes. Genesis prev is the empty string.

### How tampering shows

Every alteration surfaces as a hash that no longer reproduces.

```
edit field   → content_hash differs
edit+rehash  → all later chain_hash differ
delete       → successor prev names nothing
insert       → identical to an edit
reorder      → chain stops linking
```

The verifier advances on the recomputed hash, never the stored one.

## Responses

Eight sealed fields: `report`, `platform`, `username`, `body`, `stance`, `settled`, `evidence`,
`created_at`. Chains from the parent report, then from the previous response. Append-only: a
reply can be added, never reordered or edited. The internal account id is excluded, since a
hash a reader cannot reproduce proves nothing to them.

Only the account a report names may answer it:

| | |
|---|---|
| **X** | OAuth 2.0 authorization code with PKCE. State and verifier minted server-side, single use, expiring. Handle read from `/2/users/me` |
| **Telegram** | Login Widget. HMAC-SHA256 recomputed over the payload with a key derived from the bot token; `auth_date` freshness window defeats replay |

The handle the provider returned is compared to the handle the report names. Nothing in the
request body can name the account it is responding as. Full flows, failure paths included, in
[ARCHITECTURE §5](docs/ARCHITECTURE.md#5-responding-and-how-a-named-party-proves-who-they-are).

## Anchoring

Unbatched records fold into one RFC 6962 tree over their chain hashes. Leaves are
`SHA256(0x00‖h)`, nodes `SHA256(0x01‖l‖r)`, odd node promoted, never duplicated
([CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459)). The root goes to Solana
mainnet-beta as an SPL Memo (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`):

```
judge-anchor/1 root=<64 hex> n=<count> first=<no> last=<no>
```

No program deployed. The signature binds it, not the text.

> **Status.** The publisher account is not funded and no batch has been anchored on mainnet.
> Verification therefore returns `PENDING`, not `VERIFIED`. The publisher public key and the
> first anchoring transaction will be added here once they exist. Nothing in this repository
> asserts an on-chain event that has not happened.

## On chain, off chain, never

The list is a constraint, not a default.

```
on chain:  merkle_root, first, last, count
off chain: reports, responses, evidence, identifiers, votes
never:     IP, session data, integrity signals
```

Redaction therefore never touches the chain. It blanks content, keeps `public_no`,
`content_hash` and `chain_hash`, and sets `status='redacted'`, so removal is visible rather
than silent.

## Attestation

At filing time, before any batch exists, the archive signs the record's identity:

```
judge-attestation/1
public_no=<n>
filed_at=<iso8601>
prev_hash=<64 hex, empty for the first record>
content_hash=<64 hex>
chain_hash=<64 hex>
```

ECDSA P-256 over SHA-256, signature as base64url of the raw `r‖s` pair. It does not make
rewriting impossible; it makes rewriting provable by whoever was rewritten. A compromised key
signs from that moment on, and cannot unsign a statement already downloaded.

## Independent verification

Client-side, in this order:

```
1 rebuild canonical from the DOM
2 recompute content_hash, chain_hash
3 walk the merkle path to the root
4 getTransaction(sig, confirmed)
5 assert publisher key signed it
6 parse memo, compare roots
```

Step 4 onward takes nothing from JUDGE. Receipts carry the same material, so the check survives
the archive.

`PENDING` and `NOT_ANCHORED` are distinct outcomes and must stay distinct. Reporting a failure
as pending hides a negative; reporting pending as failure cries wolf on every unanchored batch.

## Admission control

Deterministic, server-side, pre-publication. Reads how a submission arrived, never whether its
claim is true. Resolves to publish, hold or refuse; the row is retained either way and no path
edits a filer's words.

```
to the filer:  no score, signal, counter
public API:    none of the above, ever
hold/refusal:  byte-identical wording
```

Guarantees documented, not rules: a message naming the rule is a free oracle. Public
cryptography gets stronger under review, which is why [SPEC.md](docs/SPEC.md) is exhaustive. An
abuse heuristic only gets weaker.

## Guarantees and limits

```
proves:     unchanged since filing
            ordering, no insert or delete
not:        accuracy, filer identity,
            or what anyone did
```

Two limits. Head truncation is invisible to a client-side check; only an on-chain root closes
it, and only for its range. And a reader running a verifier we served still trusts that
delivery, which is what receipts remove.

---

## Verify a receipt

Node 18 or newer, no install step.

```bash
git clone https://github.com/thejudgeproject/judge.git
cd judge

npm test                                                   # 61 tests, no network
node bin/judge-verify.mjs examples/receipt.example.json    # valid   → exit 2, PENDING
node bin/judge-verify.mjs examples/receipt.tampered.json   # tampered → exit 1, ALTERED
```

The fixtures differ only in `canonicalString`, where `a single transaction` becomes
`eleven transactions`. Every digest, the root, the path and the signature are byte-identical
between them, and the second still fails at step 1.

```bash
node bin/judge-verify.mjs receipt.json --rpc https://api.mainnet-beta.solana.com
```

`--publisher` pins the key the anchor must carry rather than trusting the one the receipt
names. `--commitment`, `--json`, `--version` as expected; all three settings also read from the
environment. See [`.env.example`](.env.example).

Exit codes: `0` verified, `1` altered or not anchored, `2` pending, `3` usage error.

```js
import { contentHash, chainHash, merkleVerify } from './reference/judge.mjs';
import { verifyReceipt, rpcReader } from './reference/receipt.mjs';

const outcome = await verifyReceipt(receipt, {
  fetchTransaction: rpcReader('https://api.mainnet-beta.solana.com'),
  publisherKey: '<key you already trust>',
});
// → { result: 'VERIFIED' | 'ALTERED' | 'PENDING' | 'NOT_ANCHORED' | 'REDACTED', checks: [...] }
```

`reference/judge.mjs` resolves Web Crypto from `globalThis` or, on Node 18, from `node:crypto`.
It was written from the specification rather than extracted from the application: agreement
between the two is then evidence that the specification is unambiguous.

## Development

```bash
npm run lint      # syntax, encoding, whitespace, no console in reference/, no em dashes
npm run links     # every relative link and heading anchor resolves
npm run scan      # secret and identity scan; --history walks every commit
npm test
npm run check     # all four, in CI order
```

CI gates on all of it: secret scan over full history, lint, link check, tests on Node 18, 20 and
22, the worked examples, and a dependency audit. Dependency-free by design, including the
tooling.

## Reporting a vulnerability

Private advisory, see [SECURITY.md](SECURITY.md). In scope and interesting: making a modified
record verify, making an unmodified one fail, forging an anchor without the publisher key,
merkle second-preimage, replaying or rebinding an attestation, responding as an account a report
does not name, or distinguishing a hold from a refusal.

## Not in this repository

The application, its migrations and operational configuration; authentication internals, session
handling and administrative functions; the admission layer's signals, weights and thresholds;
infrastructure identifiers. Everything needed to check the record without trusting us is here.
Everything whose only use is attacking or cloning the service is not.

## License

Apache-2.0. See [LICENSE](LICENSE).
