# Architecture

The public-facing architecture of JUDGE: what the components are, what moves between them, and
where the trust boundaries fall.

This document describes the system as it is built. Where something is implemented but not yet
switched on, it says so at that point rather than in a summary elsewhere. Nothing here describes
the abuse-detection rules, the administrative surface, or operational configuration, see
[What is deliberately absent](#11-what-is-deliberately-absent).

---

## 1. Shape of the system

Three processes and one external chain.

```
                    ┌──────────────────────────────────────────────┐
   reader,          │  EDGE WORKER                                 │
   filer,     ────► │  static delivery, routing, single origin     │
   responder        └───────────────────┬──────────────────────────┘
                                        │  service binding
                                        │  (no public hostname)
                                        ▼
                    ┌──────────────────────────────────────────────┐
                    │  ARCHIVE WORKER                              │
                    │  the API: filing, reading, responding,       │
                    │  sealing, chaining, batching                 │
                    └───────────────────┬──────────────────────────┘
                                        │
                              ┌─────────┴─────────┐
                              ▼                   ▼
                    ┌──────────────────┐  ┌──────────────────────┐
                    │  SQL DATABASE    │  │  PUBLISHER           │
                    │  reports,        │  │  offline signer,     │
                    │  responses,      │  │  holds the only key  │
                    │  batches, KOLs   │  │  that can anchor     │
                    └──────────────────┘  └──────────┬───────────┘
                                                     │ signed transaction
                                                     ▼
                                          ┌──────────────────────┐
                                          │  SOLANA mainnet-beta │
                                          │  SPL Memo            │
                                          └──────────────────────┘
                                                     ▲
                    reader's browser ────────────────┘
                    fetches the anchoring transaction directly,
                    from an RPC endpoint of the reader's choosing
```

The last arrow is the one that matters. Verification does not route through JUDGE. A reader
checks the anchor against Solana themselves, so the archive operator is not part of the
arithmetic that establishes whether a record is unchanged.

### Why the archive has no public hostname

The archive Worker is not reachable from the internet. The edge Worker holds the only public
origin and forwards `/api/*` to the archive over an internal service binding. Two consequences:

- the API and the site share one origin, so there is no cross-origin surface to misconfigure
- an access control applied at the edge cannot be stepped around by addressing the API directly

---

## 2. Technology

| layer | choice | why |
|---|---|---|
| edge + API runtime | Cloudflare Workers | one runtime at every location; no server to patch or leak a path from |
| storage | Cloudflare D1 (SQLite) | relational, transactional; sequence assignment must be serialisable |
| front end | one hand-written HTML document, ES5, no framework | the verifier a reader runs should be readable by that reader; no build step means the delivered bytes are the authored bytes |
| hashing | SHA-256 via Web Crypto | present in the runtime and in every browser; nothing to bundle |
| chain | Solana mainnet-beta | settlement in seconds, fees near zero, and a memo instruction that already does what is needed |
| anchoring | SPL Memo (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`) | a custom program would be more code, more cost and more to audit for the same 32 bytes |
| publisher | Node, run off the server | the signing key exists on one operator machine and never on an internet-facing host |
| reference verifier | Node 18+ / any modern browser, no dependencies | a verifier with a dependency tree is a verifier nobody audits |

There is no custom on-chain program, and there is no token.

---

## 3. Data model, at the level that matters publicly

Four record kinds are relevant to verification. Column names below are the sealed field names
from [SPEC.md](SPEC.md); non-sealed operational columns are not enumerated here.

```
reports            responses                 batches              kols
─────────          ─────────                 ───────              ────
public_no  ◄────── report                    id                   id
filed_at           platform  (x | tg)        merkle_root          name
subject_raw        username                  count                handle
subject_type       body                      first_public_no      wallet
address            stance                    last_public_no       votes
project            settled                   tx_sig               ─────────
twitter            evidence                  slot                 outside the
telegram           created_at                cluster              seal; a
associated         ─────────                 created_at           directory,
title              content_hash              ─────────            not a record
facts              chain_hash                anchored_at
incident_type
vector
hindsight
amount_sol
incident_date
tx_sig
still_active
─────────
content_hash       ◄── sealed set ends above the line in each case
chain_hash
batch_id               assigned after publication, outside the seal
status                 published | held | redacted
```

The sealed/unsealed split is the load-bearing decision. A value that can legitimately change
after publication (a vote count, the batch a record later lands in, the redaction flag) must
not be sealed, because every subsequent verification of that record would fail and a failure
that happens routinely tells a reader nothing. [SPEC §1](SPEC.md#1-sealed-fields) states the
rule normatively.

---

## 4. Filing a report

```
  submission
      │
      ▼
  ┌────────────────────────────────────────────────────────────┐
  │ 1. SHAPE      required fields present, lengths bounded,    │
  │               types coerced, handles canonicalised         │
  ├────────────────────────────────────────────────────────────┤
  │ 2. INTEGRITY  automated, server-side, deterministic.       │
  │    LAYER      reads how the submission arrived.            │
  │               never reads whether the claim is true.       │
  │               outcome: proceed, or hold for review         │
  ├────────────────────────────────────────────────────────────┤
  │ 3. SEQUENCE   public_no assigned, strictly increasing,     │
  │               inside the same transaction as the insert    │
  ├────────────────────────────────────────────────────────────┤
  │ 4. SEAL       canonical form over 18 fields (SPEC §2)      │
  │               content_hash = SHA256(canonical)             │
  ├────────────────────────────────────────────────────────────┤
  │ 5. CHAIN      chain_hash = SHA256(prev_chain_hash ‖        │
  │                                   content_hash)            │
  ├────────────────────────────────────────────────────────────┤
  │ 6. PUBLISH    visible immediately, with both hashes.       │
  │               state at this point: sealed, chained,        │
  │               NOT yet anchored                             │
  └────────────────────────────────────────────────────────────┘
```

Steps 3–5 happen together. A gap between assigning a sequence number and computing the hash
that depends on it would be a window in which two records could claim the same position.

A held submission is stored in full and is not published. Held and refused submissions return
byte-identical wording, so the outcome cannot be probed by submitting variations and watching
the reply.

**Anonymity.** No account is required to file. The archive does not store a filer identity
because there is none to store. Request metadata used by the Integrity Layer is never returned
by any public endpoint and never leaves the archive, the only thing that reaches the chain is
one 32-byte root per batch.

---

## 5. Responding, and how a named party proves who they are

A report names handles. Only the account a report actually names may answer it, and the proof
is control of that account, demonstrated to X or Telegram, never to JUDGE.

### X (OAuth 2.0, authorization code with PKCE)

```
  reader opens report ──► GET /api/auth/options?reportNo=N
                          └─► which platforms this report names,
                              and which are currently switched on

  "Respond as @handle" ──► GET /api/auth/x/start?reportNo=N
                           │   archive mints state + code_verifier,
                           │   stores them server-side against the report
                           └─► returns x.com/i/oauth2/authorize URL
                               scope: users.read tweet.read
                               code_challenge_method: S256

  person authorises on X ──► GET /api/auth/x/callback?code&state
                             │ 1. state looked up, then DELETED, single use
                             │ 2. expired state (>15 min) refused
                             │ 3. code exchanged at api.x.com for a token,
                             │    client authenticated, verifier presented
                             │ 4. GET /2/users/me → the account X says it is
                             │ 5. that username compared to the handle the
                             │    REPORT names. Mismatch → refused
                             └─► browser redirected back to the site with a
                                 single-use response token, 30 minute lifetime
```

Every exit from the callback is a redirect back to the site, including the failures. X sends
the browser there, not the page's script, so returning JSON would leave a person looking at an
error object with no way back to the report.

### Telegram (Login Widget)

```
  Telegram returns a signed payload ──► POST /api/auth/telegram
                                        │ 1. HMAC-SHA256 recomputed over the
                                        │    payload with a key derived from
                                        │    the bot token; mismatch → refused
                                        │ 2. auth_date freshness window
                                        │    enforced, so an old signed payload
                                        │    cannot be captured and replayed
                                        │ 3. username compared to the handle
                                        │    the REPORT names
                                        └─► single-use response token
```

### The invariant

**The handle is taken from the identity provider's answer, never from the request body.** A
handle typed into a form is input, not evidence. Nothing a client sends can name the account it
is responding as.

The response token is single use, expires, and is bound to one report. Presenting it posts the
response, which is then sealed and chained exactly like a report
([SPEC §5](SPEC.md#5-responses)), a response is part of the permanent record, not a comment
attached beside it.

### What this proves, and what it does not

Establishes control of the named account. Does **not** establish that the account belongs to the
person the report concerns. That limit applies to every platform that has ever verified a
handle, and stating it is more useful than implying otherwise.

---

## 6. The Integrity Layer

Its job is one sentence: **stop one person being buried under a coordinated flood, without ever
forming a view on whether a claim is true.**

Those are separate problems and conflating them is how moderation becomes editorial. The layer
reads submission behaviour: how a submission arrived, in what pattern, in relation to what else
arrived. It does not read the accusation.

Its boundary is public even though its rules are not:

| property | guarantee |
|---|---|
| where it runs | server-side, before publication, never in the client |
| determinism | same inputs, same outcome; no sampling, no model call |
| what it reads | arrival behaviour only |
| what it cannot read | whether the claim is true, and it is never asked to |
| what it cannot do | edit a submission, in any field |
| retention | a held submission is kept in full, not discarded |
| observability | its output appears on no public endpoint, in any form |
| probe resistance | held and refused submissions return byte-identical wording |
| on-chain | nothing it produces is ever anchored |

**Why the rules are not published.** Public cryptography gets stronger under review. That is
why [SPEC.md](SPEC.md) is exhaustive and the reference implementation exists. An abuse
heuristic gets weaker the moment it is described, because describing it is describing how to
pass it. The distinction is a standard one and we would rather state it than pretend this
repository is complete.

**What it is not.** It is a mitigation, not a guarantee. A patient, well-resourced, genuinely
distributed campaign is not solved by any automated check, and we do not claim it is.

---

## 7. Batching and anchoring

```
  published records not yet in a batch
      │  ordered by public_no, ascending
      ▼
  merkle tree over chain_hash values          leaf(h) = SHA256(0x00 ‖ h)
  RFC 6962 shaped                             node    = SHA256(0x01 ‖ l ‖ r)
  odd node PROMOTED, never duplicated         ← CVE-2012-2459
      │
      ▼
  batch { root, count, first_public_no, last_public_no }
      │
      ▼
  PUBLISHER, off the server
      │  builds one transaction carrying a single SPL Memo:
      │    judge-anchor/1 root=<64 hex> n=<count> first=<no> last=<no>
      │  signs it with the publisher key
      ▼
  Solana mainnet-beta
      │  confirmed
      ▼
  transaction read back and compared before the batch is recorded as anchored
```

Nothing but the root reaches the chain. Not report text, not handles, not addresses, not
evidence, not identifiers, not one byte about a filer.

**Signature, not text.** Anyone can write a transaction whose memo copies this format. What
makes a memo JUDGE's anchor is the key that signed the transaction, and verification checks the
signer before it reads the memo. Forging an anchor requires the publisher's private key, which
is not on any internet-facing host.

**Ordering of confirmation.** A batch is recorded as anchored only after the transaction is read
back from the chain at `confirmed` or higher and its memo is compared to the batch root. A
submitted transaction is not a confirmed one, and the interface never says "anchored" on the
strength of a send.

> **Status.** The publisher account is not yet funded and no batch has been anchored on
> mainnet. Until that happens, records are sealed and chained but report their state honestly as
> pending. The publisher public key and the first anchoring transaction will be published here
> when they exist. Nothing in this repository asserts an on-chain event that has not occurred.

---

## 8. Verification, end to end

Two paths. The difference between them is what the reader has to trust.

**In the page.** Convenient, and trusts the page it came from:

```
  displayed field values
      │
      ├─ recompute canonical form and content_hash        ─┐
      ├─ recompute chain_hash from the RECOMPUTED content  │  no network
      ├─ walk the merkle path to the batch root           ─┘
      │
      └─ fetch the anchoring transaction from a Solana RPC ── not JUDGE
           ├─ signed by the publisher key?
           ├─ memo parses as judge-anchor/1?
           └─ memo root == batch root?
```

**From a receipt.** The one that removes JUDGE entirely:

```
  receipt.json  (canonical bytes, hashes, batch, merkle path, signature)
      │
      ▼
  node bin/judge-verify.mjs receipt.json          ← this repository
      │                                             no dependencies
      ▼
  VERIFIED | ALTERED | PENDING | NOT_ANCHORED | REDACTED
```

A receipt is downloadable at the time of reading. Saved, it stays checkable with an
implementation that never came from the archive, including after the archive is gone.

Chain-hash recomputation deliberately advances on the **recomputed** content hash rather than
the stored one. Advancing on the stored value would let an edited record whose hash string was
left untouched still appear to link. [SPEC §8](SPEC.md#8-verification) makes this normative.

`PENDING` and `NOT_ANCHORED` are distinct outcomes and implementations must keep them distinct.
Reporting a genuine failure as "pending" hides a real negative; reporting pending as a failure
cries wolf on every batch that simply has not been anchored yet.

---

## 9. Public read surface

Read endpoints, all same-origin under `/api`:

| method | path | returns |
|---|---|---|
| `GET` | `/api/health` | liveness |
| `GET` | `/api/chain` | head chain hash, record count, latest batch and its anchor state |
| `GET` | `/api/settings` | public display settings |
| `GET` | `/api/reports` | published reports, filtered and paged |
| `GET` | `/api/reports/:public_no` | one report with its responses, hashes, batch and merkle path |
| `GET` | `/api/lookup` | handle and address lookup across published records |
| `GET` | `/api/kols` | the caller directory |
| `GET` | `/api/auth/options?reportNo=` | which platforms a report names, and which are switched on |

Write paths a person drives: `POST /api/reports` (file), `POST /api/reports/:no/responses`
(respond, with a verification token), `POST /api/kols/:id/vote`, `POST /api/abuse`.

Administrative endpoints exist, require authentication, and are not documented here or anywhere
public. Their shape is not part of the security model, since the record's integrity does not
depend on them being secret, but publishing a map of them serves an attacker and nobody else.

---

## 10. Trust boundaries

| boundary | what crosses it | what is trusted |
|---|---|---|
| browser → edge | HTTPS | TLS, and the delivered document |
| edge → archive | internal binding, no public hostname | the platform's isolation |
| archive → database | parameterised SQL only | the platform's isolation |
| publisher → chain | one signed transaction | the key stays offline |
| browser → RPC | a read the reader initiates | the RPC endpoint, which is why it is configurable |
| receipt → any verifier | a file | SHA-256, ed25519, and the chain's own history |

The residual risk, stated plainly: a reader who runs the verifier the archive served them is
trusting that delivery. Receipts and this repository exist to remove exactly that dependency,
and [SPEC §10](SPEC.md#11-trust-assumptions) records it rather than glossing it.

---

## 11. What is deliberately absent

Not oversights:

- the JUDGE application source, its schema migrations and its operational configuration
- the access gate, session handling, and every administrative function
- the Integrity Layer's signals, weights, thresholds and rules
- infrastructure identifiers, internal hostnames, and anything resembling a credential

The line is drawn in one place consistently: **everything a reader needs in order to check the
record without trusting us is public. Everything whose only use is attacking or cloning the
service is not.**
