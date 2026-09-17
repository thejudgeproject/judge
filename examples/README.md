# Examples

Two receipts. Every hash in them was computed by the reference implementation, not typed by
hand, and `test/receipt.test.mjs` treats them as known-answer vectors. If a change to the
hashing or the merkle construction ever alters them, the tests fail.

| file | what it is |
|---|---|
| `receipt.example.json` | a well-formed receipt for a record in a five-record batch |
| `receipt.tampered.json` | the same receipt with one word changed in the sealed text, and nothing else touched |

## Check them

```
node bin/judge-verify.mjs examples/receipt.example.json
```

```
  receipt   JDG-0003
  filed     2026-01-05T08:02:19.000Z
  anchor    not checked (pass --rpc to read it from the chain)

  [  ok  ] content hash  -  computed eb75975161b3fe13…
  [  ok  ] sealed field set  -  18 fields
  [  ok  ] chain hash  -  computed d284bc5337dc3ed0…
  [  ok  ] merkle path  -  3 step(s) to 18d1b9f6c4743a93…
  [  ok  ] attestation statement  -  rebuilt from the receipt, compared to the signed copy
  [  ok  ] attestation signature  -  ECDSA P-256

  PENDING  -  sealed and chained; this batch has not been anchored yet
```

`PENDING` is the correct answer, not a failure. The example batch names no anchoring
transaction, so the strongest true statement is that the record is sealed, chained and
attested, and the verifier makes that statement rather than a larger one.

```
node bin/judge-verify.mjs examples/receipt.tampered.json
```

```
  [ FAIL ] content hash  -  computed 1935eae2898d029a…

  ALTERED  -  the content fingerprint does not match the sealed bytes
```

The difference between the two files is `single transaction` becoming `eleven transactions`
inside `canonicalString`. Every hash, the merkle root, the path and the signature are byte for
byte identical between them. The fingerprint detects the change without being told where to
look.

Exit codes: `0` verified · `1` altered or not anchored · `2` pending · `3` usage error.

## Notes on the fixtures

- **The subjects are invented.** The handles, addresses, projects and incidents are placeholder
  text written for these files. No real person or account appears in them.
- **The batch has five records**, so the tree has an odd level and the promotion rule
  ([SPEC §6](../docs/SPEC.md#6-merkle-tree)) is exercised by the example rather than only by the
  test suite.
- **The attestation is real, and its key is not JUDGE's.** The signature verifies, because it
  was produced by an ECDSA P-256 key generated for this fixture and discarded immediately; only
  the public half is in the file. JUDGE's own signing key is not in this repository and its
  public half will be published alongside the first anchoring transaction.
- **`batch.recordingTransaction` is `null`,** because no batch has been anchored on mainnet yet.
  Writing a plausible-looking signature there would be a fabricated on-chain event, and this
  repository does not contain one.

## Checking an anchor

Once anchoring is live, the same command reads the transaction from whichever Solana RPC
endpoint you name, rather than from JUDGE:

```
node bin/judge-verify.mjs my-receipt.json --rpc https://api.mainnet-beta.solana.com
```

Add `--publisher <base58>` to compare the signer against a key you already trust instead of the
one the receipt names. That is the stricter check, and the one to use for a receipt somebody
else handed you.

All three settings can come from the environment instead of the command line, see
[`.env.example`](../.env.example).
