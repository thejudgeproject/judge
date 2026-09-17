# Changelog

Notable changes to the specification, the reference implementation and the verifier.

The record format is versioned separately from this package. A change to the canonical
serialization, the chain rule, the merkle construction, the memo format or the attestation
format is a breaking change to `judge-record/1` and is published as a new format version rather
than as an edit, records already sealed under a version must stay verifiable under it forever.

This package follows [semantic versioning](https://semver.org/).

## 1.0.0

First public release.

- **Record format** (`judge-record/1`): canonical serialization over 18 sealed fields, SHA-256
  content hash, hash chain across records, responses sealed and chained as records in their own
  right, and a redaction rule that keeps a removed record's position and hashes visible.
- **Merkle batching**: RFC 6962 shaped, with an odd node promoted rather than duplicated
  (the CVE-2012-2459 shape).
- **Anchoring**: a batch root written to Solana mainnet-beta in an SPL Memo instruction. A memo
  is accepted as an anchor only when the transaction carries the publisher's signature.
- **Attestation** (`judge-attestation/1`): ECDSA P-256 over a record's identity, signed at
  filing time, covering the window between publication and the next batch.
- **Receipt format** (`judge-report-proof/1`): the downloadable file that carries the sealed
  bytes, the hashes, the batch, the merkle path and the attestation.
- `reference/judge.mjs` and `reference/receipt.mjs`: dependency-free, written from the
  specification rather than extracted from the application.
- `bin/judge-verify.mjs`: checks a receipt offline, and against a Solana RPC endpoint of the
  caller's choosing when given `--rpc`. Reports its own version with `--version`, so a bug
  report can say which build produced a result.
- Specification, architecture and threat model; security policy and contribution guide.
- Secret and identity scanning, linting, documentation link checking and a test suite, all
  dependency-free and all required in CI.
