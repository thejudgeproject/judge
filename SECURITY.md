# Security policy

## Reporting a vulnerability

Open a
[private security advisory](https://github.com/thejudgeproject/judge/security/advisories/new)
on this repository. That channel is private until we publish it together, and it is the only
private channel this project operates.

Please do not open a public issue for a vulnerability, and please do not post it publicly before
we have had a chance to respond.

Include what you need to include to make the problem reproducible. A proof of concept is welcome
and is never held against you. If a receipt or a record is the clearest way to show it, strip
anything that identifies a real person first.

## What to expect

| | |
|---|---|
| acknowledgement | within 72 hours |
| initial assessment | within 7 days |
| fix or a dated plan | within 30 days for anything we can reproduce |
| credit | yours unless you would rather not be named |

We will tell you plainly if we think a report is not a vulnerability, and why. We would rather
disagree with you in writing than quietly ignore you.

## In scope, and interesting to us

- any way to make a **modified** record verify successfully
- any way to make an **unmodified** record fail verification
- forging an anchor: a memo accepted as JUDGE's without the publisher key
- forging or replaying an attestation, or making one verify over a statement describing a
  different record
- merkle path forgery, including second-preimage and odd-node attacks
- impersonating a named party through the X or Telegram verification flow, or responding as an
  account a report does not name
- probing the Integrity Layer: any way to distinguish a held submission from a refused one, or
  to learn anything about why
- an ambiguity in the specification that lets two correct implementations disagree
- anything that causes the system to report a confirmation it has not earned

## Out of scope

- reports that the archive contains claims you believe are untrue. A report is a claim, not a
  finding, and the right of reply is the mechanism for that, not this policy.
- volumetric denial of service
- findings from automated scanners with no demonstrated impact
- missing hardening headers with no exploitable consequence

## Supported versions

| version | supported |
|---|---|
| `judge-record/1` | yes, and permanently. Records sealed under a format version must stay verifiable under it forever, so a format change is published as a new version rather than as an edit |
| `judge-verify` 1.x | yes, at the latest 1.x |

## Safe harbour

Research conducted in good faith under this policy is authorised, and we will not pursue action
over it. Please do not access or modify data belonging to other people, and please stop and tell
us if you find that you can.

Testing against the specification, the reference implementation and your own receipts needs no
permission at all, and is the form of research this repository exists to make possible.
