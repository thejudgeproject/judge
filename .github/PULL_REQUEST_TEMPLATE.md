<!--
  Before opening this: if the change concerns a way to make a modified record verify, or an
  unmodified one fail, it belongs in a private security advisory first. See SECURITY.md.
-->

## What this changes

<!-- One or two sentences. What is different afterwards, not what you did. -->

## Why

<!-- The problem, not the patch. If it fixes an issue, link it. -->

## The specification

- [ ] This change does not alter the record format, the canonical serialization, the merkle
      construction, the memo format or the attestation format.
- [ ] It does alter one of them, and I have updated `docs/SPEC.md` in the same pull request,
      and said below why a format change is justified.

Records already sealed under a version must stay verifiable under it forever, so a format
change is a new version rather than an edit. If that is what this is, say so explicitly.

## Checks

- [ ] `npm run check` passes locally (lint, links, secret scan, tests)
- [ ] New behaviour arrives with a test; a fixed defect arrives with a test that failed before
- [ ] No dependency added to `reference/`. It stays readable end to end and runnable anywhere
- [ ] No credential, key, personal name, personal email, local path or identifying metadata is
      in the diff or in the commit author line
- [ ] Nothing in the documentation now claims something the tests do not demonstrate

## Anything a reviewer should look at hardest

<!-- The part you are least sure about. Saying so is not a weakness in a pull request. -->
