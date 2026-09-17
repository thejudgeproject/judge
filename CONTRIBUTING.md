# Contributing

The most useful contributions to this repository are, in order:

1. **An attack.** A way to make a modified record verify, or an unmodified one fail. See
   [SECURITY.md](SECURITY.md), report these privately first.
2. **An independent implementation.** If you write a verifier from [docs/SPEC.md](docs/SPEC.md)
   alone and it disagrees with the reference, the specification is ambiguous and we want to know
   exactly where.
3. **A test that should pass and does not**, or one that should fail and does not.
4. **A correction to the specification.** It is the contract; if it is unclear, that is a defect
   in its own right.

## Setting up

Node 18 or newer. There is nothing to install, this package has no dependencies and is not
going to acquire any.

```bash
git clone https://github.com/thejudgeproject/judge.git
cd judge
npm run check
```

`npm run check` runs the full gate, in the order CI runs it:

| command | what it does |
|---|---|
| `npm run lint` | syntax, encoding, line endings, whitespace, line length, and rules specific to this repository: no `console` in `reference/`, no unfinished markers, no dependencies in `package.json` |
| `npm run links` | every relative link and heading anchor in the documentation resolves, and every file the documentation promises exists |
| `npm run scan` | secret and identity scan over the working tree |
| `npm test` | the test suite, on your Node |

Two conveniences:

```bash
npm run lint:fix        # whitespace and line endings only; never logic
npm run scan:history    # the scan CI runs: every commit, every file, plus author metadata
```

To check a value that must never appear, such as a passcode or a key you are rotating, without writing
it into the repository in order to look for it:

```bash
SCAN_FORBIDDEN="the-value" npm run scan
```

## Ground rules

- `npm run check` must pass, and new behaviour arrives with a test.
- **No dependencies in `reference/`.** It must stay readable end to end and runnable anywhere.
  The same applies to `scripts/` and `bin/`: a repository arguing that you should not have to
  audited alongside it, which defeats the purpose.
- **The specification is normative.** If the code and the spec disagree, fix whichever is wrong,
  but say which one you decided was wrong and why.
- **A format change is a new version, not an edit.** Records already sealed under
  `judge-record/1` must remain verifiable under it forever.
- Do not add a claim to the README that the tests do not demonstrate.
- Nothing identifying goes in a commit: no personal name, personal email, local path, or
  machine name, in the diff or in the author line. CI checks the author line as well as the
  content: commit metadata identifies a person as directly as a file does.

## Style

Whatever the linter accepts. Beyond that: comments explain *why*, not *what*, the code already
says what it does. Prefer one comment that explains a non-obvious decision over several that
restate the code.

## What this repository is not

It is not the JUDGE application. Pull requests adding application features, interface work, or
abuse-detection logic will be declined, not as a judgement on the work, but because the line
between what is public here and what is not is deliberate and documented in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#11-what-is-deliberately-absent).

Conduct expectations are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
