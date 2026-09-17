# CI

Six jobs, all required on `main` and on every pull request.

| job | what it enforces |
|---|---|
| **secret scan** | `scripts/secret-scan.mjs --history`, over every commit and every file rather than the tip alone. Commit author metadata is checked as well |
| **lint** | syntax, encoding, line endings, whitespace, line length, no `console` in `reference/`, no unfinished markers, no dependencies in `package.json` |
| **documentation links** | every relative link and heading anchor resolves, and every file referenced by the documentation exists |
| **tests** | the suite on Node 18, 20 and 22 |
| **worked examples** | the valid receipt must exit `2` (`PENDING`) and the tampered one `1` (`ALTERED`). A verifier that started reporting `VERIFIED` for an unanchored record would pass the unit tests and fail here |
| **dependency audit** | the package has no dependencies; the job exists so that adding one is audited from the first commit |

The secret scan also runs on a weekly schedule, so a tree that passed at merge is rechecked
against current rules.
