# CI

Six jobs, all required on `main` and on every pull request.

| job | what it enforces |
|---|---|
| **secret scan** | `scripts/secret-scan.mjs --history`, over every commit and every file, not just the tip. Also checks commit author metadata, because an author line identifies a person as readily as file content does |
| **lint** | syntax, encoding, line endings, whitespace, line length, no `console` in `reference/`, no unfinished markers, no dependencies in `package.json` |
| **documentation links** | every relative link and heading anchor resolves, and every file the documentation promises exists. A README pointing at a file nobody wrote is worse than a README that says less |
| **tests** | the suite on Node 18, 20 and 22 |
| **worked examples** | the valid receipt must exit `2` (`PENDING`) and the tampered one `1` (`ALTERED`). A verifier that started reporting `VERIFIED` for an unanchored record would pass the unit tests and fail here |
| **dependency audit** | this package has no dependencies by design, so this exists to catch the day that changes |

The secret scan also runs weekly on a schedule: a tree that was clean on merge is not clean
forever.
