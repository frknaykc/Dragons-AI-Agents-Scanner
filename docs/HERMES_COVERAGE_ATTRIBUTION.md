# Hermes coverage attribution validation

Date: 2026-10-28. Sanitized local results; no private paths, dependency names,
configuration values or artifact excerpts appear in this report.

## Finding accuracy checkpoint

M3 checkpoint: `f40272920b879f7a7a7a9a5858d922a76371f051`.
The first CI run exposed a regression in the pinned-package/explicit-tool
vulnerability relationship. The correction preserves the MCP parser's complete
`SourceRef`, rather than only its line, in runtime dependency extraction.

Corrected checkpoint: **`05a4680b366bde78b4a70cdde7d558cc1bcf5f4f`**.
[Exact-SHA CI run 40745781378](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/40745781378)
passed with **1,656 passed, 1 skipped** plus format, lint, typing and benchmark
checks. This is the completed Milestone 1 gate; the first failed run is not a
successful checkpoint. The hosted suite ran on Ubuntu, not Windows.

The M3 commit contains `dependencies.py`, `structured_parser.py`,
`installed_agents.py`, `rules.py`, `test_finding_provenance.py`,
`test_mcp_deep_security.py`, `FINDINGS_AND_REPORTS.md` and
`COVERAGE_REVALIDATION.md` in their existing source/test/documentation directories.
The corrective commit changes only `dependencies.py` and
`test_finding_provenance.py`. Both were pushed normally to `main`.
Root `AGENTS.md`, unrelated benchmark/documentation revisions, private results
and unfinished YARA-X work were excluded. No release or tag was created.

## Cause and scope

1. `supply_chain.analyze` groups duplicate declarations by ecosystem, package name
   and dependency group within each document, excluding lockfile provenance.
   It emits one duplicate diagnostic for that document and skips the affected
   dependency checks. Equal versions do not bypass that skip. Identical package
   names in separate documents do not alone form a duplicate group.
2. The previous interface returned diagnostic strings. `Scanner.scan` wrapped
   them as warnings without a machine-readable artifact scope.
3. After dependency, graph and flow analysis, any new cross-stage diagnostic
   moved the entire fully-analyzed count to partial. Two local warnings could
   therefore turn 169 fully processed artifacts into 169 partial artifacts.
4. Dependency normalization, other dependency checks and graph/flow processing
   continue. The duplicate branch does not delete dependencies or graph edges.
   The gap concerns the skipped supply-chain checks, not unread artifact bytes.

The fix adds optional `artifact` and conservative `incomplete=True` fields to
`Diagnostic`. Duplicate and manifest/lockfile-conflict diagnostics identify the
artifact whose dependency checks were skipped. Scanner accounting intersects
those paths with the set of locally complete artifacts, preventing double
counting. Unscoped cross-stage gaps and retained-context limits still affect the
whole parsed scope. Parser/decoder limits and failed artifacts keep their
existing meaning.

Policy checks `incomplete`, rather than diagnostic presence alone. An explicitly
non-blocking warning stays visible without claiming skipped analysis. No existing
warning producer was downgraded. JSON and SARIF expose the new diagnostic fields;
CLI/TUI retain the existing layout and shared policy/counters. See the
[diagnostic contract](FINDINGS_AND_REPORTS.md#diagnostic-scope).

## Hermes-only revalidation

Only the active profile's `config.yaml`, `SOUL.md`, supported artifacts under
`skills/` and `memories/` were scanned. Other profiles, histories, authentication
stores, `.env` files and unrelated directories were excluded. No artifact command
or MCP server ran; semantic AI, OSV and network enrichment stayed disabled.

| Metric | Previous | Current |
| --- | ---: | ---: |
| Supported artifacts | 169 | 169 |
| Supported skill candidates | 165 | 165 |
| Discovered / attempted / loaded / parsed | 169 / 169 / 169 / 169 | 169 / 169 / 169 / 169 |
| Fully analyzed | 0 | 167 |
| Partially analyzed | 169 | 2 |
| Failed / skipped artifacts | 0 / 0 | 0 / 0 |
| Findings | 3 | 3 |
| Duplicate dependency warnings | 2 | 2 |
| Scan status | PARTIAL | PARTIAL |

The current affected set contains **two distinct skill artifacts**, with **two
within-document duplicate groups and four skipped dependency records**. This
count comes from the diagnostic artifact set and the actual duplicate grouping,
not from assuming that warning count equals artifact count. There were no
unscoped incomplete diagnostics or unselected supported candidates. The inventory
excluded 34 symlink file entries before admitting candidates.

A second static pass on the same inputs replaced only diagnostic artifact scope
with `None` to reproduce the legacy accounting: 0 full and 169 partial.
Findings, including their evidence/location fields, and the complete graph were
identical between the scoped and legacy-attribution passes. This controlled
comparison isolates attribution; it is not a checkout of an older scanner.
The remaining two artifacts are genuinely partial under the unchanged duplicate
handling. The scan remains incomplete, with policy exit code 3.

Before/after identity, size, modification time, mode and SHA-256 checks matched
for the admitted artifacts. Raw reports stay outside Git in a `0700` directory
with `0600` report permissions. The Python audit guard recorded no blocked
process/network attempt; it is not an OS sandbox. The real Hermes pass found
zero credential-shaped redaction candidates, so it does not independently prove
credential redaction. Existing inert redaction regressions provide that coverage.

## Verification

| Run | Collected / accounted | Passed | Failed | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: |
| M1 safe static selection | 991 | 991 | 0 | 0 | 0 |
| M1 corrected focused selection | 241 | 241 | 0 | 0 | 0 |
| M1 hosted full suite | 1,657 | 1,656 | 0 | 1 | 0 |
| M2 safe static selection | 991 | 991 | 0 | 0 | 0 |
| M2 focused coverage/provenance selection | 257 | 257 | 0 | 0 | 0 |

These are separate runs, not additive full-suite claims. The 257-case selection
includes **16 new attribution cases**. Local process/provider/acquisition
integration and unfinished YARA-X tests were excluded before collection, not
counted as pytest skips or deselections. The hosted skip is not a pass.

The safe static selection covers dependency/supply-chain, scanner, graph/PATH/FLOW,
CLI/TUI, SARIF, policy and redaction behavior. New tests cover agreeing and
conflicting duplicates, multiple affected documents/groups, unrelated documents,
manifest/lockfile conflicts, parser failure, decoder gaps, double-count prevention,
global graph failure, explicit non-blocking diagnostics, unchanged graph/findings,
and CLI/TUI/JSON/SARIF coverage and exit-code consistency.

Ruff lint and format checks passed (345 Python files, excluding private semantic
results). `mypy src scripts` passed for 63 source files. `git diff --check` passed.
The **48 finding IDs** are unchanged. All **222 main benchmark inputs** and
**15 Phase 2 v2 files** retain the checkpoint hashes; frozen expectations were
not edited.

| Deterministic corpus | TP | FP | FN |
| --- | ---: | ---: | ---: |
| Development | 50 | 0 | 0 |
| Realworld pilot | 4 | 0 | 0 |
| Negative-only holdout | 0 | 0 | 0 |
| Phase 1 | 16 | 0 | 0 |
| Phase 2 original | 8 | 0 | 1 |
| Phase 2 v2 | 8 | 0 | 0 |
| Interpreter | 4 | 0 | 0 |
| Phase 3 | 14 | 0 | 0 |
| Phase 6 original | 19 | 2 | 3 |
| Phase 6 v2 | 21 | 0 | 3 |

Recall is not applicable to the negative-only holdout. Phase 6 v2's three false
negatives remain unresolved; fixture results are not a production accuracy claim.
No rule, finding ID, severity/confidence contract, dependency or safety limit was
changed. At the time of this validation, Milestone 2 was **uncommitted** for
checkpoint review and had no hosted-CI claim. These are historical validation
results, not the CI status of a later checkpoint. Existing unrelated/private
work remained outside its scope; research-driven detection updates had not started.
