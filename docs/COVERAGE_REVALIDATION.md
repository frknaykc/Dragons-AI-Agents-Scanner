# Coverage checkpoint and finding provenance validation

Date: 2026-10-28. Sanitized results only; private artifacts and raw scan output are not included.

## Checkpoint and CI

Coverage checkpoint: [`75cddea01aeebaca1f35e1496f6770fa362da6b2`](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/commit/75cddea01aeebaca1f35e1496f6770fa362da6b2), pushed normally to `main`.
[Exact-SHA CI](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/40693099648) completed successfully. Its Ubuntu full-suite log reports **1,611 passed, 1 skipped**, followed by successful format, lint, typing and benchmark gates. The skipped test is not counted as passed. The quiet log does not name the skipped case; no Windows execution is claimed.

| Validation run | Collected / accounted | Executed, excluding skips | Passed | Failed | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| M1 local safe static selection | 991 | 991 | 991 | 0 | 0 | 0 |
| M1 local coverage selection | 176 | 176 | 176 | 0 | 0 | 0 |
| Checkpoint full CI suite | 1,612 | 1,611 | 1,611 | 0 | 1 | 0 |
| M3 local safe static selection | 991 | 991 | 991 | 0 | 0 | 0 |
| M3 local coverage/provenance selection | 218 | 218 | 218 | 0 | 0 | 0 |

Local collection counts come from the audit runner. CI's 1,612 accounted cases are the 1,611 pass and one skip outcomes, also checked against its progress markers; the quiet log has no separate collection header. Files excluded before local collection are not pytest-deselected or skipped cases. Local selections are separate runs, not a full-suite claim. M3 was not committed, pushed or tested by hosted CI.

The earlier **171 → 176** discrepancy is four oversized-token wrapper regressions plus the nearmax performance-harness regression. M3 adds **42** provenance, classification and whitespace-padding cases to that 176-case selection. The nine whitespace cases cover beginning/middle/end at approximately 4 KiB, 64 KiB and 1 MiB. Existing coverage tests retain the 10/64/65/165/1,000-skill matrix and the Unicode, HTML-comment, Base64 and hex matrices described in [the coverage validation](SCAN_COVERAGE_VALIDATION.md).

## Approved real-agent scope

Both the checkpoint scanner and the M3 working tree scanned only the previously approved Cline, Codex, Claude Code and Cursor artifacts and the active Hermes profile. Credential stores, `.env`, histories, other profiles and out-of-scope symlinks remained excluded. No artifact code, skill command or MCP server was executed; semantic AI, OSV, remote acquisition and network enrichment were disabled.

| Agent | Supported candidates | Discovered | Attempted | Parsed | Fully analyzed | Partial | Failed / skipped | Findings | Status |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Cline | 1 | 1 | 1 | 1 | 1 | 0 | 0 / 0 | 0 | COMPLETE |
| Codex | 28 | 28 | 28 | 28 | 28 | 0 | 0 / 0 | 2 | COMPLETE |
| Claude Code | 22 | 22 | 22 | 22 | 22 | 0 | 0 / 0 | 1 | COMPLETE |
| Cursor | 1 | 1 | 1 | 1 | 1 | 0 | 0 / 0 | 1 | COMPLETE |
| Hermes | 169 | 169 | 169 | 169 | 0 | 169 | 0 / 0 | 3 | PARTIAL |
| **Total** | **221** | **221** | **221** | **221** | **52** | **169** | **0 / 0** | **7** | **PARTIAL** |

These aggregate counts agree before and after M3. No supported candidate was left unselected. The Hermes inventory separately excluded 34 symlink file entries; those are not admitted supported candidates or silently skipped analysis attempts.

Hermes still has **165 supported skill candidates**. All 165 now reach parsing and local analysis, compared with the historical 64; the former 101 cap-related omissions are gone. Together with config, SOUL and two memory artifacts, Hermes has 169 selected artifacts rather than 68.

The historical total was 120 artifacts and six findings. The current seven comprise six MEDIUM findings and one HIGH `DRAGON-PI-002`; no new finding ID was introduced. That additional finding is already present with the checkpoint scanner, before the M3 location fixes. Its artifact is at position 128 in the current skill ordering. This observation is not a true-positive adjudication or proof of compromise.

Codex and Claude changed from historical PARTIAL to COMPLETE. No evasion-budget diagnostic remains in these five current scans. Codex consumed 517 evasion source regions, Claude 483 and Hermes 2,954. The inert long-document tests separately establish that late directives remain reachable; successful parsing alone is not treated as complete analysis.

Hermes retains **two `duplicate dependency definitions` diagnostics**, not evasion-budget failures. The existing cross-artifact accounting conservatively changes all parsed artifacts to partial when that stage reports a diagnostic. Thus `fully_analyzed: 0` does not mean zero local analysis: all 169 were parsed and processed, but complete cross-artifact analysis is not certified. This coarse accounting is documented rather than silently redesigned during the provenance milestone.

## Finding accuracy

- **SC-003:** runtime dependency extraction previously reused the block's opening line. It now adds the newline offset before the actual package-command match, preserving unknown locations. Both real instances moved from line 87 to line 99. The finding ID, severity, confidence, classification, evidence and source/sink fields did not change.
- **Cursor MCP-001:** the JSON parser reuses the bounded JSONC source-position composer without constructing YAML values. The real finding now has declaration line 3 instead of an unknown line. Duplicate strings and escaped keys do not determine location. Valid inputs outside the optional mapper's syntax/resource budget retain `None`; literal Unicode line separators also retain unknown JSON/JSONC positions rather than using incompatible YAML line semantics.
- **Hermes SOUL:** installed and direct discovery now agree on `soul` plus `Hermes Agent` in recognized locations. Unrelated SOUL files remain generic, and symlink file/ancestor tests retain containment protections.
- **Graph references:** `DAAS-002` now retains the existing MCP server source location. This keeps its atom-to-path references valid after JSON locations become available. Multi-server regression coverage checks that the correct server supplies the location; no graph inference was broadened.
- **Context and reporting:** command, multiline-command, frontmatter, documentation, quoted/code-block and pinned-package cases passed. CLI, TUI, JSON and SARIF agree on supported locations. Existing graph/PATH/FLOW and redaction regressions passed. No duplicate finding appeared in either real scan.
- **Real finding comparison:** the checkpoint and M3 reports have identical finding keys and unchanged severity, confidence, classification, evidence and source/sink fields. Only the two SC-003 locations and Cursor MCP-001 location changed. Existing MCP configuration, runtime-package and credential-access findings remain static observations, not proof of execution, compromise or exfiltration.

## Privacy and integrity

Raw reports remain outside the repository in a directory with mode `0700`; report files have mode `0600`. Before/after file identity, size, modification-time, mode and SHA-256 checks agree for the selected user artifacts. Those fingerprints also agree between the checkpoint and M3 scans. Repository status was unchanged by each real scan. The audit guard prohibited writes outside the private output area; no blocked process/network attempt occurred.

A local in-memory check found one credential-shaped value in the approved config scope and verified that it was absent from JSON, terminal and SARIF outputs. Agents with zero matched candidates do not constitute a credential-redaction test. Synthetic regression coverage separately exercises redaction. No credential value, endpoint value, memory content or personal instruction is published here. Audit hooks are Python tripwires for reviewed trusted code, not an OS sandbox.

## Final quality gates

- **Pytest:** 991 safe static cases passed; the separate 218-case coverage/provenance selection passed. Process/provider/acquisition integration and the unfinished YARA-X PoC were excluded before local execution, not globally skipped or weakened.
- **Ruff:** lint passed; format check passed for 343 files, excluding private semantic results.
- **mypy:** `src scripts` passed for 63 source files. `git diff --check` passed.
- **Inventory:** all **48 finding IDs** remain.
- **Frozen integrity:** all **222** main benchmark input hashes match M1, plus all **15** separately checked Phase 2 v2 files. No frozen input or expectation changed.

| Deterministic corpus | TP | FP | FN |
| --- | ---: | ---: | ---: |
| Development | 50 | 0 | 0 |
| Realworld pilot fixtures | 4 | 0 | 0 |
| Negative-only holdout | 0 | 0 | 0 |
| Phase 1 | 16 | 0 | 0 |
| Phase 2 original | 8 | 0 | 1 |
| Phase 2 v2 | 8 | 0 | 0 |
| Interpreter | 4 | 0 | 0 |
| Phase 3 | 14 | 0 | 0 |
| Phase 6 original | 19 | 2 | 3 |
| Phase 6 v2 | 21 | 0 | 3 |

The holdout has no positive examples; recall is not applicable. Original Phase 2/6 misses and original Phase 6 false positives remain unresolved. Fixture performance is not a production-accuracy estimate.

## Repository boundary and remaining limits

The checkpoint contains 29 scoped files: coverage pipeline modules, performance harness, coverage/regression tests and their documentation. Its exact manifest is available in the linked commit. Root `AGENTS.md`, the pre-existing frozen-case documentation hunk, benchmark revisions, private outputs, Phase 2 local tests and unfinished YARA-X work were excluded from that checkpoint.

Uncommitted M3 scope:

- `src/dragonscan/dependencies.py`
- `src/dragonscan/structured_parser.py`
- `src/dragonscan/installed_agents.py`
- `src/dragonscan/rules.py`
- `tests/test_finding_provenance.py` (new)
- `tests/test_mcp_deep_security.py`
- `docs/FINDINGS_AND_REPORTS.md`
- `docs/COVERAGE_REVALIDATION.md` (this report)

Existing user/private files remain untouched, including `AGENTS.md`, `benchmarks/README.md`, the pre-existing `docs/REFERENCE.md` hunk, private semantic/historical results and local benchmark/PoC trees. `pyproject.toml` and `uv.lock` are unchanged. No dependency was installed, no M3 commit/push was made, and no tag/release was created.

Unsupported names/formats, alternate installation layouts and excluded private files are not covered. Loader size, parser complexity, traversal, decoder, signature and graph budgets still apply; they can produce partial or failed results. JSON position composition adds bounded parser work, and not every valid JSON syntax has an exact location. Artifact/finding/report collections still grow with scope: the pipeline has no constant whole-process memory guarantee. The existing single-run synthetic timing/RSS observations remain in the earlier coverage report; no new throughput guarantee is claimed.

The Research-Driven Detection Updates milestone was not started.
