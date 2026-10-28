# Scan coverage validation

Date: 2026-10-28. Local working-tree validation; not a release or a real-install rescan.

This change improves the existing discovery → loading → parsing → detection → evasion → reporting pipeline. It adds no detection engine, finding ID, runtime dependency, concurrency, network access or artifact execution. `IDEA.md` remains a product vision, not a feature inventory.

## Root causes and limit audit

Source locations below refer to this revision; named functions/constants remain the primary anchors.

| Stage / source | Previous coverage loss | Current behavior and retained boundary |
| --- | --- | --- |
| Installed discovery — `src/dragonscan/installed_agents.py:734`, `discovery.py:196` | Hermes stopped at 64 artifacts; installed discovery also had cumulative entry and 256-artifact defaults. | No default cumulative artifact/entry quota. Deterministic active-first depth-first traversal, deduplication and agent-specific classification remain. Explicit user budgets still produce partial diagnostics. Known config extras count against explicit per-root budgets. |
| Local/project discovery — `src/dragonscan/discovery.py:121` | Ordinary directories had a 10,000-artifact ceiling; installed-project traversal had cumulative 8,192-entry/256-artifact ceilings. | No default total-artifact cap. Local explicit artifact-budget overflow raises `DiscoveryError`. Traversal failures preserve independently discovered artifacts when the scanner supplies a diagnostic collector. Direct callers without that collector fail closed. |
| Working traversal — `src/dragonscan/discovery.py:17`, `installed_agents.py:23` | Cumulative limits confused resource bounds with total collection size; filesystem-order prefixes could determine partial selections. | Per-directory entry buffers: installed roots 2,048, installed explicit projects 8,192, ordinary directories 100,000. Pending directories: 8,192. Depth: installed roots 4, Hermes 6, installed explicit projects 8, ordinary directories 64. An oversized directory is omitted as a unit with a diagnostic, not sampled in filesystem order. Explicit root entry budgets remain cumulative. |
| Loading — `src/dragonscan/loading.py:7` | Documents exceeding the supported loader size are rejected. This is intentional, not an evasion-region bug. | 1 MiB regular-file cap remains. Symlink rejection, file identity checks and bounded reads remain. Failure increments `failed`, not `parsed`; no successful analysis is claimed. |
| Markdown parsing — `src/dragonscan/markdown_parser.py:32` | Very complex supported-size documents can exceed parser capacity. | 40,000-token/complexity checks remain; parse failures are reported. No new Markdown chunking or reparsing is introduced. |
| Structured parsing — `src/dragonscan/structured_parser.py:43`, `jsonc.py:8`, `mcp_normalization.py:116` | Structured complexity and metadata-list budgets can reject a document. | Depth 64 / 20,000 nodes, JSONC size/nesting checks, safe YAML and alias rejection remain; MCP metadata lists retain a 4,096-item limit. JSON/TOML complexity checks follow deserialization. Direct parser calls do not themselves enforce the loader byte cap. |
| MCP text — `src/dragonscan/mcp_normalization.py:150`, `mcp_security.py:76` | Descriptions/instructions and active metadata were silently clipped at 4,096 characters, hiding late directives or breaking rejection context. | Full loader/parser-bounded metadata reaches the existing detectors and graph logic. No severity/confidence or finding-ID change. Existing semantic recognizer bounds, including the rejected-quote pattern's 1,000-character bound, remain inherent detection limits. |
| Evasion — `src/dragonscan/evasion.py:414` | A 4 KiB source-region gate and artifact-wide region/view budgets prevented analysis of ordinary long content and later independent regions. | Scanner consumes `iter_views` sequentially. Parser regions stay intact; counters/queues reset per region. Long-region output cannot exceed source length; short regions retain the 4 KiB output bound. There are no overlapping text windows and thus no window-boundary deduplication problem. |
| Decoder safety / selection — `src/dragonscan/evasion.py:53`, `evasion.py:432` | Oversized tokens could miss the candidate predicate entirely and therefore evade the incomplete-coverage diagnostic. | Oversized Base64/hex-shaped candidates also reach the diagnostic path, even without action words and inside quotes/code/comments. They are not decoded or promoted to findings solely because of size. Individual encoded-token input/decoded limits remain 4 KiB; transform depth 3, per-region attempts 12 (with the additional 128-attempt guard), views 64 and expansion ratio 8 remain. |
| Runtime dependency extraction — `src/dragonscan/dependencies.py:595`, `parsing.py` | Runtime dependencies stopped at the existing cap without propagating the limit. | The 4,096-dependency cap remains; overflow now becomes a document diagnostic and partial analysis. Manifest/specifier limits still reject unsupported complexity. |
| Cross-artifact retention — `src/dragonscan/scanner.py:58`, `scanner.py:213` | Removing collection caps without a retention boundary would retain every full document for graph/correlation. | Retain at most 32 MiB of source text / 100,000 parsed context items. Continue every artifact's local analysis and MCP inventory after overflow; mark correlation/enrichment incomplete and conservatively mark parsed artifacts partial. These are retained-context estimates, not an exact RSS cap. |
| Graph/reference analysis — `src/dragonscan/attack_graph.py:26`, `flow.py:25`, `correlation.py:21`, `mcp_correlation.py:8` | Large or branching relationship sets can exceed graph/path budgets. | Existing limits remain: 50,000 nodes / 100,000 edges; flow depth 8, 256 paths, 32 per source/branch, 16,384 traversal states; 256 correlated MCP paths. Limit exceptions/diagnostics produce incomplete reporting. References are evidence within the selected scan boundary, not permission to fetch URLs, execute targets or expand into unrelated files. |
| Signature/intelligence analysis — `src/dragonscan/signatures.py:22`, `threat_intel.py:32`, `signature_packs.py:15` | Signature decoding/candidate/hit budgets are independent of evasion. | Existing decode 4 KiB / 32 attempts / depth 1 and 256-hit bounds remain, with limit diagnostics. Pack/feed size and record limits remain; no external pack or intelligence download is performed. |
| Acquisition — `src/dragonscan/target_acquisition.py:34` | Archives have separate safety budgets; removing directory caps must not bypass them. | Unchanged: input 32 MiB, 2,048 members, 8 MiB/member, 64 MiB total, depth 16 and path length 1,024, plus existing traversal/symlink checks. Acquisition failures retain their existing status. Acquisition/process integration tests were not run in the safe static selection. |
| Accounting — `src/dragonscan/scanner.py:137`, `policy.py:26`, `reporting.py:389`, `sarif.py`, `tui.py:1057` | Artifact/parse totals did not establish complete analysis; a budget-equal count could falsely imply exhaustion; empty supported analysis could look clean. | Explicit stage counters and real diagnostics determine coverage. Zero parsed artifacts are `failed`/`scan_error`; mixed success/failure is partial. TUI no longer infers exhaustion from equality with a budget. |

Symlink containment, regular-file validation, privacy exclusions, selected scope and supported-name classification are not relaxed. Unsupported names are not counted as successful supported analysis. No real home/profile scan was performed.

## Coverage contract

The additive JSON `coverage` object is also present at SARIF `runs[0].properties.coverage`. Terminal and TUI expose attempted, parsed, full, partial and failed analysis. Finding schemas/IDs and existing provenance fields remain intact.

- `discovered`: selected, deduplicated supported artifacts returned by discovery.
- `attempted`, `loaded`, `parsed`: actual pipeline transitions; parse success alone is not complete analysis.
- `fully_analyzed`, `partially_analyzed`: parsed artifacts classified by applicable stage diagnostics. Cross-artifact limitations conservatively mark all parsed artifacts partial.
- `failed`: load/parse failures, not unsupported names outside the selected input set.
- `skipped`: zero for the scanner's supplied artifact list, which is fully attempted. TUI path-kind filtering records its known exclusions and preserves the pre-filter discovered count. Unknown remainders behind discovery limits are diagnostics, not invented counts.
- `evasion_regions`, `evasion_views`: consumed source regions and emitted analysis views, not findings or text windows.

`COMPLETE` means no diagnosed limitation in the selected supported analysis, not proof of safety. `PARTIAL` means supported analysis occurred with a diagnosed gap. No meaningful supported analysis is `FAILED`. Incomplete/error exit code remains 3; severity gating remains 1 and successful policy evaluation 0.

## Discovery results and performance

Each case used a fresh local Darwin process and an isolated synthetic HOME/TMPDIR. Skills were created in reverse order, grouped into directories, then discovered in stable order. Separate tests check explicit-target/installed-root overlap loads each artifact once, unsupported files, symlink loops/escapes, unreadable subtrees, malformed input, explicit budgets, directory-buffer/frontier overflow and depth limits.

| Skills | Discovered | Attempted | Parsed / fully analyzed | Failed / skipped | Scan seconds | Peak process RSS MiB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 10 | 10 | 10 / 10 | 0 / 0 | 0.004909 | 36.406 |
| 64 | 64 | 64 | 64 / 64 | 0 / 0 | 0.024679 | 38.594 |
| 65 | 65 | 65 | 65 / 65 | 0 / 0 | 0.025503 | 38.500 |
| 165 | 165 | 165 | 165 / 165 | 0 / 0 | 0.062030 | 39.047 |
| 1,000 | 1,000 | 1,000 | 1,000 / 1,000 | 0 / 0 | 0.369378 | 42.438 |

All five synthetic scans are complete with zero findings, errors or diagnostics. Their ordinary text has zero eligible evasion regions/views. Processing is sequential per artifact; no concurrent workers, text windows or explicit batch counter were added. A separate discovery regression verifies 10,001 ordinary-project artifacts and 1,000 installed-project artifacts; it is not a 10,001-artifact full-analysis performance claim.

For comparison, the isolated pre-change HEAD snapshot (`3dadb8d07f7a70739397b3e0b69606d8b7abf12c`) processed only 64 of 165 skills: 0.026811 seconds, 40.438 MiB, partial. At 64 skills it took 0.024366 seconds, 40.297 MiB. The higher new 165-skill elapsed time includes the previously omitted 101 skills.

## Long documents and evasion

The inert regression matrix covers approximately 4 KiB, 64 KiB and 1 MiB documents, each with beginning/middle/end Unicode-hidden, HTML-comment, Base64 and hex directives: 36 combinations. Additional tests cover former boundaries at offsets 4,094/4,095/4,096 and 65,534/65,535/65,536; 165 independent regions; original line 1,001; negation/documentation/quotes/code; benign Unicode/comments; oversized loads; decoder limits; late MCP metadata, graph provenance and redacted reports.

| Fixture | Findings | Coverage | Regions / views | Scan seconds | Peak process RSS MiB |
| --- | --- | --- | ---: | ---: | ---: |
| ~4 KiB, Unicode-hidden directive at end | One `DRAGON-PI-001` | Complete | 1 / 1 | 0.005386 | 34.234 |
| ~64 KiB, same directive at end | One `DRAGON-PI-001` | Complete | 1 / 1 | 0.070180 | 35.906 |
| ~1 MiB, same directive at end | One `DRAGON-PI-001` | Complete | 1 / 1 | 1.184337 | 67.531 |
| ~1 MiB ordinary benign text | None | Complete | 0 / 0 | 0.303188 | 51.391 |

The same ~1 MiB Unicode fixture on the isolated pre-change snapshot took 0.269849 seconds / 55.359 MiB, produced no finding and incorrectly reported complete. The new result is slower and uses more memory because the late directive now reaches normalization/detection. These are single-run observations, not statistical throughput guarantees or real-world accuracy estimates. Scan timing excludes fixture creation; RSS includes interpreter imports/setup and is a process high-water mark.

A near-1 MiB single encoded-shaped token remains partial, without being decoded or treated as malicious by size. Its performance-harness expectation now names the encoded-token diagnostic, rather than the removed source-region diagnostic. Four new bare/quoted/fenced/comment oversized-token regressions failed before the candidate-selection correction and pass afterward. Decoder-depth, expansion and transform budgets remain failure-reporting boundaries, not targets to raise for a complete label.

## Verification

Final behavioral validation after the oversized-candidate correction:

- Reviewed safe static selection: **991 passed**, 42.39 seconds.
- Discovery/installed-agent/long-document/MCP coverage plus the nearmax harness regression: **176 passed**, 24.82 seconds; disjoint from the static selection.
- No skipped tests in these two selections. They are **not the full repository suite**. Process/network integration, dynamic MCP, semantic/provider suites, acquisition integration, packaging and YARA-X workers were excluded before execution, not globally disabled or marked xfail.
- Audit event guards: 14 self-checks in the static/benchmark runners; zero blocked test/measurement attempts. These are Python tripwires for reviewed trusted tests, **not an OS sandbox**. The benchmark evaluator permits only exact `git rev-parse HEAD` subprocess calls for metadata, never artifact commands.
- Ruff lint passed; Ruff format check passed for 341 files; `mypy src scripts` passed for 63 source files; `git diff --check` passed. Existing environment used; no dependency installation.
- Inventory: **48 finding IDs**. The deterministic benchmark runner checked **222 input hashes** before/after; frozen expectations were not edited. Phase 2 v2 was checked separately with its own input hashes.

| Corpus | TP | FP | FN |
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

The holdout has no positive cases; recall is not applicable. Existing Phase 2/6 misses and original Phase 6 false positives remain visible. No unexpected new false positives were observed in the executed fixtures; this does not establish accuracy on untested inputs.

## Remaining limitations and repository scope

- Discovery directory/frontier/depth budgets, the 1 MiB loader, parser complexity, decoder, signature and graph limits can still produce partial/failed coverage. Files behind a traversal failure cannot be counted accurately without traversing them.
- Artifact identities, findings, diagnostics and report output grow with collection size. Bounded working buffers and retained context do not provide constant total memory or a hard whole-process RSS ceiling. Very large scans may use explicit budgets; streaming result storage is not introduced here.
- Long MCP metadata is revisited by several detector/graph passes; CPU work grows with input size. The 1,000-character rejected-quote recognizer and other documented detector semantics are not broadened by this task.
- Platform-specific Windows behavior and process/acquisition/network integration were not revalidated by this macOS static-only run. Earlier CI results are historical, not evidence for this working tree.
- Previous real-install counts (120 parsed artifacts, Hermes 64/165 candidates) remain historical. This task does not update them or claim improved real-world detection accuracy.

Task changes: `src/dragonscan/{discovery,installed_agents,evasion,scanner,models,policy,dependencies,parsing,mcp_normalization,mcp_security,reporting,sarif,tui}.py`; `scripts/performance_baseline.py`; new `tests/test_{complete_coverage,discovery_coverage,mcp_coverage}.py`; affected `tests/test_{evasion,installed_agents,sarif,scanner,tui}.py`; `docs/{REFERENCE,CLI_GUIDE,FINDINGS_AND_REPORTS,AGENT_COVERAGE_REVIEW,SCAN_COVERAGE_VALIDATION}.md`. Existing overlapping evasion/scanner work is preserved.

Pre-existing root `AGENTS.md`, Markdown/hidden-instruction/Phase 2 revision work, benchmark revisions and other untracked user work were not reset or deleted. `benchmarks/semantic/results/` was neither read nor changed. `pyproject.toml` and `uv.lock` were not changed. Local raw verification logs, fixture trees and measurements remain outside the repository; no real configuration content, credentials or private paths are published in this document. No commit, push, tag, release or package publication was performed.
