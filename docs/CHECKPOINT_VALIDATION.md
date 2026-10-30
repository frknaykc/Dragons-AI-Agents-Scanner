# Current-fix checkpoint validation

Validation date: 2026-10-30. Base checkpoint:
`f00a718be57e83c0349815f9d432d85d3a0160b6`.

## Scope

This checkpoint contains the malformed MCP discriminator repair, BSD/macOS
`base64 -D` recognition in the existing `DRAGON-EXEC-003` path, their regression
tests and documentation. It does not add shared-user skill discovery or an
OpenClaw adapter. CLI/TUI source and appearance are unchanged.

The MCP tests cover four adapters, local/remote forms, invalid containers and
scalars, unrelated metadata, controlled incomplete-analysis diagnostics and
continued analysis of a valid sibling instruction. The decoder tests retain
positive source locations and redacted evidence, and reject passive quotes,
documentation, negations, invalid literals and disconnected interpreter inputs.

## Local verification

- Reviewed parser/decoder/attribution selection: **238 passed**.
- Existing guarded static selection: **830 passed**.
- TUI hover/selection matrix: **6 passed**. Each case visits both 120×40 and
  80×24 layouts; short and long target paths are each repeated three times.
  Both finding nodes and their detail text are asserted using the unchanged
  `test_results_tree_groups_shared_artifacts_and_updates_detail_on_selection`.
- Ruff check and format: passed; mypy `src scripts`: passed (65 source files).
- `git diff --check`: passed.
- Finding inventory: **48 IDs**. No finding ID, severity/confidence contract,
  runtime dependency, decoder limit or parser limit changed.
- Frozen benchmarks: development 50/0/0; pilot 4/0/0; negative holdout 0/0/0;
  Phase 1 16/0/0; Phase 2 original 8/0/1; Phase 2 v2 8/0/0; interpreter 4/0/0;
  Phase 3 14/0/0; Phase 6 original 19/2/3; Phase 6 v2 **21/0/3** (TP/FP/FN).
  Frozen input hashes were checked before/after the main benchmark evaluation.
  No input or expected result was edited.

Selections overlap and are not a full-suite result. Python audit tripwires
reject process/network activity in the local tests; benchmark metadata permits
only the exact Git HEAD lookup. These are not an OS sandbox. No target code,
MCP server or semantic provider runs. Private user-state reads are blocked.

The first scratch-matrix collection stopped at that private-read guard when
pytest searched parent directories for configuration. Configuration discovery
was then explicitly restricted to the fixture directory, with the repository's
pytest configuration selected explicitly. The guard was not relaxed. Only the
subsequent successful collection is counted above.

## Unresolved TUI observation

The previously reported intermittent hover failure was not reproduced in this
bounded matrix. No deterministic application defect has been established, and
no speculative UI correction or weakened assertion was introduced. The issue
remains **unresolved**, not fixed. Headless geometry/selection tests do not
replace manual cross-terminal visual validation.

Exact-SHA hosted CI is a separate checkpoint gate; local test selections above
must not be represented as hosted full-suite or cross-platform results.
