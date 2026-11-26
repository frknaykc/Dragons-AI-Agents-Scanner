# Detection accuracy review

Review date: 2026-11-06. These changes remain uncommitted and unreleased. They do not alter the published v0.1.0 artifacts.

## Checkpoint

The earlier five-file detection change is checkpointed at `4412435e92384c2380e77540d86dd5efb95b4659`. It was committed in an isolated worktree based on remote main and pushed normally. [GitHub CI run 42179026087](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/42179026087) completed successfully for that exact SHA. That CI result does **not** cover the subsequent working-tree changes described here.

## Execution contract

Remote-execution findings require a supported literal HTTP(S) fetch whose stdout becomes interpreter program input. The same shell recognizer now serves prose, instructed fences, MCP command metadata, and execution graph relationships.

- Supported shell stdin forms: `sh`, `bash`, or `zsh`, with no arguments, `-s`, or `-s --`.
- Supported Python stdin forms retain the existing no-argument, `-`, `-u`, and `-u -` contract.
- `curl` must write to stdout; `wget` needs a supported explicit stdout option such as `-qO-`.
- A script operand, interpreter command string, output-file download, ambiguous flags, or unsupported shell syntax does not establish this source-to-sink relationship.
- The supported command-string flags are `-c`, `-lc`, and the explicitly approved equivalent `-cl`. Generic shell-mediated MCP execution remains distinct from proven remote-code execution.
- Prose can contain an explicit `, then run ...` clause. Interpreter operands are not discarded as conversational wording. For example, `sh now` specifies a script operand, not program stdin.
- Instructed fences retain direct findings and locations; this change does not invent fenced cross-file graph edges. Derived evasion evidence likewise does not establish execution graph edges.

All 48 finding IDs remain available. Existing severity/confidence metadata and reporting schemas remain unchanged. Removing an unsupported remote-execution match can expose an existing lower-severity generic MCP finding; that is a different finding, not a severity change to the remote-execution rule.

## Confirmed defects and corrections

**SSH public-key false positives.** Private-key path patterns matched the basename prefix in `.pub` and `-cert.pub` paths. The relevant credential, shell-read/body and MCP metadata checks now exclude those suffixes. Tests cover RSA, Ed25519, ECDSA and DSA paths, public-key documentation/configuration, private-key reads, private content transfer, and mixed public/private references. This is a path distinction, not a general guarantee that a public-key-related document is safe.

**Shell source-to-sink false positives.** Broad fetch/pipe regexes treated file-writing downloads and interpreter script operands as program stdin. The shared bounded recognizer now rejects those relationships without suppressing applicable generic shell findings.

**Command flag inconsistency.** `-cl` now follows the supported `-c`/`-lc` paths in wrappers, MCP rules, encoded execution, generic shell detection and graph construction. Positive and hard-negative cases compare IDs, severity/confidence, source/sink and graph edge kinds.

**Regression handling.** Strict validation exposed a derived PowerShell view that still included its original encoded-command wrapper. A whole literal encoded command now yields its decoded command as the analysis view, with original evidence provenance. Printed data, extra operands and non-stdin decoded commands have negative coverage. Literal adjacent shell quotes may already resolve in the direct tokenizer, so their unit test no longer requires redundant evasion evidence. The terminal escaping test supplies hostile evidence directly rather than depending on an invalid interpreter token being treated as executable.

## Frozen Phase 6 v2 cases

No fixture, manifest expectation or frozen ground truth was changed. Separate inert counterfactuals isolate the causes below.

| Case | Evidence and conclusion |
|---|---|
| `chain-structured-load` | Generic root `settings.json` is outside automatic directory discovery without a recognized ecosystem. The payload also ends with `bash before running diagnostics`, which supplies script operands. Removing only that suffix produces `DRAGON-EXEC-001`, but no load path. A separately generated recognized `.claude/settings.json` example produces both EXEC-001 and PATH-002. This is a discovery boundary plus ambiguous command syntax, not a missing generic detector. |
| `exec-network-python` | The fixture ends with `python3.12 before checking the report`. A separate command without those operands produces EXEC-002. The frozen expected source label is also `remote HTTP(S) content`, while the existing detector contract uses `remote HTTP(S) code source`; neither contract nor frozen expectation was changed. |
| `obf-literal-shell` | The fixture ends with `sh to complete initialization`. A separate literal decoder-to-shell command without those operands produces EXEC-003. No arbitrary decoder execution or prose-operand stripping was added. |

Strict stdin validation also rejects the trailing operands in `exec-shell-fetch` and `chain-local-load`, and removes the previous standalone shell match in `chain-structured-load`. The frozen metric therefore changes from **21 TP / 0 FP / 3 FN** to **17 TP / 0 FP / 7 FN**. Counts are expected-finding matches, not seven independent broken detectors. These mismatches remain visible; passing unit tests does not mean the frozen benchmark passes.

## Verification

- Initial accuracy RED: 50 failures and 53 passes, including 34 public-key failures and 16 shell source-to-sink failures. The flag-order extension also had a recorded failing run before implementation.
- Final full local suite: **2168 passed, 7 skipped**. The new accuracy module contributes **141 passing cases**.
- Process/network-guarded static selection: **1160 passed**, 14 audit self-checks, zero blocked attempts during tests. Audit hooks are tripwires, not an OS sandbox.
- Ruff formatting, Ruff lint, `mypy src scripts`, and `git diff --check` passed.
- The built-in inventory matches the checkpoint inventory: **48 IDs**.
- JSON/SARIF evidence and location assertions, graph/PATH/FLOW, MCP, evasion, CLI and headless TUI regressions passed. No new manual native-terminal visual acceptance was performed.

Selected deterministic results:

| Corpus | TP | FP | FN |
|---|---:|---:|---:|
| Phase 2 v2 | 8 | 0 | 0 |
| Interpreter | 4 | 0 | 0 |
| Phase 3 | 14 | 0 | 0 |
| Main corpus | 49 | 1 | 1 |
| Phase 6 v2 | 17 | 0 | 7 |

The main corpus retains an expected DAAS-002 for plain `wget URL | bash`. The scanner now reports MCP-004 instead, which the frozen expectations count as one FP and one FN. The unit test records that exact discrepancy rather than relabelling the corpus. Legacy Phase 2 remains 8/0/1 and legacy Phase 6 measures 15/2/7. Synthetic results do not establish general real-world accuracy.

## Safety and repository state

Tests used inert target text and controlled repository test fixtures. No real MCP server or scanned command was launched; semantic AI, OSV and other live intelligence services were not used. Benchmark runs used process/network audit tripwires. The full suite includes the separately authorized controlled fake-server integration tests; the guarded static selection excludes them.

The 97 baseline files outside the checkpoint-owned set and all 64 frozen Phase 2 v2 / Phase 6 v2 files retain their recorded hashes. This includes pre-existing user/private work; no private installed-agent configuration was inspected. No dependency, detection engine, release, tag, PyPI upload or additional commit/push was introduced. Local main was not reset or rebased to the checkpoint.

The development delta covers six scanner modules (`behavior`, `rules`, `detectors`, `mcp_security`, `attack_graph`, `evasion`), the new accuracy test module, four existing unit-test modules, and this review/link. The original user changes remain separate.

## Follow-up priorities

1. Define any desired natural-language command-boundary support separately, with hard negatives for genuine script operands. Keep the frozen mismatches until a reviewed contract justifies a change.
2. Specify ecosystem-aware structured configuration discovery and load-reference behavior before expanding generic filename coverage.
3. Extend independent holdout evidence for interpreter/source options and metadata contexts; review these uncommitted changes before another checkpoint.
