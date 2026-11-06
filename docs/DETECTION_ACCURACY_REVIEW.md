# Detection accuracy checkpoint

This source-only follow-up builds on checkpoint `4412435e92384c2380e77540d86dd5efb95b4659`. It does not change the published v0.1.0 release. Detection accuracy and software-quality gates are separate results; neither passing unit tests nor an explained disagreement changes frozen ground truth.

## Reviewed changes

- SSH public-key and certificate paths are excluded from private-key evidence across prose, shell evidence, MCP signals and legacy rules. Genuine private-key reads and linked transfers remain detectable.
- `DRAGON-EXEC-001`, MCP `DAAS-002`, and related graph edges use the same bounded HTTP stdout-to-shell-stdin recognition. A suspicious command alone is not evidence that downloaded bytes execute.
- Literal shell wrappers and MCP command flags recognize `-c`, `-lc` and `-cl` in their supported positions. General shell argument parsing is not implemented.
- Supported `wget -O -` routing binds the immediate operand before removing the source URL, regardless of supported option order. Download-to-file and a URL used as the output operand are rejected.
- Literal encoded payloads piped through a supported decoder into `zsh -s` or `zsh -s --` use the same stdin contract as other supported shells.
- POSIX MCP command-string inspection reads the argument following the recognized command flag, not trailing `$0`/positional arguments. Those arguments cannot independently establish control operators or encoded execution.
- A whole literal PowerShell encoded-command instruction retains its executable context in the bounded evasion view. Printed payloads, trailing operands and invalid stdin relationships do not gain remote-execution findings.

Explicitly instructed shell fences and private-key contents passed to a declared MCP tool argument were already included in the parent checkpoint. Their positive and hard-negative tests remain included. No new finding ID, severity/confidence definition, discovery expansion, external service or execution engine is introduced.

## Execution evidence contract

| Input | Required evidence / boundary |
| --- | --- |
| HTTP fetch to shell | One supported literal HTTP(S) source writing stdout, directly piped to a supported shell consuming program stdin. |
| HTTP fetch to Python | The same source evidence, with a supported Python stdin form; script operands, `-c` and `-m` do not qualify. |
| Literal encoding to interpreter | A bounded literal payload, supported decoder and unambiguous program-stdin sink. Decoded bytes are never executed. |
| Download-to-file / script operand | Does not prove execution of downloaded or decoded bytes. |
| Instructed shell fence | A parsed, active execution directive must bind to the supported shell fence. Findings retain command source lines; a fence alone does not establish cross-file execution edges. |
| MCP command metadata | Analyze the actual command string, not a trailing argument. General shell mediation (`DRAGON-MCP-004`) is distinct from proven remote stdin execution (`DAAS-002`). |
| Passive example, quotation or negation | Does not become an active execution instruction merely because it contains a command. |
| Unseparated trailing prose | May be a script operand. It is not silently discarded to increase recall. |

JSON/SARIF projections, redaction, source/sink binding and graph/PATH/FLOW limits remain covered by regression tests. These are static observations, not claims that a command actually ran.

## Frozen Phase 6 v2 disagreements

The parent checkpoint measured **21 TP / 0 FP / 3 FN**. The strict-contract follow-up measures **17 TP / 0 FP / 7 FN**. These are seven expected-finding mismatches across five cases, not seven confirmed detector defects.

### Discovery-scope mismatch (one, already present)

| Case | Missing expected ID | Reason |
| --- | --- | --- |
| `chain-structured-load` | `DRAGON-PATH-002` | Generic `settings.json` is outside recognized agent discovery. The loader reference is not discovered. In the follow-up, ambiguous execution in the child skill also independently prevents a proven execution path. |

### Ambiguous execution / ground-truth mismatches (six)

| Case | Missing expected ID | History and reason |
| --- | --- | --- |
| `exec-network-python` | `DRAGON-EXEC-002` | Already absent at the parent checkpoint. Unseparated words after Python may select a script instead of downloaded stdin. |
| `obf-literal-shell` | `DRAGON-EXEC-003` | Already absent at the parent checkpoint. Unseparated words after the shell may select a script instead of decoded stdin. |
| `chain-local-load` | `DRAGON-EXEC-001` | Newly absent under strict validation. The earlier prefix match accepted ambiguous trailing operands as execution. |
| `chain-local-load` | `DRAGON-PATH-002` | Newly absent because its required execution edge is no longer proven; a load relationship alone is insufficient. |
| `chain-structured-load` | `DRAGON-EXEC-001` | Newly absent under strict validation of the child skill's ambiguous trailing operands. Separate from the discovery-scope mismatch above. |
| `exec-shell-fetch` | `DRAGON-EXEC-001` | Newly absent under strict validation; trailing words are not assumed to be harmless commentary. |

The strict evaluator must still exit **1 / FAIL** for this set. Frozen fixtures, manifests, locks and expectations are not modified. Structured configuration discovery requires a separate ecosystem-specific review; no general `settings.json` discovery is added here.

The local Phase 2 v2 corpus measures **8 TP / 0 FP / 0 FN**. Its untracked fixtures/results are deliberately not added to this checkpoint. The committed original Phase 2 corpus remains **8 TP / 0 FP / 1 FN**. These sets must not be confused.

The existing development corpus also has a known strict-gate disagreement: **49 TP / 1 FP / 1 FN**. Its `mcp-poisoning` case expects `DAAS-002` for plain `wget`, which writes to a file rather than stdout. The follow-up reports generic shell mediation (`DRAGON-MCP-004`), producing the extra/missing-ID pair under the frozen labels. The existing `benchmark_gate.py` remains unchanged and fails. No broader production accuracy claim follows from these synthetic sets.

## Validation and scope

Pre-commit validation of the isolated source on native macOS Apple Silicon with Python 3.12.12: **2257 passed, 1 skipped**; Ruff format/lint, `mypy src scripts` and `git diff --check` passed. This is the complete suite for the scoped checkout, not the larger user's working tree with unrelated local packaging and experimental tests. Ten deterministic benchmark sets (including the external local-only Phase 2 v2 set) were measured twice with identical summaries. Both the Phase 6 v2 strict evaluator and the existing corpus gate returned **1 / FAIL**, as documented above.

`tests/test_detection_accuracy.py` and `tests/test_execution_stdin_regressions.py` supply independent inert positives and hard negatives; they do not execute target commands or start target MCP servers. The full repository suite additionally uses controlled repository-owned fake MCP subprocesses. No live Semantic AI/OSV service or real user agent configuration is used.

The test-only `detection-checkpoint.yml` workflow validates the same event SHA on Linux x86-64, Windows x86-64, macOS Intel and macOS Apple Silicon. It checks the native architecture, full tests, Ruff, mypy and the 48-ID inventory. Strict accuracy jobs remain visibly failed; they use neither `continue-on-error` nor replacement expectations. Consequently the overall workflow can be red even when all independent source-quality/native-test jobs pass. Existing quality/release workflows are unchanged. No standalone executable is built or uploaded by this workflow.

The checkpoint excludes root `AGENTS.md`, private semantic results, frozen benchmark material, local outputs, experimental YARA-X work and unrelated packaging/release edits. Headless TUI tests are automated acceptance, not manual visual review. Exact-SHA CI results must be inspected before declaring the checkpoint ready for main-integration approval.
