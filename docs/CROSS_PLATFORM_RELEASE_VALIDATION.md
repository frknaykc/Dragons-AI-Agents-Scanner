# Cross-platform release validation — 2026-10-30

## Revision and decision

**Release acceptance: FAIL. No tag, GitHub Release or PyPI publication was created.**

The development checkpoint is `848e677c129fc16dbf7d8788761840a6b49b2aee`; its [exact-SHA quality run](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/40989828405) succeeded. Shared skill discovery, documented OpenClaw defaults, MCP discriminator guards and the existing encoded-execution rule were checkpointed without new finding IDs or severity/confidence changes.

The subsequent validation-only commits are `e0f0d4f7ef630fb44816bb8381ffe3162a7385ab` and `9d59a05f05d3c422af862d57724e236da4c29bbb`. They add inert native validation and fix its Windows test-environment assumptions; they do not change scanner runtime code. These commits used `[skip ci]`: the earlier quality success must not be attributed to the later SHAs. The [latest exact-SHA native run](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/40992952727), on `9d59a05f05d3c422af862d57724e236da4c29bbb`, failed on Windows. Its other three jobs succeeded.

## Native matrix

Each job built the committed source, installed its wheel in an isolated runtime environment, and built and executed its native standalone binary. All runner environments used Python 3.12.12. No dirty-tree overlay was used.

| Platform / runner | Wheel install | CLI help / launch | TUI regressions | Inert scans | JSON / SARIF | Overall native gate |
| --- | --- | --- | --- | --- | --- | --- |
| macOS arm64 / `macos-15` | PASS | PASS | PASS | PASS | PASS | PASS |
| macOS x86-64 / `macos-15-intel` | PASS | PASS | PASS | PASS | PASS | PASS |
| Linux x86-64 / `ubuntu-24.04` | PASS | PASS | PASS | PASS | PASS | PASS |
| Windows x86-64 / `windows-2022` | PASS | PASS | FAIL | PASS | PASS | FAIL |

The installed-wheel selection contains 217 tests: each non-Windows job passed 217 with zero skips; Windows passed 214 and failed 3, with zero skips. This is a reviewed selection, **not a full-suite result**.

Wheel and binary acceptance each check 11 cases: help, unsupported version option, clean scan, encoded-execution finding, partial analysis, failed target, usage error, JSON export, SARIF export, shared Codex discovery and OpenClaw discovery. Checks include the existing `DRAGON-EXEC-003` ID, line, evidence, severity/confidence, and exit codes 0/1/2/3. The Windows job reached pytest only after these preceding assertions passed; its final summary/binary copy was not produced because the test gate failed.

`--version` is not implemented: its expected usage error is not a version-feature PASS. Package metadata identifies version 0.1.0. The README's local-checkout/uv installation route and `-tui` spelling remain accurate; no published-package installation is claimed.

### TUI scope

The native jobs test the installed wheel's headless Textual interface: selection, progress, findings, severity/confidence display, navigation, resize, export and errors. Native terminal visual acceptance remains **NOT VERIFIED** for Linux, macOS Intel and Windows. Do not equate a headless pass with a human visual review or a standalone TUI acceptance test.

A separate macOS arm64 PTY check, on the product checkpoint `848e677c129fc16dbf7d8788761840a6b49b2aee`, launched both the clean wheel and standalone executable. It checked the interactive path-selection/cancel flow, full-screen startup, resize from 100×30 to 60×24 and back, and exit 0. It did not redesign or modify the interface; this is supplemental evidence, not an exact-current-SHA PTY claim.

## Failures and release prerequisites

| Priority | Evidence | Interpretation / required follow-up |
| --- | --- | --- |
| P1 review gate, defect not established | Windows `test_tui_path_scan_and_private_json_export` writes valid JSON but fails its `0600` assertion; Windows reports mode `0666` | POSIX mode bits do not prove Windows DACL access. The export requests `0600` through `os.open` but does not explicitly enforce a Windows DACL. Verify owner-only access with a native ACL test before claiming equivalent privacy; inspect the automatic CLI report path too. No actual disclosure or insecure ACL was demonstrated. The assertion was not removed or weakened. |
| P2 | Both variants of `test_results_tree_groups_shared_artifacts_and_updates_detail_on_selection` fail after hover on Windows | Expected `Agent1`; observed a severity or finding detail. The known intermittent issue is reproduced, **not fixed**. Root cause remains unproven. Inspect actual hovered line, viewport/scroll position and event ordering before changing product behavior or test coordinates. Non-Windows successes do not resolve it. |
| P2 redistribution prerequisite | Inspected Linux and both macOS binaries contain notices for Dragons, Click and Textual, but no corresponding notice files for other bundled components such as Rich, Pygments and PyYAML | Complete runtime redistribution notices, including the Python runtime and native components, before public binary distribution. This is not an ordinary-installation failure. No packaging product change was made under the narrowly scoped installation/scan-fix authorization. |
| P3 | `--version` returns usage error | Optional usability improvement; installed metadata is available. Not an installation/scanning blocker. |
| P3 / compatibility limits | Python versions newer than 3.12, older OS versions, native visual acceptance outside macOS arm64, signing and notarization were not tested here | Retain explicit limits; do not turn optional features or signing into evidence of a scanner correctness defect. |

There is no confirmed new P1 scanner defect in this audit. The Windows privacy assurance gap still blocks an unqualified cross-platform release/privacy claim. No speculative runtime correction, broad skip, xfail, frozen benchmark change or security-assertion weakening was applied.

## Validation infrastructure corrections

The [first native run](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/40992276772) exposed two test-harness assumptions:

- Windows asyncio uses a stdlib loopback socket pair for its event-loop self-pipe. The audit tripwire initially blocked this IPC. `scripts/release_validation.py` now permits only loopback bind/connect events whose immediate code objects are exactly `socket.socketpair` and `BaseProactorEventLoop._make_self_pipe`. Arbitrary loopback traffic, external networking and process execution remain denied. Regression tests cover allowed IPC and denied call-chain/address/event cases. The final Windows run records 102 IPC events, zero forbidden attempts, and 13 audit self-checks.
- A CLI fixture set `HOME` without Windows `USERPROFILE`. `tests/test_cli_progress.py` now sets both to the same synthetic directory. The installed-agent assertion passes in the final Windows run.

Only this validation infrastructure was committed under the explicit exception. Product runtime files, interface design, runtime dependencies, `pyproject.toml` and `uv.lock` were not changed for this milestone. This report and associated documentation changes remain uncommitted for review.

## Artifact and privacy audit

Eight Python archives (wheel + sdist from each runner) and three retained native executables were inspected locally: **11 artifacts**. Package members include project source, metadata, entry point and MIT license, and match the committed source checks. The binaries were inspected as PyInstaller archives without importing or executing their contents. No private agent configuration, benchmark result, test suite or credential-signature match was found in the inspected members/data. Pattern checks are bounded checks, not a mathematical proof of absence.

The Windows executable built and ran its native smokes, but was not retained after the failing pytest step; its independent local binary member/notice/checksum audit is **NOT VERIFIED**. Windows wheel and sdist were retained and inspected. A failure must not erase the preceding smoke evidence or become a binary-inspection PASS.

SHA-256 values were independently recomputed on the downloaded artifacts. Current retained native binaries:

| File | SHA-256 |
| --- | --- |
| `dragonscan-0.1.0-linux-x86_64` | `d9f3857c34a2a77806ce85f5d663fa9b71c15791568ca6618509fdb2ee86dc56` |
| `dragonscan-0.1.0-macos-arm64` | `56ed4c316421b0c32f12e827647e06853e721aa3fa8fa841d606342a87ba59dc` |
| `dragonscan-0.1.0-macos-x86_64` | `ec3fa5f4c670684359de9c1f7ecf966ae992a6efa69531e6343b818ab8a8d94e` |

Standalone sizes are approximately 15–18 MB. Build-origin `direct_url.json` / `uv_cache.json` metadata is present; local build paths should be reviewed before public distribution. No byte-for-byte reproducibility claim is made. The sdist was built and inspected, not separately installed on every platform.

All scan targets were inert, under synthetic homes, without provider credentials. No real user-agent configuration was inspected. Dependency provisioning was explicit; acceptance operations used the offline cache. No target command, MCP server, semantic provider, OSV enrichment or container was launched. Guarded installed-wheel tests prohibit external network/process calls; the Windows stdlib IPC exception is documented above. Python audit hooks are not an OS sandbox or whole-binary network trace. Existing platform network-observation limits in [VALIDATION_NETWORK.md](VALIDATION_NETWORK.md) still apply.

## Quality and unchanged scope

Final local verification after the infrastructure correction:

- Reviewed static selection: **896 passed**, zero blocked events.
- Separate infrastructure/CLI-progress selection: **21 passed**.
- Earlier targeted discovery/MCP/coverage selection: **272 passed**; separate from the static selection, not a combined full-suite count.
- Ruff format: **360 files passed**; Ruff lint passed; mypy `src scripts`: **66 source files passed**; `git diff --check` passed.
- Finding inventory: **48 IDs**, unchanged.
- Frozen Phase 2 v2: **8 TP / 0 FP / 0 FN**.
- Frozen Phase 6 v2: **21 TP / 0 FP / 3 FN**. The three false negatives remain unresolved; frozen expectations were not edited.

The diff was reviewed against [IDEA.md](../IDEA.md). Proposed capabilities were not represented as implemented, no detection engine or mandatory service was added, and ordinary scanning remains local-first. Existing `AGENTS.md`, unrelated reference/benchmark edits, private semantic results and unfinished experiments were preserved. Private result contents were not read or committed.

## Next milestone: First Public Release Preparation

1. Establish and test Windows report ACL guarantees for both export paths; fix only with reproducible native evidence.
2. Instrument and resolve the Windows hover/selection failures without changing the visual design or hiding assertions.
3. Complete standalone third-party runtime notices and retain Windows artifacts even when validation fails.
4. Revalidate the final reviewed candidate SHA: exact-SHA quality, all native gates, artifact checksums and remaining terminal acceptance.
5. Prepare accurate release notes covering the three Phase 6 v2 false negatives and compatibility limits; obtain separate approval for any signing, tag, release or publication.
