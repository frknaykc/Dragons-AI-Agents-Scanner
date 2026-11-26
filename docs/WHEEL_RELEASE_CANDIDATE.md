# Wheel release candidate verification

## Replacement candidate

**WHEEL RELEASE READINESS: READY** for the exact artifact pair below, within the
verification scope recorded here. This is a technical RC acceptance, not
permission to publish. Review date: 2026-11-04.

The `rc/wheel-0.1.0-docs` branch incorporates wheel-first installation guidance
into the source README and the installation/CLI guides. The replacement wheel's
embedded README exactly matches that source, including the local-wheel install
command. The previous source-documentation mismatch is closed.

Only wheel-related documentation is included on top of the reviewed CI harness.
The scanner, dependencies, package version, CLI/TUI design and benchmark
expectations are unchanged. Unrelated local changes are excluded. `main` is not
updated. No tag, GitHub Release or PyPI publication is authorized by this review.

## Accepted identity and evidence

- Version: `0.1.0`.
- Exact source and workflow revision: `650e3a04ca5158e6b0c9a33f074757032e81d037`.
- [Native run 41820775382](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41820775382): successful.
- One Ubuntu job built both artifacts; all four native jobs consumed the same
  wheel and verified its SHA-256 and archive contents against that source.

| Artifact | SHA-256 |
| --- | --- |
| `dragons_ai_agent_scanner-0.1.0-py3-none-any.whl` | `3e7a6241d7a74cb579ce92a7b2b94bd499091de07a7ab5ca800b3bce2f43542e` |
| `dragons_ai_agent_scanner-0.1.0.tar.gz` | `22b6577b190cc2b9e4c95eafe4208e567c599eb254a4b05393ea32c75fb4ed39` |

This acceptance report is a documentation-only follow-up to the built source
commit. It is not included in either archive; the package inputs are unchanged.
The artifacts must remain attributed to the exact source SHA above, not to a
later report commit or an inferred release tag.

## Verified acceptance

| Native platform | Clean install / CLI / headless TUI / scan / JSON-SARIF | Installed-wheel tests |
| --- | --- | --- |
| Ubuntu 24.04 x86-64 | PASS | 249 passed, 0 skipped |
| Windows Server 2022 x86-64 | PASS | 249 passed, 0 skipped |
| macOS 15 Intel | PASS | 249 passed, 0 skipped |
| macOS 15 Apple Silicon | PASS | 249 passed, 0 skipped |

- Full exact-source suite: **1935 passed, 1 skipped**, no failures or errors.
  The seven additional passes relative to the historical product baseline are
  the unchanged archive-harness tests now included in this branch. The skip is
  `test_windows_update_preserves_store_without_network` on Linux, not a pass.
- Separate archive-harness invocation: **7 passed**.
- Ruff format: **345 files**, PASS; Ruff lint: PASS; mypy: **71 files**, PASS.
- Twine strict: PASS. Exact archive allowlists: **58 wheel members / 59 sdist
  members**. README, MIT license, entry point, source modules and RECORD checks
  passed. Local reinspection of the downloaded pair also passed.
- Windows target-details click regression passed. Private output permissions,
  synthetic Codex/OpenClaw discovery and COMPLETE/PARTIAL/FAILED paths passed.
- Every native audit recorded 13 self-checks and no unexpected blocked event.
  Windows stdlib asyncio self-pipe IPC was allowed by the existing narrow guard.
- Fresh local uv tool and venv/pip installations of the canonical wheel passed
  on macOS Apple Silicon, Python 3.12.13. Both passed help, inert scans, exit-code
  checks, JSON/SARIF with mode 0600 and synthetic agent discovery. Imports came
  from isolated site-packages, without development dependencies. `--version`
  remains unsupported and correctly returns usage exit 2.

The canonical pair, checksums, full CI log, JUnit results, four platform summaries,
audit records and local installer evidence are retained outside the repository:
`~/Dragons-validation-evidence/wheel-0.1.0-docs-rc/`.
Artifacts reside under `native-41820775382/wheel-packages/`.
The original main worktree's status and relevant document hashes were unchanged.
The workflow emitted a non-failing Node.js 20 action deprecation warning; updating
the pinned actions is separate CI maintenance, not a failure of this run.

## Historical baseline — not replacement-artifact acceptance

[Native run 41799598659](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41799598659)
validated product source `db23dd52fab34a15346df05f69c6b289ef4b680c` with harness
`0e97c399bd132c188c2848efff5ea8b1456a4309`. Its full suite passed 1928 tests with
one platform skip; each of the four native runners passed 249 installed-wheel
tests without skips. Local macOS Apple Silicon uv tool/pip checks also passed.
That candidate was NOT READY because it embedded the old checkout-first README.
Those results are historical evidence, not a pass for the replacement pair.

The unchanged detection baseline has 48 finding IDs. The prior Phase 2 v2 result
was 8 TP / 0 FP / 0 FN; Phase 6 v2 was 21 TP / 0 FP / 3 FN. The known misses are
not fixed by documentation or packaging work.

## Distribution and verification boundaries

Python 3.12+ is required; this is a pure Python wheel, not a bundled interpreter
or standalone executable. Runtime dependencies are installed separately. No
CPython/PBS runtime, native binaries, benchmark corpus, private results or
combined dependency wheelhouse belongs in the Dragons artifact pair.

Standalone redistribution remains withheld under the separate
[runtime license review](RUNTIME_LICENSE_REVIEW.md); that does not make those
absent runtime components wheel blockers. Artifact inspection is not blanket
clearance to redistribute separately installed dependencies.

Native CI uses Python 3.12.12 and the existing lock. Installation can need network
access; ordinary static scanning is local and non-executing. Acceptance uses
inert fixtures and synthetic homes, not private agent configurations. Audit
tripwires are not an OS sandbox. TUI coverage is headless; manual visual testing
in every terminal emulator and all newer Python versions remain NOT VERIFIED.
