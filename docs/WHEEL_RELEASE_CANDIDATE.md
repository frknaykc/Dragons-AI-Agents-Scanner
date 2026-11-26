# Wheel release candidate verification

Review date: 2026-11-04. **WHEEL RELEASE READINESS: NOT READY.**

The wheel passes packaging, native installation and scoped CLI/TUI acceptance.
One release-preparation blocker remains: the immutable candidate embeds the old
source-checkout README. The reviewed wheel-first installation documentation is
uncommitted and is not part of that candidate. Do not publish this package as the
final wheel-first release without accepting the documentation in a source commit,
rebuilding the pair and verifying the replacement artifacts.

Standalone redistribution questions are **not wheel blockers**: this wheel does
not redistribute CPython/PBS, libpython, libuuid, compiler runtime helpers or
Microsoft runtime DLLs.

## Identity and scope

- Package: `dragons-ai-agent-scanner`, version `0.1.0`.
- Exact product source: `db23dd52fab34a15346df05f69c6b289ef4b680c`.
- CI-only branch: `ci/wheel-release-validation`.
- CI harness revision: `0e97c399bd132c188c2848efff5ea8b1456a4309`.
- [Native wheel validation run 41799598659](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/41799598659): successful.
- No tag, GitHub Release or PyPI publication was created.
- Product, installation documentation and unrelated working-tree changes were
  not committed. Only the three authorized CI files were committed and pushed
  normally to the CI branch. `main` and `origin/main` remain at the product SHA.

The workflow checks out the immutable product separately from its own harness.
One Ubuntu build job creates the wheel/sdist pair. All four installation jobs
consume that wheel, check its SHA-256, and compare its modules and metadata to
the product checkout. The full suite runs against the committed product, not the
mixed local working tree. Controlled, test-created MCP fixtures in that suite
were separately authorized; real MCP servers and private agent configurations
were not exercised.

## Wheel and sdist audit

| Property | Verified result |
| --- | --- |
| Build backend | Hatchling; isolated build, no dependency/config changes |
| Python metadata | `Requires-Python: >=3.12` |
| Entry point | `dragonscan = dragonscan.cli:main` |
| Wheel tag | `py3-none-any`, `Root-Is-Purelib: true` |
| Runtime requirements | `click>=8.1,<9`, `markdown-it-py>=3,<5`, `PyYAML>=6,<7`, `textual>=3,<9` |
| Optional published extras | None; `dev` and `standalone` are development dependency groups |
| License | `License-Expression: MIT`; original authorized LICENSE included |
| README | Embedded as Markdown in wheel METADATA; separate file in sdist |
| Wheel members | 58: 53 Python modules and 5 dist-info files |
| Sdist members | 59: source modules, pyproject, README, IDEA, LICENSE, PKG-INFO and `.gitignore` |
| Metadata validation | Twine 7.0.0 `check --strict`: PASS |
| CLI/TUI modules | Included, byte-compared to exact source |
| Wheel RECORD | Membership, lengths and SHA-256 values checked |
| Excluded material | No benchmark corpus, test fixtures, private results, local user files, `.env`, native binaries or standalone runtime |

The archive allowlist is exact, rather than a check for selected forbidden names.
The sdist has no links or executable build hooks beyond the declared standard
build backend. `IDEA.md` is a product vision, not a claim that its proposals work.
No dependency was added or changed to simplify packaging.

The macOS local build and CI build have identical Python modules, entry point,
README metadata and license. Their WHEEL generator values differ:
Hatchling 1.32.4 locally and 1.33.0 in CI, with corresponding RECORD differences.
Their sdists are byte-identical. Rebuilding a wheel from the CI sdist succeeds;
only WHEEL/RECORD differ from the canonical CI wheel. Functional build
reproducibility is verified; cross-environment byte reproducibility is not.
The declared build backend remains unpinned; this review did not change it.

## Distribution and licensing boundary

The Dragons wheel distributes its own Python modules and the project's MIT
license, including the authorized copyright holder. Inspection found no vendored
third-party implementation or native runtime inside that wheel. The sdist also
includes project documentation and configuration, with the same license.

The package manager separately obtains runtime dependencies. The user provides
Python, or explicitly lets an installer provision it. Platform libraries and any
native extension inside a dependency remain distinct from files inside Dragons'
wheel. In particular, PyYAML's `_yaml` extension is a separately installed
package component, not a Dragons wheel member. This review does not turn the
standalone dependency/notice collection into proof of wheel contents.

The evidence directory contains the locked installed dependency inventory,
original installed license texts and their hashes. These are observations about
those distributions, not a blanket certification of every dependency's native
supply chain or authorization to redistribute a combined wheelhouse.

| Separately installed dependency | Locked version | Observed license metadata/text |
| --- | --- | --- |
| Click | 8.5.0 | BSD-3-Clause |
| markdown-it-py | 4.2.0 | MIT texts, including upstream markdown-it notice |
| PyYAML | 6.0.3 | MIT; native `_yaml` extension present separately |
| Textual | 8.2.8 | MIT |
| linkify-it-py | 2.2.0 | MIT |
| mdit-py-plugins | 0.6.1 | Installed license collection retained in inventory |
| mdurl | 0.1.2 | MIT permission text |
| platformdirs | 4.13.5 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause and installed notices |
| Rich | 15.0.0 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 and original license history |

No third-party runtime binaries or dependency wheels accompany the proposed
Dragons wheel/sdist pair. Redistributing such a bundle would require a separate
contents and licensing review. The unresolved standalone issues stay documented
in [the native runtime review](NATIVE_RUNTIME_RESOLUTION.md).

## Four-platform clean installation

| Native runner | Install | CLI | TUI | Scan | JSON/SARIF | Result |
| --- | --- | --- | --- | --- | --- | --- |
| Ubuntu 24.04 x86-64 | PASS | PASS | PASS, headless | PASS | PASS | PASS |
| Windows Server 2022 x86-64 | PASS | PASS | PASS, headless | PASS | PASS | PASS |
| macOS 15 Intel | PASS | PASS | PASS, headless | PASS | PASS | PASS |
| macOS 15 Apple Silicon | PASS | PASS | PASS, headless | PASS | PASS | PASS |

All runners use Python 3.12.12. Each creates a fresh runtime environment from
`uv.lock` without development dependencies or an editable Dragons installation,
then installs the shared wheel offline. Dependency/interpreter provisioning is a
separate network-enabled step; offline installation needs a populated cache.
The installed console runs with a synthetic home and sanitized environment, no
provider credentials, no development interpreter on PATH and no real agent data.

Each platform also passes **249 installed-wheel tests, zero skips**, loading
`dragonscan` from site-packages rather than the source tree. The selection covers
CLI/menu behavior, TUI target and installed-agent selection, path entry, progress,
finding details, keyboard/mouse interactions, terminal resize, exit/error paths,
JSON/SARIF, synthetic agent discovery and private report permissions. In
particular, Windows passes
`test_target_details_reveal_fields_and_support_click_to_continue`.

The Python audit tripwires pass 13 self-checks on each platform and record no
unexpected blocked operation. Windows permits its narrowly identified stdlib
asyncio self-pipe IPC, not arbitrary networking. These guards are not an OS
sandbox or a network packet trace. Headless tests are not manual visual
acceptance in a real terminal emulator; that scope remains **NOT VERIFIED**.

The installed command also passes these inert end-to-end checks on each runner:

- Help: exit 0. `--version` is unsupported and returns usage exit 2.
- Benign COMPLETE scan: exit 0; malicious inert finding: exit 1.
- PARTIAL and FAILED: exit 3; invalid usage: exit 2.
- JSON/SARIF reports, finding IDs, evidence and source locations.
- Private report permissions: Unix mode 0600; restricted Windows ACL checks.
- Synthetic Codex/OpenClaw installed-agent scans, not private installed agents.

## Installation and first-run experience

Recommended: `uv tool install --python 3.12 ./dragons_ai_agent_scanner-0.1.0-py3-none-any.whl`.
Fallback: a Python 3.12+ venv followed by pip installation of that local wheel.
Both methods were tested in fresh, separate directories on macOS Apple Silicon
using the exact CI wheel. Both installed commands passed help, inert scans,
status/exit-code checks, exports and synthetic installed-agent discovery. No
source checkout or development dependencies are needed to run the tool.

The ordinary resolver selected platformdirs 4.14.4, whereas native CI used the
locked 4.13.5. Both observed configurations passed their stated checks; the
allowed dependency ranges are not a promise that all future resolutions work.
The uv installer warns when the tool bin directory is absent from PATH. The
installation guide explains that setup step and distinguishes installation
network access from offline scans. A supplied local wheel is required; there is
no advertised PyPI install or unpublished standalone download.

The README installation section, installation guide and CLI guide now describe
this process. They retain existing user changes, report-storage wording, asset
links, source workflows and the existing CLI/TUI design. The candidate's embedded
README still describes the earlier checkout-first path: this is the sole open
release-preparation blocker, not an installation failure.

## Quality and frozen benchmarks

- Exact-source hosted full suite: **1928 passed, 1 skipped**. The pre-existing
  skip is `test_windows_update_preserves_store_without_network`, guarded for
  Windows ACL behavior on the Linux full-suite runner. It is not a passed test.
- Each native installed-wheel selection: **249 passed, 0 skipped**. These
  selections are not four full-suite runs.
- CI harness archive tests: **7 passed**; extra/private/native paths, missing or
  modified source modules and Unicode metadata are covered.
- Hosted exact-source Ruff format/lint and `mypy src scripts`: PASS.
- Final local-tree Ruff: **379 files formatted**, lint PASS; mypy: **72 source
  files**, PASS; `git diff --check`: PASS.
- Local affected selection: **22 passed, 2 deselected**. The two offline build
  cases were not counted as passed; fresh package/native acceptance is separate.
- Finding inventory: **48 IDs**, exact match to frozen Phase 6 v2 inventory.
- Phase 2 v2: **8 TP / 0 FP / 0 FN**; correctness checks pass.
- Phase 6 v2: **21 TP / 0 FP / 3 FN**. Its evaluation exits 1 because the three
  existing misses remain. They are not new packaging regressions or resolved
  findings. Frozen expected results were not weakened.

The Phase 6 misses remain `chain-structured-load` (`DRAGON-PATH-002`),
`exec-network-python` (`DRAGON-EXEC-002`) and `obf-literal-shell`
(`DRAGON-EXEC-003`). Benchmark evaluation uses committed product code against the
unchanged public frozen manifests. No private semantic results were read.

## Candidate artifacts and retained evidence

The canonical artifacts both come from the product SHA above and native run
41799598659. They are candidate inputs for review, not approved publication files.

| Artifact | SHA-256 |
| --- | --- |
| `dragons_ai_agent_scanner-0.1.0-py3-none-any.whl` | `338085f02c414c1afd039e247561022c889233fed365cb7b8c02cf5f26e74e79` |
| `dragons_ai_agent_scanner-0.1.0.tar.gz` | `b3ce0c8bc799982f41fb890e0116d6e17bb8b6bf4e37e49b1248e2ab12e4bac4` |

Evidence is retained outside the repository and automatic scratch cleanup:
`~/Dragons-validation-evidence/wheel-0.1.0-db23dd5/`.
The `rc-source-db23dd5/` subdirectory holds the canonical pair, checksums,
package metadata, dependency/license inventory and draft release notes.
`native-41799598659/` holds the four summaries, JUnit XML, command logs, audit
records and hosted full-suite evidence. Local install, rebuild, benchmark and
quality evidence remain separate to avoid conflating their scopes.

## Remaining gate

Accept the wheel-first documentation into an explicitly authorized source commit,
then build and verify the replacement wheel/sdist pair from that commit. The
current task leaves those edits uncommitted as requested. No runtime or detector
change is required by the evidence. Do not publish, tag or create a release while
this artifact/documentation mismatch remains. First Public Release Approval &
Publication has not begun.
