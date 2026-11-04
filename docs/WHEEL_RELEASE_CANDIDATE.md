# Wheel release candidate verification

## Replacement candidate

The `rc/wheel-0.1.0-docs` branch incorporates wheel-first installation guidance
into the source README and the installation/CLI guides. This closes the previous
candidate's source-documentation mismatch once a replacement artifact pair has
been built and verified. **Replacement artifact acceptance is pending.**

Only wheel-related documentation is included on top of the reviewed CI harness.
The scanner, dependencies, package version, CLI/TUI design and benchmark
expectations are unchanged. Unrelated local changes are excluded. `main` is not
updated. No tag, GitHub Release or PyPI publication is authorized by this review.

## Required acceptance

The existing no-publish workflow must receive the exact replacement source SHA.
One build job produces the wheel and sdist; Linux x86-64, Windows x86-64, macOS
Intel and macOS Apple Silicon must install that same wheel and verify its hash.

- Full source tests, Ruff format/lint, mypy and archive-harness tests.
- Twine strict metadata validation and exact archive membership, README, license,
  source-module and wheel RECORD checks.
- Clean installed-wheel CLI/menu, headless TUI, inert scan and JSON/SARIF checks.
- Installed-wheel tests on each native runner, including Windows target-details
  click handling, private output permissions and synthetic agent discovery.
- Separate local uv tool/pip installation checks against the canonical wheel.

Retain the exact source SHA, run URL, wheel/sdist SHA-256 values and native
summaries before declaring the replacement candidate ready. A report-only
follow-up commit does not change the accepted package inputs; identify both
revisions explicitly rather than attributing a historical build to a newer SHA.

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
