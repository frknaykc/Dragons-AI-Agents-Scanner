# Release readiness

Preparation only. Nothing has been tagged, signed, notarized or published. **REAL-WORLD ACCURACY CLAIM: NOT ESTABLISHED.** This checklist does not authorize distribution; revalidate after the checkpoint commit and before any public release.

| Area | Status | Evidence | Blocker | Next action |
| --- | --- | --- | --- | --- |
| Dragons license | Prepared | User approved MIT and `Copyright (c) 2026 Furkan ‘NaxoziwuS’ Aykaç`; root `LICENSE`, SPDX package metadata | Third-party material has separate rights | Preserve attribution and review redistribution before publication |
| Package metadata | Prepared | `pyproject.toml`: `dragons-ai-agent-scanner` 0.1.0, Python >=3.12, Click/markdown-it-py/PyYAML, `dragonscan` entry point, Hatchling, verified source URL | Authors/maintainers not declared; none inferred | Confirm whether additional identity/contact metadata is desired |
| sdist / wheel | Local verification passed | Offline archive inspection: all Python modules, README, license, metadata and wheel CLI included; no benchmarks, private semantic results, tests, credentials or caches. `twine` 7.0.0 `check --strict` passed both archives | Only Python 3.12 runtime has hosted validation; later versions not tested | Rebuild and recheck at an approved release commit |
| Docker | Local Linux arm64 validation passed | Documented `docker build -t dragonscan:local .`; isolated `--network none` CLI help and read-only inert scan passed; installed image contains MIT license | Other host architectures not checked; build dependencies may require network | Rebuild from the approved release commit if distributing an image |
| Linux standalone | Hosted build and smoke passed | [Four-platform run 38905696812](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/38905696812), commit `29c46acdcbbae3c28993a9064fd023f758bb1fb6` | Earlier binary predates license; not a releasable licensed binary | Rebuild at an approved release commit |
| Windows standalone | Hosted build and smoke passed | Same run; [Windows full-suite limits](VALIDATION_WINDOWS.md) | Optional feed update fails closed; [network observation](VALIDATION_NETWORK.md) blocked | Retain limitations; rebuild at release commit |
| macOS Intel | Hosted build and smoke passed | Same run | Unsigned/unnotarized; [network observation](VALIDATION_NETWORK.md) inconclusive | Retain limitations; sign/notarize only in authorized later milestone |
| macOS arm64 | Hosted build and smoke passed | Same run | Same limitations | Same action |
| GitHub Action | Trusted checkout validated | [Hosted Action/SARIF run 38900274145](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/38900274145), commit `b41d0e2bd7af0f82a4cd9e9fcf878aaa24071029` | External repository usage not validated | Test independently before claiming broader support |
| SARIF upload | Trusted upload accepted | Same run; finding `DRAGON-PI-002` visible in Code Scanning | Not validated from forks/untrusted PRs | Keep uploads in trusted, reviewed workflows |
| Checksums / provenance | Four digests locally verified | Downloaded the run's `release-staging-bundle`; all four files match `SHA256SUMS`; pinned PyInstaller 6.16.0, uv 0.11.7 and Python 3.12.12 in workflow | `SHA256SUMS` does not embed commit, tool, version as separate fields; workflow run/commit supply provenance. Byte-for-byte reproducibility unproven | Retain run URL and SHA, verify fresh release-built binaries; no second manifest format without need |
| Signing / notarization | Not started | Hosted binaries are unsigned; no notarization record | Public trust / macOS execution friction | Separate authorized release decision |
| GitHub Releases | Not published | Workflow stages ephemeral Actions artifacts (seven-day retention) | License/notice review and release approval | Separate publication authorization required |
| PyPI | Not published | `https://pypi.org/pypi/dragons-ai-agent-scanner/json` returned 404 at audit time; version 0.1.0 is buildable; Markdown rendering passed `twine` 7.0.0 strict check | Name availability is not guaranteed or reserved; redistribution checks outstanding | Recheck immediately before any approved publication; do not register/reserve now |

The standalone smoke test copied each native executable into a separate temporary directory and ran it without the build virtual environment, source path or Python on `PATH`. This demonstrates the tested CLI path's runtime independence on those runners, not compatibility with every installation. The verified `SHA256SUMS` from run `38905696812` (commit `29c46acdcbbae3c28993a9064fd023f758bb1fb6`) records **earlier validation binaries**, not artifacts built from the current license/metadata changes:

| File | SHA-256 |
| --- | --- |
| `dragonscan-0.1.0-linux-x86_64` | `6eb18a6459b5e7e0f0a3ed6535b695909ff46fe943848b845b9f85fd44f8a5c1` |
| `dragonscan-0.1.0-macos-arm64` | `84a53e064fe46722d68e837a35c34ead38ab535a2efdbd9688b8314d66221b10` |
| `dragonscan-0.1.0-macos-x86_64` | `9931b4085b8ed603a28e4775a0a1b79c0cf9663625726e3e71d958350356d566` |
| `dragonscan-0.1.0-windows-x86_64.exe` | `112d77c6d76cf8bd6c12c794141f43b9c8922844e4ba0004ed845fa5f04192b7` |

## Third-party material and distribution limits

`benchmarks/realworld/manifest.json`, `benchmarks/holdout/manifest.json`, `benchmarks/METHODOLOGY_HISTORY.md` and `benchmarks/licenses/` retain source references, pinned digests and third-party license texts for copied public artifacts. These benchmarks are **not** included in the Python sdist/wheel or staged standalone binaries, but are present in the public source repository. In particular the AISA excerpt's upstream MIT file credits “Bootstrap Authors” rather than the research authors; the manifest itself records this ambiguity. Obtain/confirm a valid right to redistribute that excerpt before treating the full repository as cleared. Preserve the excerpt and provenance during review; do not silently delete or relicense it. MCP documentation has separate CC-BY-4.0 attribution recorded in its manifest; check all notices if producing a source bundle including benchmarks.

The banner is an existing repository asset; screenshots are documented captures of the product in `assets/screenshots/README.md`. Neither the assets nor benchmark corpora are bundled in Python distributions; the README references images hosted in this repository. Confirm asset ownership and any applicable third-party UI/image permissions for public redistribution. A bundled standalone executable includes third-party runtime components: review their license/notice obligations and whether the published binary would carry the required notices before release. Dragons' MIT license does not license third-party content.

The generated archives use core metadata 2.5. `twine` 6.2.0 rejected that metadata version before rendering; `twine` 7.0.0 validated both archives with `check --strict`. This is a tooling compatibility limit, not evidence of a PyPI upload. No package name has been reserved.

Default static scanning reads untrusted input without executing it. Optional remote acquisition, OSV, semantic-provider calls and explicitly consented dynamic MCP execution have separate boundaries ([security model](SECURITY_MODEL.md)). Remote Git acquisition remains **NO-GO**; Windows threat-intelligence feed update fails closed without safe ACL parity; dynamic MCP uncontained execution is **not** an OS sandbox. Hosted [network observation](VALIDATION_NETWORK.md) verified Linux's monitored syscall classes, not macOS connection attempts or Windows process-attributed behavior. Semantic-provider analysis is experimental. Scanner accuracy across real-world deployments, byte-for-byte build reproducibility, and signatures/notarization are not established.

**Recommended order:** resolve third-party/asset notice rights and review metadata → verify checkpoint CI → fresh provenance-linked release builds and checksum verification → separately authorize signing, tagging, GitHub Release or PyPI publication. None of those publishing actions is part of this milestone.
