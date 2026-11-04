# Install and run Dragons

[Overview](../README.md) · [CLI guide](CLI_GUIDE.md)

## Requirements

- Python **3.12 or newer** (`pyproject.toml` requires `>=3.12`).
- [uv](https://docs.astral.sh/uv/getting-started/installation/) for the recommended isolated tool installation, or Python's `venv` and pip for the fallback.
- A local wheel file. Dragons has no published PyPI package or GitHub Release. Do not replace the local wheel path with an unverified package name.

The wheel requires Python; it does not bundle CPython, PBS or a standalone runtime. Native wheel validation covers Ubuntu 24.04 x86-64, Windows Server 2022 x86-64, macOS 15 Intel and macOS 15 Apple Silicon with Python 3.12.12. Metadata permits newer Python versions, but does not establish validation on every interpreter or operating-system version. See the [wheel verification report](WHEEL_RELEASE_CANDIDATE.md) for artifact-specific evidence and limitations.

## Recommended: install the local wheel with uv

From the directory containing the supplied or locally built wheel:

```sh
uv tool install --python 3.12 ./dragons_ai_agent_scanner-0.1.0-py3-none-any.whl
dragonscan --help
```

uv creates an isolated environment and exposes `dragonscan` on your tool path. If it warns that this directory is not on `PATH`, follow the printed shell-setup instructions and reopen the terminal. No repository clone, development dependencies or editable installation is needed. The filename contains the package version; adjust it for another reviewed artifact.

## Fallback: isolated pip installation

On macOS/Linux with a compatible `python3`:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install ./dragons_ai_agent_scanner-0.1.0-py3-none-any.whl
.venv/bin/dragonscan --help
```

On Windows the venv executables reside in `.venv\Scripts`. The native CI matrix uses uv for installation; local installer checks cover the uv tool and pip frontends on macOS Apple Silicon, not every frontend on every platform.

## Network and dependency behavior

Initial installation can access the configured Python package index and, with uv, download Python if needed. An offline installation requires a compatible interpreter and all dependency wheels in a cache or prepared wheelhouse. **Offline scanning does not imply offline installation.**

The wheel declares four runtime dependencies: Click, markdown-it-py, PyYAML and Textual. The package manager installs those and their transitive dependencies separately. Native CI uses `uv.lock`; a normal tool/pip install resolves the allowed version ranges and may choose newer compatible dependencies. Neither development tools nor PyInstaller are required to scan.

Normal static scanning needs no API keys, AI providers, Docker or running MCP server. Optional semantic analysis can send selected content to a configured provider; OSV enrichment sends dependency identifiers to an external service. Dynamic MCP execution is a separate, explicitly consented mode and is not a sandbox. Leave these options disabled for local, offline scanning. Review the [security model](SECURITY_MODEL.md) before enabling them.

## From a source checkout

```sh
# From the repository root:
uv sync --locked
uv run dragonscan --help
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md
```

`uv sync --locked --offline` also works when the pinned interpreter and dependencies are already cached (verified on macOS). `uv run` uses this checkout's locked environment. Scanning an artifact never installs its declared dependencies. The sample is an inert, bundled test fixture and returns `COMPLETE`, `PASS`, zero findings and exit 0 on the verified checkout. [See the real Terminal capture](../assets/screenshots/dragons-clean-scan.png).

### Isolated invocation from local source

From the repository root, `uvx --from . dragonscan --help` builds and runs an isolated environment from **this directory**; it does not fetch a published Dragons package. `uvx --offline --from . dragonscan --help` was verified with dependencies already cached. Initial setup may still need dependency downloads. Do not substitute `uvx dragonscan` or `pip install dragonscan`: neither names this repository's verified, published distribution.

### Build a wheel for local installation

```sh
uv build --offline --sdist --wheel
uvx --offline --from dist/dragons_ai_agent_scanner-0.1.0-py3-none-any.whl dragonscan --help
```

The example uses the default `dist/` output; if building elsewhere, pass that wheel path instead. Offline builds need cached build requirements; offline installation also needs cached runtime dependencies. Use the persistent tool or pip installation above to run without a checkout. The wheel embeds the README in package metadata and includes the MIT license; the sdist also contains the source, build configuration and project vision. Neither package includes benchmark corpora, private scan results or standalone runtime binaries.

## Standalone and container options

**Standalone executables are withheld pending redistribution compliance.** The wheel does not contain the affected CPython/PBS components; the [standalone runtime review](RUNTIME_LICENSE_REVIEW.md) therefore does not establish a blocker for the wheel. Do not treat CI executable artifacts as published downloads.

[Distribution workflow](../.github/workflows/distribution.yml) builds native **Linux x86_64, macOS arm64/x86_64 and Windows x86_64** executables with pinned PyInstaller. All four runners have built and executed their own binaries and passed the isolated help, clean scan, finding, policy, invalid-target, JSON and SARIF smoke checks ([validation run](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/runs/38905696812)). Each binary is copied into a temporary directory for testing without the source checkout or a Python interpreter on `PATH`; the operating system's runtime libraries remain necessary. A local build needs the optional `standalone` group: `uv sync --locked --group standalone`, then `uv run --locked --group standalone python scripts/build_standalone.py`; verify with `uv run --locked --group standalone python -m scripts.smoke_standalone`. The workflow retains artifacts for seven days and publishes no executable or release. macOS binaries are not signed or notarized; reproducible bytes and optional network-enabled modes have not been established.

Standalone builds now produce an adjacent `<binary>.licenses/` directory. Keep it beside the executable when copying or distributing a build: `THIRD_PARTY_NOTICES.txt` indexes the original license texts, and `manifest.json` records the binary checksum, archive-derived package inventory, package versions and outstanding native-runtime obligations. Staging verifies both the executable and notice files; `SHA256SUMS` includes both. Notice integrity is not redistribution clearance: unresolved runtime/source/relink or platform redistributable obligations block release acceptance.

For the reviewed CPython 3.12.12 / PBS 20260211 runtime, explicitly provision supplemental notices before building: `uv run --offline python scripts/provision_runtime_licenses.py --cache build/standalone/license-cache`. **This provisioning command accesses the network**, even though uv's dependency resolution is offline. It downloads only digest-pinned upstream license sources; existing corrupt caches are rejected, not replaced. Packaging itself remains offline. Other runtime versions require a separate source review and matching pins. See [runtime license review](RUNTIME_LICENSE_REVIEW.md) for provenance and unresolved release conditions.

The repository also contains a [Dockerfile](../Dockerfile) for a locally built image. Building it needs package downloads unless cached. Run without network and mount the target read-only; containers do not sandbox the explicitly consented dynamic MCP mode. See the [technical reference](REFERENCE.md#distribution-not-published).

## First scan and exports

```sh
dragonscan scan ./SKILL.md
dragonscan scan ./SKILL.md --format json --output scan.json
dragonscan scan ./SKILL.md --format sarif --output scan.sarif
```

Replace `./SKILL.md` with your local file or directory. `--output` writes a local file atomically with private permissions. Review the status, findings, source location and evidence; `PARTIAL` or `FAILED` does not mean a clean scan. [CI integration](CI_INTEGRATION.md) explains exit codes and unattended use.

Run `dragonscan` in a terminal for the numbered menu, or `dragonscan -tui` for the full-screen interface. Choose a specific local file/directory, enter its path and confirm the scan. Installed-agent selection is an explicit opt-in that reads known agent locations; validation uses synthetic homes, not private installed agents. Headless installed-wheel tests cover selection, progress, finding details, keyboard/mouse actions, resize, exit and errors. These tests are not manual visual acceptance in a terminal emulator.

## Troubleshooting

- **`uv` not found:** follow the official uv installation guide and reopen the shell.
- **Wrong Python:** use a Python 3.12+ interpreter; `requires-python = ">=3.12"` is enforced by package metadata.
- **Offline resolution fails:** pre-cache the pinned interpreter, build requirements and runtime dependencies, or run the initial sync with network access. `--offline` prevents registry access, not missing-cache errors.
- **`PATH is required`:** give `scan` a file/directory/archive path, or explicitly select `--installed-agents` (which reads known local agent locations).
- **Exit 3 / PARTIAL or FAILED:** inspect the terminal Diagnostics group or export JSON; not every unreadable or malformed file is a security finding. [Exit-code guide](CLI_GUIDE.md#exit-status-and-policy).
- **Permission denied in a container:** the image uses an unprivileged UID; provide readable files with a read-only mount rather than weakening the mount or enabling execution.
