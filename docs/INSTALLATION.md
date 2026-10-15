# Install and run Dragons

[Overview](../README.md) · [CLI guide](CLI_GUIDE.md)

## Requirements

- Python **3.12 or newer** (`pyproject.toml` requires `>=3.12`).
- [uv](https://docs.astral.sh/uv/getting-started/installation/) for the source-checkout commands. Install uv using its official instructions for your platform; then run `uv --version`. An initial dependency sync requires access to a configured Python package index unless the locked packages and interpreter are already cached.
- A local copy of this repository. No PyPI package, container image, standalone binary or GitHub Release is published by this repository.

## From a source checkout

```sh
# From the repository root:
uv sync --locked
uv run dragonscan --help
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md
```

`uv sync --locked --offline` also works when the pinned interpreter and dependencies are already cached (verified on macOS). `uv run` uses this checkout's locked environment. Scanning an artifact never installs its declared dependencies. The sample is an inert, bundled test fixture and returns `COMPLETE`, `PASS`, zero findings and exit 0 on the verified checkout. [See the real Terminal capture](../assets/screenshots/dragons-clean-scan.png).

## Isolated invocation from local source

From the repository root, `uvx --from . dragonscan --help` builds and runs an isolated environment from **this directory**; it does not fetch a published Dragons package. `uvx --offline --from . dragonscan --help` was verified with dependencies already cached. Initial setup may still need dependency downloads. Do not substitute `uvx dragonscan` or `pip install dragonscan`: neither names this repository's verified, published distribution.

## Build and run a local wheel

```sh
uv build --offline --sdist --wheel
uvx --offline --from dist/dragons_ai_agent_scanner-0.1.0-py3-none-any.whl dragonscan --help
```

The sdist and wheel build and local-wheel `uvx` help command were verified offline on macOS with cached build/runtime requirements, using an output directory outside the repository for validation. The example above uses the default `dist/` output; if building elsewhere, pass that wheel path instead. Dependencies still need to be cached for offline use. The filename includes the version from `pyproject.toml` and will change with that version. For a persistent isolated environment instead, create a Python 3.12+ venv and install the local wheel with `uv pip install --python /path/to/venv/bin/python dist/*.whl` (installation in that separate venv was **not** exercised here). The source checkout is the simplest verified path.

## Standalone and container options

[Distribution workflow](../.github/workflows/distribution.yml) specifies native **Linux x86_64, macOS arm64/x86_64 and Windows x86_64** builders, smoke tests, checksums and short-lived workflow artifacts. It does **not** publish or release executables. A local build needs the optional `standalone` group: `uv sync --locked --group standalone`, then `uv run --locked --group standalone python scripts/build_standalone.py`; verify with `uv run --locked --group standalone python -m scripts.smoke_standalone`. These commands were reviewed against the workflow but were **not run in this documentation pass**; do not treat the platform matrix as a published binary compatibility guarantee.

The repository also contains a [Dockerfile](../Dockerfile) for a locally built image. Building it needs package downloads unless cached. Run without network and mount the target read-only; containers do not sandbox the explicitly consented dynamic MCP mode. See the [technical reference](REFERENCE.md#distribution-not-published).

## First scan and exports

```sh
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md --format json --output scan.json
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md --format sarif --output scan.sarif
```

The help and sample scan were exercised; JSON and SARIF `--output` were also verified on an inert synthetic finding in a separate demo directory. `--output` writes a local file atomically. Scan your own artifact only after reviewing the [security model](SECURITY_MODEL.md). [CI integration](CI_INTEGRATION.md) covers unattended scans.

## Troubleshooting

- **`uv` not found:** follow the official uv installation guide and reopen the shell.
- **Wrong Python:** use a Python 3.12+ interpreter; `requires-python = ">=3.12"` is enforced by package metadata.
- **Offline resolution fails:** pre-cache the pinned interpreter, build requirements and runtime dependencies, or run the initial sync with network access. `--offline` prevents registry access, not missing-cache errors.
- **`PATH is required`:** give `scan` a file/directory/archive path, or explicitly select `--installed-agents` (which reads known local agent locations).
- **Exit 3 / PARTIAL or FAILED:** inspect the terminal Diagnostics group or export JSON; not every unreadable or malformed file is a security finding. [Exit-code guide](CLI_GUIDE.md#exit-status-and-policy).
- **Permission denied in a container:** the image uses an unprivileged UID; provide readable files with a read-only mount rather than weakening the mount or enabling execution.
