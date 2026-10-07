![Dragons AI Agent Scanner banner](banner.png)

# Dragons AI Agent Scanner

Scan AI-agent instructions, MCP configuration and dependency metadata for security risks **before** trusting them. Dragons reads local artifacts as data and reports the affected file, available location, severity, confidence and evidence. Findings indicate risk; they do not prove that code ran or data left the machine.

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). The package is not published to PyPI; run it from a clone:

```sh
uv sync --locked
uv run dragonscan scan ./AGENTS.md
uv run dragonscan scan ./agent-directory --format json --output scan.json
uv run dragonscan scan . --fail-on high --fail-on-incomplete
```

`scan PATH` accepts a local file, directory or `.zip`/`.tar`/`.tar.gz` archive. To see every option, run `uv run dragonscan scan --help`.

You can also build a local image and mount the scan target read-only, without container network access:

```sh
docker build -t dragonscan:local .
docker run --rm --network none -v "$PWD:/target:ro" dragonscan:local scan /target
```

Docker is not a sandbox for the experimental MCP execution mode.

## What it checks

- Agent instructions and skills (`AGENTS.md`, `SKILL.md`, `SOUL.md`, `MEMORY.md`, `CLAUDE.md`), recognized agent configuration, plugins and MCP configuration.
- Prompt-injection and persistence instructions, credential access, linked data-transfer or fetch-to-shell directives, suspicious MCP metadata and bounded obfuscation patterns.
- Python and Node dependency declarations, mutable runtime sources and selected lifecycle scripts. It does not install or resolve target dependencies.

The default scan runs locally: it does not visit links, start MCP servers, execute target code or call a model. You must opt in separately to remote acquisition, installed-agent discovery, vulnerability lookup, local intelligence feeds, semantic analysis or experimental MCP process inspection. **MCP process inspection can execute an approved local binary without OS isolation; do not use it on untrusted executables.** Semantic mode can send selected, best-effort-redacted excerpts to your chosen provider; review the target before enabling it.

## Reports and CI

Terminal output is the default; `--format json` and `--format sarif` are available. Findings alone return exit code **0**. `--fail-on high` (or another severity) returns **1** when a completed scan reaches that threshold; CLI usage errors return **2**; scan failures or incomplete analysis return **3**. Check the exit code as well as the report. `--output PATH` writes a report to a file.

The repository includes an [offline quality workflow](.github/workflows/quality.yml) and an [example GitHub Action workflow](examples/dragons-action.yml) for trusted checkouts. Do not run the local Action source from an untrusted pull-request checkout. No release, package, image or binary has been published.

## Documentation

- [Technical reference](docs/REFERENCE.md): supported formats, limits, optional modes, report fields and safety boundaries.
- [Benchmark methodology and results](benchmarks/README.md): development measurements are corpus-specific, not a general detection-accuracy claim. Real-provider semantic evaluation is not complete.
- [Product vision](IDEA.md) and [contributor safety rules](AGENTS.md). The vision includes features that are not implemented.

Develop locally with `uv run pytest`, `uv run ruff format --check .`, `uv run ruff check .` and `uv run mypy src`.
