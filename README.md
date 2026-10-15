![Dragons AI Agent Scanner banner](banner.png)

# Dragons AI Agent Scanner

Inspect AI-agent instructions, skills, MCP configurations and dependency metadata **before trusting them**. Dragons statically reads supported artifacts and reports security findings with file, severity, confidence and bounded evidence. A finding signals a risk, not proof that code ran or data was exfiltrated.

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). From a repository checkout (the package is **not published**):

```sh
uv sync --locked
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md
uv run dragonscan scan . --format json --output scan.json
```

The first command scans a bundled inert example; replace the path with your own file or directory. A completed scan with findings still exits **0** unless you request a severity gate. Follow the [installation and first-scan guide](docs/INSTALLATION.md).

## What Dragons checks

- **Agent and skill discovery:** known instruction files, agent-owned settings, MCP definitions and opt-in installed-agent locations.
- **Prompt injection and credential risks:** instruction overrides, persistence, sensitive reads and linked external transfers.
- **MCP and supply chain:** static server metadata, dangerous configuration combinations, Python/Node dependency declarations and selected lifecycle scripts.
- **Evidence flow and obfuscation:** bounded source-to-sink paths and static decoding/evasion indicators. A reported path requires evidence; it does not prove execution.
- **Optional intelligence:** local signatures/feeds; explicit OSV HTTPS lookups and experimental semantic analysis require opt-in.
- **Reporting and CI:** terminal summaries, JSON, SARIF and severity-based exit gates; an example composite Action is included.

Ordinary scans are **offline and execution-free**: no target commands, MCP servers, package installs, fetched links or model calls. Remote HTTPS acquisition, OSV and semantic requests require separate flags. Experimental dynamic MCP inspection can execute a specifically approved local binary **without an OS sandbox**; never use it on untrusted executables. See the [security model](docs/SECURITY_MODEL.md).

## CLI preview

Actual, unedited [clean-scan terminal capture](docs/assets/cli/clean-scan.txt), taken from the bundled benign fixture:

```text
Dragons Scan
Target      'benchmarks/corpus/benign-credential-guide/AGENTS.md'
Artifacts   1
Status      COMPLETE
Risk        NONE
Findings    0
Severities  CRITICAL 0, HIGH 0, MEDIUM 0, LOW 0, INFO 0
Policy      PASS
Reason      Scan complete; policy threshold not reached

Findings    None
```

This environment could not capture terminal-window screenshots; these are **text captures, not screenshots**. See the exact [`--help`](docs/assets/cli/main-help.txt), [`scan --help`](docs/assets/cli/scan-help.txt) and [diagnostic](docs/assets/cli/diagnostic.txt) captures. [CLI guide](docs/CLI_GUIDE.md) explains findings, severity colors and exit status.

## Common commands

```sh
uv run dragonscan scan ./AGENTS.md
uv run dragonscan scan ./agent-directory --fail-on high --fail-on-incomplete
uv run dragonscan scan ./bundle.zip --format sarif --output scan.sarif
uv run dragonscan scan ./agent-directory --format json --output scan.json
uv run dragonscan scan ./agent-directory --installed-agents
```

The last command also inspects known user-level agent roots: run it only if you intend to scan local configuration. `--output` writes reports atomically. [Full command and consent guide](docs/CLI_GUIDE.md).

A locally built container can scan a read-only mount with container networking disabled (build requires access to dependencies unless cached; this documentation pass did not build the image):

```sh
docker build -t dragonscan:local .
docker run --rm --network none -v "$PWD:/target:ro" dragonscan:local scan /target
```

Docker is not a sandbox for the experimental MCP execution mode.

## Supported agents

Dragons recognizes **subsets** of Claude Code, Codex, Cursor, Cline, Hermes, Kilo Code, Zed Agent and Goose artifacts; coverage differs by agent and platform. Antigravity has **no agent-specific adapter**. Synthetic tests do not validate a real installation. Read the [agent-by-agent scope and validation table](docs/SUPPORTED_AGENTS.md) before using `--installed-agents`.

## Reports and CI

`--format json` exposes findings and diagnostics; `--format sarif` emits security results for code-scanning consumers. Exit **0** means complete/pass even if findings exist, **1** means a requested severity gate failed, **2** invalid CLI usage, **3** incomplete or failed analysis. See [findings and reports](docs/FINDINGS_AND_REPORTS.md) and [CI integration](docs/CI_INTEGRATION.md). Neither SARIF upload nor hosted Code Scanning acceptance is validated.

## Limits and documentation

Static analysis can miss attacks or flag benign content. Supported file names, size limits, private-state redaction, archive/remote restrictions and experimental modes are described in the [security model](docs/SECURITY_MODEL.md) and [technical reference](docs/REFERENCE.md). No PyPI package, standalone binary, container image or GitHub Release has been published.

- [Install and first scan](docs/INSTALLATION.md) · [CLI guide](docs/CLI_GUIDE.md) · [Agent coverage](docs/SUPPORTED_AGENTS.md)
- [Security model](docs/SECURITY_MODEL.md) · [Findings and reports](docs/FINDINGS_AND_REPORTS.md) · [CI integration](docs/CI_INTEGRATION.md)
- [Technical reference](docs/REFERENCE.md) · [Benchmark methodology](benchmarks/README.md) · [Agent coverage evidence and decisions](docs/AGENT_COVERAGE_REVIEW.md)
- [Product vision](IDEA.md) (not a feature list) · [Contributor safety rules](AGENTS.md)

## License

This repository has no project-level LICENSE file. Do not assume a grant to redistribute it; the licenses in `benchmarks/licenses/` cover third-party benchmark materials, not Dragons itself.
