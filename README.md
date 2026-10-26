![Dragons AI Agents Scanner original banner](https://raw.githubusercontent.com/frknaykc/Dragons-AI-Agents-Scanner/main/assets/branding/banner.png)

# Dragons AI Agent Security Scanner

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-24546a)](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/INSTALLATION.md) [![Offline quality and security regression](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/actions/workflows/quality.yml) [![GitHub stars](https://img.shields.io/github/stars/frknaykc/Dragons-AI-Agents-Scanner?style=flat&label=Stars)](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/stargazers)

**Inspect AI agent components before you trust them.** Dragons statically scans agent instructions, skills, MCP configurations and related dependency metadata. Findings include the affected location, bounded evidence, severity and confidence. You can investigate suspicious behavior without executing the inspected component. A finding warrants review; it does not prove compromise.

> [!WARNING]
> **Development status.** Dragons is under active development. Evaluate its results in context and review the [security limitations](#security-boundaries) before relying on a scan. Contributions and technical feedback are welcome.

## Quick start

You need Python 3.12+, [uv](https://docs.astral.sh/uv/) and a local checkout of this repository.

> [!IMPORTANT]
> Dragons is not published on PyPI or distributed through GitHub Releases. Run the commands below from the repository root.

```sh
uv sync --locked
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md
```

The bundled file is an inert test artifact. Its scan produces:

| Result | Value |
| --- | --- |
| Scan status | `COMPLETE` |
| Security findings | 0 |
| Policy evaluation | `PASS` |
| Exit code | 0 |

Replace the example path with a supported file or directory of your own. The first `uv sync` may download this project's locked dependencies. **Scanning a target does not install that target's dependencies.**

[Installation options](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/INSTALLATION.md) · [CLI commands](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/CLI_GUIDE.md)

Run `uv run dragonscan` in an interactive terminal for an icon-led, line-oriented target menu: choose all known local agents, one known agent or a local file/directory, then confirm before scanning. Run `uv run dragonscan -tui` for the full-screen Textual interface with scoped selection and a browsable report. Both interfaces scan locally by default. For a one-shot scan without either interface, pass a target or scan flags directly (`uv run dragonscan ./AGENTS.md --format json` or `uv run dragonscan --installed-agents`); the existing `scan PATH` and `scan --installed-agents` forms still work. Installed-agent scans save a private JSON report by default when terminal output is selected.

## See the scanner

The images below capture real macOS Terminal sessions using inert test fixtures. They are not simulated terminal interfaces, and no malicious payload was executed. The [screenshot verification log](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/assets/screenshots/README.md) records the command, fixture, exit code and capture method for each image. Tap an image to enlarge it on mobile.

### Clean scan

One supported document, no security findings.

![Terminal showing Dragons scanning a bundled inert AGENTS.md file with COMPLETE status, zero findings and PASS policy](https://raw.githubusercontent.com/frknaykc/Dragons-AI-Agents-Scanner/main/assets/screenshots/dragons-clean-scan.png)

### Security finding

A synthetic instruction-override fixture produces a finding without executing the fixture's instructions.

![Terminal showing a DRAGON-PI-001 high-severity finding in an inert synthetic SKILL.md](https://raw.githubusercontent.com/frknaykc/Dragons-AI-Agents-Scanner/main/assets/screenshots/dragons-security-finding.png)

[Main help screenshot](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/assets/screenshots/dragons-help.png) · [Severity gate screenshot (exit 1)](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/assets/screenshots/dragons-severity-policy.png) · [All commands and reports](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/CLI_GUIDE.md)

## What Dragons detects

Dragons looks for security indicators in supported AI agent artifacts using static analysis.

| Inspection surface | Examples of statically detectable indicators |
| --- | --- |
| Agent instructions and skills | Instruction overrides, persistence mechanisms and suspicious trust-boundary changes |
| Credentials and data transfer | Sensitive-data reading directives linked to external transmission; evidence-based source/sink paths |
| MCP configurations | Exposed or potentially dangerous server definitions and mutable execution references |
| Dependency metadata | Selected package risks, lifecycle scripts and optional OSV vulnerability lookups |
| Encoded or obfuscated content | Bounded static decoding and context-aware evasion indicators |

### Detection limits

No detector covers every attack. Static evidence cannot establish whether a target was executed, contacted a server or exfiltrated data. Findings require review in context; false positives and false negatives remain possible.

[Finding interpretation](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/FINDINGS_AND_REPORTS.md) · [Technical scope](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/REFERENCE.md)

## Agent coverage

Dragons recognizes selected file and configuration formats associated with Claude Code, Codex, Cursor, Cline, Hermes Agent, Kilo Code, Zed Agent and Goose.

> [!IMPORTANT]
> **Partial platform support.** These are supported artifact subsets, not full integrations. Coverage varies by file format and platform; some locations have only synthetic-fixture validation. Antigravity has no agent-specific adapter. See the [coverage table and gaps](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/SUPPORTED_AGENTS.md) before treating a platform as supported for your particular setup.

Scanning a path does not search your installed agents. To inspect known local agent roots, opt in separately:

```sh
uv run dragonscan scan --installed-agents
```

This option reads known local locations; it does not prove an agent is installed or active. The terminal summary lists only discovered agents and counts the artifact types scanned. A detailed JSON report is saved to a new private `~/dragonscan-*/scan.json` directory and its exact path appears under `Report`. Review it locally before sharing; it may contain local paths and excerpts. [Installed-agent details](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/SUPPORTED_AGENTS.md)

To scan larger known agent directories, adjust the discovery budgets with `--max-entries-per-root`, `--max-artifacts`, `--max-artifacts-per-root` and `--max-depth`; use `--agent` to select one known agent. A reached limit is reported as partial coverage, not a clean scan. File-size, format and security exclusions still apply. [Options and limits](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/CLI_GUIDE.md)

## How it works

**Discover → Parse → Detect → Evidence/Flow → Risk → Report**

| Stage | What happens |
| --- | --- |
| Discover | Identify supported files and configurations at the selected target. |
| Parse | Load within resource limits and parse supported formats as untrusted data. |
| Detect | Run independent rules to identify suspicious static indicators. |
| Evidence/Flow | Connect sources, sinks and possible paths where the available evidence permits. |
| Risk | Assign finding severity; the highest finding severity sets the overall risk level. |
| Report | Present findings with locations and bounded supporting evidence. |

Missing source, sink or flow information means Dragons could not establish that relationship; it does not prove the relationship is impossible. [Reports explained](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/FINDINGS_AND_REPORTS.md)

## Terminal, JSON and SARIF

Dragons writes terminal output by default. Use `--format` and `--output` for local reports:

```sh
uv run dragonscan scan ./AGENTS.md
uv run dragonscan scan ./agent-directory --format json --output scan.json
uv run dragonscan scan ./agent-directory --format sarif --output scan.sarif --fail-on high
```

Terminal findings appear in individual cards with evidence, confidence, review checks, false-positive considerations and remediation. Scan limits appear as a short coverage summary, not as security findings; detailed diagnostics and the full agent inventory are in JSON. A partial scan is not a negative security result.

`./AGENTS.md` and `./agent-directory` are example paths; supply your own supported artifact or directory. Reports are written to the local filesystem. `--fail-on high` opts into a policy failure when a completed scan finds a high- or critical-severity issue.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed; findings may still exist if no requested severity threshold was met. |
| `1` | A completed scan met the `--fail-on` threshold. |
| `2` | Invalid CLI usage or option. |
| `3` | Analysis was incomplete or failed. |

Generating SARIF does **not** upload a report to GitHub. A separate [hosted CI validation](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/CI_INTEGRATION.md#sarif-artifacts-and-code-scanning) confirmed ingestion of a trusted synthetic finding; uploads from external repositories are not validated. [Exit codes and policy](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/CLI_GUIDE.md#exit-status-and-policy) · [CI integration](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/CI_INTEGRATION.md)

## Security boundaries

Default local scans are **offline and non-executing**. Dragons reads supported targets as untrusted data. It does not run target scripts, start declared MCP servers, follow URLs found in artifacts, install target packages or call an AI model.

The following operations require separate opt-in:

| Operation | Boundary |
| --- | --- |
| Remote HTTPS acquisition (`--remote`) | Downloads one explicitly selected public HTTPS artifact. |
| OSV lookup (`--vuln-check`) | Sends normalized package names and exact versions to OSV. |
| Experimental semantic analysis (`--semantic`) | May transmit selected excerpts to an external provider. Redaction is best-effort and cannot guarantee removal of all sensitive data. |
| Dynamic MCP inspection (`--dynamic-mcp`) | Requires additional consent and exact selection; uncontained execution may launch the selected executable. |

> [!CAUTION]
> **Dynamic MCP execution is not sandboxed by the operating system when uncontained execution is authorized.** Do not authorize untrusted binaries. This mode is separate from the default static scan.

Static analysis cannot certify that an artifact is safe. Review findings, paths and report contents before sharing them. [Security model and limitations](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/SECURITY_MODEL.md)

## Offline scanning with Docker

A locally built image can scan a read-only mount with container networking disabled:

```sh
docker build -t dragonscan:local .
docker run --rm --network none -v "$PWD:/target:ro" dragonscan:local scan /target
```

`--network none` disables container networking and `-v "$PWD:/target:ro"` mounts the current directory read-only at `/target`. Image creation may download this project's dependencies unless cached. Do not treat this container setup as a sandbox for separately authorized dynamic MCP execution.

## Documentation

| Get started | Understand results | Operate safely |
| --- | --- | --- |
| [Installation](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/INSTALLATION.md) | [Findings and reports](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/FINDINGS_AND_REPORTS.md) | [Security model](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/SECURITY_MODEL.md) |
| [CLI guide](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/CLI_GUIDE.md) | [Supported agents](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/SUPPORTED_AGENTS.md) | [CI integration](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/CI_INTEGRATION.md) |

[Technical reference](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/REFERENCE.md) · [Benchmark methodology](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/benchmarks/README.md) · [Agent coverage evidence](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/AGENT_COVERAGE_REVIEW.md) · [Product vision (proposals, not features)](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/IDEA.md)

## Release and license status

Dragons remains under development. There is no published PyPI package, standalone executable, official container image or GitHub Release.

> [!IMPORTANT]
> **License notice.** Dragons' own source code is licensed under [MIT](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/LICENSE). Third-party benchmark artifacts retain their own licenses and attribution; the MIT grant for Dragons does not replace their redistribution terms.

See [installation](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/blob/main/docs/INSTALLATION.md) for verified local usage.

## Contributions and feedback

Technical feedback and contributions are welcome, especially around detection accuracy, artifact coverage, false positives, evidence and flow analysis, documentation and tests. Include a reproducible example when reporting a detection gap; use inert fixtures and avoid sharing private configurations or credentials.
