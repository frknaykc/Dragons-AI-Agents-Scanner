![Dragons AI Agent Scanner banner](banner.png)

# Dragons AI Agent Scanner

Local-first, static security scanning of selected AI agent artifacts. See [IDEA.md](IDEA.md) for the broader product vision and [AGENTS.md](AGENTS.md) for contributor safety rules.

## Current scope

`dragonscan scan PATH` accepts a local file or directory. It recognizes `SKILL.md`, `AGENTS.md`, `SOUL.md`, `MEMORY.md`, `CLAUDE.md`, `mcp.json`, `.mcp.json`, `mcp-config.json`, and `claude_desktop_config.json` (case-insensitive). Within `.claude`, `.codex`, `.cursor`, `.gemini`, `.windsurf` and `.openclaw` trees it also recognizes `config`/`settings` JSON, YAML or TOML files and `hooks.json`; `.claude-plugin/plugin.json` is plugin metadata, and `package.json` under `skills/` is a dependency manifest. Explicit `config`/`settings` files are accepted even without ecosystem context. Other unrelated JSON/YAML/TOML files are ignored in directory scans; explicit unsupported files produce an error. Ecosystem is reported only when the directory context identifies it. A generic config with a top-level `mcpServers` object is reclassified as MCP configuration after parsing.

Files are read locally as UTF-8, up to 1 MiB each; symlinks and binary/NUL data are rejected. Markdown, JSON, YAML and TOML are parsed as inert data; neither fenced code nor MCP commands are run. YAML aliases and unsafe tags are rejected, and structured nesting/node counts are bounded. Malformed files generate scan errors, not security findings. Scanning does not fetch URLs, launch servers, decode payloads, or install referenced packages. Detections are **static indications**, not proof of compromise or execution.

Built-in detections retain `DAAS-001` (credential file read linked to an external send) and `DAAS-002` (MCP download piped into a shell). New `DRAGON-*` IDs cover instruction override and security bypass (`PI`), sensitive-data access (`CRED`), linked source-to-external-sink transfers (`EXFIL`), instructed download-to-shell execution (`EXEC`), modification of persistent agent guidance (`PERSIST`), promotion of remote instructions to policy (`TRUST`), bidirectional format controls and Base64 decode-to-shell (`OBF`), and unpinned runtime packages or URL-embedded credentials in MCP definitions (`MCP`). Each finding has a separate severity (potential impact) and confidence (evidence strength); the overall risk is the highest finding severity, not a probability score. Sensitive access alone is lower severity than an explicitly linked transfer. Findings include the affected artifact and available line, a bounded explanation, sanitized evidence and, where applicable, generic source/sink labels. Reported URLs and credential values are never copied into finding evidence.

```sh
uv sync
uv run dragonscan scan ./AGENTS.md
uv run dragonscan scan ./AGENTS.md --format json
uv run dragonscan scan ./agent --fail-on high
```

Exit code 0 means no finding at the selected threshold, 1 means at least one finding meets it, and 2 means a scan error or invalid CLI usage. A scan with unreadable/malformed artifacts is incomplete and exits 2 even if other findings are present. `--fail-on` defaults to `high`.

## Development

Python 3.12+ and `uv` are required. `uv.lock` records resolved dependencies.

```sh
uv run pytest
uv run ruff format --check .
uv run ruff check .
uv run mypy src
```

The scanner pipeline is in `src/dragonscan/`: discovery/classification, bounded loading, format-dispatched parsing into `Document`, local behavior observation, independent legacy and new detectors, risk aggregation, then terminal/JSON reporting. `Document` retains Markdown blocks/spans, structured entries with key paths and typed values, MCP server metadata, explicit relationships, and source references (path, format and line/range where the parser provides it). JSON/TOML entries and server definitions from those formats have no precise line information; YAML entries and servers retain line ranges. Markdown inline references use their enclosing block's line range. Soft/hard breaks in Markdown instructions retain their line separation. Secret-bearing `env`/header values are not retained in normalized entries; MCP metadata stores environment-variable **names** only. URLs in configuration metadata are stripped of credentials, query and fragment; a boolean records whether MCP URL userinfo was present. Raw untrusted content is not included in parser diagnostics.

JSON output retains `path` and `kind` for each artifact and adds `source_format` and nullable `ecosystem`; the finding schema and exit codes are unchanged. Existing `DAAS-*` IDs, CLI options, and `Rule.detect(Document)` signatures remain supported. `Scanner(rules=...)` selects only those legacy Python rules as before; `Scanner(detectors=...)` may select contextual detectors alongside the default legacy rules. New `EngineDetector.detect(DetectionContext)` takes a document, non-secret observations, and prior findings **from that artifact**. `DetectionMetadata` validates IDs, required fields, impact/confidence/classification and applicable artifact types; `DeclarativeDetector` uses exact observation kinds rather than evaluating an untrusted rule expression. There is no rule-file loader or YARA compatibility in this release. Custom `Rule.artifact_types` values should use the `ArtifactKind` string values (`skill`, `memory`, `soul`, `agent_config`, etc.). Tests materialize inert corpus strings under exact artifact filenames in pytest temporary directories; never execute or install their contents. Source distributions exclude tests and test artifacts.

Not implemented: remote repository/archive/system scanning, script AST parsing or execution, dynamic inspection, SARIF/Markdown output, dependency resolution, cross-artifact taint/attack-path analysis, network lookups, or semantic/LLM analysis. The source/sink check is limited to an explicitly linked instruction and a two-line window; it does not follow variable flows or prove that data leaves the host. Context filters suppress many quoted/code/negated examples, but static heuristics can still miss paraphrases or misread unusual prose. The parsed relationships record explicit references only; they do not establish that referenced files, packages or URLs are safe or reachable.
