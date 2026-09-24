# Dragons AI Agent Scanner

Local-first, static security scanning of selected AI agent artifacts. See [IDEA.md](IDEA.md) for the broader product vision and [AGENTS.md](AGENTS.md) for contributor safety rules.

## Current scope

`dragonscan scan PATH` accepts a local file or directory. It recognizes `SKILL.md`, `AGENTS.md`, `SOUL.md`, `MEMORY.md`, `CLAUDE.md`, `mcp.json`, `.mcp.json`, `mcp-config.json`, and `claude_desktop_config.json` (case-insensitive). Within `.claude`, `.codex`, `.cursor`, `.gemini`, `.windsurf` and `.openclaw` trees it also recognizes `config`/`settings` JSON, YAML or TOML files and `hooks.json`; `.claude-plugin/plugin.json` is plugin metadata, and `package.json` under `skills/` is a dependency manifest. Explicit `config`/`settings` files are accepted even without ecosystem context. Other unrelated JSON/YAML/TOML files are ignored in directory scans; explicit unsupported files produce an error. Ecosystem is reported only when the directory context identifies it. A generic config with a top-level `mcpServers` object is reclassified as MCP configuration after parsing.

Files are read locally as UTF-8, up to 1 MiB each; symlinks and binary/NUL data are rejected. Markdown, JSON, YAML and TOML are parsed as inert data; neither fenced code nor MCP commands are run. YAML aliases and unsafe tags are rejected, and structured nesting/node counts are bounded. Malformed files generate scan errors, not security findings. Scanning does not fetch URLs, launch servers, or install referenced packages. The only detections remain a credential-read instruction paired with an external send instruction and an MCP shell command string that pipes a download into a shell; no other detections are claimed.

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

The scanner pipeline is in `src/dragonscan/`: discovery/classification, bounded loading, format-dispatched parsing into `Document`, rule detection, risk aggregation, then terminal/JSON reporting. `Document` retains Markdown blocks/spans, structured entries with key paths and typed values, MCP server metadata, explicit relationships, and source references (path, format and line/range where the parser provides it). JSON/TOML entries and server definitions from those formats have no precise line information; YAML entries and servers retain line ranges. Markdown inline references use their enclosing block's line range. Secret-bearing `env`/header values are not retained in normalized entries; MCP metadata stores environment-variable **names** only. URLs in configuration metadata are stripped of credentials, query and fragment. Raw untrusted content is not included in parser diagnostics.

JSON output retains `path` and `kind` for each artifact and adds `source_format` and nullable `ecosystem`; the finding schema and exit codes are unchanged. The built-in instruction rule now applies to instruction/skill/memory/soul documents and the MCP rule also examines embedded servers in agent settings. Custom `Rule.artifact_types` values should use the `ArtifactKind` string values (`skill`, `memory`, `soul`, `agent_config`, etc.); detector call signatures remain unchanged. `Scanner(rules=...)` accepts Python `Rule` objects without changes to the CLI. Tests materialize inert corpus strings under exact artifact filenames in pytest temporary directories; never execute or install their contents. Source distributions exclude tests and test artifacts.

Not implemented: remote repository/archive/system scanning, script AST parsing or execution, dynamic inspection, SARIF/Markdown output, dependency resolution, taint/attack-path analysis, network lookups, or semantic/LLM analysis. The parsed relationships record explicit references only; they do not establish that referenced files, packages or URLs are safe or reachable.
