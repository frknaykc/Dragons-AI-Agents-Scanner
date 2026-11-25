# Supported agent artifacts

[Overview](../README.md) · [Coverage evidence and upstream sources](AGENT_COVERAGE_REVIEW.md) · [Full discovery inventory](REFERENCE.md#installed-agent-environments-opt-in)

`dragonscan scan PATH` reads supported artifacts at an explicit local path. `dragonscan scan --installed-agents` **opts into** bounded discovery of known local roots; adding `PATH` includes that project. An identified location is not evidence that the agent is installed, running or connected. The table describes **static subsets**, not complete agent integrations. “Synthetic” means tests used inert fixtures; it does not mean a real installation was scanned.

| Agent | Static discovery status | Selected surfaces | Validation and gaps |
| --- | --- | --- | --- |
| Claude Code | **Supported subset** | User `.claude` and `~/.claude.json` MCP definitions, project `.claude` and root `.mcp.json`, skills and instructions | Synthetic. Explicit project-local MCP map only for matching project; approval, disabled lists and effective cross-file precedence **not verified**. Real install **not verified**. |
| Codex | **Supported subset** | User/project `.codex/config.toml`, known instructions/skills, neutral shared `~/.agents/skills`, TOML `mcp_servers` | Synthetic. Project trust and effective layered overrides **not verified**; real install **not verified**. |
| Cursor | **Partial** | `.cursor` MCP/settings, project `rules/*.mdc`, Cursor-owned user/project skills | Synthetic. Editor-managed rules, shared `.agents` ownership and activation **not verified**. Plain `.md` rule support is **not claimed**; real install **not verified**. |
| Cline | **Partial** | Known `.cline` MCP/settings, selected project rules/skills, neutral shared `~/.agents/skills` | Synthetic and prior metadata-only observation; **real artifact scan not verified**. Credential-bearing `providers.json`, histories and databases are excluded; hooks/plugins/workflows are not full coverage. |
| Hermes Agent | **Partial** | Known user `.hermes/config.yaml`, selected-profile instructions/skills/memories, static `mcp_servers` | Synthetic and [scoped local validation](HERMES_COVERAGE_ATTRIBUTION.md). No default fixed per-root artifact cap; depth, directory, parsing and correlation budgets still apply. Effective configuration merging and live server state are not resolved. |
| Kilo Code | **Partial** | Known user/project `kilo.json`/`kilo.jsonc`, project rules, static `mcp` | Synthetic; real installation not locally validated. Effective merged configuration and redirected roots are not reconstructed. |
| Zed Agent | **Partial** | Platform-known user settings and project `.zed/settings.json`, static `context_servers` | Synthetic; real installation not locally validated. Extensions and effective merged settings are excluded. |
| Goose | **Partial** | Known platform-specific user `config.yaml`, enabled supported `stdio`/`streamable_http` extensions | Synthetic; real installation not locally validated. Disabled, built-in or unsupported extensions do not become active server entries; extensions are **not executed**. |
| OpenClaw | **Partial** | Default `.openclaw/openclaw.json` strict-JSON subset; managed skills, default workspace skills/instructions/memory, neutral shared `~/.agents/skills` | Synthetic. JSON5-only syntax, custom/profile roots, configured extra directories, installation metadata and effective activation are not resolved. No real OpenClaw state or services were accessed. |
| Antigravity | **Not supported** (feasibility **partial**) | No agent-specific adapter | Shared `.agents`/`.gemini` locations do not establish Antigravity ownership. Agent-specific discovery and real-install validation **not verified**. |

“Supported subset” means documented files and the parser's recognized schema have synthetic coverage, **not** every product feature. Static inventory includes declared MCP definitions, not proof of a successfully started server. User-level opt-in may read local configuration; do not use it to infer a product's active policy. See the [dated source ledger](AGENT_COVERAGE_REVIEW.md) for per-surface provenance and version caveats. More agents have bounded selectors in the [technical reference](REFERENCE.md#installed-agent-environments-opt-in); this table answers the specifically reviewed set only.

## Shared user skills and OpenClaw defaults

Installed-agent discovery includes `~/.agents/skills` when no agent filter is
given, or when selecting Codex, Cline, OpenClaw, Goose, Kilo Code or Zed Agent. This is a neutral shared
location, not an inferred installed product: artifact origins retain `agent: null`.
Physical duplicates are scanned once while their source locations are retained.
An explicit project/directory scan does not implicitly add user-level roots.

OpenClaw discovery uses the existing adapter and bounded selectors for
`~/.openclaw/skills`, `~/.openclaw/workspace/skills` and
`~/.openclaw/workspace/.agents/skills`, plus known instruction names in the
default workspace. It does not crawl arbitrary adjacent state or follow a
configuration's redirected roots. See [scope, upstream sources and regression
evidence](DISCOVERY_DETECTION_VALIDATION.md) for exact limits and validation.

## Automatic discovery versus explicit selection

The following distinctions apply to the nine reviewed ecosystems. **Path** means
`scan PATH`; **installed** means opt-in known-home discovery, optionally with an
explicit project. A directory target stays inside that directory. It does not
search parent repositories, resolve the agent's active profile, or add a home
directory. A standalone file can retain generic classification even when an
installed location would select a product-specific parser.

| Ecosystem | Automatically recognized subset | Explicit selection and remaining limits |
| --- | --- | --- |
| OpenClaw | Installed `~/.openclaw/openclaw.json`, managed/default workspace skills and named workspace instructions; the same known layouts work as path targets. | Only strict JSON parses. JSON5 comments, trailing commas and single-quoted/unquoted syntax fail parsing; `.json5` is unsupported. `OPENCLAW_CONFIG_PATH`, named profiles, `$include`, configured workspaces and `skills.load.extraDirs` do not expand discovery. |
| Cursor | Project `.cursor/rules/**/*.mdc`, known `.cursor` MCP/settings and owned `skills/**/SKILL.md`. | An explicitly selected `.mdc` also uses the Cursor Markdown parser, including a downloaded rule outside `.cursor`. Other `.mdc` files outside the known rules tree are not auto-discovered. Arbitrary `.md` files in `rules/` do not become Cursor rules. |
| Hermes | Path discovery recognizes `.hermes.md`, `HERMES.md`, `AGENTS.override.md`, `AGENTS.md`, `CLAUDE.md` and legacy `.cursorrules`, including descendants. Installed discovery covers the fixed `.hermes` config/SOUL/skills/memories/cron subset and supported profile layouts. | The same instruction aliases work as explicit file targets. `HERMES_HOME` does not redirect automatic discovery. Select a custom root explicitly; arbitrary copied configs do not necessarily retain the Hermes adapter. No effective profile/config merging or instruction precedence is computed. |
| Goose | Installed platform config: `~/.config/goose/config.yaml` on macOS/Linux; `AppData/Roaming/Block/goose/config/config.yaml` relative to home on Windows. Shared user skills are included for `--agent Goose`; project `SKILL.md` files use ordinary path discovery. | A standalone Goose `config.yaml` can parse as generic configuration without the Goose extension adapter. `.goosehints` is unsupported even as an explicit file. No `CONTEXT_FILE_NAMES` expansion. |
| Kilo Code | Known user `~/.config/kilo/kilo.{json,jsonc}`, project `kilo.{json,jsonc}` / `.kilo/kilo.{json,jsonc}`, project `.kilo/rules/**/*.md` and skills, plus shared user skills. | `kilo.json[c]` keeps its adapter on direct selection. Installed discovery does not include the documented global `~/.kilo/skills` or legacy `.kilocode/rules` roots. Explicit directory targets still discover named `SKILL.md` files. `skills.paths`, `skills.urls` and instruction globs do not expand discovery. |
| Zed | Installed platform settings and `AGENTS.md` under `~/.config/zed` or Windows `AppData/Roaming/Zed`; project `.zed/settings.json`; shared user skills for `--agent 'Zed Agent'`. | Direct `.zed/settings.json` selects the adapter; direct user `settings.json` can remain generic and miss `context_servers` normalization. `AGENTS.md`, `CLAUDE.md` and `.cursorrules` have path support; most other Zed aliases, including `.rules` and `AGENT.md`, do not. |
| Claude Code | Named `CLAUDE.md` and `SKILL.md`, known `.claude/settings.json`, installed `~/.claude.json`, project `.mcp.json`. | The generic `CLAUDE.local.md` name and arbitrary `.claude/{rules,commands,agents}/*.md` names are unsupported. `settings.local.json` has no dedicated override/merge model. Generic parsing is not evidence of effective settings. |
| Codex | Named `AGENTS.md` and `AGENTS.override.md` at each scanned level, `.codex/config.toml`, owned skills and shared user skills. `AGENTS.override.md` alone is sufficient to identify a `.codex` root. | Both instruction names work as explicit targets. `CODEX_HOME`, `project_doc_fallback_filenames` and root-to-CWD precedence do not change discovery. Both base and override files remain in the static inventory. |
| Cline | Known `.cline/data/settings/{global-settings,cline_mcp_settings}.json`, `.cline/rules/**/*.md`, `.cline/skills/**/SKILL.md`, project `.clinerules/**/*.md` and shared user skills. | Known settings retain their adapter on direct selection. The single-file `.clinerules` alias, `CLINE_DIR`, `~/Documents/Cline` compatibility paths and `~/.agents/AGENTS.md` are not automatic installed coverage. Workflows, agents, hooks and plugins do not have complete discovery. Credential-bearing `providers.json` stays excluded. |

Shared skills keep neutral origins (`agent: null`) regardless of the selected
consumer. The bounded shared inventory is not a simulation of each product's
catalog: for example, Zed documents only direct-child skill directories, whereas
Dragons can inventory nested `SKILL.md` files within its existing depth budget.
The scanner does not claim those nested files are active Zed skills. Likewise,
same-name project and user skills remain separate origins rather than applying
runtime shadowing.

## Instruction semantics and local references

- **Cursor:** `.mdc` frontmatter separates `description`, `globs` and
  `alwaysApply` from actionable body text. Missing, malformed or unsupported
  frontmatter produces a diagnostic and partial coverage. The scanner does not
  decide which rules an editor activated or expand globs against edited files.
- **Hermes and Codex:** upstream loaders implement per-directory overrides and
  root-to-current-directory precedence. Hermes also has its own alias order.
  Dragons inventories supported files inside the selected root, including
  shadowed files; it does not assemble an effective system prompt. Generic
  `AGENTS.override.md` does not imply ownership by either product.
- **Goose, Zed, Claude Code and Cline:** product-specific fallback orders,
  toggles, path-scoped activation, Claude `@path` imports and nested loading
  are not emulated. A discovered Markdown document only establishes content
  available for static analysis.
- **Structured configuration:** adapters recognize distinct schemas: Goose
  `extensions`, Kilo `mcp`, Zed `context_servers`, Hermes/Codex `mcp_servers`,
  and supported Claude/Cline/Cursor `mcpServers`. Matching filenames or field
  names do not make these schemas interchangeable. Generic string inspection
  does not establish a documented execution or file-loading relationship.
- **Local references:** explicit Markdown load directives can create
  `loads_file` relations; links alone remain references. Kilo `instructions`
  supports a bounded literal relative `.md` relation, not glob expansion.
  Graph resolution stays under the selected root and can link already parsed
  artifacts; it does not recursively load referenced content. Missing,
  unsupported, outside-root and symlink targets do not create proven execution
  paths. No URLs, commands, plugins or imported files run during static scanning.

## Reading completeness correctly

`complete` and `fully_analyzed` describe the selected **supported static
analysis**, not every upstream setting, every file on disk or the agent's
effective runtime behavior. Unsupported names and unselected custom roots are
outside discovery totals. Unknown fields may receive generic content analysis
without a dedicated semantic model or an individual unsupported-field warning.
In particular, a strict-JSON OpenClaw file can parse without resolving its
`$include` or redirected roots. Do not interpret that as complete OpenClaw
configuration coverage.

A recognized JSON5-only OpenClaw configuration produces a parse diagnostic:
alone it is `failed`; beside a parsed supported artifact it makes the scan
`partial`. Malformed Cursor frontmatter and reached discovery budgets also
prevent a clean `complete` result. JSON and SARIF use the same policy as terminal
reports. See [analysis coverage](REFERENCE.md#analysis-coverage) for counter and
exit-status definitions.

### Upstream format references

Paths and semantics above were checked against these public references on
2026-11-25. Upstream formats can change independently of scanner support.

- [OpenClaw configuration](https://docs.openclaw.ai/gateway/configuration) and [skills](https://docs.openclaw.ai/tools/skills)
- [Cursor rules](https://cursor.com/docs/context/rules)
- [Hermes context files](https://hermes-agent.nousresearch.com/docs/user-guide/features/context-files) and [skills](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills)
- [Goose skills](https://github.com/block/goose/blob/main/documentation/docs/guides/context-engineering/using-skills.md), [hints](https://github.com/block/goose/blob/main/documentation/docs/guides/context-engineering/using-goosehints.md) and [configuration](https://github.com/block/goose/blob/main/documentation/docs/guides/config-files.md)
- [Kilo skills](https://kilo.ai/docs/customize/skills) and [rules](https://kilo.ai/docs/customize/custom-rules)
- [Zed skills](https://github.com/zed-industries/zed/blob/main/docs/src/ai/skills.md) and [instructions](https://github.com/zed-industries/zed/blob/main/docs/src/ai/instructions.md)
- [Claude directories](https://code.claude.com/docs/en/claude-directory) and [memory/imports](https://code.claude.com/docs/en/memory)
- [Codex instruction discovery](https://developers.openai.com/codex/guides/agents-md/) and [skills](https://developers.openai.com/codex/skills/)
- [Cline configuration](https://docs.cline.bot/getting-started/config)
