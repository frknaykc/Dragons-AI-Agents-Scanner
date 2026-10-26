# CLI guide

[Overview](../README.md) · [Install first](INSTALLATION.md) · [Findings and reports](FINDINGS_AND_REPORTS.md)

All source-checkout examples use `uv run dragonscan`. Run `uv run dragonscan --help` and `uv run dragonscan scan --help` for the current flags; earlier help captures: [main](assets/cli/main-help.txt), [scan](assets/cli/scan-help.txt). The examples below use bundled inert fixtures where actual output is quoted. Paths such as `./agent-directory` and `./bundle.zip` are placeholders for **your local files**, not bundled samples. [Real Terminal screenshots and reproduction details](../assets/screenshots/README.md).

## Interactive terminal

Run `uv run dragonscan` for a line-oriented, icon-led menu with numbered choices for all known local agents, one known agent or a local file/directory. Enter a choice and, when needed, an agent or path; review the target and answer the explicit scan confirmation. Choosing No cancels without scanning. The CLI uses the same static scanner and terminal report as a one-shot scan, but it does not provide the full-screen TUI's scope controls or results tree. Run `uv run dragonscan scan` without a target for the same menu. Both menu entry points require terminal input and output; neither runs in a pipe or CI job.

Run `uv run dragonscan -tui` in an interactive terminal to open the Textual interface. A centered Braille dragon with an animated loading indicator leads straight to target selection. The banner shows a centered DRAGONSCAN block-letter wordmark above “AI AGENT SCANNER”, with package version and local/static status in a side column on wide terminals. Smaller terminals use a compact wordmark or plain text and hide the side column. A separate welcome panel sits above three supported target rows; on spacious terminals the Braille dragon appears as a decorative side panel, while narrower terminals keep the form full width. Shortcuts appear in a compact icon-and-label bar: the leading action is highlighted, while each hint keeps its actual key in brackets. The labels follow the current step and shorten or disappear when terminal width is limited. The icon-led target rows distinguish all agents, one agent and a local path without suggesting numbered shortcuts. These are keyboard hints, not clickable controls. Click a target row to select it, or use the arrow keys. Enter on One known agent expands a labeled agent picker; Enter on the picker opens its list, Up/Down selects an agent and Enter confirms. Enter on Specific file / directory expands a labeled path input with local relative-path examples (such as `./agent-directory/SKILL.md` or `./agent-directory`); type your local path there. The expanded panel can also be opened by clicking the selected row again. Esc closes the list first, then collapses the detail panel. Tab reaches the panel’s Continue button, which also works with a mouse; Enter in the path input continues once a path is supplied. Shorter terminals scroll the detail area to keep the active field and example visible. Tab/Shift-Tab moves between fields, Up/Down and Space change list selections. On the Ready to scan screen, review the target and limits; Enter or the Start local scan button begins analysis, while Esc returns to scope (or first closes an open agent menu). On the results screen, focus starts on the agent tree when scanned artifacts exist (otherwise on export). Agents list associated scanned paths and findings grouped by severity; a shared artifact appears beneath each associated agent, while explicit or unassociated artifacts appear under Local target. Expand agents and severity groups with Enter or Right, collapse with Left, and select entries with Up/Down or a mouse click. The inspector on the right (below the tree on narrow terminals) shows a selected finding’s severity, confidence, artifact location, evidence, reason and remediation, or the full scanned path. Tab reaches export controls, Ctrl+E exports, and Ctrl+R starts a new scan. The results screen keeps coverage status (COMPLETE, PARTIAL or FAILED) and severity counts visible above the tree and diagnostics, even after export; “no findings” only describes analyzed content. In installed-agent mode, adjust entries per root, total/per-root artifacts and traversal depth; all supported file types remain enabled. For a local directory, choose supported artifact groups, adjust artifact budget and optionally limit traversal depth (root is depth 0). Type-group filtering does not apply inside archives, and depth/budget options require a directory. A deliberately reduced scope is marked as partial, not clean for excluded files; reaching the artifact budget is reported conservatively as incomplete coverage. During scanning an animated indicator shows activity, not a percentage. Findings expand by agent and severity; coverage diagnostics remain a separate selectable tree entry; the result can be exported to a **new** file as text, JSON or SARIF. The interface never overwrites an existing export and does not enable network-based analysis or dynamic execution. It requires a terminal; scripts and redirected commands should pass a target or `--installed-agents` directly (with or without `scan`).

To copy text from the interface, drag to select it and press Ctrl+C. On macOS, the selection is also sent to the system clipboard; on other platforms, copying uses the terminal's clipboard support (OSC 52). Ctrl+C without a selection does not copy. For terminal-native selection instead, use your terminal's selection modifier and copy shortcut.

## Help and first scan

```sh
uv run dragonscan --help
uv run dragonscan -tui
uv run dragonscan scan --help
uv run dragonscan benchmarks/corpus/benign-credential-guide/AGENTS.md
uv run dragonscan --installed-agents --agent Codex --format json
```

Help prints usage and exits **0**. The bundled sample scan exits **0** with `COMPLETE`, `PASS` and no findings; no target content is executed. [Help screenshot](../assets/screenshots/dragons-help.png) · [Clean scan screenshot](../assets/screenshots/dragons-clean-scan.png). Initial `uv run` may resolve this project's dependencies unless the environment is already synced; use `uv sync --locked` first ([installation](INSTALLATION.md)).

## Local file and directory

```sh
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md
uv run dragonscan scan ./agent-directory
```

Use the first command for one supported artifact and the second for a local directory of supported artifacts. The first was verified: `Status COMPLETE`, `Policy PASS`, `Findings 0`, exit **0** ([full terminal capture](assets/cli/clean-scan.txt)). Directory scanning is useful for configs and skills in the same tree; the placeholder command requires a directory you provide. Normal scans do not traverse installed-agent homes. Missing targets return **3** with a grouped operational diagnostic; [verified diagnostic capture](assets/cli/diagnostic.txt). An unsupported or unreadable target may also return **3**.

A local directory scan normally stops with an operational error if it contains more than 10,000 classified artifacts; no truncated result is shown as complete. To raise that budget, use `uv run dragonscan scan ./agent-directory --max-artifacts 20000`. This option does not apply to archives, remote acquisitions or local Git mode. Only supported classified files are analyzed; skipped symlinks, excluded names, unreadable files and per-file parser limits still apply.

## Installed-agent discovery (explicit opt-in)

```sh
uv run dragonscan scan --installed-agents
uv run dragonscan scan ./project --installed-agents
```

The first scans known user-level roots; the second adds the explicitly selected project. Use only when you consent to reading those local locations. The [supported agents table](SUPPORTED_AGENTS.md) identifies what is selected. These commands were checked against CLI parsing and scanner implementation but **not run on a real user installation for this guide**. A known location does not prove installation, activation or runtime MCP connectivity. Resolution can be partial (exit **3**), and a complete result with no gated findings exits **0**.

With default terminal output, `--installed-agents` saves a separate private JSON report under `~/dragonscan-*/scan.json` and prints its location. `--format json`/`sarif` or `--output PATH` use the selected output instead. To focus or enlarge **known user-root discovery**, for example: `uv run dragonscan scan --installed-agents --agent Codex --max-entries-per-root 10000 --max-artifacts 2000 --max-artifacts-per-root 1000 --max-depth 12`. Each option accepts a positive integer; omitted options retain defaults (2,048 entries per root, 256 artifacts globally, per-root caps set by the agent layout and layout-specific depth). `--agent` selects a documented agent identity; it is only valid with `--installed-agents`. These overrides do not change the separately bounded explicit project scan, the 1 MiB per-file loader, supported formats, symlink/credential exclusions or detector budgets. On exhaustion the report retains a coverage diagnostic and partial resolution; a complete status does not prove all possible agent data was scanned.

## Severity gate and completion

```sh
uv run dragonscan scan benchmarks/corpus/pi-override/SKILL.md --fail-on high
uv run dragonscan scan ./agent-directory --fail-on high --fail-on-incomplete
```

The first uses an inert synthetic detection fixture. It produced `Status COMPLETE`, `Risk HIGH`, `Policy POLICY_VIOLATION`, `DRAGON-PI-001` (high confidence) and exit **1**. The finding's original path is absolute, so it is **not embedded in this guide**. The [security-finding](../assets/screenshots/dragons-security-finding.png) and [severity-gate](../assets/screenshots/dragons-severity-policy.png) screenshots use a copy in a generic shared demo directory; their exact setup and commands are in the [capture log](../assets/screenshots/README.md). `--fail-on` accepts `critical`, `high`, `medium`, `low`, `info` (lowercase); it gates a completed scan at or above the selected severity. `--fail-on-incomplete` additionally gates selected semantic candidate coverage and partial installed-agent resolution; analysis diagnostics can already make a scan partial. A partial/failed scan exits **3** even if it also has threshold findings.

Interactive terminal output colors severity/status labels; output redirected to a file or disabled with `NO_COLOR` is plain text. Findings are ordered by severity; a summary at the top shows status, risk, counts and policy. Operational `ERROR`, `WARNING` and `COVERAGE` diagnostics are grouped separately from security findings.

## JSON and SARIF exports

```sh
uv run dragonscan scan benchmarks/corpus/benign-credential-guide/AGENTS.md --format json --output scan.json
uv run dragonscan scan benchmarks/corpus/pi-override/SKILL.md --format sarif --output scan.sarif --fail-on high
```

JSON and SARIF `--output` were also exercised on the synthetic finding with exit **0** (no severity gate); both produced parseable local files. The `--output` destination must have a writable parent and stays local. It suppresses stdout but **does not suppress exit 1 or 3**. Inspect the file and exit code separately. The gated finding SARIF has `ruleId: DRAGON-PI-001`, `level: error`, `startLine: 1`, `runs[0].properties.policy.status: policy_violation`; unlike terminal/JSON, its repository URI is relative. [Report fields and a path-free SARIF excerpt](FINDINGS_AND_REPORTS.md).

## Local archives and Git trees

```sh
uv run dragonscan scan ./bundle.zip
uv run dragonscan scan ./checkout --git
```

Use archives for local `.zip`, `.tar`, `.tar.gz` or `.tgz` targets; acquisition is bounded and scanning remains static. `--git` selects a **local** working tree; it does not clone, fetch or execute Git. The flags were checked in CLI and acquisition code, not run against a documentation-specific archive. Exit codes follow the same policy; extraction/validation failures yield **3**. See [archive safeguards](REFERENCE.md#archive-git-and-remote-targets).

## Network and optional intelligence

```sh
uv run dragonscan scan https://example.org/public/SKILL.md --remote
uv run dragonscan scan ./project --vuln-check
uv run dragonscan scan ./project --intel ./trusted-feed.json
```

These are **syntax examples, not executed in this guide**. `--remote` fetches one explicitly provided public HTTPS artifact, not a Git repository; the placeholder URL is not asserted to exist. `--vuln-check` sends normalized package names and exact versions over HTTPS to OSV. `--intel` loads a separately selected **local** feed and can be repeated; `dragonscan intel update --url ... --sha256 ... --store ...` is a separate operator-invoked network operation, not part of a scan. Do not run these on sensitive data without reviewing the [network and privacy boundaries](SECURITY_MODEL.md).

## Experimental semantic mode

```sh
uv run dragonscan scan ./project --semantic --semantic-url https://trusted-provider.example/v1/chat/completions --semantic-model MODEL
```

**Configuration syntax only; no model was called.** Requires an explicitly chosen trusted OpenAI-compatible provider and model. It can transmit selected, best-effort-redacted excerpts; provider credentials are read from documented environment variables, not CLI arguments. Model opinions are not deterministic evidence. The private-HTTP exception and separately consented, unsandboxed dynamic MCP mode are described in the [technical reference](REFERENCE.md). Ordinary scans never enable either one.

## Exit status and policy

| Code | Meaning | Observed example |
| --- | --- | --- |
| **0** | Completed scan, no requested severity violation; findings may exist | Benign fixture |
| **1** | Completed scan, `--fail-on` threshold met | Synthetic `pi-override` fixture |
| **2** | Invalid CLI usage/option | Click usage validation |
| **3** | Scan failed or analysis incomplete | Missing target fixture |

`COMPLETE`, `PARTIAL`, `FAILED` describe analysis completion. `PASS`, `POLICY_VIOLATION`, `INCOMPLETE`, `SCAN_ERROR` describe the decision. Severity measures impact, confidence measures evidence strength. Neither status nor severity certifies that the scanned code is safe. See [report interpretation](FINDINGS_AND_REPORTS.md).
