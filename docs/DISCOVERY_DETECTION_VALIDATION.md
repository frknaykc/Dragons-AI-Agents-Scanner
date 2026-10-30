# Shared skills, OpenClaw and encoded-execution validation

Snapshot: 2026-10-30. This follow-up supersedes the discovery gaps in
[the earlier research snapshot](DETECTION_RESEARCH.md), not its historical test
counts. Results below use inert local fixtures, not real installed-agent state.

## Discovery audit and supported subset

The existing pipeline remains discovery/classification → bounded loading →
`Document` parsing → behavior and independent detectors → bounded evasion views →
proven graph/flow correlations → risk/policy and terminal/JSON/SARIF reporting.
`installed_agents.py` still delegates skill traversal to `discovery.py`; no
second discovery or detection engine was introduced.

| Entry point | Supported selection | Scope and limits |
|---|---|---|
| Explicit supported file | Known skill/instruction/config file; verified OpenClaw workspace aliases | Original file identity, source format and finding location retained |
| Explicit directory | Supported files beneath the selected boundary, including project `.agents/skills` | Does not implicitly add home roots or follow external references |
| Installed-agent scan | Existing known agent roots plus neutral `~/.agents/skills` | Explicit opt-in; no home-directory crawl |
| Selected agent | Shared user skills included for Codex, Cline and OpenClaw, or with no agent filter | Shared origins have `agent: null`; a potential consumer is not an ownership claim |
| OpenClaw defaults | `~/.openclaw/openclaw.json`, root instruction subset, `skills`, `workspace/skills`, `workspace/.agents/skills`, known workspace instruction names and `workspace/memory/*.md` | Existing adapter extended, not newly invented; generic adjacent config/history files excluded |

OpenClaw documents workspace and personal shared skill roots and local skill
precedence; Cline also documents global `~/.agents/skills`.[1][5] Codex's skill
format uses `SKILL.md` plus optional scripts/resources.[4] Dragons inventories
supported local files, not which copy the runtime actually activates.

OpenClaw's workspace map includes AGENTS, SOUL, TOOLS, IDENTITY, USER, HEARTBEAT,
BOOT, BOOTSTRAP, MEMORY and dated memory files.[2] Its configuration supports
JSON5 and custom workspace selection.[3] This adapter supports the **strict-JSON
subset** of the default config; unsupported JSON5 syntax fails visibly rather
than being repaired or executed. Custom state/profile roots, configured extra
skill directories and workspace redirection are not followed automatically.

The official skill-format examples document `metadata.openclaw`, dependency
installation declarations, `.clawhub/origin.json` and `.clawhub/lock.json`.[11]
These are **not** normalized as installation provenance or verified activation
state. Missing/malformed optional skill metadata does not prevent Markdown-body
analysis; `SKILL.md` frontmatter is not a complete OpenClaw schema validator.
Supporting scripts, arbitrary adjacent files and MCP/tool runtime behavior are
not newly supported. Local links retain the existing relationship model; they
do not authorize opening targets outside the selected boundary or running code.

The neutral shared group appears only when artifacts or a meaningful diagnostic
exist. Physical hardlinks are scanned once while their distinct origins are
retained. A neutral origin updates only the environment with the same root and
source, so parse failures do not falsely leave it complete. Symlink escapes,
loops, unreadable entries and explicit traversal limits retain diagnostics.
No fixed total-artifact cap was added. Resource/depth limits remain bounded;
145-skill collections and six-level nested skills have regression coverage.

## Detection coverage and selected improvements

VirusTotal describes malicious prerequisites and encoded delivery in skills;
Invariant demonstrates tool-description poisoning; Snyk describes an injection
chain reaching CI/cache/package publication.[8][9][10] These are documented attack
techniques, **not** evidence that every related payload is detected or that a
local finding represents an attack that ran. No malicious sample or IOC URL was
retrieved. The exact synthetic command variants below are not claimed to be
published attack payloads.

| Technique / relevant artifacts | Current detection | Confirmed gap / classification | Action |
|---|---|---|---|
| Active prompt override in SKILL/instruction Markdown | Context-aware PI rules | Already supported for explicit forms | Retain quote/negation controls |
| Hidden/transformed instructions | Bounded evasion views with original provenance | Already supported subset; arbitrary transformations unsupported | Retain resource and action-context limits |
| Tool poisoning in declared MCP metadata | PI/MCP detectors on normalized fields | Live/changed tool descriptions unsupported offline | No runtime probing |
| Credential theft and exfiltration | Explicit sensitive access and linked source→sink evidence | Arbitrary paraphrases need further research | No keyword-only rule; ordinary memory reads remain benign |
| Remote execution / installation instructions | Existing literal fetch→interpreter EXEC rules | Already supported subset | Retain regression suite |
| Literal encoded `echo -n` input | Existing EXEC-003 required a two-token `echo` | Confirmed FN, fixed | Accept exactly one `-n` flag and one literal token |
| Explicit shell stdin selection | Existing EXEC-003 required bare shell argv | Confirmed FN, fixed | Accept `sh`/`bash -s` and `-s --`, without further operands |
| Persistence in agent instructions | Existing persistence signals | Further research needed for new discriminating forms | No speculative new rule |
| Supply-chain/CI compromise | Visible declarations, install behavior and supply-chain indicators | Registry/cache integrity unsupported by local static declarations | Keep offline default and optional intelligence separate |
| Cross-file instruction chains | Proven local relationships and PATH/FLOW rules | Unresolved/derived-only references cannot prove a path | Preserve frozen boundary cases |
| Runtime indirect injection / temporal tool replacement | Supported local inputs can be examined | Unsupported input/temporal model | No new runtime or snapshot subsystem |

The Bash manual documents `echo -n` suppressing its final newline and `-s`
reading commands from standard input.[6][7] The root cause was exact argv
recognition in `literal_encoded_pipeline`, not a parser or evasion-depth failure.
Six inert positives failed before the change; all pass afterward. They exercise
Base64 (`-d`, `-D`, `--decode`), hex, shell and Python stdin through the public
scanner. Assertions retain original line 3, source/sink labels, fixed evidence
and absence of literal/decoded bytes from evidence.

The expanded hard negatives cover quotation, documentation, negation, variables,
invalid data, extra pipeline stages, output-only decoding, file operands,
`-c`, syntax-check `-n`, and ambiguous mixed flags. The pipeline accepts only
unambiguous argv; it does not evaluate shell expressions or script operands.
There are 60 added hard-negative instances and six added positives. The existing
48 IDs, EXEC-003 high severity/high confidence, 4096 input/decoded limits and
non-executing behavior remain unchanged. No graph path is synthesized.

## Verification

| Gate | Observed result |
|---|---|
| M1 checkpoint | `8d0bc8163594cdf50ad6c7781094377f9a55d929`, normal push to `main` |
| Exact-SHA GitHub CI | Run `40983376954`, completed / success; does not cover uncommitted M2/M3 |
| Reviewed safe static pytest selection | 896 passed; includes CLI/TUI/reporting, MCP, behavior, evasion, supply-chain, graph and flow |
| Separate focused discovery/parser selection | 272 passed, including 45 new shared/OpenClaw cases and 44 malformed-MCP cases |
| Detection suite within static selection | 185 passed; not an additional disjoint test total |
| Ruff / type checks | Lint and format passed; `mypy src scripts` passed on 65 source files |
| Finding inventory | 48 IDs |
| Phase 2 v2 | 8 TP / 0 FP / 0 FN |
| Phase 6 v2 | 21 TP / 0 FP / 3 FN; existing FNs remain unresolved |

An isolated source install used the committed archive plus the three changed
runtime modules, its own virtualenv and `uv sync --locked --offline`. Ten CLI
entry-point smoke checks passed against that installed package: help, file and
directory scans, selected Codex/shared and OpenClaw/shared/workspace discovery,
partial malformed configuration, failed invalid-UTF-8 and missing targets, and
JSON/SARIF encoded-execution findings with an explicit high-severity policy.
The smoke runner used a synthetic home and empty credential environment; no
network/process audit tripwire fired. Scan checks invoked the CLI through
`CliRunner`; the installed `dragonscan --help` console entry point was also
launched separately with a synthetic home and empty credential environment.
This is a cached source installation, not a fresh online/PyPI or cross-platform
packaging claim.

These are separate selections, **not a full-suite result**. No tests were globally
skipped or assertions weakened. Process/network/provider/YARA-X integration
suites were not run. Python audit tripwires recorded no forbidden process,
network or real-private-state access in the reported selections; these checks
are not an OS sandbox. Benchmark verification retained its narrow permission for
`git rev-parse HEAD` metadata only. Frozen inputs and expectations were not edited.

The intermittent TUI hover issue remains **unresolved**, not fixed: the M1 bounded
six-case repeat matrix passed, as did the final selected TUI suite, but no reliable
root-cause reproduction was found. CLI/TUI design files were not changed.

At this validation snapshot, M2/M3 were uncommitted for review. Root `AGENTS.md`, private semantic results,
local benchmark work and incomplete YARA-X experiments are outside this change.
An independent read-only review found no confirmed correctness/security defect
in the scoped production/test changes; it did not run tests or modify files.
No release, tag, runtime dependency, parser-limit change, cloud requirement or
next-milestone implementation was introduced.

## Sources

[1] https://docs.openclaw.ai/tools/skills
[2] https://docs.openclaw.ai/concepts/agent-workspace
[3] https://docs.openclaw.ai/gateway/configuration
[4] https://learn.chatgpt.com/docs/build-skills
[5] https://docs.cline.bot/getting-started/config
[6] https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html
[7] https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html
[8] https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html
[9] https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
[10] https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions
[11] https://docs.openclaw.ai/clawhub/skill-format
