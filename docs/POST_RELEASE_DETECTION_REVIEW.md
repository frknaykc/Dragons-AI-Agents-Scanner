# Post-release validation and detection review

Review date: 2026-11-04. Public release: [v0.1.0](https://github.com/frknaykc/Dragons-AI-Agents-Scanner/releases/tag/v0.1.0), source `9709d71bb9d4a9ec997a3fbca508646b954607bc`.

The detection changes described below are **unreleased working-tree changes**. They do not change the published wheel or sdist. This review evaluates static evidence, not successful exploitation or general malware-detection accuracy.

## Published distribution and usability

The public release was accessible without authentication. The annotated tag resolves to the approved source. Its only uploaded assets are the wheel, sdist and `SHA256SUMS`; no standalone executables or private reports were uploaded. Downloaded bytes matched the published checksums:

| Asset | SHA-256 |
|---|---|
| Wheel | `3e7a6241d7a74cb579ce92a7b2b94bd499091de07a7ab5ca800b3bce2f43542e` |
| Sdist | `22b6577b190cc2b9e4c95eafe4208e567c599eb254a4b05393ea32c75fb4ed39` |
| SHA256SUMS | `e7306b314277af7aefc864f6110c1b8fc258ff5998f43c5ba8de8b8e0509ae48` |

Fresh `uv tool` and pip virtual-environment installations used the downloaded wheel, separate from the development checkout, on macOS ARM64/Python 3.12.13. Both passed CLI startup, benign/finding scans, file/directory targets, synthetic installed Codex/OpenClaw selection, COMPLETE/PARTIAL/FAILED states and JSON/SARIF export. Exit codes were clean `0`, finding `1`, usage `2`, incomplete/failed `3`. Export files had mode `0600`. `--version` remains unsupported (usage exit `2`); it is not a newly reproduced defect.

A real OS PTY exercised the interactive menu and completed a benign scan with exit `0`. Separately, **249 installed-wheel headless acceptance tests passed**, including target details/click routing. This is not manual visual acceptance in a native terminal application. Manual visual acceptance remains **NOT VERIFIED**. No critical user-facing installation/usability defect was reproduced. Installation may provision dependencies; ordinary scans require neither API keys nor Docker/cloud services.

## Existing engine and evidence boundaries

All source paths below are relative to `src/dragonscan/`. Existing regression suites and frozen corpora complement this source review.

| Layer | Existing behavior and formats | Required evidence / false-positive protection | Remaining boundary |
|---|---|---|---|
| Discovery/loading | Named Markdown artifacts, selected agent configuration aliases, dependency manifests; bounded traversal and loading | Explicit target or selected installed root; regular files, symlink/path boundaries, size/depth limits | Arbitrary filenames and agent-specific runtime expansion are not universally supported |
| Parsing | Markdown blocks/spans; bounded JSON/JSONC, YAML, TOML normalization | Reject malformed/duplicate structured data; separate prose, quotes and code | Parsed metadata is not proof that an agent executes it |
| Behavioral detection | Override, bypass, sensitive access/transfer, remote execution, persistence and external instruction authority | Imperatives, negation, same-source pronouns and related destinations; direct findings preserve source/sink | Natural-language paraphrases and general shell programs remain partial |
| Signatures | Built-in PowerShell signature plus optional packs/IOC matching | Context, bounded decoding and signature evidence; examples do not automatically imply execution | No general antivirus/binary-emulation claim; no new signature engine |
| Evasion | Bounded Unicode, escape, percent, Base64/hex and lexical normalization | Original provenance, transformation budgets, exclusion of secret-bearing config values | Arbitrary encodings or executing a decoder are outside default scanning |
| MCP | Static tool descriptions/instructions/schema fields, runtime/transport/pinning and credential configuration | Explicit metadata/control/data relationships; capability co-location alone is not transfer | Live server behavior, unseen tool output and remote mutation are not established by static input |
| Supply chain | Python/Node declarations, locks, registry configuration, lifecycle/install instructions | Resolve only compatible local declarations/locks; distinguish mutable dependencies from execution | No automatic dependency install, registry reputation or OSV lookup |
| Graph/PATH/FLOW | Selected local references and explicit control/data/execution relationships | Root containment, reference resolution and traversal budgets; no URL following | Merely linking files or listing tools does not establish a flow |
| Reporting/risk | Terminal/JSON/SARIF; locations, evidence, severity/confidence and provenance | Deterministic projections; highest severity and counts rather than an arbitrary aggregate score | Findings indicate statically evidenced risk, not a completed compromise |

Relevant modules: `discovery.py`, `loading.py`, `markdown_parser.py`, `structured_parser.py`, `behavior.py`, `rules.py`, `detectors.py`, `signatures.py`, `evasion.py`, `mcp_security.py`, `dependencies.py`, `supply_chain.py`, `attack_graph.py`, `correlation.py`, `flow.py`, `reporting.py`, `sarif.py`.

## Research-to-coverage matrix

Statuses apply to the stated behavior, not an entire attack family. **SUPPORTED** means the specified inert behavior is detected; **PARTIAL** means only bounded variants are covered; **CONFIRMED FN** requires a reproduced miss; **UNSUPPORTED** is a known scope boundary; **NEEDS RESEARCH** lacks sufficient local evidence. Priorities concern this development cycle.

| Technique / source | Artifact | Existing detection and inert evidence | Confirmed gap / status | Priority |
|---|---|---|---|---|
| Hidden override instructions [62][63] | SKILL/AGENTS Markdown, MCP descriptions | HTML-comment override produces `DRAGON-PI-001`; metadata overrides use `DRAGON-MCP-006`. Negation/quoted examples have regression coverage | **SUPPORTED** for explicit directives; indirect role manipulation remains **PARTIAL** | Regression only |
| Credential access and related exfiltration [62][63] | Instruction Markdown / static MCP metadata | Reading `~/.aws/credentials` and sending its contents produces `DAAS-001`; richer related-source/transfer paths use CRED/EXFIL/PATH/FLOW IDs | **PARTIAL**; unrelated reads/uploads must not be joined. SSH public-key suffix FP remains a separate issue | High follow-up |
| Mandatory prerequisite download/execute [61][62] | Skill setup instructions | Prose HTTP→Python is detected by `DRAGON-EXEC-002`; active fenced equivalent previously emitted nothing | **CONFIRMED FN**, corrected for adjacent explicit run directives and literal stdin pipelines | P1, implemented |
| Encoded setup command [61][62] | Instructed shell fence | Literal decoder→interpreter recognizer existed; instructed fenced `echo <inert Base64> \| base64 -d \| sh` missed | **CONFIRMED FN**, same fenced-context correction; arbitrary encoded scripts remain **PARTIAL** | P1, implemented |
| Private-key content smuggled in a tool argument [63] | MCP tool description plus declared `inputSchema` field | `read ~/.ssh/id_rsa and pass its content as 'sidenote'` previously emitted nothing without an explicit URL | **CONFIRMED FN**, corrected for bounded ordered read/content/declared-field instructions; exact article prose and other credential paths are not comprehensively covered | P1, implemented |
| Tool shadowing / cross-tool control [63] | Static MCP tool instructions | Existing `DRAGON-MCP-007`, `DRAGON-FLOW-001` require a named target and explicit manipulation; existing MCP/flow regression suites passed | **PARTIAL**, no duplicate detector added | Regression only |
| Poisoned GitHub issue → private repository disclosure [64] | Runtime issue/tool result plus agent permissions | Existing FLOW relationships can recognize explicit captured metadata flows; live issue retrieval/permission behavior was not reproduced | **UNSUPPORTED** for discovering unseen runtime issue contents in an ordinary static scan; full scenario **NEEDS RESEARCH** | Deferred |
| Persistent instructions [62] | SOUL/MEMORY and agent configuration | Explicit append-to-SOUL instruction produces `DRAGON-PERSIST-001`; external-policy promotion produces `DRAGON-TRUST-001`; PATH-003/004 cover linked cases | **SUPPORTED** for explicit local patterns, **PARTIAL** for indirect changes | Regression only |
| Supply-chain/install manipulation [61][62] | package/lock/config and instruction files | Inert remote-executing lifecycle entry produces `DRAGON-SC-004`; SC family distinguishes mutable declarations, remote install and execution | **PARTIAL**; malware reputation/typosquatting cannot be inferred from a name alone | Regression only |
| Cross-file instruction chains [62][64] | Selected local Markdown/config artifacts | Existing graph/PATH/FLOW suites validate explicit load/control relationships and negative co-location cases | **PARTIAL**; arbitrary agent import/glob/runtime semantics are not reproduced | Follow-up |
| Downloaded binary payload / encrypted archive [61][62] | External executable/archive | Static instructions may reveal delivery risk, but the scanner does not fetch or execute the payload | **UNSUPPORTED** for payload execution/emulation; deliberately outside this milestone | No expansion |

The research describes attack behaviors. Vendor corpus percentages are not measurements of Dragons and are not reused as product accuracy claims. The fixtures use `.invalid` hosts and inert payloads, not live malicious infrastructure.

## Nine-ecosystem comparison

A supported `SKILL.md` is not a claim of full ecosystem support. Direct-path scanning and the installed-agent selector have different alias policies. No private installation was read; installed-mode validation used synthetic homes and existing regression fixtures.

| Ecosystem | Documented formats / semantics | Current Dragons coverage | Remaining limits |
|---|---|---|---|
| Claude Code [33][1] | CLAUDE/AGENTS instructions, `@` imports, SKILL bundles; plugin/MCP metadata | Named Markdown, selected settings/MCP files, plugin metadata and hooks; installed-agent adapter | Does not emulate all `@` import precedence, arbitrary plugin code or agent runtime |
| Codex [35][34][36] | AGENTS/AGENTS.override and configured fallback names, SKILL bundles, `config.toml` MCP | AGENTS/SKILL and selected Codex configuration; synthetic installed selection verified | Override/custom fallback names and skill UI metadata are not universally classified |
| Cursor [8][37][11] | `.cursor/rules/*.mdc`, AGENTS, skills, `mcp.json` | `.mdc` is recognized through the selected installed-project adapter; AGENTS/SKILL/MCP supported | Direct generic traversal does not share every installed-mode alias; no runtime applicability/glob simulation |
| Cline [13][12][47] | `.clinerules/`, `.cline/rules/`, AGENTS, skills and MCP settings | Selected rules directories plus skill/MCP/global-settings aliases; Cline regression suites passed | Direct generic directory scanning is narrower; scripts/hooks are not executed |
| Hermes [52][50][53] | `.hermes.md`/HERMES, AGENTS.override/AGENTS/CLAUDE, SOUL; skills, profiles, memories and `config.yaml` MCP | Selected profile-aware skills/memory/SOUL/config/cron aliases; ordinary named instructions | `.hermes.md` and override precedence are not fully represented; plugin/hook runtime excluded |
| OpenClaw [56][20][57] | Workspace instruction/memory files, skills and JSON5 configuration; plugin runtime modules | Selected workspace aliases, shared skills and supported config/MCP normalization | Not a complete JSON5/runtime/plugin implementation; private sessions/credentials remain outside selection |
| Goose [60][43][55] | `.goosehints`, SKILL bundles, YAML recipes/config/extensions | SKILL content and selected Goose extension configuration; Goose regression suite passed | `.goosehints` and recipe/subrecipe execution semantics are not complete native formats |
| Kilo Code [28][25][26] | `kilo.jsonc` MCP and instruction path/glob list; skills; legacy rules | Kilo JSON/JSONC normalization and selected `.kilo/rules` | Does not emulate every instruction glob/legacy alias or embedded skill command |
| Zed [44][46][29] | AGENTS, skills, project/personal settings with `context_servers` | AGENTS/SKILL, selected `.zed/settings.json` and user settings/MCP normalization | Legacy fallback filenames, skill discovery/layout and runtime precedence are not exhaustively modeled |

These are coverage boundaries, not evidence that all unsupported formats contain attacks. No extra ecosystem or automatic scan root was added. Shared instructed-Markdown handling was prioritized over broadening discovery into personal directories.

## Two minimal improvements

### 1. Instructed shell-fence context

Root cause: execution recognizers operated on active prose observations; Markdown code fences were intentionally excluded. A separate bounded helper now recognizes a shell block immediately preceded by an unambiguous `Run this command:` / `Execute the following command:`-style directive. It reuses literal Python/decoder recognizers and the existing HTTP stdout checks, adding shell stdin validation. It does not treat every code example as an instruction.

The existing `DRAGON-EXEC-001/002/003` detectors emit the findings. Quotes, negations, examples, intervening headings, non-shell fences, comments, echo-only strings, fetch-to-file commands, script operands and non-consuming interpreter modes remain negatives. Generic prose/MCP fetch-to-shell false positives identified during review were not broadened or silently claimed fixed.

### 2. Private-key content passed into a declared tool argument

Root cause: metadata poisoning did not connect an explicit private-key read to a schema argument when no URL/ordinary network-transfer verb appeared. The existing `DRAGON-MCP-006` now also requires an ordered read of an exact SSH private-key filename, same-file content wording and a matching declared field. Public-key/certificate/backup suffixes, other data, undeclared fields, negation, quoted examples and fenced examples are negatives for this new path.

This is a narrow static metadata pattern, not general natural-language coreference. Other credential paths, multi-sentence paraphrases and the full unmodified article payload remain partial. No field name alone is suspicious.

### Contracts and limits

- No new finding IDs, dependencies, network requests or rule engine.
- Existing severity/confidence remain: EXEC high/high; MCP-006 high/medium.
- Fenced findings point to the actual command line; MCP findings retain the existing containing-tool-object location contract.
- Source/sink, evidence and JSON/SARIF severity/confidence/location consistency have regression assertions.
- Direct findings do not fabricate cross-file PATH/FLOW relationships, HTTP exfiltration or actual execution. New fence recognition does not add graph propagation; that remains a follow-up with separate evidence requirements.
- No CLI/TUI redesign, configuration schema migration or published artifact change.

## Verification

`tests/test_postrelease_detection.py` contains 63 parametrized cases: 31 previously missed positives, 28 hard negatives and four already-supported behavior regressions. Before correction: **31 failed / 32 passed**, with failures at the missing-detection assertions. After correction: **63 passed**. The focused selection including existing detection-gap and MCP regressions passed **147 tests**. During GREEN, tests were aligned with the actual existing MCP source/sink and containing-object location contracts, rather than changing those contracts to fit new assertions.

| Gate | Result |
|---|---|
| Broad pytest selection, excluding `tests/test_dynamic_mcp.py` | **1990 passed, 7 skipped** |
| Audited static selection, including new cases, scanner/parser, MCP, supply chain, evasion, graph/FLOW and CLI/TUI/reporting | **1019 passed**, 14 audit self-checks, zero blocked attempts during tests |
| Ruff lint / format | Passed; 381 Python files already formatted |
| `mypy src scripts` | Passed; 72 source files |
| `git diff --check` | Passed |
| Built-in finding inventory | **48 before / 48 after**, identical ID sets |
| Frozen Phase 2 v2 / Phase 6 v2 files | **64 file hashes unchanged** |
| Pre-existing tracked user modifications | **14 file hashes unchanged** |

The audit hooks deny subprocess/network events in the reviewed static selection; they are tripwires, not an OS sandbox. The benchmark driver permits only `git rev-parse HEAD` metadata reads. Dynamic MCP tests were excluded from the broad selection. Six optional YARA-X isolation tests lacked their separate interpreter; one Windows ACL test does not apply on macOS. No YARA-X integration was added or enabled. No actual MCP server, live semantic provider, OSV lookup or scanned artifact command was run. New source was tested locally; historical four-platform release CI is not evidence for these uncommitted changes.

| Deterministic corpus | TP | FP | FN |
|---|---:|---:|---:|
| Phase 1 | 16 | 0 | 0 |
| Phase 2 original | 8 | 0 | 1 |
| **Phase 2 v2** | **8** | **0** | **0** |
| Interpreter | 4 | 0 | 0 |
| Phase 3 | 14 | 0 | 0 |
| Main corpus | 50 | 0 | 0 |
| Realworld fixture corpus | 4 | 0 | 0 |
| Holdout (one case) | 0 | 0 | 0 |
| Phase 6 original | 19 | 2 | 3 |
| **Phase 6 v2** | **21** | **0** | **3** |

All ten measurements completed with zero execution failures. This does **not** mean all correctness gates passed: original Phase 6 has five correctness mismatches; Phase 6 v2 retains three false negatives and three correctness mismatches (strict evaluation is nonzero). No frozen expectations were edited. Synthetic results do not establish general real-world accuracy.

## Built-in finding inventory

48 IDs, unchanged; optional families are included in this inventory but are not automatically enabled:

- `DAAS-001`, `DAAS-002`
- `DRAGON-CRED-001`
- `DRAGON-EXEC-001`, `DRAGON-EXEC-002`, `DRAGON-EXEC-003`
- `DRAGON-EXFIL-001`
- `DRAGON-FLOW-001`, `DRAGON-FLOW-002`
- `DRAGON-MCP-001`, `DRAGON-MCP-002`, `DRAGON-MCP-003`, `DRAGON-MCP-004`, `DRAGON-MCP-005`, `DRAGON-MCP-006`, `DRAGON-MCP-007`, `DRAGON-MCP-008`, `DRAGON-MCP-009`, `DRAGON-MCP-010`, `DRAGON-MCP-011`, `DRAGON-MCP-012`
- `DRAGON-OBF-001`, `DRAGON-OBF-002`
- `DRAGON-PATH-001`, `DRAGON-PATH-002`, `DRAGON-PATH-003`, `DRAGON-PATH-004`
- `DRAGON-PERSIST-001`
- `DRAGON-PI-001`, `DRAGON-PI-002`
- `DRAGON-SC-001`, `DRAGON-SC-002`, `DRAGON-SC-003`, `DRAGON-SC-004`, `DRAGON-SC-005`, `DRAGON-SC-006`, `DRAGON-SC-007`
- `DRAGON-SEM-001`, `DRAGON-SEM-002`, `DRAGON-SEM-003`, `DRAGON-SEM-004`, `DRAGON-SEM-005`
- `DRAGON-SIG-001`, `DRAGON-TI-001`, `DRAGON-TRUST-001`
- `DRAGON-VULN-001`, `DRAGON-VULN-002`, `DRAGON-VULN-003`

## Repository and next milestone

Only `src/dragonscan/behavior.py`, `src/dragonscan/detectors.py`, `src/dragonscan/mcp_security.py`, the new regression test and this reference document belong to this change. Pre-existing user edits, private/local results and frozen ground truth remain untouched. No commit, push, tag, release or PyPI publication was performed. The local HEAD remains the pre-existing checkout; it was not reset to the public-release commit. Release source equality was checked before development, and changes remain uncommitted for review.

Highest-value next tasks for **v0.1.x Detection Improvements & User Feedback**:

1. Resolve the three frozen Phase 6 v2 false negatives with individual inert reproducers, preserving ground truth.
2. Fix the independently reproduced SSH public-key false positives across prose, shell, legacy rules and MCP paths without suppressing mixed real-secret findings.
3. Unify literal stdin/command-string validation across prose, MCP and graph paths, including the confirmed MCP `-cl` flag miss; retain negative script-operand cases.
4. Add narrowly scoped discovery regressions for documented instruction aliases and explicit reference chains, starting with shared AGENTS overrides and Hermes/Goose formats; do not widen private roots.
5. Perform manual native-terminal visual acceptance on supported platforms and collect redacted user false-positive/false-negative fixtures before proposing another release.

## Sources

[1] https://code.claude.com/docs/en/plugins-reference — Plugin manifest reference
[8] https://cursor.com/docs/rules — Rules
[11] https://cursor.com/docs/mcp — Model Context Protocol (MCP)
[12] https://docs.cline.bot/customization/skills — Skills - Cline
[13] https://docs.cline.bot/customization/cline-rules — Rules - Cline
[20] https://docs.openclaw.ai/tools/skills — Skills
[25] https://kilo.ai/docs/customize/skills — Skills
[26] https://kilo.ai/docs/automate/mcp/using-in-kilo-code — Using MCP in Kilo Code
[28] https://kilo.ai/docs/customize/custom-rules — Custom Rules
[29] https://zed.dev/docs/ai/mcp — Model Context Protocol | Model Context Protocol (MCP) in Zed
[33] https://code.claude.com/docs/en/memory — How Claude remembers your project
[34] https://learn.chatgpt.com/docs/build-skills — Build skills | ChatGPT Learn
[35] https://learn.chatgpt.com/docs/agent-configuration/agents-md — Custom instructions with AGENTS.md | ChatGPT Learn
[36] https://learn.chatgpt.com/docs/extend/mcp?surface=cli — Model Context Protocol | ChatGPT Learn
[37] https://cursor.com/docs/skills — Agent Skills
[43] https://goose-docs.ai/docs/guides/recipes/recipe-reference
[44] https://zed.dev/docs/ai/instructions
[46] https://zed.dev/docs/ai/skills
[47] https://docs.cline.bot/getting-started/config
[50] https://hermes-agent.nousresearch.com/docs/user-guide/features/skills
[52] https://hermes-agent.nousresearch.com/docs/user-guide/features/context-files
[53] https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp
[55] https://goose-docs.ai/docs/guides/config-file
[56] https://docs.openclaw.ai/concepts/agent-workspace
[57] https://docs.openclaw.ai/gateway/configuration
[60] https://goose-docs.ai/docs/guides/context-engineering/using-goosehints
[61] https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html — From Automation to Infection: How OpenClaw AI Agent Skills Are Being ...
[62] https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub — Snyk Finds Prompt Injection in 36%, 1467 Malicious Payloads ...
[63] https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks — MCP Security Notification: Tool Poisoning Attacks
[64] https://invariantlabs.ai/blog/mcp-github-vulnerability — GitHub MCP Exploited: Accessing private repositories via MCP
