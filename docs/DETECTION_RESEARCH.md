# Detection research and local product validation

Research snapshot: 2026-10-28. This is a bounded comparison of current code with
primary documentation and technical attack reports, not a claim of ecosystem-wide
coverage or general detection accuracy. Examples are inert; no artifact code,
MCP server, downloaded script, semantic provider or external rule pack was run.
Research fetched public documentation only, never scanned user content.

## Research basis

VirusTotal describes skills whose apparent functionality conceals instructions to
download and execute prerequisites, including a Base64-obfuscated macOS delivery
step. The security-relevant evidence is the execution workflow, not merely the
presence of a URL, encoding, or a skill name.[1]

Invariant demonstrates malicious instructions inside tool descriptions and a
separate GitHub MCP attack where attacker-controlled public content redirects an
agent toward private data.[4][6] Snyk documents an indirect-injection chain through
GitHub Actions cache poisoning and package publication; detecting an instruction
is not equivalent to verifying an entire compromised release pipeline.[7]

These are reports of demonstrated techniques, not evidence that a local target
has performed those actions. Their prevalence figures, antivirus verdict counts,
and claims about an AI classifier's effectiveness are not adopted as Dragons
accuracy measurements. No listed malicious sample, IOC destination or payload was
fetched or executed.

## Technique coverage matrix

**Status vocabulary:** already detected and tested means the stated static subset;
partial means only some necessary evidence is modeled; confirmed FN requires an
inert reproduction; unsupported means outside the current input/execution model;
needs research means no sufficiently discriminating reproduction was established.
Priorities below are future detection work, not a severity assigned to a finding.

| Technique / artifact and suspicious evidence | Existing coverage and verification | Gap / status | Layer; priority |
|---|---|---|---|
| Direct prompt override in skill/instruction text: active instructions to replace prior authority | `DRAGON-PI-001` and related context-aware PI detectors; `test_detection_engine.py`, `test_detection_quality_hard_negatives.py` | **Already detected and tested**, explicit forms only; quoting, safety explanations and negation are not equivalent to active orders | Behavioral; maintain |
| MCP tool poisoning: description conceals unrelated instructions, overrides other tools or requests secrets.[4] | Static descriptions/instructions in normalized server metadata; PI/MCP rules, `test_mcp_security.py` | **Partial**: runtime `tools/list` responses, changed descriptions and UI visibility are not observed by an ordinary offline scan | Parsing / behavioral; high |
| Credential theft from agent instructions or tool metadata.[1][4] | Explicit sensitive-file access and credential-to-sink evidence; `test_mcp_security.py`, `test_flow.py`, `test_evaluation_fixes.py` | **Partial**: arbitrary aliases and natural-language paraphrases remain limited. Ordinary `MEMORY.md` reads are not credential access | Behavioral / flow; high |
| Exfiltration through otherwise trusted tools and private-repository content.[6] | Explicit local source→sink facts, PATH/FLOW rules; `test_attack_graph.py`, `test_flow.py` | **Partial**: no access to live issue text, private data or runtime tool arguments; adjacency alone must not create a flow | Graph / flow; high |
| Remote code execution / dangerous prerequisite installation in skills.[1] | Literal fetch→shell/Python paths, existing EXEC rules; `test_detection_engine.py` | **Already detected and tested**, literal active subset. Plain install documentation or a download without execution is not the same evidence | Behavioral; maintain |
| Encoded literal input decoded directly into an interpreter.[1] | `DRAGON-EXEC-003`, bounded validation of literal Base64/hex and direct stdin sinks | **Confirmed FN fixed**: macOS `base64 -D` was omitted. Other encodings, dynamic variables and arbitrary shell expressions remain unsupported | Normalization / behavioral; implemented |
| Hidden or transformed instructions, including formatting that can conceal meaning.[4] | Bounded evasion views and action-context checks; `test_evasion.py`, `test_remaining_detection_gaps.py` | **Partial**: invisible characters alone are not malicious; inert examples are not promoted to executable instructions | Normalization / signatures; medium |
| Malicious external instruction loading.[1] | Explicit load/reference facts, credential and execution combinations; `test_attack_graph.py`, `test_flow.py` | **Partial**: external URLs are not fetched; a reference cannot prove the remote file's behavior. A normal documentation link is benign | Parsing / graph; medium |
| Cross-file instruction chains | Proven local references and source/sink links; graph/flow regression suites | **Partial**: unresolved or derived-only links cannot prove a path. General multi-file semantic intent needs further research | Parsing / graph; medium |
| Persistent agent instructions, hooks or scheduled execution | Existing persistence patterns and bounded instruction/memory inputs | **Partial / needs research**: no new broadly discriminating persistence detector justified in this source set. Legitimate memory updates are not credential theft | Behavioral; medium |
| Supply-chain compromise through prompt-injected CI and poisoned build caches.[7] | Visible install/package declarations and supply-chain indicators; `test_dependencies.py`, `test_supply_chain.py`, `test_vulnerability.py` | **Partial**: manifest evidence does not establish registry provenance, cache contents or publication integrity. OSV remains opt-in | Supply chain; high |
| Tool-description changes after trust (“rug pull”).[4] | Current static metadata can be examined | **Unsupported** as a temporal attack: ordinary scans do not maintain authenticated runtime-description snapshots | Input / temporal state; defer |
| Agent configuration manipulation | Structured configuration, permission/config signals and MCP normalization; `test_direct_agent_configs.py`, `test_kilo_jsonc.py` | **Partial**: effective trust/override precedence is not reproduced. Malformed discriminator values now yield diagnostics instead of aborting all analysis | Parsing; P2 fixed |
| Indirect injection arriving in a live issue, search result or tool response.[6][7] | Explicitly supplied supported local artifacts can be scanned for existing patterns | **Unsupported live input**, not a confirmed offline-detector FN. Do not fetch private repos or execute tools to manufacture coverage | Discovery / input; defer |

A rule's existence is not proof that every published attack is caught. Most rows
are deliberately partial. No additional finding ID, severity or confidence
contract was introduced. Signature matching remains an adjunct to context-aware
behavior, not a replacement for it.

## Agent and skill format comparison

The existing `installed_agents.py`, `discovery.py` and `structured_parser.py`
adapters were compared with the sources below. “Direct scan” and “installed-agent
discovery” are different capabilities. Configuration merging, enabled-skill
selection and live tool state are not inferred from successful parsing.

| Ecosystem | Documented structure | Current subset and remaining gap |
|---|---|---|
| Claude Code | `.claude/skills/<name>/SKILL.md`, supporting files and retained `.claude/commands/*.md` compatibility.[13] | Known instruction/skill/config roots and static MCP. General command-file discovery, dynamic skill preparation and effective activation need a separate bounded coverage evaluation; skill code is never run |
| Codex | Repository and user `.agents/skills`, with ancestor-to-repository-root traversal documented.[14] | Legacy `.codex` configuration and owned skills supported. Inert probes confirm **project `.agents/skills` is selected**, but **user `~/.agents/skills` is omitted** from installed scans. Direct scanning still detects the same instruction. Ancestor traversal and shared ownership need explicit design |
| Cursor | Project rules use `.cursor/rules/*.mdc`; plain `.md` there is not a project rule.[15] | Existing `.mdc`, owned skills and static MCP subset aligns with that rule extension. Editor activation and shared-skill ownership are not established; do not broaden to all Markdown just to increase counts |
| Cline | Global/project `.cline`, settings under `.cline/data/settings`, legacy `.clinerules`, shared `.agents` instructions/skills.[16] | Current selected settings, rules and skills; no credentials, logs or histories. Shared user skill roots and broad plugin/hook/workflow semantics need work; ordinary project shared skills already traverse through generic discovery |
| Hermes | YAML `mcp_servers`, command/URL forms and environment references.[21] | Selected-profile config, skills, instructions and memories; scoped coverage attribution already checkpointed. Effective merging, runtime discovery and token stores are outside ordinary static analysis |
| Goose | YAML `config.yaml`, `extensions`, with platform-dependent user configuration locations.[22] | Existing stdio/streamable-HTTP extension subset; disabled/builtin/unsupported entries are not invented as active MCP servers. Recipes and dynamic extension metadata need separate research |
| Kilo Code | User `~/.config/kilo/kilo.json[c]`, root or `.kilo/kilo.json[c]`, top-level `mcp`.[23] | Existing bounded JSONC/discovery adapters. Malformed server discriminators now skip with an incomplete-analysis diagnostic. Redirected roots and merged effective config remain out of scope |
| Zed | Settings `context_servers`; local/remote servers and extension-provided servers.[20] | Existing settings-based subset; extension execution, OAuth stores, ACP forwarding and runtime tool changes are not reconstructed |
| OpenClaw | Skill frontmatter, skill-local supporting files, workspace and shared `.agents/skills`, declared `metadata.openclaw` requirements/install metadata.[12] | Generic explicit `SKILL.md` analysis only; **no installed OpenClaw adapter**. Managed/profile roots, install metadata and activation semantics need bounded discovery/parsing work, not a broad home-directory crawl |

The shared user skill gap is not fixed by simply attributing every `.agents` file
to Codex: Cline and OpenClaw also document shared roots.[14][16][12] Deduplication,
multiple origins, selected-agent scope and user privacy need to remain correct.
No real home directory was scanned for this research.

## Implemented changes

### P2: malformed MCP discriminator types

`structured_parser.py` tested an untrusted list/dict in a set before checking its
type. Kilo `type` and Claude/Codex/Hermes transport/type paths could raise an
uncaught `TypeError`, preventing a report for otherwise valid sibling artifacts.

The minimal fix validates discriminator types before membership checks. It reuses
existing unsupported-schema diagnostics; it does not catch arbitrary exceptions
or pretend an unsupported server was analyzed. Tests cover local and remote
shapes, lists, objects, booleans, integers and unknown strings across four
adapters, plus unrelated metadata controls. A sibling instruction remains fully
analyzed while the malformed configuration is partial. No server command runs.

`tests/test_mcp_schema_types.py`: 16 crashing cases before the fix; all 44 cases
pass after it. Related parser/attribution selection: 137 passed.

### Detection: macOS Base64 decoder spelling

The VirusTotal report supports investigating an encoded macOS delivery step; it
does not establish that this exact synthetic pipeline was the published payload.[1]
The host's macOS `base64` manual (`bintrans(1)`, Base64 decoding options) confirms
that uppercase `-D` is a decoding flag. The existing literal-pipeline recognizer
now accepts that spelling alongside `-d` and `--decode`.

Two inert shell/Python examples failed the existing `DRAGON-EXEC-003` expectation
before the change and pass afterward. Eleven Base64 hard-negative contexts
were also exercised with `-D`, alongside the existing invalid-hex control:
quotation, documentation, negation, encoded data
without execution, non-stdin sinks, variables, extra stages, and invalid input.
Assertions preserve line 3, existing source/sink labels and redacted evidence.
The 4096-character/byte limits, active-instruction requirement, severity and
confidence are unchanged. No new decoder, evaluator or subprocess was added.

`tests/test_detection_engine.py` plus remaining-gap regressions: 174 passed.
This is one research-driven detection improvement, not three speculative ones.
The MCP repair is product correctness, not a new threat-detection rule.

## Verification and limits

- Checkpoint: `f00a718be57e83c0349815f9d432d85d3a0160b6`; GitHub Actions run
  `40755313790` belongs to that SHA. Subsequent fixes/research remain uncommitted.
- Clean source installation used the committed archive, its own virtualenv and
  locked cached dependencies (`uv sync --locked --offline`). Existing user
  installation was not changed. This is not a fresh online/PyPI installation test.
- Installed CLI smoke passed without provider credentials: launch/help, static
  benign/positive scans, COMPLETE/PARTIAL/FAILED outcomes, JSON/SARIF exports and
  restrictive export permissions. No Docker, cloud or MCP execution was needed.
- Clean-install UI selection initially had 81 passes and one hover-test failure;
  its isolated diagnostic rerun passed. The later safe static selection passed
  the UI tests it includes, but no source fix was made for the intermittent
  hover behavior. Headless checks are not a manual visual review of every terminal.
- Final safe static selection: **1005 passed**. Separate reviewed focused
  selection: **254 passed, 1 deselected**. These overlap and must not be added
  together or described as a full-suite run. The deselection excludes an actual
  subprocess-based CLI inventory test from this guarded local selection.
- Scratch discovery reproduction: **2 passed**, distinguishing project support
  from the missing user shared root; it is separate from frozen benchmarks.
- An additional replay of the new tests against the checkpoint archive was
  stopped before collection: the clean-install privacy guard refused pytest's
  attempt to read the working repository's `pyproject.toml`. The guard was not
  relaxed. This attempt is not counted as a test result or detector regression.
- Audit tripwires recorded no blocked operations during the successful static,
  focused and benchmark runs. They are
  guards on reviewed trusted Python tests, **not an OS sandbox**. Benchmark
  evaluation permits only the exact Git HEAD metadata command, not target code.
- Ruff lint/format and mypy pass; **48 finding IDs** remain. No runtime dependency
  or manifest/lockfile change. Evidence and reporting regression selections pass.
- Deterministic frozen results below are unchanged; frozen expectations were not
  edited. New schema and decoder tests are separate from those scores.
- Resource/evasion/graph guards remain tested and unchanged. No new comparative
  performance benchmark was run; no general latency or memory improvement is claimed.

| Frozen set | TP | FP | FN |
|---|---:|---:|---:|
| Development | 50 | 0 | 0 |
| Pilot | 4 | 0 | 0 |
| Negative holdout | 0 | 0 | 0 |
| Phase 1 | 16 | 0 | 0 |
| Phase 2 original | 8 | 0 | 1 |
| Phase 2 v2 | 8 | 0 | 0 |
| Interpreter | 4 | 0 | 0 |
| Phase 3 | 14 | 0 | 0 |
| Phase 6 original | 19 | 2 | 3 |
| Phase 6 v2 | 21 | 0 | 3 |

The negative-only holdout has no recall denominator. Phase 6 v2's three remaining
false negatives are not resolved by this change. Small synthetic sets do not
establish accuracy on arbitrary real skills or agents.

## Next priorities

1. Bound shared user `.agents/skills` discovery with correct multi-agent origins,
   deduplication and explicit user-selected scope.
2. Evaluate OpenClaw skill roots and declared install metadata with inert positive
   and benign fixtures; preserve local-first/no-execution behavior.
3. Reproduce and stabilize the intermittent TUI hover/selection test without
   weakening keyboard, resize or final-results behavior.
4. Investigate the three frozen Phase 6 v2 false negatives without changing their
   original ground truth or fabricating graph connections.
5. Extend clean-install validation to supported OS/distribution paths and obtain
   a new exact-SHA CI run only after the uncommitted changes are reviewed.

## Sources

[1] https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html
[4] https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
[6] https://invariantlabs.ai/blog/mcp-github-vulnerability
[7] https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions
[12] https://docs.openclaw.ai/tools/skills.md
[13] https://code.claude.com/docs/en/skills
[14] https://developers.openai.com/codex/skills
[15] https://cursor.com/docs/context/rules
[16] https://docs.cline.bot/getting-started/config
[20] https://zed.dev/docs/ai/mcp
[21] https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference
[22] https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/config-files.md
[23] https://kilo.ai/docs/automate/mcp/using-in-kilo-code