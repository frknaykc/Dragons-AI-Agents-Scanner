# Local stdio Dynamic MCP: capability and adversarial contract

This is a development test matrix, not a sandbox certification. Run `uv run --offline pytest -q tests/test_dynamic_mcp.py`. All executable fixtures are synthetic, local and explicitly selected in tests; default scanning does not start a server. Neither `--dynamic-mcp` alone nor a target config can grant execution consent.

## Isolation policy

`required_isolation` requires enforced filesystem read/write confinement and network denial. Neither is implemented on Linux, macOS or Windows, so inspection is **blocked** on every host in this mode. The pre-existing separate `--allow-uncontained-mcp` consent enables `legacy_uncontained` on POSIX only. This is **not safe for untrusted executables** on a real host. Windows remains blocked, with no silent fallback. No OS sandbox is inferred from private cwd, shell-free argv, environment filtering or timeout. A VM/container with independently enforced isolation is an operator responsibility, not a feature of Dragons.

| Capability | Linux/macOS legacy POSIX | Windows | Limitation |
| --- | --- | --- | --- |
| Explicit consent, fixed executable, shell-free argv | available | unavailable | Executable can change between validation and launch; executable can itself have side effects. |
| Parent environment filtering, private temporary cwd | available | unavailable | Child receives fixed PATH; cwd is not filesystem confinement. Secrets on host disk remain readable. |
| Wall-clock session, stdout/stderr, JSON-RPC and item limits | available | unavailable | Stops inspection after budget, not all filesystem/network/CPU side effects. |
| Same-process-group cleanup | available | unavailable | Detached descendants can escape; failure to signal or reap is not proof of cleanup. |
| Filesystem read/write isolation, network denial | unsupported | unsupported | Required mode blocks rather than treating voluntary non-use as isolation. |
| CPU, memory, process-count, open-file limits | unsupported | unsupported | A process can exhaust resources before the wall timeout. |

Capabilities in JSON describe **availability**, not active enforcement for a blocked scan. `dynamic_mcp.mode` distinguishes legacy from required isolation. A completed legacy observation is self-reported metadata, not evidence that a listed tool executed. `inventory_comparison` is populated only for an explicit nonempty static inventory on the exactly selected declaration and a completed matching list method; a config with only a command has no comparable inventory. No dynamic finding ID or graph edge is produced. The single snapshot cannot detect metadata drift across requests.

## Threat model

Assume the approved executable is adversarial. The statuses below describe this implementation, not external VM containment:

| Threat | Required mode | Explicit legacy mode |
| --- | --- | --- |
| Host secret theft / filesystem read and write / symlink or traversal inside child | prevented (no launch) | unsupported; config path validation does not constrain child |
| Parent environment-variable theft | prevented (no launch) | bounded: only fixed PATH forwarded; host files still available |
| Network exfiltration | prevented (no launch) | unsupported |
| Child-process escape / process bomb | prevented (no launch) | same-group descendants bounded best-effort; detached escape and process-count unsupported |
| CPU/memory exhaustion | prevented (no launch) | unsupported hard quotas; wall time bounded for scanner waiting |
| Disk exhaustion | prevented (no launch) | unsupported disk quota; temporary cwd removed after normal cleanup |
| Stdout/stderr flooding, oversized messages, many tools | prevented (no launch) | bounded by byte/message/item/structure limits; no raw stderr reported |
| Protocol flooding, malformed JSON-RPC, unexpected notifications, invalid UTF-8 | prevented (no launch) | detected and stopped with failed/partial diagnostic |
| Hang, slow response, premature exit | prevented (no launch) | bounded by initialize and session deadlines; failed/partial diagnostic |
| Working-directory abuse / cleanup failure | prevented (no launch) | private cwd only; filesystem access outside it is unsupported; cleanup best-effort |

## Tested cases and known gaps

`tests/test_dynamic_mcp.py` checks default non-execution; opt-in refusal; unique config/path and symlink validation; success and partial results; failed initialize, premature exit, timeout, malformed/deep JSON, invalid IDs/UTF-8, stdout/stderr flood, unexpected notifications, item/protocol limits, secret environment filtering, method non-invocation, temporary cwd removal on success/failure, and same-process-group child cleanup after parent exit. It also checks comparable and non-comparable static inventories, two synthetic metadata snapshots in the comparison helper, and demonstrates that explicit legacy consent permits synthetic file read/write and a loopback connection outside the private cwd. Normal fixture timings are exposed as per-phase milliseconds in JSON; skipped phases are absent and no absolute CI speed gate is set.

Local baseline (macOS, 2026-10-01, five sequential scans of the repository's normal synthetic fixture in a private temporary directory, median of `time.monotonic()` measurements): static scan **0.397 ms**, explicit legacy dynamic scan including static scan **49.813 ms**. Dynamic phase medians: launch **1.266 ms**, initialize **46.624 ms**, tools/list **0.099 ms**, prompts/list **0.065 ms**, resources/list **0.043 ms**, process total **49.365 ms**. This is a local synthetic measurement, not an upper bound, not an OS resource limit, and not a claim about arbitrary MCP servers. The timeout/flood suite is bounded; 37 focused tests ran in 11.57 seconds on this host.

No positive filesystem/network isolation test is claimed: it is unsupported and required mode blocks before launch. There is no hard limit for resource/process count, no way to reliably catch a deliberately detached child, no network egress enforcement, no CPU or memory quota, no second snapshot for drift, and no measured production-provider/tool behavior. Legacy mode must not be described as a sandbox. Remote MCP transports, package runners, credential forwarding, resource reads, tool execution, and automatic security findings are outside this phase.
