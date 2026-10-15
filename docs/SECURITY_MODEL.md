# Security model and limits

[Overview](../README.md) · [CLI consent options](CLI_GUIDE.md) · [Technical bounds](REFERENCE.md)

## Default scan

Dragons treats supported local files as **untrusted data**. It reads and statically parses instruction files, skills, recognized config and dependency metadata. It does not execute a target script, import an artifact as code, install target dependencies, follow links, start a declared MCP server, fetch a URL or call a model. Even when Dragons decodes a bounded Base64/hex excerpt for analysis, it does not execute that excerpt. A finding signals evidence of risk, not observed execution or exfiltration.

Normal local scanning rejects symlinks and binary/NUL files, reads at most **1 MiB per file**, bounds structured nesting and node counts, and rejects unsafe YAML tags/aliases. Directory and archive traversal have budgets and path guards. A skipped/malformed artifact can produce `PARTIAL` and exit **3**, not a false clean bill of health. Do not turn a scan target's embedded commands, URLs or prompts into operator instructions. See [exact parser and archive limits](REFERENCE.md#current-scope).

## Secrets and report handling

MCP environment/header fields are treated as references or redacted literals rather than retained raw credentials; finding evidence is bounded and sanitized. The private `~/.claude.json` projection selects user MCP definitions and only the explicitly matching project's local definitions instead of exposing unrelated private state to raw signatures. These controls are **not a guarantee that arbitrary sensitive data cannot appear in a report**: paths, authored text and diagnostics may expose context; semantic redaction is best-effort. Review JSON/SARIF before sharing or uploading it. Never scan real private configs just to verify a product claim; synthetic tests do not establish real-install safety or complete behavior.

## Explicit network modes

- `--remote` opts into downloading a **single public HTTPS artifact**. It is not a remote Git clone; redirects, destination, size and content are constrained. Local `--git` reads an existing working tree without invoking Git or fetching anything. Remote Git acquisition is **not supported**.
- `--vuln-check` queries OSV over HTTPS with normalized package names and exact versions. This shares dependency metadata with OSV, not scan artifact bodies by default.
- `--intel PATH` or `--intel-store PATH` reads explicitly selected **local** intelligence. `dragonscan intel update` is a separate, explicit HTTPS download with operator-supplied digest; a digest alone is not publisher authentication. Scans do not update feeds.
- `--semantic` is **experimental**. It requires an explicit provider URL and model, and can send selected excerpts to that provider; best-effort redaction is insufficient assurance for sensitive targets. A model verdict is advisory and does not prove a deterministic source/sink/path. `--allow-private-semantic-http` is a separate keyless HTTP exception for literal RFC1918 IPv4 hosts.

These features are off by default. No external request or semantic provider call was made to produce this documentation.

## Dynamic MCP boundary

`--dynamic-mcp` requests local stdio MCP metadata inspection. It is blocked without additional explicit consent to uncontained execution and exact server/executable selection. **`--allow-uncontained-mcp` can run the specified local binary without filesystem or network OS isolation.** The scan target does not grant that consent. Do not approve a binary supplied by an untrusted artifact. A Docker container is not a certified sandbox for this mode. See [runtime contract and development tests](../benchmarks/dynamic/README.md); these do not certify hostile-server containment.

## Interpreting evidence

A `source` is a sensitive input or influence surface; a `sink` is an external transfer or execution destination. Attack paths exist only when the scanner can link the necessary static evidence; unrelated mentions do not create edges. Severity expresses possible impact, confidence expresses evidence strength; neither is probability of compromise. Some findings have no line number or graph. Static detectors can produce false positives and false negatives, especially with unusual formats, renamed artifacts, dynamic behavior and unsupported runtime precedence. The development benchmark and five-case real-world pilot are **corpus-specific**; **REAL-WORLD ACCURACY CLAIM: NOT ESTABLISHED**. Review source and context before taking action. [Report field guide](FINDINGS_AND_REPORTS.md).
