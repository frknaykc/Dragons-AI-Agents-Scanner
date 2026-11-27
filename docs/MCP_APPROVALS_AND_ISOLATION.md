# MCP declaration approvals and isolated inspection

## Compare declarations offline

Use `mcp-baseline` when you have a **local JSON declaration**, not a running server. Read the actual config (endpoint, permissions, descriptions and schemas) before approving it. `review` prints identities and digests so that secrets and schema bodies are not copied into a report.

```console
dragonscan mcp-baseline review /project/.mcp.json
dragonscan mcp-baseline approve /project/.mcp.json --digest REVIEWED_DIGEST
dragonscan mcp-baseline compare /project/.mcp.json
```

`approve` requires the exact candidate digest from review; it is the only command that writes. `compare` returns JSON and exits **0** for unchanged, **1** for `changed` (`DRAGON-MCP-013`), or **3** for `partial`, including a missing, unreadable, invalid or unprotected snapshot. Neither a missing snapshot nor a changed declaration is automatically approved. Review again before approving an intentional change. A difference is a reason to review an approval, not proof of a malicious server, tool call, or runtime policy violation. These commands neither start processes nor follow URLs.

- The qualified identity is the absolute, non-symlink source path (stored as a digest), server name, and tool name. Moving a config needs its own approval. Tool names on different servers are independent. Output distinguishes added/removed servers or tools, changed server declarations, tool schema, and other tool metadata (including descriptions and instructions).
- Format v1 covers the `mcpServers` object and explicitly declared inline `tools` arrays; every tool needs an `inputSchema` object. Omitted inventories, ambiguous keys, duplicate tool names, and unsupported identifiers are incomplete, not empty. Other top-level config sections and runtime lists are outside scope. Names must be 1–128 ASCII letters, digits, `_`, `.`, `:` or `-`. Inputs are capped at 512 KiB, 128 servers, 1,024 tools, 48 nesting levels and 32,768 nodes.
- Canonical SHA-256 digests use sorted JSON object keys; whitespace and inventory ordering are immaterial. Arrays **inside** schema or tool metadata retain their order. All non-`tools` server fields contribute to the server declaration digest, including an endpoint, environment or permissions change. This is structural comparison, not full JSON Schema equivalence.
- Approval files live under `~/.dragonscan-mcp-approvals/`, not next to the input. The POSIX store uses a private owner-controlled directory, descriptor-relative no-follow opens, owner-only regular files and atomic replacement. Do not set `HOME` from the target. This does not protect an account whose owner, administrator or trusted runtime is compromised. Windows currently fails closed for this workflow.

## Isolated inspector

`--dynamic-mcp` alone does not execute a target. The experimental isolated path requires an operator-selected server, absolute executable and a full **local image ID** (`--mcp-isolation-image sha256:…`, 64 lowercase hex digits). Never take this ID, executable approval or other consent from a scanned declaration. The image is trusted code: review its complete filesystem for secrets and its runtime utilities for integrity. No image is resolved by tag, built, installed or pulled. Do not combine an isolation image with `--allow-uncontained-mcp`.

The candidate requires native Linux, an already-running local Docker Engine on `/var/run/docker.sock`, `/usr/bin/docker`, `runc`, cgroup v2, process inspection via `/proc`, and kernel pidfds. The reviewed image must contain `/usr/bin/env`, GNU `/usr/bin/timeout`, and `/usr/local/bin/python3` with its standard library for the harmless preflight; it cannot declare any volumes. Only the explicitly selected single executable (at most 16 MiB) is copied into private staging and bind-mounted read-only. No adjacent source, home, engine socket, host credentials or target-provided environment is supplied. The executable must run with only the image's reviewed runtime files; sibling imports or host-specific shebangs are not portable.

Before each target, the inspector runs its own harmless fixture with the **same** image and launch restrictions. It checks a missing host-only marker, unreachable host loopback listener, loopback-only interface inventory, read-only root and executable, nonroot UID, empty capabilities, seccomp and no-new-privileges, and the actual CPU, memory, swap, PID and file limits. It forks one sleeping child, removes the container, and requires that host pidfds for the fixture tree signal exit. Failure refuses the target; it does not switch to legacy execution. A passing probe enables only one bounded, metadata-only stdio inspection. Default scan is unchanged.

Limits: no container network except private loopback; read-only root; 0.5 CPU, 96 MiB memory with no swap, 16 processes, 64 open file descriptors, 1 MiB regular file size. The target has a 12-second in-container watchdog in addition to the existing narrower protocol deadlines and output limits. Container output is not retained by the engine log driver. The scanner checks removal by unique name; incomplete cleanup is not success. Docker's kernel, daemon, native runtime and the reviewed image remain trusted. This is not VM isolation or a general-purpose sandbox.

### Acceptance status

The live test passed on the [recorded Ubuntu ARM64 configuration](P1-DOGRULAMA.md) with Docker Engine 29.1.3. Other Linux configurations have not been verified. Windows and macOS refuse isolated launch; Docker Desktop image inspection on macOS does not attest Linux process cleanup through native pidfds. macOS `sandbox-exec` is not an alternative backend.

On an **authorized native Linux test machine**, use an already reviewed, provisioned local image ID; run the production boundary probe and a purpose-built, harmless metadata fixture through the inspector with:

```console
DRAGONSCAN_TEST_DOCKER_IMAGE=sha256:REVIEWED_LOCAL_IMAGE_ID uv run --frozen --offline pytest -q tests/test_mcp_sandbox.py -k live_isolated
```

A skip is not a pass. No external service, real MCP server, outbound test destination or package download is required. The [existing process-only mode](REFERENCE.md#explicit-local-mcp-process-inspection-experimental) remains independently consented and has **no** filesystem or network isolation.
