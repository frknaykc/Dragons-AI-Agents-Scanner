# DSE-015: macOS isolation decision

**Keep isolated MCP inspection blocked on macOS 27.0 (Darwin 27.0.0, arm64).** On this host we could not establish a hard resident-memory quota before target launch. No native backend is registered. The [DSE-015 acceptance criteria](../Dragons-Security-Engine-Development-Guide-v2.md#dse-015--constrained-dynamic-mcp-backend-p1) also require process, CPU and time limits, filesystem and network isolation, and descendant cleanup.

## Native quota probe

A disposable, unprivileged process called the local `libSystem` resource-limit functions on itself, with no MCP target or memory pressure test. The 96 MiB limit matches the [Linux candidate](../src/dragonscan/mcp_sandbox.py).

| Call | Observed result |
| --- | --- |
| `getrlimit(RLIMIT_RSS, &limits)` | Success; soft and hard limits both `9223372036854775807` (`RLIM_INFINITY`). |
| `setrlimit(RLIMIT_RSS, &limits)` with both fields set to `96 * 1024 * 1024` bytes | `-1`, `errno == EINVAL`. |
| `getrlimit(RLIMIT_RSS, &limits)` after the failed call | Both limits still `RLIM_INFINITY`. |

The installed macOS SDK's `usr/include/sys/resource.h` defines `RLIMIT_RSS` as an alias for `RLIMIT_AS`. Its `getrlimit(2)` manual describes preferential reclamation under memory pressure from processes *exceeding* their declared resident set size. Neither the alias nor the documented reclamation policy provides evidence of a hard ceiling. Polling RSS and killing the process after it crosses a threshold would not enforce one either.

`/usr/bin/sandbox-exec` is present. Even if a Seatbelt profile denied all child creation, that would not supply the missing memory quota. We stopped at the failed prerequisite; this investigation did not verify denial of child creation, descendant cleanup, or any other Seatbelt boundary.

## Local Linux alternative

Passive checks found the Docker CLI, Docker Desktop, UTM and the Docker networking helper. They found no Docker socket at the standard system, Desktop, Colima or OrbStack paths, no running guest identifiable from the usual hypervisor process names, and no `.utm` bundle in UTM's default VM directory. These checks do not exclude a guest in a custom location. We did not contact a daemon, start a VM or inspect any image.

The existing backend requires the scanner to run **inside Linux**, with access to the local Docker daemon and Linux pidfds. A macOS Docker client cannot satisfy that check. To qualify Linux, run the [live acceptance test](../tests/test_mcp_sandbox.py) inside an authorized, already-running Linux environment with a reviewed, preprovisioned image. To revisit macOS, first identify a kernel-enforced memory quota that applies before target execution and verify it with a bounded synthetic fixture. Neither route changes the other platform's support status.
