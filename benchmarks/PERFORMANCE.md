# Offline performance baseline

Run from the repository root with an **already synchronized** environment (no network or dependency installation):

```sh
uv run --offline python scripts/performance_baseline.py --smoke
uv run --offline python scripts/performance_baseline.py --full
uv run --offline python scripts/performance_baseline.py --case files:1000
```

Use `python scripts/performance_baseline.py ...` inside an existing environment to avoid even `uv` resolution. The harness writes inert, generated `SKILL.md` data to disposable local directories and deletes it afterward. It never executes/imports/installs the generated artifacts or follows the synthetic `.invalid` graph URLs. It does not read the quality corpus, use remote intelligence, or enable dynamic MCP, semantic or vulnerability providers. Each case has a separate Python process for RSS isolation; `--smoke` runs five small cases and is suitable for CI. `--full` is manual and can use substantial CPU, disk metadata operations, and memory. No absolute pass/fail performance thresholds are imposed.

| Case | What is timed | Validation / limits |
| --- | --- | --- |
| `files:100`, `files:1000`, `files:10000` | Real local discovery + default static `Scanner.scan` of small, ordinary files | Exactly N discovered/reported artifacts; zero errors. Files generated *before* timing. 10,000 is the discovery maximum; does not exceed it. |
| `nearmax:1` | Real discovery + default static scan of a 1 MiB − 1 byte inert, single-token text artifact | Loads successfully, but evasion analysis skips the >4 KiB source region; explicitly `status: partial`, `partial: 1`, one diagnostic. This is measured incomplete coverage, not a fully scanned artifact. |
| `oversize:1` | Real discovery + default static scan of a sparse `SKILL.md` measuring 1 MiB + 1 byte | Exactly one reported load error; no content loaded. |
| `ioc:100`, `ioc:10000` | `Matcher` index construction + a single exact hash-match detection on an in-memory synthetic feed | Exactly N indexed indicators and one finding. Deliberately bypasses feed parsing/loading: production file policy allows **512 records/feed, 16 feed files**, so 10,000 is **not** an accepted on-disk feed workload. This is an index stress test only. |
| `graph:100`, `graph:10000` | `build_graph` on synthetic in-memory documents and URL relationships, groups of ≤20 nodes | Exactly N nodes and expected edges; does not measure scanner correlations or filesystem discovery. URL references are parsed only, never fetched. |
| `high_branch:1000` | `build_graph` on one synthetic document with 999 outgoing references | Exactly 1,000 nodes/999 edges; below graph node/edge safety caps. |

JSON `schema_version: 1` contains `environment`, and per-case `status`, `counters` (`requested`, `processed`, `artifacts`, `bytes`, `findings`, `errors`, `partial` for file cases, optionally `edges`/`max_fanout`), `metrics` (`wall_seconds`, `phases_seconds`, `files_per_second`, `mb_per_second`, `peak_rss_mb`), and `error`. Timing is `time.perf_counter()` around the named work phases; it **excludes** fixture generation and interpreter startup. File throughput uses processed files divided by discovery + scan time; MiB/s uses successfully loaded payload bytes (thus zero on non-file and rejected oversize workloads). Peak RSS is the OS process high-water mark in MiB, including interpreter and generated input setup, not an isolated scan-only allocation. Unexpected failures exit nonzero and include available partial counters; expected `nearmax` partial coverage remains exit 0 but never reports `status: ok`. Failed subprocess/timeout cases may only have `requested` and `processed: 0`. Compare runs on the same host and Python environment; caches, filesystem and process startup affect results. Save output explicitly if needed, e.g. `... --full > baseline.json` (the harness does not write into the repo).
