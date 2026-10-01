# Semantic development corpus: offline coverage snapshot

Command: `uv run --offline python -m scripts.semantic_benchmark benchmarks/semantic/corpus/manifest.json --format terminal`

The 51 inert cases are all in the development split. This snapshot is **not** a semantic-provider evaluation. One obvious SEM-001 positive is a deterministic control, not an incremental semantic success.

| Expected ID | Positives | Negatives (hard) | Candidate-eligible positives | Deterministic mapped-positive proxy | Any deterministic finding on positives |
| --- | ---: | ---: | ---: | ---: | ---: |
| DRAGON-SEM-001 | 6 | 5 (1) | 4 / 6 | 1 / 6 | 1 / 6 |
| DRAGON-SEM-002 | 5 | 5 (1) | 5 / 5 | 0 / 5 | 0 / 5 |
| DRAGON-SEM-003 | 5 | 5 (1) | 5 / 5 | 0 / 5 | 0 / 5 |
| DRAGON-SEM-004 | 5 | 5 (1) | 2 / 5 | 0 / 5 | 0 / 5 |
| DRAGON-SEM-005 | 5 | 5 (1) | 1 / 5 | 0 / 5 | 0 / 5 |
| **Total** | **26** | **25 (5)** | **17 / 26** | **1 / 26** | **1 / 26** |

Nine expected positives never reach a semantic candidate under the current default selector. Candidate eligibility is a category/artifact proxy, not a validated evidence-localized recall measure. Deterministic mapped overlap is likewise a category proxy; these numbers are specific to this synthetic corpus. Baseline scanner produced no deterministic findings for the 25 negatives in this run. No provider was contacted; false-positive/false-negative rates, semantic additional TP, provider recall, repeated-run stability and confidence calibration are **NOT MEASURED — real provider evaluation not run**. The offline harness can rerun each case three times to check selection consistency; this does not measure LLM stability.

See [CONTRACTS.md](CONTRACTS.md) for labels and [METHODOLOGY.md](METHODOLOGY.md) for denominators, partial/failure handling and opt-in provider setup. The separate deterministic Benchmark v2 remains unchanged.
