# Benchmark methodology

Dragons has three offline deterministic corpora and separate experimental semantic work. These are **small, selected evaluation sets**, not estimates of general deployment accuracy. **REAL-WORLD ACCURACY CLAIM: NOT ESTABLISHED.** The [complete earlier methodology and provenance notes](METHODOLOGY_HISTORY.md) are preserved verbatim; manifests, artifacts, digests, licenses, ground truth and historical baselines remain unchanged.

| Corpus | What it measures | Ground truth |
| --- | --- | --- |
| [Development](corpus/manifest.json) | Synthetic/curated cases for detector regression and ID-level scoring; contains a checked-in, non-blind holdout split | Manifest schema 1, expected finding IDs and optional occurrence assertions |
| [Real-world pilot](realworld/manifest.json) | A small set of licensed, pinned public artifacts; not representative of the ecosystem | Manifest schema 2, exhaustive expected occurrences |
| [Independent holdout](holdout/manifest.json) | Separately sourced, checked-in negative cases; not a hidden/blind evaluation | Manifest schema 2, expected absences and occurrence-level checks |

## Run locally

From the repository root with locked dependencies cached, all runs are local and offline:

```sh
uv run --offline python -m scripts.benchmark benchmarks/corpus/manifest.json --format json
uv run --offline python -m scripts.benchmark benchmarks/realworld/manifest.json --format json
uv run --offline python -m scripts.benchmark benchmarks/holdout/manifest.json --format json
```

Initial setup is described in [installation](../docs/INSTALLATION.md); `--offline` fails if required packages/interpreter are not cached. The runner reads selected local artifacts as untrusted data. It does not start agents or MCP servers, follow artifact URLs or call a semantic provider. No command above rewrites a manifest or baseline. Exit **0** means complete with no explicit correctness failure; **1** means correctness assertions failed; **2** means partial/configuration failure. Inspect the JSON, not just the exit code. Do not redirect `--format baseline` into [baseline.json](baseline.json) without explicit review.

## Interpret results

- **Development:** the scoring unit is `(case, finding ID)`. TP = expected ID found; FN = expected ID absent; FP = actual security ID not expected, including extra IDs on malicious cases. Multiple locations of the same ID collapse **only for this ID metric**. Optional occurrence assertions separately check category, location and evidence.
- **Pilot and independent holdout:** the primary unit is an **expected occurrence**, including artifact, line, category and evidence (and source/sink/path where asserted). A wrong occurrence is one FP **and** one FN. Unexpected IDs count once per logical case. ID-level values are secondary; mismatch details and targeted absences appear in the JSON.
- Precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2TP/(2TP+FP+FN). When the relevant denominator is zero the metric is `null`, **not** 100%. The negative-only independent holdout can support a false-positive observation, not precision/recall/F1 on positive detections.
- A passing corpus can reflect tuning to known examples. A small pilot and checked-in holdout cannot establish prevalence, recall on unseen attacks or safety of arbitrary artifacts. Coverage of registered rule IDs is not recall.

Each public-artifact case records its source, version/reference, SHA-256, license/redistribution permission and curation rationale in the manifest and its [historical provenance notes](METHODOLOGY_HISTORY.md); third-party license texts are in [licenses/](licenses/). Do not use these licenses as a license for Dragons itself. Schema 2 rejects overlapping IDs and identical artifact bytes across pilot and independent holdout. The AISA case is a licensed short excerpt, **not** a scan of its complete upstream source. See the preserved notes for the precise freeze, baseline comparisons, corpus revisions and known methodological limits.

## Experimental semantic evaluation

Semantic candidate selection and scoring are separate from deterministic regression. [Methodology](semantic/METHODOLOGY.md) · [Offline snapshot](semantic/OFFLINE.md) · [Threat contracts](semantic/CONTRACTS.md) · [Candidate-selection limits](semantic/CANDIDATE_SELECTION.md). These documents do not establish live provider accuracy; private provider results under `semantic/results/` are not part of this repository's public benchmark evidence.
