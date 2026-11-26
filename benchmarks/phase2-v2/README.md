# Phase 2 v2: MEMORY contract correction

This user-approved revision preserves all 12 artifact files byte-for-byte. It changes only the expected finding list for `phase2-linked-artifacts`, plus the corpus version. The original [Phase 2 manifest](../phase2/manifest.json) and historical results remain unchanged.

| Case | Original expectation | Revised expectation |
| --- | --- | --- |
| `phase2-linked-artifacts` | `DRAGON-EXFIL-001`, `DRAGON-CRED-001`, `DRAGON-PATH-001` | `DRAGON-EXFIL-001`, `DRAGON-PATH-001` |

`linked-artifacts/SKILL.md:1` loads `./MEMORY.md`. Loading memory alone does not establish credential access. `linked-artifacts/MEMORY.md:1` explicitly directs an API-token transfer, which still produces `DRAGON-EXFIL-001`; the explicit file load still supports `DRAGON-PATH-001`. The detector reports linked transfer rather than an additional standalone credential-access finding for the same source. Explicit credential access without transfer remains covered by the other unchanged cases and the MEMORY contract tests.

The [revision record](revision.json) contains the approved old/new expectations, both manifest SHA-256 values and every unchanged artifact hash. `tests/test_phase2_revision.py` checks the exact revision, artifact identity, original/current measurements and identical scanner findings across the two corpora.

## Measurement

Run from the repository root with dependencies already installed:

```sh
uv run --offline python -m scripts.benchmark benchmarks/phase2-v2/manifest.json --format json
```

The original corpus measures **8 TP / 0 FP / 1 FN** under the approved MEMORY policy. The revised corpus measures **8 TP / 0 FP / 0 FN**. The removed FN is a ground-truth correction, not a detector improvement. Do not compare these recalls as if they used identical expectations. No other expectation, occurrence assertion or case classification changes.
