# Candidate selection quality — development-only, offline

Checkpoint: clean `main == origin/main == fa167d6c4bc9bd3c98a58eebc1e0b1f7972a60d6`. The historical selector baseline below was collected **before** editing `select()` by running default local scans of all 51 manifest cases and calling `select()` once per case. The final numbers use `uv run --offline python -m scripts.semantic_benchmark benchmarks/semantic/corpus/manifest.json --repeats 1 --format terminal`. Both measurements use the same artifacts and `SemanticLimits` defaults. They do not measure model decisions or real-world rates; no provider was contacted.

## Actual path and selection boundary

Discovery/classification and bounded loading produce parsed `Document` instances. `select()` only visits parsed Markdown instructions, declared MCP tool descriptions/instructions, and suspect MCP prompt/resource descriptions. Markdown instructions are admitted by the legacy lexical suspicion signal, same-line deterministic finding, or (now) conjunctions of an imperative with source/authority, future agent behavior, or private access material/transfer/outside-recipient context. MCP tools with description or instructions are eligible without a lexical gate; `behavior_mismatch` requires both fields. Prompt/resource descriptions still require the legacy lexical signal. A Markdown candidate can allow SEM-001/004/005 simultaneously; tools can allow SEM-001…005 as constrained by their fields. Neither graph relationships nor a semantic verdict grant new eligibility or authority.

The *instruction text itself*, or the declared MCP metadata pair, is the snippet: not the surrounding file. Every candidate has a fixed internal `reason` (`suspicious instruction signal`, `static finding at instruction`, one of the three compound contexts, `declared MCP tool metadata`, or `suspicious MCP metadata`). Static rank and number of attached static IDs sort candidates first, then kind, artifact path, and line. Redacted/truncated snippet hashes deduplicate with kind, static evidence and category; first occurrence wins. The default 16-candidate cap applies **after** ordering/deduplication. `enrich()` redacts each selected candidate before the provider, truncates to 2,048 characters with a partial-analysis diagnostic, then applies request count/body/time limits. A failed redaction drops the candidate with a diagnostic. The system prompt, strict response schema, deterministic findings, graph and taint boundaries are unchanged. Ordering and deduplication are deterministic for fixed input; ties and different scan roots may change which candidate fits the cap. Selector lexical gates do not establish a finding.

## Nine historical misses

All nine were `AGENTS.md` instruction paragraphs parsed and eligible for SEM-001/004/005 in principle. Each had zero produced candidates, zero budget overflow, no snippet selected and no static finding on its instruction line. Thus **9/9 were selector-gate misses**; **0/9 were scope, deduplication, ordering, budget or snippet misses**. The independent artifact is identified by `corpus/<case>/AGENTS.md`; the expected behavior is defined in [CONTRACTS.md](CONTRACTS.md).

| Case | ID | Expected behavior / missing gate | Final reason |
| --- | --- | --- | --- |
| `sem-001-p02` | SEM-001 | Retrieved paragraph promoted to governing authority over the user's request; no legacy suspicion word | instruction hierarchy context |
| `sem-001-p03` | SEM-001 | Attached note decides constraints and replaces requested format; no legacy suspicion word | instruction hierarchy context |
| `sem-004-p02` | SEM-004 | Durable response style for later chats; neither legacy `persist` nor `future sessions` form | future agent behavior context |
| `sem-004-p03` | SEM-004 | Hidden approval condition reused next conversation; no legacy suspicion word | future agent behavior context |
| `sem-004-p04` | SEM-004 | Long-lived agent profile directive survives restart; no legacy suspicion word | future agent behavior context |
| `sem-005-p01` | SEM-005 | Private account recovery material passed to unrelated reviewer; no legacy explicit secret word | sensitive material transfer context |
| `sem-005-p02` | SEM-005 | Confidential login details relayed raw to third party; no legacy explicit secret word | sensitive material transfer context |
| `sem-005-p03` | SEM-005 | Private access credentials exposed to outside reader; legacy singular `credential` does not cover plural | sensitive material transfer context |
| `sem-005-p04` | SEM-005 | Team session material forwarded to unrelated party; no legacy explicit secret word | sensitive material transfer context |

The compound gates operate on any parsed instruction, not case IDs or deterministic PI regex copies. They require multiple signals and avoid explicit negations/discussions at this new gate. This is bounded heuristic routing, not an intent detector; paraphrases without the signals can still be missed. Existing lexical/static admission is retained, so some security documentation and benign MCP metadata still reach a provider. Hard-negative expectation `false` is used only for three documentation cases that stay unselected; all nine historical positive misses are labeled `true`. Semantic-negative does **not** mean selector-negative.

## Before → after (one selection per case)

| Measure | Before | After |
| --- | ---: | ---: |
| Positive cases with category-eligible candidate | 17 / 26 | 26 / 26 |
| Negative cases with category-eligible candidate | 14 / 25 | 14 / 25 |
| Positive candidate instances | 17 | 26 |
| Negative candidate instances | 14 | 14 |
| Total selected candidates | 31 | 40 |
| Candidate precision proxy (positive instances / total) | 17 / 31 = 0.548387 | 26 / 40 = 0.650000 |
| Raw candidate text bytes (UTF-8) | 5,350 | 6,685 |
| Prospective redacted, truncated snippet bytes (UTF-8) | 5,350 | 6,685 |
| Redacted / privacy-skipped / truncated candidate instances | 0 / 0 / 0 | 0 / 0 / 0 |
| Omitted by candidate budget | 0 | 0 |

By ID, eligible positives: SEM-001 **4/6 → 6/6**; SEM-002 **5/5 → 5/5**; SEM-003 **5/5 → 5/5**; SEM-004 **2/5 → 5/5**; SEM-005 **1/5 → 5/5**. The SEM-001 deterministic-control case remains one of the six; it is not an incremental semantic true positive. Negative cases by ID remain 2, 5, 5, 1, 1 selected. Increased prospective snippet payload is **1,335 bytes** (+25% vs 5,350), not full request cost (schema and context excluded). The zero-redaction count means no corpus fixture contained a matching secret, **not** that redaction is unnecessary or complete. Candidate precision is a *development-corpus proxy*, not semantic/provider precision; 100% recall on this small seen corpus is not a deployment generalization claim.

## Boundaries exercised

Focused tests use unrelated formulations and negative controls for security documentation, negated disclosure/persistence, benign preferences and benign account documentation. A selected future-context instruction retains its relevant segment without copying a separate unrelated secret paragraph; provider request serialization omits its raw fixture value. A long contextual instruction makes analysis partial on truncation. Thirty mildly suspicious paragraphs produce a deterministic first four under a four-candidate cap, a 26-omitted diagnostic, and no classification of those omitted as semantic negatives. Offline benchmark records reason, input bytes, redacted snippet bytes, budget omissions, privacy drops and truncations without writing source text. Provider-call controls use a fake transport only. Detection ID registry, scanner default and deterministic Benchmark v2 are not modified. Real provider quality and privacy for secrets outside the existing redaction patterns remain unmeasured.
