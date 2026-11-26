# Phase 4: isolated YARA-X experiment

This experiment does not run in the production scanner. It uses six **trusted, local** YARA rules and 15 independent synthetic, inert samples (7 positives and 8 hard negatives). Labels and rationales are fixed in `compare.py`, independently of either engine's output. Samples are materialized only in a temporary scratch directory, scanned locally, and removed. No sample commands, MCP servers or remote endpoints are executed or contacted. No external rule packs or serialized compiled rules are accepted. Rule matches are **candidates**, not verified attacks or new finding IDs.

## Reproduce

After explicit approval, install the pinned `yara-x==1.22.0` wheel into an isolated interpreter *outside this repository*. Do not modify `pyproject.toml`, `uv.lock`, or the project's environment. With that interpreter available:

```sh
YARAX_PYTHON=/path/to/isolated/bin/python
PYTHONDONTWRITEBYTECODE=1 uv run --offline python benchmarks/phase4/compare.py --yarax-python "$YARAX_PYTHON"
DRAGON_PHASE4_YARAX_PYTHON="$YARAX_PYTHON" PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 uv run --offline pytest -p no:cacheprovider tests/test_phase4_poc.py -q
```

The optional PoC tests skip if the isolated interpreter is not supplied; they are **not** a passed YARA-X verification in that case. This runner is POSIX-only (`resource`); Windows Python wheel availability is not Windows isolation validation.

## Fixed comparison (macOS ARM64, Python 3.12, YARA-X 1.22.0)

A candidate is any medium-or-higher Dragons finding, or any matching YARA-X rule. Each case counts once. The two detectors' semantics differ; candidate TP/FP/FN here are **not** production detection accuracy. Synthetic examples are deliberately small and do not extend the existing Phase 1–3, development, real-world or holdout sets.

| Engine | TP | FP | FN |
| --- | ---: | ---: | ---: |
| Dragons | 6 | 0 | 1 |
| YARA-X PoC | 5 | 7 | 2 |

The single YARA-only positive was an explicitly requested XOR-obfuscated command. Its rule also matched a passive XOR sample (FP), so that result is **not** justification for a high-severity finding. Four positives were shared (direct shell instruction, hex decoder, MCP command, instruction override). Dragons alone found the nested Base64 instruction and remote Python pipeline. YARA-X's seven hard-negative matches came from quoted, fenced and prohibited commands; passive XOR; MCP description; unrelated decoder/sink; and hex documentation. The ordinary skill was negative for both. The overlap with the existing 48 finding IDs was already represented by existing `DRAGON-EXEC-001`, `DRAGON-EXEC-003`, `DAAS-002` and `DRAGON-PI-001`; the two Dragons-only cases used `DRAGON-EXEC-001` and `DRAGON-EXEC-002`.

The rules exercise text patterns, literal hex bytes, XOR string matching, multi-condition logic, encoded-decoder indicators, skill instructions and MCP JSON. They do **not** show native YARA decoding of arbitrary Base64 or a source/sink graph.

Cold compile mean/p95 across 15 child processes: approximately **3.25/17.80 ms**. Repeated scan mean/p95 across 600 in-process iterations: approximately **0.00275/0.00171 ms**, respectively (the first scan increases the mean); process startup, Dragons scan time and I/O are excluded from these figures. Maximum observed child peak RSS was **37,535,744 bytes** (~35.8 MiB), not a memory ceiling. Re-run for machine-specific figures.

## Resource and security boundary

The parent bounds input to 1 MiB, child JSON envelope to 1.4 MB and rule text to 16 KiB; the worker disables `include` on `Compiler`, scans bytes rather than opening target paths, caps each pattern's match count at 16, sets a 1-second YARA-X scan timeout and repeats bounded inputs 40 times. A fresh `python -I` child is given an 8-second wall timeout and a POSIX CPU soft/hard limit of 2/3 seconds. Tests confirmed include rejection, input-limit failure, termination on a wall timeout, POSIX CPU-limit termination and UTF-8 byte-offset-to-line conversion. Scanning is local; the worker has no network code. **It is not a hardened sandbox**: no OS-enforced network denial; native library processing remains in the worker; memory enforcement is not reliable on tested macOS (attempted `RLIMIT_AS`/`RLIMIT_DATA` settings failed). Linux's configured 1-GiB address-space cap and Windows isolation have **not** been tested. Scanner timeouts and compiler resource bounds are not a substitute for OS isolation. Do not feed untrusted YARA rule source to this experiment.

## Integration feasibility (not implemented)

If additional validation justifies integration, keep YARA-X **opt-in** and separate from the validated JSON signature pack loader. The latter currently rejects `.yar` and `type: yara`; do not reinterpret existing packs silently. Use versioned, locally curated rule bundles, validate metadata/IDs independently, compile in a restricted process with includes disabled and enforce a byte/rule/CPU/wall/**memory** budget before enabling untrusted targets. Do not ingest serialized compiled rules from users. Map rule identifier and source provenance to a separately approved finding ID contract. Include only rule identifier, artifact and validated position plus a non-sensitive indicator label in evidence, not the matched bytes or decoded payload. Use the UTF-8 file bytes to map byte offset to line (test includes a multibyte prefix); ensure the actual artifact identity and parsed context are verified before reporting. Suppress duplicate equivalent evidence from existing Dragons IDs using artifact/line/behavior identity, not simple rule-name equality. Gate severity on active instruction or executable MCP context and confirmed behavioral relationship, retaining hard-negative tests. A YARA string hit alone should not create a dangerous-execution finding.

Upstream YARA-X 1.22.0 publishes Python >=3.9 `cp39-abi3` wheels for macOS 14+ ARM64/x86_64, manylinux glibc 2.28+ aarch64/x86_64, and Windows x64. Only macOS ARM64 was run here. The macOS ARM64 wheel is approximately 8.6 MB compressed; this environment's installed package is 29,503,819 bytes, predominantly its native extension. Standalone binary growth has **not** been measured. YARA-X is BSD-3-Clause; binary redistribution requires retaining license notice/conditions/disclaimer in accompanying materials and prohibits endorsement using rights-holder/contributor names. Confirm license notices and distribution footprint before shipping.

Sources: [official Python API](https://virustotal.github.io/yara-x/docs/api/python/), [includes](https://virustotal.github.io/yara-x/docs/writing_rules/including-files/), [v1.22.0 release files](https://pypi.org/project/yara-x/1.22.0/#files), [upstream license](https://github.com/VirusTotal/yara-x/blob/main/LICENSE).

**Decision: NEEDS MORE VALIDATION.** XOR matching produced one unique candidate but a passive-sample FP, while most positive matches duplicated existing behaviors. Reliable memory/network confinement, Windows/Linux execution, representative corpora and packaging size remain unproven. Do not start production integration without a separate decision.
