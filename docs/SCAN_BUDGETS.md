# Scan budgets, artifact identity and cancellation

A scan has one allowance shared by its artifacts. Starting another scan with the same `Scanner` creates a fresh allowance. These defaults apply to local scans, the static scan of an acquired target, and the combined installed/project analysis. The per-file safe loader remains limited to 1 MiB.

| Default | What is bounded |
| --- | --- |
| 4,096 artifacts | Artifacts admitted for loading; overlap in installed/project scans is deduplicated first. |
| 64 MiB | Bytes read from artifact files, including bytes later rejected as binary or invalid UTF-8. A file that cannot fit is not parsed as a prefix. |
| 128 regions; 256 views | Source regions entered by the evasion decoder and derived views admitted to detectors. Per-region limits still apply. |
| 4,096 findings | Returned findings across static analysis and requested enrichment. A yielding rule is consumed only up to the remaining capacity plus one overflow witness. |
| 512 diagnostics; 512 errors | Static scanner buffers. A final coverage diagnostic can also identify the stop reason. Optional providers have separate bounded diagnostics. |

The scanner's directory inventory uses an additional 250,000-entry walk limit per explicit directory target. Installed scans apply a cumulative 2,048-entry default to each fixed known root. An explicit per-root override can raise that to 250,000. Standalone discovery retains its own contract. An explicit local `--max-artifacts` at or below the scan ceiling still fails if exceeded. An incomplete inventory can report the number admitted, not the unknown size of the rest of the tree.

Partial scans keep findings already obtained. Inspect `coverage.bytes_read`, `attempted`, `skipped`, `evasion_regions`, `evasion_views` and diagnostics. A cooperative stop sets `coverage.budget_stopped`. Coverage gaps yield CLI exit 3, not a clean result. An independent read/parse error can still take precedence in policy. The vulnerability provider produces batches of up to 512 new findings; if this batch cannot fit, the scanner does not start it and reports the gap. Semantic candidate and response limits are tightened to fit remaining capacity.

```python
from threading import Event
from dragonscan.scan_budget import ScanLimits
from dragonscan.scanner import Scanner

stop = Event()
scanner = Scanner(limits=ScanLimits(timeout_seconds=10), cancelled=stop.is_set)
```

The deadline uses a monotonic clock and is **cooperative**, not a wall-clock guarantee. There is no default scan timeout. The scanner checks at admission boundaries, including before classifying files or descending into directories in the explicit inventory, before file reads and parsing, between yielded rule findings, between evasion transformations, and between graph and enrichment stages. Once observed, a stop is sticky for that scan. An in-flight directory enumeration, installed-root walk, OS read, parser, eager detector, graph operation or provider batch can finish before control returns. These limits are not a memory quota for Python or a hard CPU, DNS, network or subprocess timeout. Acquisition precedes the static scan; its timeout does not become this scan's deadline. Enforcing a hard time bound would require an isolated cancellable worker, process-tree termination and verified cleanup rather than another clock check inside a blocking call.

For a successfully loaded artifact, JSON `raw_sha256` identifies the exact bytes read; `text_sha256` identifies the UTF-8 parser input before format-specific processing. A leading UTF-8 BOM is removed for the latter; line endings are preserved. Hashes come from the same bounded read. File identity in offline signatures and threat intelligence uses raw bytes, not the text digest or a decoded view. The acquisition source hash remains distinct from these per-artifact hashes.
