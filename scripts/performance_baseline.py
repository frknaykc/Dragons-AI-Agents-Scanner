"""Reproducible offline scanner throughput probes; never execute fixture content.

Run: uv run --offline python scripts/performance_baseline.py --smoke
     uv run --offline python scripts/performance_baseline.py --full
Output is one JSON document; each case runs in a fresh Python interpreter for RSS isolation.
"""

import argparse
import json
import platform
import resource
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Allow the checked-out project to run without installation (dependencies must already exist).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dragonscan.attack_graph import build_graph  # noqa: E402
from dragonscan.discovery import discover  # noqa: E402
from dragonscan.loading import MAX_BYTES  # noqa: E402
from dragonscan.models import (  # noqa: E402
    Artifact,
    ArtifactKind,
    Document,
    Relationship,
    SourceFormat,
    SourceRef,
    Target,
)
from dragonscan.scanner import Scanner  # noqa: E402
from dragonscan.threat_intel import Feed, Matcher, Record  # noqa: E402


@dataclass(frozen=True)
class Workload:
    kind: str
    size: int

    @property
    def name(self) -> str:
        return f"{self.kind}:{self.size}"


FULL = (
    Workload("files", 100),
    Workload("files", 1000),
    Workload("files", 10000),
    Workload("nearmax", 1),
    Workload("oversize", 1),
    Workload("ioc", 100),
    Workload("ioc", 10000),
    Workload("graph", 100),
    Workload("graph", 10000),
    Workload("high_branch", 1000),
)
SMOKE = (
    Workload("files", 10),
    Workload("oversize", 1),
    Workload("ioc", 10),
    Workload("graph", 20),
    Workload("high_branch", 50),
)


def workloads(smoke: bool) -> tuple[Workload, ...]:
    return SMOKE if smoke else FULL


def peak_rss_mb() -> float:
    """OS high-water RSS (macOS bytes, Linux KiB), including interpreter/setup."""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024, 3)


def _files(case: Workload, root: Path, counters: dict[str, int]) -> dict[str, float]:
    oversized = case.kind == "oversize"
    nearmax = case.kind == "nearmax"
    count = 1 if oversized or nearmax else case.size
    content = b"# Synthetic skill\nA small, inert description of local usage.\n"
    if nearmax:
        # Long, inert, single-token input just below the loader cap; no parsing shortcut.
        prefix = b"# Synthetic skill\n"
        content = prefix + b"Z" * (MAX_BYTES - len(prefix) - 2) + b"\n"
        if len(content) >= MAX_BYTES:
            raise RuntimeError("nearmax fixture exceeds loader cap")
    for index in range(count):
        path = root / f"artifact-{index:05d}" / "SKILL.md"
        path.parent.mkdir()
        if oversized:
            # A syntactically harmless but rejected artifact; write outside timed scan.
            with path.open("wb") as stream:
                stream.truncate(MAX_BYTES + 1)
        else:
            path.write_bytes(content)
    counters.update(artifacts=0, bytes=0, findings=0, errors=0, partial=0)
    start = time.perf_counter()
    discovered = discover(Target(root))
    counters["artifacts"] = len(discovered)
    discovered_at = time.perf_counter()
    report = Scanner().scan(Target(root), artifacts=discovered)
    end = time.perf_counter()
    counters.update(
        processed=len(report.artifacts),
        artifacts=len(report.artifacts),
        bytes=0 if oversized else count * len(content),
        findings=len(report.findings),
        errors=len(report.errors),
    )
    if len(discovered) != count or len(report.artifacts) != count:
        raise RuntimeError("incomplete artifact discovery/scan")
    if oversized:
        if len(report.errors) != 1 or "exceeds 1 MiB limit" not in report.errors[0]:
            raise RuntimeError("oversize artifact was not rejected")
        counters["partial"] = 1
    elif nearmax:
        if len(report.errors) != 1 or "evasion source region too large" not in report.errors[0]:
            raise RuntimeError("unexpected nearmax analysis diagnostic")
        counters["partial"] = 1
    elif report.errors:
        raise RuntimeError("ordinary synthetic files produced scanner errors")
    return {"discovery": discovered_at - start, "scan": end - discovered_at}


def _ioc(case: Workload, root: Path, counters: dict[str, int]) -> dict[str, float]:
    # The matcher itself is stress-tested beyond on-disk policy limits: a single
    # actual feed is capped at 512 records and at most 16 files can be loaded.
    records = tuple(
        Record(
            f"synthetic-{index}", "sha256", f"{index + 1:064x}", "suspicious", "Synthetic baseline"
        )
        for index in range(case.size)
    )
    start = time.perf_counter()
    matcher = Matcher((Feed("synthetic", "1", records),))
    counters["processed"] = len(matcher.index)
    indexed_at = time.perf_counter()
    path = root / "SKILL.md"  # Only a model identity: no file is opened or created.
    document = Document(Artifact(path, ArtifactKind.SKILL, SourceFormat.MARKDOWN))
    findings = matcher.detect(document, records[-1].value)
    counters.update(artifacts=1, bytes=0, findings=len(findings), errors=0)
    end = time.perf_counter()
    if len(matcher.index) != case.size or len(findings) != 1:
        raise RuntimeError("IOC index/match coverage differs from request")
    return {"index": indexed_at - start, "match": end - indexed_at}


def _graph(case: Workload, root: Path, counters: dict[str, int]) -> dict[str, float]:
    # Graph workload groups up to 20 nodes under each inert document; high-branch
    # intentionally attaches every edge to one document (1000 edges, below caps).
    branch = case.kind == "high_branch"
    group_size = case.size if branch else 20
    documents = []
    for group in range(0, case.size, group_size):
        path = root / f"synthetic-{group:05d}" / "SKILL.md"
        artifact = Artifact(path, ArtifactKind.SKILL, SourceFormat.MARKDOWN)
        location = SourceRef(path, SourceFormat.MARKDOWN, 1)
        relationships = tuple(
            Relationship("references_url", f"https://baseline.invalid/{index}", location)
            for index in range(group + 1, min(group + group_size, case.size))
        )
        documents.append(Document(artifact, relationships=relationships))
    start = time.perf_counter()
    graph = build_graph(root, tuple(documents), {})
    counters.update(
        processed=len(graph.nodes),
        artifacts=len(documents),
        bytes=0,
        findings=0,
        errors=0,
        edges=len(graph.edges),
        max_fanout=group_size - 1,
    )
    end = time.perf_counter()
    if len(graph.nodes) != case.size or len(graph.edges) != case.size - len(documents):
        raise RuntimeError("synthetic graph node/edge coverage differs from request")
    return {"build_graph": end - start}


def measure(case: Workload, root: Path) -> dict[str, Any]:
    """Run one trusted local workload; fixture generation is excluded from wall time."""
    if case not in (*FULL, *SMOKE) and not (case.kind == "high_branch" and 1 <= case.size <= 1000):
        raise ValueError(f"unsupported workload: {case.name}")
    counters: dict[str, int] = {"requested": case.size, "processed": 0}
    phases: dict[str, float] = {}
    start = time.perf_counter()
    try:
        if case.kind in {"files", "nearmax", "oversize"}:
            phases = _files(case, root, counters)
        elif case.kind == "ioc":
            phases = _ioc(case, root, counters)
        else:
            phases = _graph(case, root, counters)
        seconds = sum(phases.values())
        status = "partial" if case.kind == "nearmax" else "ok"
        error = None
    except Exception as exc:
        seconds = time.perf_counter() - start
        status = "error"
        error = f"{type(exc).__name__}: {exc}"
    # Total time measures named phases only, never fixture construction. On error,
    # elapsed time is approximate and covers the attempted setup/measurement.
    metrics: dict[str, float | dict[str, float]] = {
        "wall_seconds": round(seconds, 6),
        "files_per_second": round(counters.get("processed", 0) / seconds, 3)
        if case.kind in {"files", "nearmax", "oversize"} and seconds > 0
        else 0.0,
        "mb_per_second": round(counters.get("bytes", 0) / (1024 * 1024 * seconds), 3)
        if seconds > 0
        else 0.0,
        "peak_rss_mb": peak_rss_mb(),
        "phases_seconds": {name: round(value, 6) for name, value in phases.items()},
    }
    return {
        "case": case.name,
        "status": status,
        "counters": counters,
        "metrics": metrics,
        "error": error,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selected = parser.add_mutually_exclusive_group(required=True)
    selected.add_argument("--smoke", action="store_true", help="five quick cases")
    selected.add_argument("--full", action="store_true", help="all ten baseline cases")
    selected.add_argument("--case", choices=[item.name for item in (*FULL, *SMOKE)])
    # Internal subprocess transport: no shell, no arbitrary file/command arguments.
    selected.add_argument(
        "--_worker", choices=[item.name for item in (*FULL, *SMOKE)], help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    if args._worker:
        with tempfile.TemporaryDirectory(prefix="dragonscan-perf-") as directory:
            case = next(item for item in (*FULL, *SMOKE) if item.name == args._worker)
            print(json.dumps(measure(case, Path(directory)), sort_keys=True))
        return 0
    cases = (
        SMOKE
        if args.smoke
        else FULL
        if args.full
        else tuple(item for item in FULL if item.name == args.case)
        or tuple(item for item in SMOKE if item.name == args.case)
    )
    results = []
    for case in cases:
        try:
            child = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--_worker", case.name],
                capture_output=True,
                text=True,
                timeout=900,
                check=True,
            )
            results.append(json.loads(child.stdout))
        except (subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
            results.append(
                {
                    "case": case.name,
                    "status": "error",
                    "counters": {"requested": case.size, "processed": 0},
                    "metrics": {},
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
    output = {
        "schema_version": 1,
        "mode": "smoke" if args.smoke else "full" if args.full else "case",
        "environment": {
            "python": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
            "max_artifact_bytes": MAX_BYTES,
            "rss_unit": "MiB",
            "throughput_unit": "MiB/s",
        },
        "results": results,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 1 if any(item["status"] == "error" for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
