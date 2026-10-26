"""Frozen synthetic evaluation using the existing offline benchmark and scorers.

Run: uv run --offline python -m scripts.phase6_evaluation
Writes only stdout. Corpus labels and historical baselines are never updated.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts import benchmark

DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks/phase6/manifest.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_freeze(manifest: Path) -> dict[str, Any]:
    """Verify labels, provenance and the complete target file set before any scan."""
    root = manifest.resolve().parent
    lock_path = root / "ground_truth.lock.json"
    if manifest.is_symlink() or lock_path.is_symlink():
        raise ValueError("symlink manifest or lock")
    lock: dict[str, Any] = json.loads(lock_path.read_text(encoding="utf-8"))
    if digest(manifest) != lock["manifest_sha256"]:
        raise ValueError("ground truth changed after freeze")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    names = [case["id"] for case in data["cases"]]
    if len(set(names)) != len(names) or set(names) != set(lock["cases"]):
        raise ValueError("provenance coverage mismatch")
    files: set[str] = set()
    for case in data["cases"]:
        target = root / case["artifact"]
        if target.is_symlink() or not target.resolve().is_relative_to(root):
            raise ValueError("unsafe target")
        paths = [target, *target.rglob("*")] if target.is_dir() else [target]
        for path in paths:
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise ValueError("unsafe corpus path")
            if path.is_file():
                files.add(path.relative_to(root).as_posix())
        expected_label = "positive" if case["expected"] else "negative"
        if lock["cases"][case["id"]]["label"] != expected_label:
            raise ValueError("label mismatch")
    if files != set(lock["files"]):
        raise ValueError("corpus file set changed after freeze")
    for name, expected in lock["files"].items():
        if digest(root / name) != expected:
            raise ValueError(f"corpus changed after freeze: {name}")
    return lock


def summarize(result: dict[str, Any], lock: dict[str, Any]) -> dict[str, Any]:
    """Keep ID metrics and exact asserted occurrence metrics explicitly separate."""
    rows = result["cases"]
    categories = sorted({case["category"] for case in lock["cases"].values()})
    per_category = {}
    for category in categories:
        selected = [row for row in rows if lock["cases"][row["id"]]["category"] == category]
        counts = benchmark._totals(selected)
        counts["evaluated_cases"] = len(selected)
        counts["positive_cases"] = sum(bool(row["expected"]) for row in selected)
        counts["negative_cases"] = sum(not row["expected"] for row in selected)
        counts["incomplete_cases"] = sum(
            lock["cases"][failure["case"]]["category"] == category for failure in result["failures"]
        )
        per_category[category] = counts
    # Reuse the established one-to-one matcher, not a new detector or scoring model.
    occurrence = benchmark._real_counts(rows)
    result.update(
        evaluation_kind="synthetic-non-blind-frozen",
        manifest_sha256=lock["manifest_sha256"],
        source_policy=lock["source_policy"],
        per_attack_category=per_category,
        occurrence_summary=occurrence["summary"],
        occurrence=occurrence["occurrence"],
        field_coverage=occurrence["field_coverage"],
        semantic="not-run",
        dynamic_mcp="not-run",
        source_snapshot={
            path.relative_to(DEFAULT_MANIFEST.parents[2]).as_posix(): digest(path)
            for directory in ("src/dragonscan", "scripts")
            for path in sorted((DEFAULT_MANIFEST.parents[2] / directory).glob("*.py"))
        },
    )
    return result


def run(manifest: Path) -> dict[str, Any]:
    lock = validate_freeze(manifest)
    result = benchmark.run(manifest)
    # Detect concurrent corpus/label changes instead of blessing mixed inputs.
    if validate_freeze(manifest) != lock:
        raise ValueError("freeze changed during evaluation")
    return summarize(result, lock)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        result = run(args.manifest)
    except (OSError, ValueError, KeyError, TypeError, benchmark.BenchmarkError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "completed":
        return 2
    return int(
        bool(result["summary"]["fp"] or result["summary"]["fn"] or result["correctness"]["failed"])
    )


if __name__ == "__main__":
    raise SystemExit(main())
