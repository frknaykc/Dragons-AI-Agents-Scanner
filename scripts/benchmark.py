"""Offline, source-only detection-quality measurement over explicit local ground truth.

Run with: uv run --offline python -m scripts.benchmark benchmarks/corpus/manifest.json
"""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

from dragonscan.discovery import DiscoveryError, discover
from dragonscan.models import Target
from dragonscan.scanner import Scanner

_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z", re.ASCII)
_FINDING_ID = re.compile(r"(?<![A-Z0-9-])(?:DAAS|DRAGON-[A-Z]+)-\d{3}(?!\d)")
_ALLOWED = frozenset(
    {
        "id",
        "artifact",
        "classification",
        "split",
        "provenance",
        "notes",
        "expected",
        "expected_categories",
        "expected_findings",
        "expected_absent",
        "intel_feed",
    }
)
_MAX_MANIFEST = 256_000
_FIELDS = frozenset(
    {
        "id",
        "category",
        "artifact",
        "line",
        "evidence_contains",
        "source",
        "sink",
        "severity",
        "path_edges",
        "path_nodes",
        "flow_edges",
        "flow_nodes",
    }
)


class BenchmarkError(ValueError):
    """Invalid ground truth or unsafe/unavailable corpus artifact."""


def registry() -> tuple[str, ...]:
    """Use the same distributed source ID inventory as the existing registry regression."""
    source = Path(__file__).resolve().parents[1] / "src" / "dragonscan"
    identifiers: set[str] = set()
    for module in source.glob("*.py"):
        identifiers.update(_FINDING_ID.findall(module.read_text(encoding="utf-8")))
    return tuple(sorted(identifiers))


def _string(value: Any, label: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= limit or not value.isprintable():
        raise BenchmarkError(f"invalid {label}")
    return value


def _inside(root: Path, name: Any, *, file_only: bool = False) -> Path:
    text = _string(name, "corpus path", 160)
    # Portable, POSIX-style logical paths, independent of host path separators.
    parts = text.split("/")
    if any(
        not _ID.fullmatch(part) and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", part)
        for part in parts
    ):
        raise BenchmarkError("unsafe corpus path")
    if any(part in {".", ".."} for part in parts) or "\\" in text or ":" in text:
        raise BenchmarkError("unsafe corpus path")
    path = root.joinpath(*parts)
    if path.resolve() != path.absolute() or not path.resolve().is_relative_to(root):
        raise BenchmarkError("symlink or corpus escape")
    if not path.exists() or (file_only and not path.is_file()):
        raise BenchmarkError("missing corpus artifact")
    if path.is_dir():
        for directory, dirs, files in os.walk(path, followlinks=False):
            if any((Path(directory) / name).is_symlink() for name in (*dirs, *files)):
                raise BenchmarkError("symlink inside corpus artifact")
    return path


def load_manifest(path: Path) -> tuple[str, list[dict[str, Any]]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_MANIFEST:
        raise BenchmarkError("invalid manifest file")
    root = path.resolve().parent
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        raise BenchmarkError("invalid manifest JSON") from exc
    if (
        not isinstance(data, dict)
        or set(data) != {"schema_version", "corpus_version", "cases"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
    ):
        raise BenchmarkError("unsupported manifest schema")
    version = _string(data["corpus_version"], "corpus version", 40)
    cases = data["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 256:
        raise BenchmarkError("invalid case count")
    ids = set(registry())
    seen: set[str] = set()
    for entry in cases:
        if (
            not isinstance(entry, dict)
            or not {"id", "artifact", "classification", "split", "provenance", "notes", "expected"}
            <= set(entry)
            or not set(entry) <= _ALLOWED
        ):
            raise BenchmarkError("invalid case fields")
        name = _string(entry["id"], "case ID", 80)
        if not _ID.fullmatch(name) or name in seen:
            raise BenchmarkError("duplicate or invalid case ID")
        seen.add(name)
        if (
            entry["classification"] not in ("malicious", "benign")
            or entry["split"] not in ("development", "holdout")
            or entry["provenance"] not in ("synthetic", "curated", "real-world-derived")
        ):
            raise BenchmarkError("invalid case classification, split or provenance")
        _string(entry["notes"], "case notes", 512)
        target = _inside(root, entry["artifact"])
        try:
            if not discover(Target(target)):
                raise BenchmarkError("no discoverable artifact")
        except DiscoveryError as exc:
            raise BenchmarkError("invalid scan target") from exc
        if "intel_feed" in entry:
            _inside(root, entry["intel_feed"], file_only=True)
        expected = entry["expected"]
        if (
            not isinstance(expected, list)
            or any(
                not isinstance(item, str) or item not in ids or item.startswith("DRAGON-SEM-")
                for item in expected
            )
            or len(expected) != len(set(expected))
            or (entry["classification"] == "benign" and expected)
            or (entry["classification"] == "malicious" and not expected)
        ):
            raise BenchmarkError("invalid or duplicate expected finding IDs")
        absent = entry.get("expected_absent", [])
        if (
            not isinstance(absent, list)
            or any(not isinstance(item, str) or item not in ids for item in absent)
            or len(absent) != len(set(absent))
            or set(absent) & set(expected)
        ):
            raise BenchmarkError("invalid or conflicting hard-negative IDs")
        categories = entry.get("expected_categories", {})
        if (
            not isinstance(categories, dict)
            or not set(categories) <= set(expected)
            or any(
                not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value)
                for value in categories.values()
            )
        ):
            raise BenchmarkError("invalid expected categories")
        findings = entry.get("expected_findings", [])
        if not isinstance(findings, list) or len(findings) > 128:
            raise BenchmarkError("invalid expected findings")
        for item in findings:
            if (
                not isinstance(item, dict)
                or not set(item) <= _FIELDS
                or item.get("id") not in expected
            ):
                raise BenchmarkError("invalid expected finding fields or ID")
            for key, value in item.items():
                if key == "id":
                    continue
                if key == "line":
                    if type(value) is not int or value < 1:
                        raise BenchmarkError("invalid finding line")
                elif key == "artifact":
                    _inside(root, value, file_only=True)
                elif key in {"path_edges", "path_nodes", "flow_edges", "flow_nodes"}:
                    if (
                        not isinstance(value, list)
                        or len(value) > 32
                        or any(
                            not isinstance(part, str)
                            or not 1 <= len(part) <= 256
                            or not part.isprintable()
                            for part in value
                        )
                    ):
                        raise BenchmarkError("invalid finding path")
                elif key == "severity":
                    if value not in {"info", "low", "medium", "high", "critical"}:
                        raise BenchmarkError("invalid finding severity")
                elif key in {"source", "sink"} and value is None:
                    pass
                else:
                    _string(value, f"finding {key}")
    return version, sorted(cases, key=lambda item: item["id"])


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def measure(expected: set[str], actual: set[str]) -> dict[str, int | float | None]:
    tp, fp, fn = len(expected & actual), len(actual - expected), len(expected - actual)
    precision = round(tp / (tp + fp), 6) if tp + fp else None
    recall = round(tp / (tp + fn), 6) if tp + fn else None
    f1 = round(2 * tp / (2 * tp + fp + fn), 6) if tp + fp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def _totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = 0
    for row in rows:
        tp += len(set(row["expected"]) & {item["id"] for item in row["actual"]})
        fp += len({item["id"] for item in row["actual"]} - set(row["expected"]))
        fn += len(set(row["expected"]) - {item["id"] for item in row["actual"]})
    # Count micro decisions, not the union of IDs across cases.
    total = measure(set(), set())
    total.update(
        tp=tp,
        fp=fp,
        fn=fn,
        precision=round(tp / (tp + fp), 6) if tp + fp else None,
        recall=round(tp / (tp + fn), 6) if tp + fn else None,
        f1=round(2 * tp / (2 * tp + fp + fn), 6) if tp + fp + fn else None,
    )
    return total


def _differences(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    return [
        field
        for field, value in expected.items()
        if field != "id"
        and (
            value not in (actual.get("evidence") or "")
            if field == "evidence_contains"
            else value != actual.get(field)
        )
    ]


def _assign_exact(
    entry_index: int,
    expected: list[dict[str, Any]],
    actual: list[dict[str, Any]],
    matches: dict[int, int],
    visited: set[int],
) -> bool:
    entry = expected[entry_index]
    for index, item in enumerate(actual):
        if index in visited or item["id"] != entry["id"] or _differences(entry, item):
            continue
        visited.add(index)
        if index not in matches or _assign_exact(
            matches[index], expected, actual, matches, visited
        ):
            matches[index] = entry_index
            return True
    return False


def _correctness(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    checked = failed = negative_checked = negative_failed = 0
    for row in rows:
        actual = row["actual"]
        categories = row.get("expected_categories", {})
        category_mismatches = [
            {
                "id": item["id"],
                "expected": categories[item["id"]],
                "actual": item.get("category"),
                "artifact": item.get("artifact"),
                "line": item.get("line"),
            }
            for item in actual
            if item["id"] in categories and item.get("category") != categories[item["id"]]
        ]
        expected_findings = row.get("expected_findings", [])
        forbidden = row.get("expected_absent", [])
        present = {item["id"] for item in actual}
        negative_mismatches = sorted(set(forbidden) & present)
        negative_checked += len(forbidden)
        negative_failed += len(negative_mismatches)
        paired: set[int] = set()
        missing: list[dict[str, Any]] = []
        mismatches: list[dict[str, Any]] = []
        # Augment exact matches so broad expectations cannot steal a specific one's only match.
        matches: dict[int, int] = {}
        exact = {
            index
            for index in range(len(expected_findings))
            if _assign_exact(index, expected_findings, actual, matches, set())
        }
        paired.update(matches)
        for index, entry in enumerate(expected_findings):
            if index in exact:
                continue
            candidates = [
                (len(_differences(entry, item)), item_index, _differences(entry, item))
                for item_index, item in enumerate(actual)
                if item_index not in paired and item["id"] == entry["id"]
            ]
            if candidates:
                _, item_index, fields = min(candidates)
                paired.add(item_index)
                mismatches.append(
                    {"expected": entry, "actual": actual[item_index], "fields": fields}
                )
            else:
                missing.append(entry)
        asserted_ids = {entry["id"] for entry in expected_findings}
        extra = [
            item
            for index, item in enumerate(actual)
            if item["id"] in asserted_ids and index not in paired
        ]
        assertions = len(category_mismatches) + len(expected_findings) + len(extra)
        checked += len(expected_findings) + sum(item["id"] in categories for item in actual)
        failed += (
            len(category_mismatches)
            + len(missing)
            + len(mismatches)
            + len(extra)
            + len(negative_mismatches)
        )
        if assertions or missing or mismatches or forbidden:
            cases.append(
                {
                    "case": row["id"],
                    "split": row["split"],
                    "category_mismatches": category_mismatches,
                    "missing_occurrences": missing,
                    "mismatches": mismatches,
                    "unexpected_occurrences": extra,
                    "hard_negative_mismatches": negative_mismatches,
                }
            )
    return {
        "checked": checked,
        "failed": failed,
        "hard_negative_checked": negative_checked,
        "hard_negative_failed": negative_failed,
        "status": "failed" if failed else "passed",
        "cases": cases,
    }


def evaluate(
    rows: list[dict[str, Any]], corpus_version: str, *, failures: list[dict[str, str]] | None = None
) -> dict[str, Any]:
    failures = failures or []
    rows = sorted(rows, key=lambda item: item["id"])
    all_ids = registry()
    fp: list[dict[str, Any]] = []
    fn: list[dict[str, Any]] = []
    for row in rows:
        expected = set(row["expected"])
        actual = {item["id"] for item in row["actual"]}
        unexpected_seen: set[str] = set()
        for finding in row["actual"]:
            if finding["id"] not in expected and finding["id"] not in unexpected_seen:
                fp.append({"case": row["id"], **finding})
                unexpected_seen.add(finding["id"])
        for identifier in sorted(expected - actual):
            fn.append(
                {
                    "case": row["id"],
                    "id": identifier,
                    "category": row.get("expected_categories", {}).get(identifier),
                    "notes": row["notes"],
                    "actual_ids": sorted(actual),
                }
            )
    fp.sort(key=lambda item: (item["case"], item["id"], item["artifact"], item["line"] or 0))
    per_rule = {}
    for identifier in all_ids:
        positives = [row for row in rows if identifier in row["expected"]]
        false_positives = sum(
            identifier in {finding["id"] for finding in row["actual"]}
            and row["id"] not in {p["id"] for p in positives}
            for row in rows
        )
        true_positives = sum(
            any(finding["id"] == identifier for finding in row["actual"]) for row in positives
        )
        support = len(positives)
        per_rule[identifier] = {
            "positive_support": support,
            "benign_exposure": sum(row["classification"] == "benign" for row in rows),
            "tp": true_positives,
            "fp": false_positives,
            "fn": support - true_positives,
            "precision": round(true_positives / (true_positives + false_positives), 6)
            if true_positives + false_positives
            else None,
            "recall": round(true_positives / support, 6) if support else None,
            "f1": round(
                2
                * true_positives
                / (2 * true_positives + false_positives + support - true_positives),
                6,
            )
            if true_positives + false_positives + support - true_positives
            else None,
        }
    supported = [identifier for identifier in all_ids if per_rule[identifier]["positive_support"]]
    summary = _totals(rows)
    summary.update(
        evaluated_cases=len(rows),
        failed_cases=len(failures),
        malicious_cases=sum(row["classification"] == "malicious" for row in rows),
        benign_cases=sum(row["classification"] == "benign" for row in rows),
    )
    return {
        "schema_version": 1,
        "corpus_version": corpus_version,
        "status": "partial" if failures else "completed",
        "summary": summary,
        "splits": {
            split: {
                **_totals([row for row in rows if row["split"] == split]),
                "evaluated_cases": sum(row["split"] == split for row in rows),
            }
            for split in ("development", "holdout")
        },
        "coverage": {
            "total_rules": len(all_ids),
            "supported": supported,
            "unsupported": sorted(set(all_ids) - set(supported)),
            "semantic_excluded": [i for i in all_ids if i.startswith("DRAGON-SEM-")],
        },
        "per_rule": per_rule,
        "correctness": _correctness(rows),
        "cases": rows,
        "false_positives": fp,
        "false_negatives": fn,
        "failures": sorted(failures, key=lambda item: item["case"]),
    }


def run(manifest: Path) -> dict[str, Any]:
    version, cases = load_manifest(manifest)
    root = manifest.resolve().parent
    rows: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for case in cases:
        try:
            target = root / case["artifact"]
            feeds = (root / case["intel_feed"],) if "intel_feed" in case else ()
            # Fresh scanner per case; no installed feeds or opt-in external features.
            report = Scanner(intel_feeds=feeds).scan(Target(target))
            if (
                report.errors
                or report.intelligence_status == "partial"
                or report.vulnerability_status == "partial"
                or report.semantic_status == "partial"
                or report.dynamic_status in ("partial", "failed", "blocked")
            ):
                raise BenchmarkError("incomplete static scan")
            actual = []
            for finding in report.findings:
                artifact = finding.artifact.resolve().relative_to(root).as_posix()
                actual.append(
                    {
                        "id": finding.detection_id,
                        "category": finding.category,
                        "severity": finding.severity.value,
                        "artifact": artifact,
                        "line": finding.line,
                        "evidence": finding.evidence,
                        "source": finding.source,
                        "sink": finding.sink,
                        "path_edges": [step.edge for step in finding.path],
                        "path_nodes": (
                            [finding.path[0].source] + [step.target for step in finding.path]
                        )
                        if finding.path
                        else [],
                        "flow_edges": list(finding.flow.edges) if finding.flow else [],
                        "flow_nodes": list(finding.flow.nodes) if finding.flow else [],
                    }
                )
            actual.sort(key=lambda x: (x["id"], x["artifact"], x["line"] or 0, x["source"] or ""))
            rows.append(
                {
                    "id": case["id"],
                    "split": case["split"],
                    "classification": case["classification"],
                    "provenance": case["provenance"],
                    "artifact": case["artifact"],
                    "notes": case["notes"],
                    "expected": case["expected"],
                    "expected_categories": case.get("expected_categories", {}),
                    "expected_findings": case.get("expected_findings", []),
                    "expected_absent": case.get("expected_absent", []),
                    "actual": actual,
                }
            )
        except (BenchmarkError, DiscoveryError, OSError, ValueError, RuntimeError) as exc:
            failures.append({"case": case["id"], "error": type(exc).__name__})
    return evaluate(rows, version, failures=failures)


def baseline(result: dict[str, Any]) -> dict[str, Any]:
    """Stable measured summary, excluding raw case-by-case scan output."""
    return {
        "schema_version": result["schema_version"],
        "corpus_version": result["corpus_version"],
        "status": result["status"],
        "summary": result["summary"],
        "splits": result["splits"],
        "coverage": result["coverage"],
        "per_rule": result["per_rule"],
        "correctness": {
            key: value for key, value in result["correctness"].items() if key != "cases"
        },
        "false_positives": result["false_positives"],
        "false_negatives": result["false_negatives"],
        "failures": result["failures"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline development benchmark; no quality gate")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--format", choices=("terminal", "json", "baseline"), default="terminal")
    args = parser.parse_args()
    try:
        result = run(args.manifest)
    except BenchmarkError as exc:
        parser.error(str(exc))
    if args.format in ("json", "baseline"):
        print(
            json.dumps(
                baseline(result) if args.format == "baseline" else result, indent=2, sort_keys=True
            )
        )
    else:
        summary = result["summary"]
        print(
            f"Status: {result['status']} | Cases: {summary['evaluated_cases']}"
            f" | Failed: {summary['failed_cases']}"
        )
        for label, values in (("Overall", result["summary"]), *result["splits"].items()):
            print(
                f"{label}: TP {values['tp']} FP {values['fp']} FN {values['fn']}"
                f" precision {values['precision']} recall {values['recall']} F1 {values['f1']}"
            )
        coverage = result["coverage"]
        print(f"Rule support: {len(coverage['supported'])}/{coverage['total_rules']}")
        correctness = result["correctness"]
        print(
            f"Correctness: {correctness['checked']} field/occurrence checks, "
            f"{correctness['hard_negative_checked']} targeted negatives, "
            f"{correctness['failed']} failed"
        )
        for case in correctness["cases"]:
            if any(
                case[key]
                for key in (
                    "category_mismatches",
                    "missing_occurrences",
                    "mismatches",
                    "unexpected_occurrences",
                    "hard_negative_mismatches",
                )
            ):
                summary = ", ".join(
                    f"{label} {len(case[key])}"
                    for label, key in (
                        ("category", "category_mismatches"),
                        ("missing", "missing_occurrences"),
                        ("wrong", "mismatches"),
                        ("extra", "unexpected_occurrences"),
                        ("hard-negative", "hard_negative_mismatches"),
                    )
                )
                print(f"  {case['case']}: {summary}")
        for kind in ("false_positives", "false_negatives"):
            print(f"{kind}: {[(item['case'], item['id']) for item in result[kind]]}")
    if result["status"] != "completed":
        return 2
    return 1 if result["correctness"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
