"""Offline, source-only detection-quality measurement over explicit local ground truth.

Run with: uv run --offline python -m scripts.benchmark benchmarks/corpus/manifest.json
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import date
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
        "fn_causes",
        "intel_feed",
    }
)
_MAX_MANIFEST = 256_000
_REAL_SPLITS = {"realworld-benign", "realworld-malicious", "independent-holdout"}
# Ground-truth occurrence support, not detector performance or independent samples.
_ATTACK_CLASSES = {
    "prompt-injection": frozenset({"DRAGON-PI-001", "DRAGON-PI-002"}),
    "credential-access": frozenset({"DRAGON-CRED-001"}),
    "exfiltration": frozenset({"DAAS-001", "DRAGON-EXFIL-001", "DRAGON-PATH-001"}),
    "dangerous-execution": frozenset(
        {"DAAS-002", "DRAGON-EXEC-001", "DRAGON-OBF-002", "DRAGON-PATH-002"}
    ),
    "persistence": frozenset({"DRAGON-PERSIST-001", "DRAGON-PATH-003", "DRAGON-PATH-004"}),
    "remote-trust": frozenset({"DRAGON-TRUST-001", "DRAGON-PATH-003", "DRAGON-PATH-004"}),
    "mcp-poisoning": frozenset({"DRAGON-MCP-006", "DRAGON-MCP-008"}),
    "package-runtime-execution": frozenset({"DRAGON-SC-003", "DRAGON-SC-006"}),
    "supply-chain": frozenset({f"DRAGON-SC-{n:03d}" for n in range(1, 8)}),
    "obfuscation-evasion": frozenset({"DRAGON-OBF-001", "DRAGON-OBF-002"}),
    "sensitive-data-handling": frozenset(
        {"DAAS-001", "DRAGON-CRED-001", "DRAGON-EXFIL-001", "DRAGON-PATH-001"}
    ),
    "cross-artifact-attack-chain": frozenset(
        {"DRAGON-PATH-001", "DRAGON-PATH-002", "DRAGON-PATH-003", "DRAGON-PATH-004"}
    ),
}
_PROVENANCE_FIELDS = {
    "source_type",
    "source",
    "reference",
    "observed_date",
    "license",
    "redistribution",
    "rationale",
    "expected_behavior",
    "curation_notes",
    "sha256",
}
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
        part not in {".mcp.json"}
        and not _ID.fullmatch(part)
        and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", part)
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


def _real_provenance(value: Any, target: Path) -> str:
    if not isinstance(value, dict) or set(value) != _PROVENANCE_FIELDS:
        raise BenchmarkError("incomplete real-world provenance")
    for key in _PROVENANCE_FIELDS - {"sha256"}:
        _string(value[key], f"provenance {key}", 1024)
    if not value["reference"].startswith("https://") or value["license"].lower() == "unknown":
        raise BenchmarkError("unverifiable real-world source or license")
    if value["redistribution"] != "permitted":
        raise BenchmarkError("fixture redistribution not permitted")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value["observed_date"]):
        raise BenchmarkError("invalid provenance date")
    try:
        date.fromisoformat(value["observed_date"])
    except ValueError as exc:
        raise BenchmarkError("invalid provenance date") from exc
    digest = _string(value["sha256"], "artifact digest", 64)
    if (
        not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not target.is_file()
        or target.stat().st_size > 2_000_000
    ):
        raise BenchmarkError("invalid artifact digest, directory or size")
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise BenchmarkError("artifact digest mismatch")
    return digest


def _schema(path: Path) -> tuple[int, dict[str, Any]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_MANIFEST:
        raise BenchmarkError("invalid manifest file")
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        raise BenchmarkError("invalid manifest JSON") from exc
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int:
        raise BenchmarkError("unsupported manifest schema")
    schema = data["schema_version"]
    if schema == 1 and set(data) == {"schema_version", "corpus_version", "cases"}:
        return schema, data
    if (
        schema == 2
        and set(data) == {"schema_version", "corpus_version", "suite", "cases"}
        and data["suite"] in ("realworld", "holdout")
    ):
        return schema, data
    raise BenchmarkError("unsupported manifest schema")


def load_manifest(path: Path) -> tuple[str, list[dict[str, Any]]]:
    schema, data = _schema(path)
    root = path.resolve().parent
    version = _string(data["corpus_version"], "corpus version", 40)
    cases = data["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 256:
        raise BenchmarkError("invalid case count")
    ids = set(registry())
    seen: set[str] = set()
    digests: set[str] = set()
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
        if schema == 1:
            if "fn_causes" in entry:
                raise BenchmarkError("FN taxonomy is only supported by schema 2")
            if (
                entry["classification"] not in ("malicious", "benign")
                or entry["split"] not in ("development", "holdout")
                or entry["provenance"] not in ("synthetic", "curated", "real-world-derived")
            ):
                raise BenchmarkError("invalid case classification, split or provenance")
        else:
            split = entry["split"]
            if (
                split not in _REAL_SPLITS
                or (data["suite"] == "holdout") != (split == "independent-holdout")
                or entry["classification"] not in ("benign", "malicious")
                or (split == "realworld-benign" and entry["classification"] != "benign")
                or (split == "realworld-malicious" and entry["classification"] != "malicious")
            ):
                raise BenchmarkError("development/holdout isolation or invalid classification")
        _string(entry["notes"], "case notes", 512)
        target = _inside(root, entry["artifact"])
        if schema == 2:
            digest = _real_provenance(entry["provenance"], target)
            if digest in digests:
                raise BenchmarkError("duplicate logical artifact content")
            digests.add(digest)
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
        if schema == 2 and (
            "intel_feed" in entry or "DRAGON-TI-001" in expected or "DRAGON-TI-001" in absent
        ):
            raise BenchmarkError("TI must be measured separately from deterministic detection")
        causes = entry.get("fn_causes", {})
        if schema == 2 and (
            not isinstance(causes, dict)
            or not set(causes) <= set(expected)
            or any(
                not isinstance(value, str)
                or value
                not in {
                    "missing detector",
                    "parser limitation",
                    "unsupported schema",
                    "discovery gap",
                    "context/semantic limitation",
                    "normalization problem",
                    "occurrence matching issue",
                    "source/sink modeling problem",
                    "evidence/location mismatch",
                    "other",
                }
                for value in causes.values()
            )
        ):
            raise BenchmarkError("invalid FN root-cause taxonomy")
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
        if schema == 2 and (
            set(expected) != {item.get("id") for item in findings if isinstance(item, dict)}
            or (entry["classification"] == "benign" and not absent)
        ):
            raise BenchmarkError("real-world positive occurrences or targeted negatives required")
        for item in findings:
            if (
                schema == 2
                and isinstance(item, dict)
                and not {"id", "artifact", "line", "evidence_contains", "category"} <= set(item)
            ):
                raise BenchmarkError("real-world occurrence lacks location, evidence or category")
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
    if schema == 2 and root.name in {"realworld", "holdout"}:
        other = (
            root.parent / ("holdout" if root.name == "realworld" else "realworld") / "manifest.json"
        )
        if other.is_file():
            other_schema, other_data = _schema(other)
            if other_schema != 2 or not isinstance(other_data["cases"], list):
                raise BenchmarkError("invalid independent suite")
            other_ids = {
                item["id"]
                for item in other_data["cases"]
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            }
            other_digests = {
                value
                for item in other_data["cases"]
                if isinstance(item, dict) and isinstance(item.get("provenance"), dict)
                if isinstance(value := item["provenance"].get("sha256"), str)
            }
            if seen & other_ids or digests & other_digests:
                raise BenchmarkError("real-world/holdout logical case overlap")
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


def _real_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    correctness = _correctness(rows)
    by_case = {item["case"]: item for item in correctness["cases"]}
    tp = fp = fn = 0
    fn_taxonomy: dict[str, int] = {}
    field_keys = {
        "location": {"artifact", "line"},
        "evidence": {"evidence_contains"},
        "category": {"category"},
        "source": {"source"},
        "sink": {"sink"},
        "path": {"path_edges", "path_nodes", "flow_edges", "flow_nodes"},
    }
    field_coverage = {
        name: {"asserted": 0, "correct": 0, "mismatched": 0, "missing": 0} for name in field_keys
    }
    occurrence = {
        key: 0
        for key in (
            "correct",
            "wrong_location",
            "wrong_evidence",
            "wrong_source_sink",
            "wrong_path",
            "wrong_category",
            "missing",
            "extra",
        )
    }
    for row in rows:
        details = by_case.get(row["id"], {})
        missing = details.get("missing_occurrences", [])
        mismatches = details.get("mismatches", [])
        extra = details.get("unexpected_occurrences", [])
        tp += len(row["expected_findings"]) - len(missing) - len(mismatches)
        fn += len(missing) + len(mismatches)
        for entry in [*missing, *(item["expected"] for item in mismatches)]:
            cause = row.get("fn_causes", {}).get(entry["id"], "unclassified")
            fn_taxonomy[cause] = fn_taxonomy.get(cause, 0) + 1
        fp += len(mismatches) + len(extra)
        # Unasserted IDs on a case count once each, not once per filesystem occurrence.
        fp += len({item["id"] for item in row["actual"]} - set(row["expected"]) - {"DRAGON-TI-001"})
        occurrence["correct"] += len(row["expected_findings"]) - len(missing) - len(mismatches)
        occurrence["missing"] += len(missing)
        occurrence["extra"] += len(extra)
        for entry in row["expected_findings"]:
            for name, fields in field_keys.items():
                if fields & entry.keys():
                    field_coverage[name]["asserted"] += 1
        for entry in missing:
            for name, fields in field_keys.items():
                if fields & entry.keys():
                    field_coverage[name]["missing"] += 1
        for mismatch in mismatches:
            for name, fields in field_keys.items():
                if fields & set(mismatch["fields"]):
                    field_coverage[name]["mismatched"] += 1
        for mismatch in mismatches:
            fields = set(mismatch["fields"])
            for label, selected in (
                ("wrong_location", {"artifact", "line"}),
                ("wrong_evidence", {"evidence_contains"}),
                ("wrong_source_sink", {"source", "sink", "flow_edges", "flow_nodes"}),
                ("wrong_path", {"path_edges", "path_nodes"}),
                ("wrong_category", {"category"}),
            ):
                occurrence[label] += bool(fields & selected)
    for counts in field_coverage.values():
        counts["correct"] = counts["asserted"] - counts["missing"] - counts["mismatched"]
    precision = round(tp / (tp + fp), 6) if tp + fp else None
    recall = round(tp / (tp + fn), 6) if tp + fn else None
    f1 = round(2 * tp / (2 * tp + fp + fn), 6) if tp + fp + fn else None
    return {
        "summary": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "evaluated_cases": len(rows),
        },
        "occurrence": occurrence,
        "field_coverage": field_coverage,
        "targeted_negative_failures": correctness["hard_negative_failed"],
        "correctness": correctness,
        "ti": {
            "matches": sum(item["id"] == "DRAGON-TI-001" for row in rows for item in row["actual"])
        },
        "fp_taxonomy": {"unclassified": fp} if fp else {},
        "fn_taxonomy": fn_taxonomy,
    }


def measure_realworld(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Score exact occurrences, retaining legacy case×ID measurements as diagnostics only."""
    result = _real_counts(rows)
    supported_ids = set().union(*_ATTACK_CLASSES.values())
    expected = [
        assertion
        for row in rows
        if row.get("expected")
        for assertion in row.get("expected_findings", [])
    ]
    class_counts = {
        name: sum(item["id"] in identifiers for item in expected)
        for name, identifiers in _ATTACK_CLASSES.items()
    }
    result["attack_class_coverage"] = {
        name: {
            "represented": bool(count),
            "scored_occurrences": count,
            "unique_malicious_artifacts": len(
                {
                    row.get("provenance", {}).get("sha256") or row.get("artifact", row["id"])
                    for row in rows
                    if row.get("classification") == "malicious"
                    and any(
                        item["id"] in _ATTACK_CLASSES[name]
                        for item in row.get("expected_findings", [])
                    )
                }
            ),
        }
        for name, count in class_counts.items()
    }
    result["unmapped_expected_ids"] = sorted({item["id"] for item in expected} - supported_ids)
    result["id_level"] = _totals(
        [
            {**row, "actual": [item for item in row["actual"] if item["id"] != "DRAGON-TI-001"]}
            for row in rows
        ]
    )
    splits = (
        ("independent-holdout",)
        if any(row["split"] == "independent-holdout" for row in rows)
        else ("realworld-benign", "realworld-malicious")
    )
    result["splits"] = {
        split: _real_counts([row for row in rows if row["split"] == split])["summary"]
        for split in splits
    }
    result["artifact_types"] = {
        kind: _real_counts([row for row in rows if Path(row["artifact"]).suffix == kind])["summary"]
        for kind in sorted({Path(row["artifact"]).suffix for row in rows if "artifact" in row})
    }
    result["source_classes"] = {
        kind: _real_counts(
            [
                row
                for row in rows
                if isinstance(row.get("provenance"), dict)
                and row["provenance"]["source_type"] == kind
            ]
        )["summary"]
        for kind in sorted(
            {
                row["provenance"]["source_type"]
                for row in rows
                if isinstance(row.get("provenance"), dict)
            }
        )
    }
    result["observed_by_severity"] = {
        severity: sum(item.get("severity") == severity for row in rows for item in row["actual"])
        for severity in ("info", "low", "medium", "high", "critical")
    }
    return result


def run(manifest: Path) -> dict[str, Any]:
    schema, data = _schema(manifest)
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
                    **({"fn_causes": case.get("fn_causes", {})} if schema == 2 else {}),
                    "actual": actual,
                }
            )
        except (BenchmarkError, DiscoveryError, OSError, ValueError, RuntimeError) as exc:
            failures.append({"case": case["id"], "error": type(exc).__name__})
    if schema == 1:
        return evaluate(rows, version, failures=failures)
    result = measure_realworld(rows)
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        scanner_commit = commit.stdout.strip() if commit.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        scanner_commit = None
    result.update(
        schema_version=2,
        corpus_version=version,
        suite=data["suite"],
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        scanner_commit=scanner_commit,
        status="partial" if failures else "completed",
        failures=failures,
        cases=rows,
        semantic="not-evaluated",
        ti_status="not-evaluated-no-explicit-feed",
    )
    result["summary"]["failed_cases"] = len(failures)
    return result


def baseline(result: dict[str, Any]) -> dict[str, Any]:
    """Stable measured summary, excluding raw case-by-case scan output."""
    if result["schema_version"] == 2:
        return {
            key: value for key, value in result.items() if key not in {"cases", "correctness"}
        } | {
            "correctness": {
                key: value for key, value in result["correctness"].items() if key != "cases"
            }
        }
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
        if result["schema_version"] == 2:
            print(
                f"{result['suite']} {result['corpus_version']} | Status: {result['status']}"
                f" | Cases: {summary['evaluated_cases']} | Failed: {summary['failed_cases']}"
                f" | SHA-256: {result['manifest_sha256']} | Scanner: {result['scanner_commit']}"
            )
            for label, values in (("Overall", summary), *result["splits"].items()):
                print(
                    f"{label}: TP {values['tp']} FP {values['fp']} FN {values['fn']}"
                    f" precision {values['precision']} recall {values['recall']} F1 {values['f1']}"
                )
            print(f"Occurrence: {result['occurrence']}")
            print(f"Attack-class support (not accuracy): {result['attack_class_coverage']}")
            print(f"Unmapped expected IDs: {result['unmapped_expected_ids']}")
            print(f"Targeted negative failures: {result['targeted_negative_failures']}")
            print(f"TI: {result['ti_status']} | Semantic: {result['semantic']}")
            return 2 if result["status"] != "completed" else 0
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
