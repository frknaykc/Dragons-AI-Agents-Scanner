"""Separate semantic evaluation; offline by default, no provider-quality claim without opt-in.

Run: uv run --offline python -m scripts.semantic_benchmark benchmarks/semantic/corpus/manifest.json
"""

import argparse
import json
import os
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

from dragonscan.discovery import DiscoveryError, discover
from dragonscan.loading import LoadError, load_text
from dragonscan.models import Target
from dragonscan.parse_errors import ParseError
from dragonscan.parsing import parse
from dragonscan.scanner import Scanner
from dragonscan.semantic import VERSION, SemanticLimits, SemanticProvider, redact, select
from dragonscan.semantic_provider import OpenAICompatibleProvider
from scripts.benchmark import BenchmarkError, _differences, _inside, _string, _unique_pairs

# A category-level proxy, NOT proof that a static finding establishes semantic intent.
_IDS = {
    "DRAGON-SEM-001": ("prompt_injection", {"DRAGON-PI-001", "DRAGON-PI-002"}),
    "DRAGON-SEM-002": ("tool_poisoning", {"DRAGON-MCP-006"}),
    "DRAGON-SEM-003": ("behavior_mismatch", {"DRAGON-MCP-008"}),
    "DRAGON-SEM-004": ("persistence_intent", {"DRAGON-PERSIST-001"}),
    "DRAGON-SEM-005": ("sensitive_data_intent", {"DRAGON-MCP-010"}),
}
_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z", re.ASCII)
_CLASS = re.compile(r"[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*\Z", re.ASCII)
_MAX_MANIFEST = 256_000
_NOT_MEASURED = "NOT MEASURED"


def load_manifest(path: Path) -> list[dict[str, Any]]:
    """Validate all paths before scanning any case. No artifact is imported or executed."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_MANIFEST:
        raise BenchmarkError("invalid semantic manifest file")
    root = path.resolve().parent
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        raise BenchmarkError("invalid semantic manifest JSON") from exc
    if not isinstance(data, dict) or set(data) != {"version", "cases"} or data["version"] != "1.0":
        raise BenchmarkError("unsupported semantic manifest schema")
    cases = data["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 256:
        raise BenchmarkError("invalid semantic case count")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) - {"expected_finding", "expected_candidate"} != {
            "id",
            "artifact",
            "semantic_id",
            "expected",
            "class",
            "split",
        }:
            raise BenchmarkError("invalid semantic case fields")
        name = _string(case["id"], "semantic case ID", 80)
        if not _ID.fullmatch(name) or name in seen:
            raise BenchmarkError("duplicate or invalid semantic case ID")
        seen.add(name)
        if (
            not isinstance(case["semantic_id"], str)
            or case["semantic_id"] not in _IDS
            or type(case["expected"]) is not bool
            or ("expected_candidate" in case and type(case["expected_candidate"]) is not bool)
            or case["split"] != "development"
            or not _CLASS.fullmatch(_string(case["class"], "semantic class", 80))
        ):
            raise BenchmarkError("invalid semantic case metadata")
        target = _inside(root, case["artifact"], file_only=True)
        if target.name not in {"AGENTS.md", "mcp.json"}:
            raise BenchmarkError("semantic artifact must be an instruction or MCP metadata file")
        if "expected_finding" in case:
            finding = case["expected_finding"]
            if not case["expected"] or not isinstance(finding, dict) or not finding:
                raise BenchmarkError("invalid semantic finding expectation")
            if set(finding) - {
                "id",
                "category",
                "artifact",
                "line",
                "evidence_contains",
                "severity",
            }:
                raise BenchmarkError("invalid semantic finding expectation fields")
            if "id" in finding and finding["id"] != case["semantic_id"]:
                raise BenchmarkError("semantic finding expectation ID mismatch")
            if "category" in finding and finding["category"] != "semantic":
                raise BenchmarkError("invalid semantic finding category")
            if (
                "artifact" in finding
                and _inside(root, finding["artifact"], file_only=True) != target
            ):
                raise BenchmarkError("semantic finding artifact mismatch")
            if "line" in finding and (type(finding["line"]) is not int or finding["line"] < 1):
                raise BenchmarkError("invalid semantic finding line")
            if "severity" in finding and finding["severity"] not in {"low", "medium"}:
                raise BenchmarkError("invalid semantic finding severity")
            if "evidence_contains" in finding:
                _string(finding["evidence_contains"], "semantic evidence", 256)
        try:
            if not discover(Target(target)):
                raise BenchmarkError("no discoverable semantic artifact")
        except DiscoveryError as exc:
            raise BenchmarkError("invalid semantic scan target") from exc
    return sorted(cases, key=lambda item: item["id"])


class _ObservedProvider:
    """Count provider exceptions without storing requests, responses, or error messages."""

    def __init__(self, provider: SemanticProvider):
        self.provider = provider
        self.identity = provider.identity
        self.model = provider.model
        self.exceptions: list[str] = []

    def analyze(self, request: dict[str, object], timeout: float, max_response: int) -> bytes:
        try:
            return self.provider.analyze(request, timeout, max_response)
        except Exception as exc:
            self.exceptions.append(type(exc).__name__)
            raise


def _partial_reason(report: Any, provider_errors: list[str]) -> str | None:
    if (
        report.errors
        or report.intelligence_status == "partial"
        or report.vulnerability_status == "partial"
    ):
        return "scan_failure"
    if report.semantic_status != "partial":
        return None
    diagnostics = report.semantic_diagnostics
    if provider_errors or any(
        "rate limited" in d or "provider or response failure" in d for d in diagnostics
    ):
        return "provider_failure"
    if any("schema rejected" in d for d in diagnostics):
        return "schema_reject"
    if any("budget" in d or "size limit" in d for d in diagnostics):
        return "budget_partial"
    return "other_partial"


def _inside_case(finding: Any, root: Path, target: Path) -> bool:
    path = finding.artifact.resolve()
    return path.is_relative_to(root) and (
        path == target or target.is_dir() and path.is_relative_to(target)
    )


def _observation(
    report: Any,
    baseline: Any,
    case: dict[str, Any],
    root: Path,
    target: Path,
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    identifier = case["semantic_id"]
    category, _ = _IDS[identifier]
    eligible = []
    for finding in report.findings:
        semantic = finding.semantic
        if semantic is None or semantic.category != category:
            continue
        valid = (
            _inside_case(finding, root, target)
            and (finding.detection_id == identifier or finding.detection_id in _IDS[identifier][1])
            and (finding.detection_id != identifier or finding.category == "semantic")
        )
        if valid:
            eligible.append(finding)
    new = [f for f in eligible if f.detection_id == identifier]
    expected_finding = case.get("expected_finding")
    occurrence_match = None
    if expected_finding is not None:
        checked = {"id": identifier, **expected_finding}
        occurrence_match = any(
            not _differences(
                checked,
                {
                    "id": f.detection_id,
                    "category": f.category,
                    "artifact": str(f.artifact.resolve().relative_to(root)),
                    "line": f.line,
                    "evidence": f.evidence,
                    "severity": f.severity.value,
                },
            )
            for f in new
        )
    annotations = [f for f in eligible if f.detection_id != identifier]
    buckets = sorted({f.confidence.value for f in eligible})
    static_occurrences = Counter(
        (f.detection_id, f.category, f.artifact.resolve(), f.line, f.severity.value)
        for f in baseline.findings
    )
    annotation_fields_match = True
    for f in annotations:
        actual = {
            "id": f.detection_id,
            "category": f.category,
            "artifact": f.artifact.resolve(),
            "line": f.line,
            "severity": f.severity.value,
        }
        match = next(
            (
                original
                for original in baseline.findings
                if static_occurrences[
                    (
                        original.detection_id,
                        original.category,
                        original.artifact.resolve(),
                        original.line,
                        original.severity.value,
                    )
                ]
                and original.detection_id == f.detection_id
                and original.artifact == f.artifact
                and original.line == f.line
            ),
            None,
        )
        if match is None:
            annotation_fields_match = False
            continue
        expected = {
            "id": match.detection_id,
            "category": match.category,
            "artifact": match.artifact.resolve(),
            "line": match.line,
            "severity": match.severity.value,
        }
        annotation_fields_match &= not _differences(expected, actual)
        static_occurrences[tuple(expected.values())] -= 1
    location_matches = []
    for f in new:
        ref = f.semantic.candidate_id if f.semantic else ""
        index = int(ref[1:]) - 1 if re.fullmatch(r"S[1-9][0-9]*", ref) else -1
        if 0 <= index < len(candidates):
            expected = {
                "id": identifier,
                "category": "semantic",
                "artifact": candidates[index]["artifact"],
                "line": candidates[index]["line"],
            }
            actual = {
                "id": f.detection_id,
                "category": f.category,
                "artifact": f.artifact.resolve(),
                "line": f.line,
            }
            location_matches.append(not _differences(expected, actual))
        else:
            location_matches.append(False)
    # No evidence, rationale, raw provider output or untrusted diagnostic text persisted.
    return {
        "detected": bool(eligible),
        "expected_finding_match": occurrence_match,
        "additional": bool(new),
        "enrichment": bool(annotations),
        "confidence": buckets,
        "severity": sorted({f.severity.value for f in eligible}),
        "new_severity_policy_valid": all(f.severity.value in {"low", "medium"} for f in new),
        "candidate_location_match": all(location_matches) if new else None,
        "annotation_fields_match": annotation_fields_match,
        "location_present": all(f.line is not None for f in eligible) if eligible else None,
        "id_category_artifact_valid": bool(eligible),
        "mismatched_outputs": sum(
            f.semantic is not None and f.semantic.category == category and f not in eligible
            for f in report.findings
        ),
        "other_semantic_ids_for_review": sorted(
            {
                f.detection_id
                for f in report.findings
                if f.detection_id.startswith("DRAGON-SEM-") and f not in eligible
            }
        ),
    }


def _selection(
    report: Any, target: Path, root: Path, semantic_id: str, limits: SemanticLimits
) -> dict[str, Any]:
    # Parse the same discovered artifacts for the public select() call. The scanner may
    # additionally enrich its internal documents with supply-chain metadata.
    documents = tuple(parse(artifact, load_text(artifact.path)) for artifact in report.artifacts)
    candidates, overflow, count = select(documents, report.findings, limits)
    category = _IDS[semantic_id][0]
    eligible_candidates = sum(
        category in c.categories
        and c.artifact.resolve().is_relative_to(root)
        and (
            c.artifact.resolve() == target
            or target.is_dir()
            and c.artifact.resolve().is_relative_to(target)
        )
        for c in candidates
    )
    sanitized = [redact(c.text) for c in candidates]
    normalized = [
        "".join(" " if unicodedata.category(ch) in {"Cc", "Cf", "Cs"} else ch for ch in c.text)
        for c in candidates
    ]
    return {
        "eligible": eligible_candidates > 0,
        "eligible_candidates": eligible_candidates,
        "selected": len(candidates),
        "available": count,
        "overflow": overflow,
        "omitted_by_budget": count - len(candidates),
        "text_bytes": sum(len(c.text.encode("utf-8")) for c in candidates),
        "snippet_bytes": sum(
            len(safe[: limits.max_snippet].encode("utf-8"))
            for safe in sanitized
            if safe is not None
        ),
        "redacted": sum(
            safe is None or safe != text for safe, text in zip(sanitized, normalized, strict=True)
        ),
        "privacy_skipped": sum(safe is None for safe in sanitized),
        "truncated": sum(len(safe) > limits.max_snippet for safe in sanitized if safe is not None),
        "reasons": sorted({c.reason for c in candidates}),
        "_candidates": [{"artifact": c.artifact.resolve(), "line": c.line} for c in candidates],
    }


def _repeat(
    case: dict[str, Any], root: Path, provider: SemanticProvider | None, limits: SemanticLimits
) -> dict[str, Any]:
    target = root / case["artifact"]
    baseline = Scanner().scan(Target(target))
    if (
        baseline.errors
        or baseline.intelligence_status == "partial"
        or baseline.vulnerability_status == "partial"
    ):
        return {"status": "scan_failure"}
    _, static_ids = _IDS[case["semantic_id"]]
    static_tp = any(
        f.detection_id in static_ids and _inside_case(f, root, target) for f in baseline.findings
    )
    try:
        selection = _selection(baseline, target, root, case["semantic_id"], limits)
    except (LoadError, ParseError, DiscoveryError, OSError, ValueError):
        return {"status": "scan_failure"}
    candidate_locations = selection.pop("_candidates")
    row: dict[str, Any] = {
        "status": "complete",
        "static_tp_proxy": static_tp,
        "deterministic_finding": any(_inside_case(f, root, target) for f in baseline.findings),
        "candidate": selection,
    }
    if provider is None:
        row["semantic"] = _NOT_MEASURED
        return row
    observer = _ObservedProvider(provider)
    semantic_report = Scanner(semantic_provider=observer, semantic_limits=limits).scan(
        Target(target)
    )
    reason = _partial_reason(semantic_report, observer.exceptions)
    row["status"] = reason or "complete"
    row["semantic"] = _observation(
        semantic_report, baseline, case, root, target, candidate_locations
    )
    row["semantic"]["selected"] = semantic_report.semantic_candidates_selected
    row["semantic"]["analyzed"] = semantic_report.semantic_candidates_analyzed

    # Compare deterministic findings across both scans; semantic enrichment may annotate
    # a finding, but must not modify its ID/category/artifact/line/severity.
    def static_keys(report: Any) -> Counter[tuple[str, str, str, int | None, str]]:
        return Counter(
            (f.detection_id, f.category, str(f.artifact.resolve()), f.line, f.severity.value)
            for f in report.findings
            if not f.detection_id.startswith("DRAGON-SEM-")
        )

    row["static_unchanged"] = static_keys(baseline) == static_keys(semantic_report)
    if not row["static_unchanged"]:
        row["status"] = "scan_failure"
    return row


def _stability(case: dict[str, Any], runs: list[dict[str, Any]], provider: bool) -> str:
    if not provider:
        return _NOT_MEASURED
    if any(run["status"] != "complete" for run in runs):
        return "inconclusive"
    correct = [
        run["semantic"]["detected"] == case["expected"]
        and run["semantic"]["expected_finding_match"] is not False
        and not run["semantic"]["mismatched_outputs"]
        for run in runs
    ]
    if all(correct):
        return "stable-correct"
    if not any(correct):
        return "stable-incorrect"
    return "flaky"


def run(
    manifest: Path,
    *,
    provider: SemanticProvider | None = None,
    repeats: int = 3,
    limits: SemanticLimits | None = None,
) -> dict[str, Any]:
    if not 1 <= repeats <= 30:
        raise BenchmarkError("repeats must be between 1 and 30")
    cases = load_manifest(manifest)
    root = manifest.resolve().parent
    limits = limits or SemanticLimits()
    rows = []
    for case in cases:
        runs = [_repeat(case, root, provider, limits) for _ in range(repeats)]
        rows.append(
            {
                **{key: value for key, value in case.items() if key != "expected_finding"},
                "runs": runs,
                "stability": _stability(case, runs, provider is not None),
            }
        )
    selections = [
        (row, run["candidate"]) for row in rows for run in row["runs"] if "candidate" in run
    ]
    selected_positive = sum(s["eligible"] for row, s in selections if row["expected"])
    selected_negative = sum(s["eligible"] for row, s in selections if not row["expected"])
    total_candidates = sum(s["selected"] for _, s in selections)
    positive_candidates = sum(s["eligible_candidates"] for row, s in selections if row["expected"])
    candidate_selection = {
        "positive_selected": selected_positive,
        "negative_selected": selected_negative,
        "positive_candidates": positive_candidates,
        "negative_candidates": sum(s["selected"] for row, s in selections if not row["expected"]),
        "total_candidates": total_candidates,
        "candidate_recall": round(
            selected_positive / sum(row["expected"] for row, _ in selections), 6
        )
        if any(row["expected"] for row, _ in selections)
        else None,
        "candidate_precision_proxy": round(positive_candidates / total_candidates, 6)
        if total_candidates
        else None,
        "text_bytes": sum(s["text_bytes"] for _, s in selections),
        "snippet_bytes": sum(s["snippet_bytes"] for _, s in selections),
        "redacted": sum(s["redacted"] for _, s in selections),
        "privacy_skipped": sum(s["privacy_skipped"] for _, s in selections),
        "truncated": sum(s["truncated"] for _, s in selections),
        "omitted_by_budget": sum(s["omitted_by_budget"] for _, s in selections),
        "expectation_checks": sum("expected_candidate" in row for row, _ in selections),
        "expectation_failures": sum(
            s["eligible"] != row["expected_candidate"]
            for row, s in selections
            if "expected_candidate" in row
        ),
    }
    per_id: dict[str, Any] = {}
    for identifier in _IDS:
        group = [r for r in rows if r["semantic_id"] == identifier]
        baseline_valid = [(r, run) for r in group for run in r["runs"] if "candidate" in run]
        complete = [(r, run) for r, run in baseline_valid if run["status"] == "complete"]
        positives = [(r, run) for r, run in complete if r["expected"]]
        negatives = [(r, run) for r, run in complete if not r["expected"]]
        baseline_positives = [(r, run) for r, run in baseline_valid if r["expected"]]
        offline = {
            "positive": sum(r["expected"] for r in group),
            "negative": sum(
                not r["expected"] and r["class"] not in {"hard-negative", "hard_negative"}
                for r in group
            ),
            "hard_negative": sum(
                not r["expected"] and r["class"] in {"hard-negative", "hard_negative"}
                for r in group
            ),
            "candidate_recall_proxy": (
                round(
                    sum(run["candidate"]["eligible"] for _, run in baseline_positives)
                    / len(baseline_positives),
                    6,
                )
                if baseline_positives
                else None
            ),
            "static_tp_proxy": sum(run["static_tp_proxy"] for _, run in baseline_positives),
            "deterministic_finding_positive": sum(
                run["deterministic_finding"] for _, run in baseline_positives
            ),
            "positive_exposure": len(baseline_positives),
        }
        if provider is None:
            per_id[identifier] = {**offline, "provider_quality": _NOT_MEASURED}
            continue
        clean_pos = [(r, run) for r, run in positives if run["semantic"] != _NOT_MEASURED]
        clean_neg = [(r, run) for r, run in negatives if run["semantic"] != _NOT_MEASURED]
        buckets = {
            bucket: {"positive": 0, "negative": 0, "correct": 0, "incorrect": 0}
            for bucket in ("high", "medium", "low", "absent")
        }
        for r, run in (*clean_pos, *clean_neg):
            confidence = run["semantic"]["confidence"] or ["absent"]
            for bucket in confidence:
                buckets[bucket]["positive" if r["expected"] else "negative"] += 1
                if bucket != "absent":
                    buckets[bucket][
                        "correct"
                        if r["expected"] and run["semantic"]["expected_finding_match"] is not False
                        else "incorrect"
                    ] += 1
        eligible_positive = [(r, run) for r, run in clean_pos if run["candidate"]["eligible"]]

        def correct_hit(run: dict[str, Any]) -> bool:
            return bool(
                run["semantic"]["detected"]
                and run["semantic"]["expected_finding_match"] is not False
            )

        per_id[identifier] = {
            **offline,
            "provider_quality": {
                "tp": sum(
                    run["semantic"]["detected"]
                    and run["semantic"]["expected_finding_match"] is not False
                    for _, run in clean_pos
                ),
                "fp": sum(run["semantic"]["detected"] for _, run in clean_neg),
                "fn": sum(
                    not run["semantic"]["detected"]
                    or run["semantic"]["expected_finding_match"] is False
                    for _, run in clean_pos
                ),
                "tn": sum(not run["semantic"]["detected"] for _, run in clean_neg),
                "provider_recall_given_candidate": (
                    round(
                        sum(correct_hit(run) for _, run in eligible_positive)
                        / len(eligible_positive),
                        6,
                    )
                    if eligible_positive
                    else None
                ),
                "end_to_end_semantic_recall": (
                    round(sum(correct_hit(run) for _, run in clean_pos) / len(clean_pos), 6)
                    if clean_pos
                    else None
                ),
                "semantic_only_fp": sum(
                    run["semantic"]["detected"] and not run["static_tp_proxy"]
                    for _, run in clean_neg
                ),
                "semantic_only_fn": sum(
                    not run["static_tp_proxy"] and not correct_hit(run) for _, run in clean_pos
                ),
                "additional_tp": sum(
                    run["semantic"]["additional"]
                    and run["semantic"]["expected_finding_match"] is not False
                    and not run["static_tp_proxy"]
                    for _, run in clean_pos
                ),
                "duplicate_or_enrichment_tp": sum(
                    run["semantic"]["detected"]
                    and run["semantic"]["expected_finding_match"] is not False
                    and (run["static_tp_proxy"] or run["semantic"]["enrichment"])
                    for _, run in clean_pos
                ),
                "expected_finding_checks": sum(
                    run["semantic"]["expected_finding_match"] is not None for _, run in clean_pos
                ),
                "expected_finding_failures": sum(
                    run["semantic"]["expected_finding_match"] is False for _, run in clean_pos
                ),
                "candidate_misses": sum(
                    not run["candidate"]["eligible"] and not run["semantic"]["detected"]
                    for _, run in clean_pos
                ),
                "provider_misses": sum(
                    run["candidate"]["eligible"]
                    and (
                        not run["semantic"]["detected"]
                        or run["semantic"]["expected_finding_match"] is False
                    )
                    for _, run in clean_pos
                ),
                "confidence_by_truth": buckets,
            },
        }
    statuses = Counter(run["status"] for row in rows for run in row["runs"])
    return {
        "schema_version": 2,
        "corpus_version": "1.0",
        "semantic_version": VERSION,
        "provider": {"identity": provider.identity, "model": provider.model}
        if provider
        else _NOT_MEASURED,
        "repeats": repeats,
        "status": "partial" if any(s != "complete" for s in statuses) else "completed",
        "run_statuses": dict(sorted(statuses.items())),
        "per_id": per_id,
        "candidate_selection": candidate_selection,
        "cases": rows,
        "measurements_4_to_10": _NOT_MEASURED
        if provider is None
        else "see per_id.provider_quality and cases",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Semantic evaluation (offline unless explicitly opted in)"
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--provider-url")
    parser.add_argument("--model")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--format", choices=("json", "terminal"), default="terminal")
    args = parser.parse_args()
    if bool(args.provider_url) != bool(args.model):
        parser.error("--provider-url and --model must be provided together")
    try:
        provider = (
            OpenAICompatibleProvider(
                args.provider_url, args.model, os.environ.get("DRAGONSCAN_SEMANTIC_API_KEY")
            )
            if args.provider_url
            else None
        )
        result = run(args.manifest, provider=provider, repeats=args.repeats)
    except (BenchmarkError, ValueError) as exc:
        parser.error(str(exc))
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Status: {result['status']} | repeats: {result['repeats']}")
        print(f"Provider: {result['provider']}")
        print(f"Candidate selection: {result['candidate_selection']}")
        for identifier, item in result["per_id"].items():
            print(
                f"{identifier}: +{item['positive']} -{item['negative']} "
                f"hard-{item['hard_negative']}"
            )
            print(
                f"  candidate recall proxy={item['candidate_recall_proxy']} "
                f"static TP proxy={item['static_tp_proxy']}/{item['positive_exposure']}"
            )
            print(f"  provider={item['provider_quality']}")
    return 2 if result["status"] != "completed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
