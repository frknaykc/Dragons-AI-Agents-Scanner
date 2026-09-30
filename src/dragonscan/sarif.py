"""SARIF 2.1.0 projection of existing security findings; no detection or I/O."""

import json
import ntpath
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import quote

from dragonscan.models import Finding, ScanReport, Severity
from dragonscan.risk import ORDER
from dragonscan.semantic import redact

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _safe(text: str, limit: int = 1024) -> str:
    # Redact before truncation; refuse oversized or incomplete sensitive input.
    cleaned = redact(text)
    return cleaned[:limit] if cleaned is not None else "<redacted>"


def _uri(report: ScanReport, artifact: Path) -> str | None:
    value = str(artifact)
    if report.acquisition_kind and report.acquisition_kind.startswith("remote"):
        if not report.acquisition_source:
            return None
        target = str(report.target)
        if value == target or value.startswith(target + "!"):
            value = report.acquisition_source + value[len(target) :]
        else:
            return None  # Do not expose an unprojected acquisition workspace path.
    cleaned = redact(value)
    if cleaned is None or cleaned != value:
        return None  # Never place a redacted/invalid path in source identity.
    if value.startswith("https://"):
        return quote(value, safe="/:!")
    # On POSIX, Path treats Windows drive/UNC paths as relative text.
    if "\\" in value or (len(value) > 1 and value[1] == ":"):
        windows = PureWindowsPath(ntpath.normpath(value))
        if not windows.is_absolute():
            return None
        normalized = windows.as_posix()
        return (
            "file:" + quote(normalized, safe="/:!")
            if normalized.startswith("//")
            else ("file:///" + quote(normalized, safe="/:!"))
        )
    if report.acquisition_kind == "archive":
        return "file://" + quote(value, safe="/:!") if artifact.is_absolute() else None
    physical = artifact.resolve(strict=False)
    try:
        return quote(physical.relative_to(Path.cwd().resolve()).as_posix(), safe="/:!")
    except ValueError:
        return "file://" + quote(physical.as_posix(), safe="/:!")


def _result(report: ScanReport, finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.detection_id,
        "level": _LEVEL[finding.severity],
        "message": {
            "text": f"{_safe(finding.explanation, 512)} Evidence: {_safe(finding.evidence, 384)}"
        },
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "classification": finding.classification.value,
        },
    }
    if finding.intelligence is not None:
        info = finding.intelligence
        result["properties"]["threatIntelligence"] = {
            "indicatorType": info.indicator_type,
            "indicator": _safe(info.indicator, 256),
            "context": info.context,
            "sources": [
                {
                    "feed": source.feed_id,
                    "version": source.feed_version,
                    "record": source.record_id,
                    "source": _safe(source.source, 128),
                    "classification": source.classification,
                }
                for source in info.sources
            ],
        }
    uri = _uri(report, finding.artifact)
    if uri is not None:
        physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if finding.line is not None and finding.line > 0:
            physical["region"] = {"startLine": finding.line}
        result["locations"] = [{"physicalLocation": physical}]
    return result


def _rule(findings: list[Finding]) -> dict[str, Any]:
    representative = min(
        findings,
        key=lambda item: (
            ORDER.index(item.severity),
            _safe(item.title),
            _safe(item.explanation),
            _safe(item.category),
        ),
    )
    contextual = representative.signature is not None or representative.intelligence is not None
    rule: dict[str, Any] = {
        "id": representative.detection_id,
        "name": _safe(representative.title, 256),
        "shortDescription": {"text": _safe(representative.title, 256)},
        "fullDescription": {
            "text": (
                _safe(representative.title, 256) + ". Context is reported per result."
                if contextual
                else _safe(representative.explanation)
            )
        },
        "properties": {"category": _safe(representative.category, 128)},
    }
    # Contextual severity has no single rule-wide default; each result has its own level.
    if not (
        contextual
        or representative.semantic is not None
        or representative.vulnerability is not None
    ):
        rule["defaultConfiguration"] = {"level": _LEVEL[representative.severity]}
    return rule


def sarif_report(report: ScanReport) -> str:
    """Emit only security findings; diagnostics stay in the existing report formats."""
    by_id: dict[str, list[Finding]] = {}
    for finding in report.findings:
        by_id.setdefault(finding.detection_id, []).append(finding)
    rules = [_rule(by_id[identifier]) for identifier in sorted(by_id)]
    results = [_result(report, finding) for finding in report.findings]
    results.sort(
        key=lambda item: (
            item["ruleId"],
            item.get("locations", [{}])[0]
            .get("physicalLocation", {})
            .get("artifactLocation", {})
            .get("uri", ""),
            item.get("locations", [{}])[0]
            .get("physicalLocation", {})
            .get("region", {})
            .get("startLine", 0),
            item["message"]["text"],
            item["level"],
            json.dumps(item, sort_keys=True, ensure_ascii=True),
        )
    )
    return json.dumps(
        {
            "$schema": _SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Dragons AI Agent Scanner", "rules": rules}},
                    "results": results,
                }
            ],
        },
        indent=2,
        ensure_ascii=True,
    )
