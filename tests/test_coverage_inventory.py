"""Coverage counts derive from actual built-ins and explicit ground truth."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dragonscan.detectors import BUILTIN_DETECTORS, SourceSinkDetector
from dragonscan.rules import BUILTIN_RULES
from dragonscan.scanner import Scanner
from dragonscan.signatures import BUILTIN_SIGNATURES
from scripts.benchmark import registry
from scripts.coverage_inventory import ROOT, builtin_registry, inventory


def test_registry_parity_and_scanner_metadata() -> None:
    actual = builtin_registry()
    assert set(actual) == set(registry())
    assert len(actual) == 46
    scanner = Scanner()
    metadata = {rule.detection_id for rule in BUILTIN_RULES}
    metadata.update(detector.metadata.detection_id for detector in BUILTIN_DETECTORS)
    metadata.update(
        detector.access_metadata.detection_id
        for detector in BUILTIN_DETECTORS
        if isinstance(detector, SourceSinkDetector)
    )
    metadata.update(signature.detection_id for signature in BUILTIN_SIGNATURES)
    assert scanner.signature_engine is not None
    assert {sig.detection_id for sig in scanner.signature_engine.signatures} <= metadata
    assert metadata <= set(actual)
    assert actual["DRAGON-PATH-001"].startswith("scanner:")
    assert inventory()["ids"]["DRAGON-PATH-001"]["graph_path_applicable"]
    assert not inventory()["ids"]["DRAGON-PI-001"]["graph_path_applicable"]
    assert actual["DRAGON-SEM-001"] == "semantic"


def test_uncovered_is_calculated_from_manifest() -> None:
    result = inventory()
    rows = result["ids"]
    default = {key for key, value in rows.items() if value["execution_group"] == "default"}
    uncovered = {key for key in default if not rows[key]["benchmark_positive"]}
    assert result["summary"]["built_in_ids"] == len(rows) == 46
    assert result["summary"]["default_ids"] == len(default)
    assert result["summary"]["default_uncovered_count"] == len(uncovered)
    assert result["summary"]["default_uncovered_count"] == 0
    assert set(result["summary"]["default_uncovered_ids"]) == uncovered
    assert rows["DRAGON-FLOW-002"]["graph_path_assertion"]
    assert rows["DRAGON-CRED-001"]["source_sink_assertion"]
    assert rows["DRAGON-MCP-001"]["benchmark_hard_negative"]
    assert all(
        row["unit_positive"] is None and row["unit_negative"] is None for row in rows.values()
    )
    assert all(
        row["execution_group"] != "default"
        for key, row in rows.items()
        if key.startswith("DRAGON-SEM-")
    )
    assert result == inventory()


def test_explicit_hard_negative_and_occurrence_not_inferred(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": [
                    {
                        "id": "positive",
                        "split": "development",
                        "expected": ["DAAS-001"],
                        "expected_findings": [
                            {
                                "id": "DAAS-001",
                                "artifact": "a/SKILL.md",
                                "line": 3,
                                "source": "file",
                                "sink": "endpoint",
                                "path_edges": ["references"],
                            }
                        ],
                    },
                    {"id": "bare", "split": "holdout", "expected": ["DRAGON-PI-001"]},
                    {
                        "id": "negative",
                        "split": "holdout",
                        "expected": [],
                        "expected_absent": ["DAAS-001"],
                    },
                ],
            }
        )
    )
    rows = inventory(manifest)["ids"]
    assert rows["DAAS-001"]["benchmark_hard_negative"]
    assert rows["DAAS-001"]["occurrence_assertion"]
    assert rows["DAAS-001"]["source_sink_assertion"]
    assert rows["DAAS-001"]["graph_path_assertion"]
    assert rows["DRAGON-PI-001"]["holdout"]
    assert not rows["DRAGON-PI-001"]["occurrence_assertion"]
    assert not rows["DRAGON-PI-001"]["benchmark_hard_negative"]


def test_cli_json_is_deterministic_and_missing_manifest_unknown(tmp_path: Path) -> None:
    command = [sys.executable, "-m", "scripts.coverage_inventory", str(tmp_path / "missing.json")]
    first = subprocess.check_output(command, cwd=ROOT)
    assert first == subprocess.check_output(command, cwd=ROOT)
    payload = json.loads(first)
    assert payload["manifest"] is None
    assert not any(row["benchmark_positive"] for row in payload["ids"].values())


def test_invalid_manifest_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        '{"schema_version":1,"cases":[{"id":"case","split":"holdout",'
        '"expected":["DRAGON-NONEXISTENT-001"]}]}'
    )
    with pytest.raises(ValueError, match="unknown expected ID"):
        inventory(manifest)
