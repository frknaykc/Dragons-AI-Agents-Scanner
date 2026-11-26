"""Coverage counts derive from actual built-ins and explicit ground truth."""

import csv
import json
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dragonscan.catalog import STAGE_IDS
from dragonscan.detectors import BUILTIN_DETECTORS, SourceSinkDetector
from dragonscan.models import Target
from dragonscan.report_context import evidence_kind
from dragonscan.rules import BUILTIN_RULES
from dragonscan.scanner import Scanner
from dragonscan.signatures import BUILTIN_SIGNATURES
from scripts.benchmark import registry
from scripts.coverage_inventory import ROOT, builtin_registry, inventory


def test_proposal_ledger_covers_every_guide_id_once() -> None:
    with (ROOT / "docs/reference-rule-ledger.csv").open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    sizes = {
        "PI": 15,
        "RCE": 12,
        "SEC": 13,
        "PER": 10,
        "OBF": 11,
        "MCP": 18,
        "SKL": 15,
        "SUP": 17,
        "WEB": 18,
        "CFG": 15,
    }
    assert len(rows) == sum(sizes.values())
    assert {r["reference_id"] for r in rows} == {
        f"{family}-{i:03}" for family, n in sizes.items() for i in range(1, n + 1)
    }
    assert all(
        r["family_tasks"]
        and r["disposition"] in {"existing", "revise", "new", "deferred", "not-applicable"}
        for r in rows
    )
    guide = (ROOT / "Dragons-Security-Engine-Development-Guide-v2.md").read_text()
    backlog = guide.split("## 15. Detection rule backlog", 1)[1].split("### 15.A", 1)[0]
    manifest = json.loads((ROOT / "benchmarks/corpus/manifest.json").read_text())
    expected = {case["id"]: case["expected"] for case in manifest["cases"]}
    registered = builtin_registry()
    roadmap = (ROOT / "roadmap.md").read_text()
    tasks = set(re.findall(r"^\| \[[ x]\] (DSE-\d{3}) ·", roadmap, re.M))
    for row in rows:
        ref = row["reference_id"]
        assert set(row["family_tasks"].split()) <= tasks, ref
        assert row["reason"] and row["reason"] != "source_definition_missing", ref
        if row["disposition"] in {"existing", "revise"}:
            assert row["rule_id"] in registered, ref
            assert row["rule_id"] in expected[row["benchmark_case"]], ref
            assert row["evidence"] != "unknown", ref
        elif row["disposition"] == "new":
            assert f"| {row['rule_id']} | Yeni |" in backlog, ref
            assert row["rule_id"] not in registered, ref
            assert not row["benchmark_case"] and row["evidence"] == "unknown", ref
        else:
            assert not row["rule_id"] and not row["benchmark_case"], ref
            assert row["evidence"] == "unknown", ref
            assert f"DRAGON-{ref}" not in registered, ref
            assert f"| DRAGON-{ref} |" not in backlog, ref
            if row["disposition"] == "deferred":
                assert row["review_task"] in tasks and row["reopen_when"].strip(), ref


def test_public_ids_from_assessment_are_preserved() -> None:
    report = (ROOT / "Dragons-Technical-Assessment-2026-11-26.md").read_text()
    appendix = report.split("\n## Ek B.", 1)[1].split("\n## Ek C.", 1)[0]
    baseline = set(re.findall(r"^#### ((?:DRAGON-[A-Z]+|DAAS)-\d{3})\b", appendix, re.M))
    baseline.update(re.findall(r"^\| `(DRAGON-SEM-\d{3})` —", appendix, re.M))
    assert len(baseline) == 48
    assert baseline <= set(builtin_registry())


def test_mapped_cases_emit_the_recorded_static_evidence() -> None:
    corpus = ROOT / "benchmarks/corpus"
    manifest = json.loads((corpus / "manifest.json").read_text())
    artifacts = {case["id"]: corpus / case["artifact"] for case in manifest["cases"]}
    with (ROOT / "docs/reference-rule-ledger.csv").open(encoding="utf-8", newline="") as source:
        mapped = [
            row for row in csv.DictReader(source) if row["disposition"] in {"existing", "revise"}
        ]
    scanner = Scanner()
    results = {
        case: {
            (f.detection_id, evidence_kind(f))
            for f in scanner.scan(Target(artifacts[case])).findings
        }
        for case in {row["benchmark_case"] for row in mapped}
    }
    for row in mapped:
        assert (row["rule_id"], row["evidence"]) in results[row["benchmark_case"]], row[
            "reference_id"
        ]


@pytest.mark.parametrize(
    "identifier", ["DRAGON-PATH-002", "DRAGON-SEM-001", "DRAGON-SIG-001", "DRAGON-TI-001"]
)
def test_rule_cannot_impersonate_a_different_producer(identifier: str) -> None:
    with pytest.raises(ValueError, match="duplicate rule ID"):
        Scanner(rules=(replace(BUILTIN_RULES[0], detection_id=identifier),))


def test_registry_parity_and_scanner_metadata() -> None:
    actual = builtin_registry()
    assert set(actual) == set(registry())
    assert len(actual) == 49
    assert STAGE_IDS == {key for key, source in actual.items() if source.startswith("scanner:")}
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
    assert result["summary"]["built_in_ids"] == len(rows) == 49
    assert result["summary"]["default_ids"] == len(default)
    assert result["summary"]["default_uncovered_count"] == len(uncovered)
    assert uncovered == {"DRAGON-EXEC-002", "DRAGON-EXEC-003", "DRAGON-EXEC-004"}
    assert set(result["summary"]["default_uncovered_ids"]) == uncovered
    interpreter = inventory(ROOT / "benchmarks/interpreter/manifest.json")["ids"]["DRAGON-EXEC-002"]
    assert interpreter["benchmark_positive"] and interpreter["benchmark_hard_negative"]
    assert interpreter["source_sink_assertion"] and interpreter["occurrence_assertion"]
    encoded = inventory(ROOT / "benchmarks/phase3/manifest.json")["ids"]["DRAGON-EXEC-003"]
    assert encoded["benchmark_positive"] and encoded["benchmark_hard_negative"]
    assert encoded["source_sink_assertion"] and encoded["occurrence_assertion"]
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
