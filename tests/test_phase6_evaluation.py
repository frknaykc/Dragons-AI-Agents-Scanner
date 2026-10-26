"""Harness checks use disposable cases, not the frozen evaluation examples."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import benchmark, phase6_evaluation


def frozen(tmp_path: Path, *, broken: bool = False) -> Path:
    target = tmp_path / "sample"
    target.mkdir()
    (target / "SKILL.md").write_text("# Review\n\nSummarize public release notes.\n")
    if broken:
        (target / "mcp.json").write_text("{")
    case = {
        "id": "sample",
        "artifact": "sample",
        "classification": "benign",
        "split": "holdout",
        "provenance": "synthetic",
        "notes": "Disposable harness case",
        "expected": [],
        "expected_findings": [],
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"schema_version": 1, "corpus_version": "test", "cases": [case]})
    )
    lock = {
        "manifest_sha256": phase6_evaluation.digest(manifest),
        "files": {
            path.relative_to(tmp_path).as_posix(): phase6_evaluation.digest(path)
            for path in target.iterdir()
        },
        "cases": {"sample": {"category": "test", "label": "negative"}},
        "source_policy": "Disposable synthetic harness fixture",
    }
    (tmp_path / "ground_truth.lock.json").write_text(json.dumps(lock))
    return manifest


@pytest.mark.parametrize("mutation", ["artifact", "label", "extra", "missing", "symlink"])
def test_freeze_rejects_changes_before_scanner(tmp_path, monkeypatch, mutation):
    manifest = frozen(tmp_path)
    target = tmp_path / "sample/SKILL.md"
    if mutation == "artifact":
        target.write_text("Changed input")
    elif mutation == "label":
        manifest.write_text(manifest.read_text().replace('"benign"', '"malicious"'))
    elif mutation == "extra":
        (target.parent / "mcp.json").write_text("{}")
    elif mutation == "missing":
        target.unlink()
    else:
        target.unlink()
        target.symlink_to(manifest)

    def forbidden(*args, **kwargs):
        pytest.fail("scanner must not run after frozen-input mismatch")

    monkeypatch.setattr(benchmark, "run", forbidden)
    with pytest.raises(ValueError):
        phase6_evaluation.run(manifest)


def test_partial_is_not_a_successful_negative(tmp_path):
    result = phase6_evaluation.run(frozen(tmp_path, broken=True))
    assert result["status"] == "partial"
    assert result["summary"]["evaluated_cases"] == 0
    assert result["summary"]["failed_cases"] == 1
    counts = result["per_attack_category"]["test"]
    assert counts["negative_cases"] == 0 and counts["incomplete_cases"] == 1
    assert counts["precision"] is None and counts["recall"] is None


def test_negative_only_has_no_recall(tmp_path):
    result = phase6_evaluation.run(frozen(tmp_path))
    assert result["status"] == "completed"
    assert result["summary"]["evaluated_cases"] == 1
    assert result["summary"]["recall"] is None
    assert result["per_attack_category"]["test"]["recall"] is None


def test_evaluation_freeze_and_category_coverage_without_scanning():
    manifest = phase6_evaluation.DEFAULT_MANIFEST
    lock = phase6_evaluation.validate_freeze(manifest)
    cases = json.loads(manifest.read_text())["cases"]
    assert len(cases) == 36
    assert len(lock["files"]) == 40
    categories = {case["category"] for case in lock["cases"].values()}
    assert len(categories) == 9
    for category in categories:
        labels = [case["label"] for case in lock["cases"].values() if case["category"] == category]
        assert labels.count("positive") == labels.count("negative") == 2
    for case in cases:
        assert {item["id"] for item in case["expected_findings"]} == set(case["expected"])
        assert lock["cases"][case["id"]]["expected_evidence"]


def test_id_hits_do_not_hide_wrong_occurrences_or_extra_findings():
    ident = "DRAGON-PI-001"
    expected = {
        "id": ident,
        "artifact": "sample/SKILL.md",
        "line": 3,
        "evidence_contains": "override",
    }
    row = {
        "id": "sample",
        "split": "holdout",
        "classification": "malicious",
        "notes": "Disposable scoring example",
        "expected": [ident],
        "expected_findings": [expected],
        "actual": [
            {"id": ident, "artifact": "sample/SKILL.md", "line": 4, "evidence": "unrelated"},
            {"id": "DRAGON-PI-002", "artifact": "sample/SKILL.md", "line": 4},
        ],
    }
    lock = {
        "cases": {"sample": {"category": "test"}},
        "manifest_sha256": hashlib.sha256(b"disposable").hexdigest(),
        "source_policy": "Harness test",
    }
    result = phase6_evaluation.summarize(benchmark.evaluate([row], "test"), lock)
    assert result["summary"]["tp"] == 1 and result["summary"]["fp"] == 1
    assert result["occurrence_summary"]["tp"] == 0
    assert result["occurrence_summary"]["fp"] == 2
    assert result["occurrence_summary"]["fn"] == 1
    assert result["field_coverage"]["location"]["mismatched"] == 1
    assert result["field_coverage"]["evidence"]["mismatched"] == 1
