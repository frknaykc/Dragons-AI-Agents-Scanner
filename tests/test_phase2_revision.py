"""Protect the approved, data-only Phase 2 expectation revision."""

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.benchmark import run

ROOT = Path(__file__).resolve().parents[1] / "benchmarks"


def test_phase2_revision_changes_only_the_approved_expectation() -> None:
    original = ROOT / "phase2"
    revised = ROOT / "phase2-v2"
    revision = json.loads((revised / "revision.json").read_text())
    old = json.loads((original / "manifest.json").read_text())
    new = json.loads((revised / "manifest.json").read_text())
    expected = deepcopy(old)
    expected["corpus_version"] = "phase2-2"
    case = next(c for c in expected["cases"] if c["id"] == "phase2-linked-artifacts")
    assert case["expected"] == revision["old_expected"]
    case["expected"].remove("DRAGON-CRED-001")
    assert case["expected"] == revision["new_expected"]
    assert new == expected
    for base, key in [(original, "original_manifest_sha256"), (revised, "revised_manifest_sha256")]:
        assert hashlib.sha256((base / "manifest.json").read_bytes()).hexdigest() == revision[key]
    artifact_paths = set()
    for case in old["cases"]:
        target = original / case["artifact"]
        artifact_paths.update(
            str(p.relative_to(original))
            for p in (target.rglob("*") if target.is_dir() else [target])
            if p.is_file()
        )
    assert set(revision["unchanged_artifact_sha256"]) == artifact_paths
    for relative, digest in revision["unchanged_artifact_sha256"].items():
        for base in (original, revised):
            assert hashlib.sha256((base / relative).read_bytes()).hexdigest() == digest


def test_phase2_correction_does_not_claim_a_detector_improvement() -> None:
    old = run(ROOT / "phase2" / "manifest.json")
    new = run(ROOT / "phase2-v2" / "manifest.json")
    for result, expected in [(old, (8, 0, 1)), (new, (8, 0, 0))]:
        assert not result["failures"]
        assert tuple(result["summary"][key] for key in ("tp", "fp", "fn")) == expected
        assert result["correctness"]["status"] == "passed"
    old_cases = {c["id"]: c for c in old["cases"]}
    for case in new["cases"]:
        # Graph node paths differ only because the same bytes live in a separate corpus.
        actual = json.dumps(case["actual"], sort_keys=True).replace("/phase2-v2/", "/phase2/")
        assert actual == json.dumps(old_cases[case["id"]]["actual"], sort_keys=True)
