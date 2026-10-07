"""Admission decisions remain separate from scored benchmark inputs."""

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.benchmark import load_manifest, registry

ROOT = Path(__file__).resolve().parents[1] / "benchmarks"
GATES = {
    "full",
    "immutable",
    "sha256",
    "redistribution",
    "static_behavior",
    "independent_reference",
    "taxonomy",
    "independent_expected_occurrence",
    "no_execution",
    "no_duplicate",
}
REQUIRED = {
    "candidate_id",
    "source",
    "immutable_version",
    "artifact_path",
    "reference",
    "completeness",
    "license_status",
    "redistribution_status",
    "static_observability",
    "expected_attack_classes",
    "expected_finding_ids",
    "ground_truth_confidence",
    "artifact_sha256",
    "gate",
    "decision",
    "reason",
}


def validate_ledger(data: dict, scored: dict, referenced: set[str], holdout: set[str]) -> None:
    assert data["schema_version"] == 1
    entries = data["entries"]
    assert entries and len({entry["candidate_id"] for entry in entries}) == len(entries)
    scored_ids = set(scored)
    assert not scored_ids & holdout
    assert not referenced & (scored_ids | holdout)
    assert referenced <= {entry["candidate_id"] for entry in entries}
    admitted = {entry["candidate_id"] for entry in entries if entry["decision"] == "admitted"}
    assert admitted == {"skillscan-keychain-poc"}
    for entry in entries:
        assert set(entry) == REQUIRED
        assert set(entry["gate"]) == GATES
        assert all(type(value) is bool for value in entry["gate"].values())
        assert entry["source"] and entry["immutable_version"] and entry["artifact_path"]
        assert entry["reference"].startswith("https://")
        assert entry["license_status"] and entry["redistribution_status"] and entry["reason"]
        assert isinstance(entry["expected_attack_classes"], list)
        assert isinstance(entry["expected_finding_ids"], list)
        assert set(entry["expected_finding_ids"]) <= set(registry())
        assert entry["decision"] in {"admitted", "reference-only"}
        if entry["decision"] == "reference-only":
            assert entry["candidate_id"] not in scored_ids
            assert not all(entry["gate"].values())
            continue
        assert all(entry["gate"].values())
        assert entry["completeness"] == "full"
        assert entry["redistribution_status"].startswith("permitted")
        assert entry["artifact_sha256"] == scored[entry["candidate_id"]]["provenance"]["sha256"]
        assert entry["artifact_sha256"] not in holdout
        assert set(entry["expected_finding_ids"]) == set(scored[entry["candidate_id"]]["expected"])
        target = ROOT / "realworld" / scored[entry["candidate_id"]]["artifact"]
        assert hashlib.sha256(target.read_bytes()).hexdigest() == entry["artifact_sha256"]


def inputs() -> tuple[dict, dict, set[str], set[str]]:
    data = json.loads((ROOT / "realworld" / "candidate-ledger.json").read_text())
    _, cases = load_manifest(ROOT / "realworld" / "manifest.json")
    _, holdout = load_manifest(ROOT / "holdout" / "manifest.json")
    references = json.loads((ROOT / "realworld" / "malicious-references.json").read_text())
    return (
        data,
        {case["id"]: case for case in cases},
        {entry["case_id"] for entry in references["entries"]},
        {case["id"] for case in holdout} | {case["provenance"]["sha256"] for case in holdout},
    )


def test_candidate_ledger_and_admission_contract() -> None:
    validate_ledger(*inputs())
    license_text = (ROOT / "licenses" / "SKILLSCAN-LICENSE").read_text()
    assert "Copyright (c) 2026 Noah Mitchem" in license_text
    assert "Permission is hereby granted" in license_text
    _, cases = load_manifest(ROOT / "realworld" / "manifest.json")
    assert len([case for case in cases if case["classification"] == "malicious"]) == 2
    assert len([case for case in cases if case["classification"] == "benign"]) == 3
    assert len([case for case in cases if case["id"].endswith("-excerpt")]) == 1
    assert len([case for case in cases if case["id"] == "skillscan-keychain-poc"]) == 1


@pytest.mark.parametrize(
    "mutation", ["duplicate", "license", "gate", "reference", "hash", "holdout"]
)
def test_candidate_ledger_rejects_invalid_admission(mutation: str) -> None:
    data, scored, references, holdout = inputs()
    data = copy.deepcopy(data)
    entry = data["entries"][0]
    if mutation == "duplicate":
        data["entries"].append(copy.deepcopy(entry))
    elif mutation == "license":
        entry["redistribution_status"] = "unverified"
    elif mutation == "gate":
        entry["gate"]["static_behavior"] = False
    elif mutation == "reference":
        references.add(entry["candidate_id"])
    elif mutation == "hash":
        entry["artifact_sha256"] = "0" * 64
    else:
        holdout.add(entry["candidate_id"])
    with pytest.raises(AssertionError):
        validate_ledger(data, scored, references, holdout)
