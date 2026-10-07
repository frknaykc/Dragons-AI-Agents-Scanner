"""Independent corpus boundaries and occurrence-level scoring, using inert inputs."""

import hashlib
import json
import socket
import sys
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.benchmark import BenchmarkError, load_manifest, measure_realworld, run


def fixture(tmp_path: Path, *, suite: str = "realworld") -> tuple[Path, dict]:
    root = tmp_path / suite
    artifact = root / "example" / "SKILL.md"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        f"---\nname: example\ndescription: Documentation\n---\nOrdinary {suite} notes.\n"
    )
    entry = {
        "id": "sample-h" if suite == "holdout" else "sample-a",
        "artifact": "example/SKILL.md",
        "classification": "benign",
        "split": "independent-holdout" if suite == "holdout" else "realworld-benign",
        "notes": "No suspicious behavior in reviewed content",
        "expected": [],
        "expected_absent": ["DRAGON-PI-001"],
        "expected_findings": [],
        "provenance": {
            "source_type": "official-repository",
            "source": "Example project",
            "reference": "https://example.org/project/commit/file",
            "observed_date": "2026-10-03",
            "license": "Apache-2.0",
            "redistribution": "permitted",
            "rationale": "Maintainer documentation, no incident claim",
            "expected_behavior": "No targeted injection finding",
            "curation_notes": "Minimal synthetic test; not a real-world case",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        },
    }
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(
            {"schema_version": 2, "corpus_version": "test", "suite": suite, "cases": [entry]}
        )
    )
    return manifest, entry


def test_pinned_research_artifacts_preserve_measured_false_negatives() -> None:
    manifest = Path(__file__).resolve().parents[1] / "benchmarks/realworld/manifest.json"
    result = run(manifest)
    assert result["corpus_version"] == "realworld-0.4"
    assert result["summary"]["evaluated_cases"] == 5
    assert (result["summary"]["tp"], result["summary"]["fp"], result["summary"]["fn"]) == (1, 0, 3)
    assert result["occurrence"]["correct"] == 1
    assert result["occurrence"]["missing"] == 3
    skill = next(case for case in result["cases"] if case["id"] == "skillscan-keychain-poc")
    assert skill["actual"] == []
    assert skill["classification"] == "malicious"
    assert len(skill["expected_findings"]) == 3
    assert result["fn_taxonomy"]["parser limitation"] == 3
    assert result["occurrence"]["wrong_source_sink"] == 0
    assert result["field_coverage"]["source"]["correct"] == 1
    assert result["field_coverage"]["sink"]["correct"] == 1
    assert result["field_coverage"]["path"]["asserted"] == 0
    assert result["attack_class_coverage"]["exfiltration"] == {
        "represented": True,
        "scored_occurrences": 3,
        "unique_malicious_artifacts": 2,
    }
    assert result["attack_class_coverage"]["credential-access"] == {
        "represented": True,
        "scored_occurrences": 1,
        "unique_malicious_artifacts": 1,
    }
    assert (
        result["attack_class_coverage"]["sensitive-data-handling"]["unique_malicious_artifacts"]
        == 2
    )
    assert result["attack_class_coverage"]["persistence"] == {
        "represented": False,
        "scored_occurrences": 0,
        "unique_malicious_artifacts": 0,
    }
    assert result["attack_class_coverage"]["mcp-poisoning"]["scored_occurrences"] == 0
    assert result["splits"]["realworld-benign"]["evaluated_cases"] == 3
    assert result["splits"]["realworld-benign"]["fp"] == 0
    assert result["targeted_negative_failures"] == 0


def test_realworld_manifest_isolated_and_reproducible(tmp_path: Path) -> None:
    path, entry = fixture(tmp_path)
    version, cases = load_manifest(path)
    assert version == "test" and cases[0]["id"] == entry["id"]
    with (
        patch.object(socket.socket, "connect", side_effect=AssertionError("network")),
        patch.object(urllib.request, "urlopen", side_effect=AssertionError("remote fetch")),
    ):
        result = run(path)
    assert result["schema_version"] == 2
    assert result["manifest_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["summary"]["evaluated_cases"] == 1
    assert result["summary"]["precision"] is None
    assert result["correctness"]["hard_negative_checked"] == 1
    assert "development" not in result["splits"]


def test_holdout_rejects_development_and_realworld(tmp_path: Path) -> None:
    path, entry = fixture(tmp_path, suite="holdout")
    assert run(path)["splits"]["independent-holdout"]["evaluated_cases"] == 1
    for split in ("development", "realworld-benign"):
        path.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "corpus_version": "test",
                    "suite": "holdout",
                    "cases": [{**entry, "split": split}],
                }
            )
        )
        with pytest.raises(BenchmarkError):
            load_manifest(path)


def test_realworld_provenance_integrity_and_duplicate_rejection(tmp_path: Path) -> None:
    path, entry = fixture(tmp_path)
    data = json.loads(path.read_text())
    for change in (
        {"sha256": "0" * 64},
        {"reference": "file:///private"},
        {"license": "unknown"},
        {"rationale": ""},
        {"observed_date": "20261344"},
        {"redistribution": "unknown"},
    ):
        data["cases"] = [{**entry, "provenance": {**entry["provenance"], **change}}]
        path.write_text(json.dumps(data))
        with pytest.raises(BenchmarkError):
            load_manifest(path)
    data["cases"] = [entry, {**entry, "id": "sample-b"}]
    path.write_text(json.dumps(data))
    with pytest.raises(BenchmarkError, match="duplicate logical"):
        load_manifest(path)


def test_positive_manifest_requires_exhaustive_occurrence_fields(tmp_path: Path) -> None:
    path, entry = fixture(tmp_path)
    expected = {
        "id": "DRAGON-PI-001",
        "category": "prompt-manipulation",
        "artifact": "example/SKILL.md",
        "line": 5,
        "evidence_contains": "sample",
        "source": None,
        "sink": None,
        "path_edges": [],
    }
    entry.update(
        classification="malicious",
        split="realworld-malicious",
        expected=["DRAGON-PI-001"],
        expected_absent=[],
    )
    data = {"schema_version": 2, "corpus_version": "test", "suite": "realworld", "cases": [entry]}
    entry["expected_findings"] = [expected]
    path.write_text(json.dumps(data))
    assert load_manifest(path)[1][0]["expected_findings"] == [expected]
    entry["expected_findings"] = [{"id": "DRAGON-PI-001"}]
    path.write_text(json.dumps(data))
    with pytest.raises(BenchmarkError, match="occurrence lacks"):
        load_manifest(path)


def test_realworld_occurrence_mismatch_is_not_tp() -> None:
    expected = {
        "id": "DRAGON-PI-001",
        "artifact": "a/SKILL.md",
        "line": 2,
        "evidence_contains": "injection",
        "source": "reader",
        "sink": "executor",
        "path_edges": ["read"],
    }
    actual = {
        "id": "DRAGON-PI-001",
        "artifact": "a/SKILL.md",
        "line": 3,
        "evidence": "injection",
        "source": "wrong",
        "sink": "executor",
        "path_edges": ["other"],
        "category": "prompt-manipulation",
        "severity": "high",
    }
    rows = [
        {
            "id": "one",
            "split": "realworld-malicious",
            "classification": "malicious",
            "expected": ["DRAGON-PI-001"],
            "expected_findings": [expected],
            "expected_absent": [],
            "actual": [actual],
            "notes": "test",
        }
    ]
    result = measure_realworld(rows)
    assert (result["summary"]["tp"], result["summary"]["fp"], result["summary"]["fn"]) == (0, 1, 1)
    assert (
        result["summary"]["precision"]
        == result["summary"]["recall"]
        == result["summary"]["f1"]
        == 0.0
    )
    assert result["occurrence"]["wrong_location"] == 1
    assert result["occurrence"]["wrong_source_sink"] == 1
    assert result["occurrence"]["wrong_path"] == 1
    assert result["field_coverage"]["location"] == {
        "asserted": 1,
        "correct": 0,
        "mismatched": 1,
        "missing": 0,
    }
    assert result["field_coverage"]["source"]["mismatched"] == 1
    assert result["field_coverage"]["sink"]["correct"] == 1
    assert result["field_coverage"]["path"]["mismatched"] == 1
    assert result["field_coverage"]["category"]["asserted"] == 0
    assert result["id_level"]["tp"] == 1


def test_field_coverage_counts_missing_and_unscorable_fields() -> None:
    rows = [
        {
            "id": "missing",
            "split": "realworld-malicious",
            "classification": "malicious",
            "expected": ["DRAGON-EXFIL-001"],
            "expected_findings": [
                {
                    "id": "DRAGON-EXFIL-001",
                    "artifact": "a/SKILL.md",
                    "line": 2,
                    "evidence_contains": "password",
                    "category": "data-exfiltration",
                    "source": "password",
                    "sink": "external URL",
                }
            ],
            "expected_absent": [],
            "fn_causes": {"DRAGON-EXFIL-001": "source/sink modeling problem"},
            "actual": [],
            "notes": "test",
        }
    ]
    result = measure_realworld(rows)
    assert result["summary"]["tp"] == 0
    assert result["summary"]["fp"] == 0
    assert result["summary"]["fn"] == 1
    assert result["summary"]["precision"] is None
    assert result["summary"]["recall"] == result["summary"]["f1"] == 0.0
    assert result["fn_taxonomy"] == {"source/sink modeling problem": 1}
    assert result["attack_class_coverage"]["exfiltration"]["scored_occurrences"] == 1
    assert result["attack_class_coverage"]["credential-access"]["scored_occurrences"] == 0
    for name in ("location", "evidence", "category", "source", "sink"):
        assert result["field_coverage"][name] == {
            "asserted": 1,
            "correct": 0,
            "mismatched": 0,
            "missing": 1,
        }
    assert result["field_coverage"]["path"]["asserted"] == 0


def test_curated_fn_taxonomy_rejects_unknown_causes(tmp_path: Path) -> None:
    path, entry = fixture(tmp_path)
    entry.update(
        classification="malicious",
        split="realworld-malicious",
        expected=["DRAGON-PI-001"],
        expected_absent=[],
        expected_findings=[
            {
                "id": "DRAGON-PI-001",
                "artifact": "example/SKILL.md",
                "line": 1,
                "evidence_contains": "sample",
                "category": "prompt-manipulation",
            }
        ],
        fn_causes={"DRAGON-PI-001": "invented taxonomy"},
    )
    path.write_text(
        json.dumps(
            {"schema_version": 2, "corpus_version": "test", "suite": "realworld", "cases": [entry]}
        )
    )
    with pytest.raises(BenchmarkError, match="root-cause"):
        load_manifest(path)


def test_full_poc_and_excerpt_are_scored_but_references_are_not() -> None:
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "realworld"
    _, cases = load_manifest(root / "manifest.json")
    malicious = [case for case in cases if case["classification"] == "malicious"]
    assert [case["id"] for case in malicious] == [
        "aisa-password-link-excerpt",
        "skillscan-keychain-poc",
    ]
    for case in malicious:
        assert (
            hashlib.sha256((root / case["artifact"]).read_bytes()).hexdigest()
            == case["provenance"]["sha256"]
        )
    assert (root / malicious[1]["artifact"]).stat().st_size == 579
    references = json.loads((root / "malicious-references.json").read_text())
    assert len(references["entries"]) == 3
    assert not {entry["case_id"] for entry in references["entries"]} & {
        case["id"] for case in cases
    }
    benign = next(case for case in cases if case["id"] == "awesome-copilot-sandbox-install")
    assert benign["classification"] == "benign" and benign["expected_findings"] == []
    assert (
        hashlib.sha256((root / benign["artifact"]).read_bytes()).hexdigest()
        == benign["provenance"]["sha256"]
    )


def test_attack_class_coverage_uses_expected_occurrences_not_scanner_hits() -> None:
    rows = [
        {
            "id": identifier.lower(),
            "split": "realworld-malicious",
            "classification": "malicious",
            "expected": [identifier],
            "expected_findings": [
                {"id": identifier, "artifact": "a/SKILL.md", "line": 1, "evidence_contains": "test"}
            ],
            "expected_absent": [],
            "actual": [],
            "notes": "test",
        }
        for identifier in (
            "DRAGON-PI-001",
            "DRAGON-MCP-006",
            "DRAGON-SIG-001",
            "DAAS-001",
            "DAAS-002",
            "DRAGON-PATH-001",
            "DRAGON-FLOW-001",
        )
    ]
    rows.append(
        {
            "id": "benign",
            "split": "realworld-benign",
            "classification": "benign",
            "expected": [],
            "expected_findings": [],
            "expected_absent": ["DRAGON-EXEC-001"],
            "actual": [],
            "notes": "test",
        }
    )
    result = measure_realworld(rows)
    assert result["summary"]["fn"] == 7
    assert result["attack_class_coverage"]["prompt-injection"]["scored_occurrences"] == 1
    assert result["attack_class_coverage"]["mcp-poisoning"]["scored_occurrences"] == 1
    assert result["attack_class_coverage"]["exfiltration"]["scored_occurrences"] == 2
    assert result["attack_class_coverage"]["dangerous-execution"]["scored_occurrences"] == 1
    assert result["attack_class_coverage"]["cross-artifact-attack-chain"]["scored_occurrences"] == 1
    assert result["unmapped_expected_ids"] == ["DRAGON-FLOW-001", "DRAGON-SIG-001"]


def test_targeted_negative_and_ti_separation() -> None:
    rows = [
        {
            "id": "benign",
            "split": "realworld-benign",
            "classification": "benign",
            "expected": [],
            "expected_findings": [],
            "expected_absent": ["DRAGON-PI-001"],
            "actual": [
                {"id": "DRAGON-PI-001", "artifact": "a/SKILL.md", "line": 1},
                {"id": "DRAGON-TI-001", "artifact": "a/SKILL.md", "line": 2},
            ],
            "notes": "test",
        }
    ]
    result = measure_realworld(rows)
    assert result["summary"]["fp"] == 1
    assert result["targeted_negative_failures"] == 1
    assert result["ti"]["matches"] == 1
    assert result["fp_taxonomy"]["unclassified"] == 1
    assert result["id_level"]["fp"] == 1


def test_cross_suite_identity_collision_is_rejected(tmp_path: Path) -> None:
    real, first = fixture(tmp_path)
    holdout, second = fixture(tmp_path, suite="holdout")
    assert load_manifest(real)[0] == "test"
    data = json.loads(holdout.read_text())
    data["cases"] = [{**second, "id": first["id"]}]
    holdout.write_text(json.dumps(data))
    with pytest.raises(BenchmarkError, match="overlap"):
        load_manifest(real)


def test_targeted_negative_does_not_hide_behind_valid_positive() -> None:
    expected = {
        "id": "DAAS-001",
        "category": "prompt-manipulation",
        "artifact": "a/SKILL.md",
        "line": 3,
        "evidence_contains": "attack",
    }
    actual = {
        "id": "DAAS-001",
        "category": "prompt-manipulation",
        "artifact": "a/SKILL.md",
        "line": 3,
        "evidence": "attack",
    }
    rows = [
        {
            "id": "one",
            "split": "realworld-malicious",
            "expected": ["DAAS-001"],
            "expected_findings": [expected],
            "expected_absent": ["DRAGON-PI-001"],
            "actual": [actual, {"id": "DRAGON-PI-001", "artifact": "a/SKILL.md", "line": 4}],
            "notes": "test",
        }
    ]
    result = measure_realworld(rows)
    assert (result["summary"]["tp"], result["summary"]["fp"], result["summary"]["fn"]) == (1, 1, 0)
    assert result["targeted_negative_failures"] == 1
    assert result["occurrence"]["correct"] == 1
