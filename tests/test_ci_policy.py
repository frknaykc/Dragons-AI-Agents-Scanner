"""Offline CI policy and renderer contract tests."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from dragonscan.cli import main
from dragonscan.models import (
    Classification,
    Confidence,
    Finding,
    InstalledEnvironment,
    ScanReport,
    Severity,
)
from dragonscan.policy import evaluate


def finding(path: Path, severity: Severity) -> Finding:
    return Finding(
        "DAAS-001",
        "test",
        "Test",
        severity,
        Confidence.HIGH,
        Classification.RISKY,
        path,
        "A static finding",
        "bounded evidence",
        "Review",
        "test",
        line=2,
    )


@pytest.mark.parametrize(
    ("severities", "changes", "expected", "code"),
    [
        ((), {}, "pass", 0),
        ((Severity.LOW,), {}, "pass", 0),
        ((Severity.HIGH,), {}, "policy_violation", 1),
        ((Severity.CRITICAL,), {}, "policy_violation", 1),
        ((Severity.MEDIUM, Severity.HIGH), {}, "policy_violation", 1),
        ((), {"acquisition_status": "partial"}, "incomplete", 3),
        ((Severity.HIGH,), {"acquisition_status": "partial"}, "incomplete", 3),
        ((), {"errors": ("parse failure",)}, "scan_error", 3),
        ((), {"acquisition_status": "blocked"}, "scan_error", 3),
        ((), {"acquisition_status": "failed"}, "scan_error", 3),
        ((), {"semantic_status": "partial"}, "incomplete", 3),
        ((), {"vulnerability_status": "partial"}, "incomplete", 3),
        ((), {"dynamic_status": "blocked"}, "incomplete", 3),
    ],
)
def test_policy_and_three_formats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    severities: tuple[Severity, ...],
    changes: dict[str, object],
    expected: str,
    code: int,
) -> None:
    report = replace(
        ScanReport(
            tmp_path, (), tuple(finding(tmp_path / "SKILL.md", level) for level in severities)
        ),
        **changes,
    )
    monkeypatch.setattr("dragonscan.cli.scan_target", lambda target: report)
    assert evaluate(report, Severity.HIGH).status == expected
    outputs = {}
    for fmt in ("terminal", "json", "sarif"):
        response = CliRunner().invoke(
            main, ["scan", str(tmp_path), "--fail-on", "high", "--format", fmt]
        )
        assert response.exit_code == code, response.output
        outputs[fmt] = response.stdout
    assert f"Policy      {expected.upper()}" in outputs["terminal"]
    assert f"Findings    {len(severities)}" in outputs["terminal"]
    assert json.loads(outputs["json"])["policy"]["status"] == expected
    assert (
        json.loads(outputs["json"])["scan_status"]
        == {
            "pass": "complete",
            "policy_violation": "complete",
            "incomplete": "partial",
            "scan_error": "failed",
        }[expected]
    )
    sarif_run = json.loads(outputs["sarif"])["runs"][0]
    assert sarif_run["properties"]["policy"]["status"] == expected
    assert len(sarif_run["results"]) == len(severities)
    assert all(item["ruleId"] == "DAAS-001" for item in sarif_run["results"])
    assert "parse failure" not in outputs["sarif"]


def test_explicit_strict_coverage_and_default_compatibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = InstalledEnvironment("agent", tmp_path, "local", (), "discovered", resolution="partial")
    report = ScanReport(tmp_path, (), (), installed_environments=(env,))
    monkeypatch.setattr("dragonscan.cli.scan_target", lambda target: report)
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(tmp_path)]).exit_code == 3
    result = runner.invoke(
        main, ["scan", str(tmp_path), "--fail-on-incomplete", "--format", "json"]
    )
    assert result.exit_code == 3
    assert json.loads(result.output)["policy"]["status"] == "incomplete"


def test_output_file_is_atomic_and_stdout_clean(tmp_path: Path) -> None:
    source = tmp_path / "SKILL.md"
    source.write_text("An ordinary instruction.\n")
    destination = tmp_path / "results.sarif"
    result = CliRunner().invoke(
        main, ["scan", str(source), "--format", "sarif", "--output", str(destination)]
    )
    assert result.exit_code == 0 and result.stdout == ""
    assert json.loads(destination.read_text())["version"] == "2.1.0"
    before = destination.read_bytes()
    bad = CliRunner().invoke(
        main, ["scan", str(source), "--format", "sarif", "--output", str(tmp_path)]
    )
    assert bad.exit_code == 3
    assert destination.read_bytes() == before
    assert not list(tmp_path.glob(".dragonscan-*"))


def test_invalid_threshold_does_not_start_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("dragonscan.cli.scan_target", lambda target: pytest.fail("scanner invoked"))
    assert CliRunner().invoke(main, ["scan", str(tmp_path), "--fail-on", "HIGH"]).exit_code == 2


def test_unexpected_scanner_failure_is_not_policy_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(target: object) -> ScanReport:
        raise RuntimeError("provider debug secret")

    monkeypatch.setattr("dragonscan.cli.scan_target", broken)
    for fmt in ("terminal", "json", "sarif"):
        response = CliRunner().invoke(main, ["scan", str(tmp_path), "--format", fmt])
        assert response.exit_code == 3
        assert "provider debug secret" not in response.output
        if fmt == "json":
            assert json.loads(response.stdout)["policy"]["status"] == "scan_error"


@pytest.mark.parametrize("name", ["unsupported.bin", "mcp.json"])
def test_real_invalid_target_never_becomes_clean_or_sarif_vulnerability(
    tmp_path: Path, name: str
) -> None:
    path = tmp_path / name
    path.write_text("{" if name == "mcp.json" else "not a supported artifact")
    for fmt in ("terminal", "json", "sarif"):
        response = CliRunner().invoke(main, ["scan", str(path), "--format", fmt])
        assert response.exit_code == 3, response.output
        if fmt == "json":
            data = json.loads(response.stdout)
            assert data["findings"] == [] and data["policy"]["status"] == "scan_error"
        if fmt == "sarif":
            assert json.loads(response.stdout)["runs"][0]["results"] == []
