"""Terminal-only UX contracts; scanned text remains inert input."""

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from dragonscan import cli
from dragonscan.models import Classification, Confidence, Diagnostic, Finding, ScanReport, Severity
from dragonscan.policy import evaluate
from dragonscan.reporting import json_report, sarif_report, terminal_report


def _finding(path: Path, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        "DAAS-001",
        "test",
        "Title",
        severity,
        Confidence.HIGH,
        Classification.RISKY,
        path,
        "Explanation",
        "Evidence",
        "Review",
        "test",
        line=2,
    )


def test_scan_help_groups_and_safety_warnings() -> None:
    assert cli.main is not None
    help_text = CliRunner().invoke(cli.main, ["scan", "--help"]).output
    assert all(
        section in help_text for section in ("Target:", "Policy:", "Output:", "Optional analysis:")
    )
    assert help_text.index("Target:") < help_text.index("Policy:") < help_text.index("Output:")
    assert "remote Git is" in help_text and "unavailable" in help_text
    assert "sends excerpts" in help_text and "OSV over HTTPS" in help_text
    assert "blocked without required isolation" in help_text
    assert "WITHOUT network or filesystem" in help_text
    assert CliRunner().invoke(cli.main, ["--help"]).exit_code == 0


@pytest.mark.parametrize("status", ["complete", "partial", "failed"])
def test_status_and_severity_styling(tmp_path: Path, status: str) -> None:
    report = ScanReport(
        tmp_path, (), tuple(_finding(tmp_path / "SKILL.md", severity) for severity in Severity)
    )
    if status == "partial":
        report = replace(report, diagnostics=(Diagnostic("coverage", "skipped region"),))
    if status == "failed":
        report = replace(report, errors=("load error",))
    policy = evaluate(report)
    colored = terminal_report(report, policy, color=True)
    plain = terminal_report(report, policy)
    assert f"Status      {status.upper()}" in plain
    assert "\x1b[" in colored and "\x1b[" not in plain
    assert re.sub(r"\x1b\[[0-9;]+m", "", colored) == plain
    for severity in Severity:
        assert severity.value.upper() in colored
        assert f"{severity.value.upper()}  DAAS-001" in plain
    assert "Policy      " in plain and policy.status.upper() in plain
    assert "  File      " in plain and "  Evidence  " in plain and "  Reason    " in plain


def test_diagnostics_grouping_and_machine_formats_unchanged(tmp_path: Path) -> None:
    report = ScanReport(
        tmp_path,
        (),
        (),
        diagnostics=tuple(
            Diagnostic("coverage", f"artifact-{n}: region skipped") for n in range(100)
        )
        + (Diagnostic("warning", "broken metadata"),),
    )
    text = terminal_report(report)
    assert "COVERAGE: 100" in text and "100 x region skipped" in text
    assert text.index("Diagnostics") < text.index("Findings    None")
    assert "WARNING: 1" in text and "Example: artifact-0: region skipped" in text
    assert "artifact-99" not in text
    assert len(json.loads(json_report(report))["diagnostics"]) == 101
    assert "\x1b" not in json_report(report) + sarif_report(report)


def test_untrusted_text_never_becomes_terminal_control(tmp_path: Path) -> None:
    hostile = "[bold]\x1b[31m\n\u202e"
    finding = replace(
        _finding(tmp_path / ("SKILL" + hostile + ".md")),
        title=hostile,
        explanation=hostile,
        evidence=hostile,
    )
    report = ScanReport(tmp_path, (), (finding,), diagnostics=(Diagnostic("warning", hostile),))
    colored = terminal_report(report, color=True)
    assert hostile not in colored
    assert "\\x1b" in colored and "\\n" in colored and "\\u202e" in colored
    assert colored.count("\x1b[") == colored.count("\x1b[0m") * 2


def test_cli_tty_no_color_and_machine_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = ScanReport(tmp_path, (), (_finding(tmp_path / "SKILL.md"),))
    monkeypatch.setattr(cli, "scan_target", lambda target: report)
    runner = CliRunner()
    monkeypatch.setattr(cli, "_terminal_color_enabled", lambda: True)
    color = runner.invoke(cli.main, ["scan", str(tmp_path)])
    assert color.exit_code == 0 and "\x1b[" in color.stdout
    for fmt in ("json", "sarif"):
        response = runner.invoke(cli.main, ["scan", str(tmp_path), "--format", fmt])
        assert response.exit_code == 0 and "\x1b[" not in response.stdout
        assert response.stdout.startswith("{")
    file_path = tmp_path / "report.txt"
    output = runner.invoke(cli.main, ["scan", str(tmp_path), "--output", str(file_path)])
    assert output.exit_code == 0 and not output.stdout and "\x1b[" not in file_path.read_text()
    monkeypatch.setattr(cli, "_terminal_color_enabled", lambda: False)
    assert "\x1b[" not in runner.invoke(cli.main, ["scan", str(tmp_path)]).stdout


def test_color_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert cli._terminal_color_enabled()
    monkeypatch.setenv("NO_COLOR", "")
    assert not cli._terminal_color_enabled()
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False)
    assert not cli._terminal_color_enabled()
