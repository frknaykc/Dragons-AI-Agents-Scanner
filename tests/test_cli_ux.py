"""Terminal-only UX contracts; scanned text remains inert input."""

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from dragonscan import cli
from dragonscan.models import (
    Artifact,
    ArtifactKind,
    Classification,
    Confidence,
    Diagnostic,
    Finding,
    InstalledEnvironment,
    ScanReport,
    Severity,
    SourceFormat,
)
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
        assert f"┌─ {severity.value.upper()}" in plain
    assert "Policy      " in plain and policy.status.upper() in plain
    assert "Rule:           DAAS-001" in plain
    assert all(
        f"{label}:" in plain
        for label in ("File", "Evidence", "Reason", "Check", "False positive", "Fix")
    )
    assert "\x1b[38;5;208mMEDIUM" in colored
    assert "\x1b[1;36mCheck:" in colored


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
    assert "Coverage    100 limited analyses; 1 warning" in text
    assert text.index("Findings (0)") < text.index("Scan coverage & diagnostics")
    assert "Example:" not in text and "artifact-0" not in text
    assert "artifact-99" not in text
    assert len(json.loads(json_report(report))["diagnostics"]) == 101
    assert "\x1b" not in json_report(report) + sarif_report(report)


def test_finding_cards_scope_and_guidance_are_terminal_only(tmp_path: Path) -> None:
    report = ScanReport(
        tmp_path,
        (),
        (
            replace(
                _finding(tmp_path / "config.toml", Severity.MEDIUM),
                detection_id="DRAGON-MCP-001",
                title="Unpinned MCP runtime package",
                confidence=Confidence.MEDIUM,
                evidence="MCP server invokes a mutable package or container image reference",
            ),
        ),
        diagnostics=(Diagnostic("coverage", "installed-agent scan limit reached"),),
    )
    plain = terminal_report(report)
    assert "╔═ Findings (1)" in plain and "┌─ MEDIUM" in plain
    assert plain.index("Findings (1)") < plain.index("Scan coverage & diagnostics")
    assert "mutable" in plain and "version or digest" in plain
    assert "Confidence:     MEDIUM" in plain
    assert "no package was fetched" not in plain  # Not asserted by this synthetic finding.
    assert "not security findings" in plain
    assert "Check:" not in json_report(report)


def test_finding_card_wraps_long_untrusted_fields_without_terminal_controls(tmp_path: Path) -> None:
    report = ScanReport(
        tmp_path,
        (),
        (replace(_finding(tmp_path / ("x" * 180 + ".md")), evidence="\x1b[31m" + "x" * 200),),
    )
    plain = terminal_report(report)
    assert "\\x1b[31m" in plain and "\x1b[31m" not in plain
    assert all(len(line) <= 80 for line in plain.splitlines() if line.startswith(("│", "┌", "└")))


def test_installed_summary_is_compact_and_lists_only_discovered_agents(tmp_path: Path) -> None:
    report = ScanReport(
        tmp_path,
        (
            Artifact(tmp_path / "SKILL.md", ArtifactKind.SKILL, SourceFormat.MARKDOWN),
            Artifact(tmp_path / "mcp.json", ArtifactKind.MCP_CONFIG, SourceFormat.JSON),
            Artifact(tmp_path / "AGENTS.md", ArtifactKind.INSTRUCTIONS, SourceFormat.MARKDOWN),
        ),
        (),
        installed_environments=(
            InstalledEnvironment(
                "Codex", tmp_path, "local", (), "discovered", resolution="partial"
            ),
            InstalledEnvironment("Codex", tmp_path / "other", "local", (), "discovered"),
            InstalledEnvironment("Absent", tmp_path / "absent", "local", (), "not_found"),
            InstalledEnvironment("Claude", tmp_path / "claude", "local", (), "discovered"),
        ),
        diagnostics=(Diagnostic("coverage", "region skipped"), Diagnostic("warning", "invalid")),
    )
    text = terminal_report(report, report_path=tmp_path / "scan.json")
    header = text.split("╔═ Findings")[0]
    assert "Agents      Claude, Codex (2 found; 1 partial root)" in header
    assert "Scanned     Skills 1, MCP configs 1, instructions 1" in header
    assert f"Report      {ascii(str(tmp_path / 'scan.json'))}" in header
    assert "Artifacts   3" in header
    assert "Absent" not in text and "installation=not_checked" not in text
    assert "Coverage    1 limited analysis; 1 warning; 1 partial agent root" in text
    assert "Installed agents (inventory only)" not in text
    assert "installed_agents" in json.loads(json_report(report))


def test_installed_default_saves_private_json_and_retains_exit_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(cli.Path, "home", lambda: home)
    report = ScanReport(
        home,
        (),
        (),
        installed_environments=(
            InstalledEnvironment(
                "Codex", home / ".codex", "local", (), "discovered", resolution="partial"
            ),
        ),
    )
    monkeypatch.setattr(cli.Scanner, "scan_installed", lambda self, target: report)
    result = CliRunner().invoke(cli.main, ["scan", "--installed-agents"])
    assert result.exit_code == 3
    files = list(home.glob("dragonscan-*/scan.json"))
    assert len(files) == 1
    saved = json.loads(files[0].read_text())
    assert saved["policy"]["status"] == "incomplete"
    assert saved["installed_agents"]["environments"][0]["agent"] == "Codex"
    assert f"Report      {ascii(str(files[0]))}" in result.stdout
    assert "See the JSON report" in result.stdout
    assert result.stdout.index("Agents      Codex") < result.stdout.index("Findings (0)")
    assert not list(home.glob("dragonscan-*/scan.json.tmp"))
    if cli.os.name != "nt":
        assert files[0].parent.stat().st_mode & 0o077 == 0
        assert files[0].stat().st_mode & 0o077 == 0


def test_installed_json_does_not_save_implicit_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(
        cli.Scanner, "scan_installed", lambda self, target: ScanReport(tmp_path, (), ())
    )
    result = CliRunner().invoke(cli.main, ["scan", "--installed-agents", "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["target"] == str(tmp_path)
    assert not list(tmp_path.glob("dragonscan-*/scan.json"))


def test_explicit_terminal_output_is_not_mislabeled_as_json(tmp_path: Path) -> None:
    report = ScanReport(tmp_path, (), (), diagnostics=(Diagnostic("coverage", "skipped"),))
    text = terminal_report(report, report_path=tmp_path / "report.json")
    assert "Use --format json --output PATH" in text
    assert "See the JSON report" not in text


def test_installed_report_write_failure_is_not_a_clean_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli.Scanner, "scan_installed", lambda self, target: ScanReport(tmp_path, (), ())
    )

    def denied(**kwargs: object) -> str:
        raise OSError("private path")

    monkeypatch.setattr(cli.tempfile, "mkdtemp", denied)
    result = CliRunner().invoke(cli.main, ["scan", "--installed-agents"])
    assert result.exit_code == 3
    assert result.stdout == ""
    assert "Private report output failed" in result.stderr
    assert "private path" not in result.output


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
