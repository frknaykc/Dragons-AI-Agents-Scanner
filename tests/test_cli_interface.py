"""Entry-point routing and line-oriented CLI selection."""

import json
from pathlib import Path

from click.testing import CliRunner
from pytest import MonkeyPatch

from dragonscan import cli
from dragonscan.installed_agents import SPECS


def test_direct_path_and_options_match_scan_subcommand(tmp_path: Path) -> None:
    target = tmp_path / "SKILL.md"
    target.write_text("ordinary guidance")
    runner = CliRunner()
    original = runner.invoke(cli.main, ["scan", str(target), "--format", "json"])
    direct = runner.invoke(cli.main, [str(target), "--format", "json"])
    options_first = runner.invoke(cli.main, ["--format", "json", str(target)])
    assert original.exit_code == direct.exit_code == options_first.exit_code == 0
    assert (
        json.loads(original.output) == json.loads(direct.output) == json.loads(options_first.output)
    )
    assert "DRAGONSCAN" not in direct.output
    assert runner.invoke(cli.main, ["--format", "json"]).exit_code == 2
    assert runner.invoke(cli.main, ["--not-a-flag", str(target)]).exit_code == 2
    assert runner.invoke(cli.main, ["intel", "--help"]).exit_code == 0


def test_direct_installed_flags_are_one_shot(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    root = tmp_path / ".codex"
    root.mkdir()
    (root / "config.toml").write_text("title = 'test'")
    monkeypatch.setattr("dragonscan.installed_agents.Path.home", lambda: tmp_path)
    result = CliRunner().invoke(
        cli.main, ["--installed-agents", "--agent", "Codex", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.output)["artifacts"]) == 1
    assert not list(tmp_path.glob("dragonscan-*/scan.json"))


def test_tui_is_explicit_and_rejects_scan_arguments(monkeypatch: MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    monkeypatch.setattr("dragonscan.tui.run_tui", lambda: calls.append("tui"))
    runner = CliRunner()
    assert runner.invoke(cli.main, ["-tui"]).exit_code == 0
    assert calls == ["tui"]
    assert runner.invoke(cli.main, ["-tui", "scan", "./SKILL.md"]).exit_code == 2
    assert calls == ["tui"]
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: False)
    assert runner.invoke(cli.main, ["-tui"]).exit_code == 2


def test_guided_path_scans_only_after_confirmation(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    target = tmp_path / "SKILL.md"
    target.write_text("ordinary guidance")
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(cli, "_terminal_color_enabled", lambda: False)
    runner = CliRunner()
    cancelled = runner.invoke(cli.main, [], input=f"3\n{target}\nn\n")
    assert cancelled.exit_code == 0, cancelled.output
    assert "▤" in cancelled.output and "READY TO SCAN" in cancelled.output
    assert "Scan cancelled." in cancelled.output and "Findings" not in cancelled.output
    confirmed = runner.invoke(cli.main, [], input=f"3\n{target}\ny\n")
    assert confirmed.exit_code == 0, confirmed.output
    assert "Status      COMPLETE" in confirmed.output
    assert "Policy      PASS" in confirmed.output
    assert "\x1b[" not in confirmed.output
    via_scan = runner.invoke(cli.main, ["scan"], input=f"3\n{target}\ny\n")
    assert via_scan.exit_code == 0, via_scan.output
    assert "Status      COMPLETE" in via_scan.output


def test_guided_one_agent_and_all_agents_cancel_without_scanning(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    runner = CliRunner()
    one = runner.invoke(cli.main, [], input="2\n1\nn\n")
    assert one.exit_code == 0, one.output
    assert SPECS[0].kind in one.output and "Scan cancelled." in one.output
    all_agents = runner.invoke(cli.main, [], input="1\nn\n")
    assert all_agents.exit_code == 0, all_agents.output
    assert "Known local agents" in all_agents.output
    assert "Scan cancelled." in all_agents.output


def test_guided_noninteractive_and_aborted_input_do_not_scan(
    monkeypatch: MonkeyPatch,
) -> None:
    runner = CliRunner()
    assert runner.invoke(cli.main, []).exit_code == 2
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    assert runner.invoke(cli.main, [], input="").exit_code != 0
