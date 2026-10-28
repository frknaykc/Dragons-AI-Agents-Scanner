"""Interactive scan selection and local report browsing."""

import asyncio
import json
from pathlib import Path

from click.testing import CliRunner
from pytest import MonkeyPatch
from textual.widgets import Input, Select, SelectionList, Static, Tree

from dragonscan.cli import main
from dragonscan.models import ScanReport
from dragonscan.tui import ScanApp


def test_noninteractive_entrypoints_require_target_or_terminal() -> None:
    for args in ([], ["scan"]):
        result = CliRunner().invoke(main, args)
        assert result.exit_code == 2
    assert CliRunner().invoke(main, ["scan", "--agent", "Codex"]).exit_code == 2


def test_explicit_agent_scan_is_noninteractive_and_accepts_discovery_budgets(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    root = tmp_path / ".codex"
    root.mkdir()
    (root / "config.toml").write_text("title = 'test'")
    monkeypatch.setattr("dragonscan.installed_agents.Path.home", lambda: tmp_path)
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--installed-agents",
            "--agent",
            "Codex",
            "--max-entries-per-root",
            "4096",
            "--max-artifacts",
            "512",
            "--max-artifacts-per-root",
            "300",
            "--max-depth",
            "8",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert len(data["artifacts"]) == 1
    assert {entry["agent"] for entry in data["installed_agents"]["environments"]} == {"Codex"}
    assert not list(tmp_path.glob("dragonscan-*/scan.json"))


def test_local_directory_artifact_budget_can_be_raised_without_hiding_limits(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr("dragonscan.discovery.MAX_FILES", 1)
    for name in ("AGENTS.md", "SKILL.md"):
        (tmp_path / name).write_text("ordinary guidance")
    limited = CliRunner().invoke(main, ["scan", str(tmp_path), "--format", "json"])
    assert limited.exit_code == 3
    assert "artifact count exceeds limit" in limited.output
    complete = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--max-artifacts", "2", "--format", "json"]
    )
    assert complete.exit_code == 0, complete.output
    assert len(json.loads(complete.output)["artifacts"]) == 2
    assert CliRunner().invoke(main, ["scan", str(tmp_path), "--max-depth", "2"]).exit_code == 2


def test_tui_path_scan_and_private_json_export(tmp_path: Path) -> None:
    target = tmp_path / "SKILL.md"
    target.write_text("ordinary guidance")
    output = tmp_path / "report.json"

    async def run() -> None:
        app = ScanApp()
        async with app.run_test() as pilot:
            assert app.stage == "splash"
            assert app.query_one("#splash").display
            assert "Loading" in str(app.query_one("#splash-progress", Static).render())
            app._end_splash()
            assert app.stage == "target"
            assert "Welcome to DragonScan" in str(
                app.query_one("#target .welcome-heading", Static).render()
            )
            assert app.focused is app.query_one("#mode")
            assert "Change target" in str(app.query_one("#navigation", Static).render())
            assert "Enter" in str(app.query_one("#navigation", Static).render())
            for expected in ("scope", "confirm"):
                await pilot.press("enter")
                await pilot.pause()
                assert app.stage == expected
            await pilot.press("escape")
            await pilot.pause()
            assert app.stage == "scope"
            app._set_mode("path")
            app.query_one("#path", Input).value = str(target)
            app.query_one("#artifacts", Input).value = "2"
            await pilot.press("enter")
            await pilot.pause()
            assert "require a local directory" in str(app.query_one("#status", Static).render())
            app.query_one("#artifacts", Input).value = ""
            await pilot.press("enter")
            await pilot.pause()
            assert app.stage == "confirm"
            await pilot.press("enter")
            for _ in range(30):
                await pilot.pause(0.05)
                if app.report is not None:
                    break
            assert app.report is not None, str(app.query_one("#status", Static).content)
            assert app.report.artifacts[0].path == target
            app.query_one("#export-path", Input).value = str(output)
            app.set_focus(app.query_one("#export-path", Input))
            await pilot.press("ctrl+e")
            await pilot.pause()
            assert json.loads(output.read_text())["target"] == str(target)
            assert output.stat().st_mode & 0o777 == 0o600
            await pilot.press("ctrl+e")
            await pilot.pause()
            assert json.loads(output.read_text())["target"] == str(target)

    asyncio.run(run())


def test_tui_agent_selection_and_budgets_are_forwarded(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []

    def fake_scan(self: object, **kwargs: object) -> ScanReport:
        calls.append(kwargs)
        return ScanReport(tmp_path, (), ())

    monkeypatch.setattr("dragonscan.tui.Scanner.scan_installed", fake_scan)
    monkeypatch.setattr(
        "dragonscan.cli._save_installed_report", lambda *args: tmp_path / "scan.json"
    )

    async def run() -> None:
        app = ScanApp()
        async with app.run_test() as pilot:
            app._end_splash()
            await pilot.press("right", "enter", "enter", "down", "enter")
            assert app.query_one("#agent", Select).value == "Codex"
            await pilot.press("tab", "enter")
            await pilot.pause()
            app.query_one("#entries", Input).value = "4096"
            await pilot.press("enter")
            await pilot.pause()
            assert app.stage == "confirm"
            await pilot.press("enter")
            for _ in range(30):
                await pilot.pause(0.05)
                if app.report is not None:
                    break
            assert app.report is not None
            assert calls == [
                {
                    "agent": "Codex",
                    "max_entries_per_root": 4096,
                    "max_artifacts": None,
                    "max_artifacts_per_root": None,
                    "max_depth": None,
                }
            ]
            assert app.saved_path == tmp_path / "scan.json"
            assert app.query_one("#findings-tree", Tree) is not None

    asyncio.run(run())


def test_tui_findings_expand_and_sarif_export(tmp_path: Path) -> None:
    fixture = Path(__file__).resolve().parents[1] / "benchmarks/corpus/pi-override/SKILL.md"
    destination = tmp_path / "findings.sarif"

    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(100, 40)) as pilot:
            app._end_splash()
            app._set_mode("path")
            app.query_one("#path", Input).value = str(fixture)
            await pilot.press("enter", "enter")
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("enter")
            for _ in range(30):
                await pilot.pause(0.05)
                if app.report is not None:
                    break
            assert app.report is not None and app.report.findings
            tree = app.query_one("#findings-tree", Tree)
            group = tree.root.children[0]
            assert app.focused is tree
            await pilot.press("enter")
            await pilot.pause()
            assert group.is_expanded
            severity = group.children[0]
            await pilot.press("down", "enter")
            await pilot.pause()
            assert severity.is_expanded
            await pilot.press("down")
            await pilot.pause()
            assert tree.get_node_at_line(tree.cursor_line) is severity.children[0]
            assert "EVIDENCE" in str(app.query_one("#finding-content", Static).render())
            app.query_one("#export-format", Select).value = "sarif"
            app.query_one("#export-path", Input).value = str(destination)
            await pilot.press("ctrl+e")
            await pilot.pause()
            assert json.loads(destination.read_text())["version"] == "2.1.0"

    asyncio.run(run())


def test_tui_directory_scope_excludes_kinds_and_depth_with_coverage(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("ordinary guidance")
    (tmp_path / "mcp.json").write_text("{}")
    nested = tmp_path / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "SKILL.md").write_text("ordinary skill")

    async def run() -> None:
        app = ScanApp()
        async with app.run_test(size=(90, 30)) as pilot:
            app._end_splash()
            app._set_mode("path")
            app.query_one("#path", Input).value = str(tmp_path)
            await pilot.press("enter", "enter")
            await pilot.pause()
            app.query_one("#kinds", SelectionList).deselect("mcp")
            app.query_one("#depth", Input).value = "1"
            await pilot.press("enter")
            await pilot.pause()
            assert app.stage == "confirm"
            assert app.report is None
            assert "guidance" in str(app.query_one("#review", Static).render())
            await pilot.press("enter")
            for _ in range(30):
                await pilot.pause(0.05)
                if app.report is not None:
                    break
            assert app.report is not None
            assert {item.path.name for item in app.report.artifacts} == {"AGENTS.md"}
            assert app.policy is not None and app.policy.scan_status == "partial"
            coverage = " ".join(item.message for item in app.report.diagnostics)
            assert "Excluded artifacts: 1" in coverage and "depth limited to 1" in coverage
            assert app.stage == "results"
            await pilot.press("ctrl+r")
            await pilot.pause()
            assert app.stage == "target"

    asyncio.run(run())


def test_tui_empty_group_rejected_before_scan(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("ordinary guidance")

    async def run() -> None:
        app = ScanApp()
        async with app.run_test() as pilot:
            app._end_splash()
            app._set_mode("path")
            app.query_one("#path", Input).value = str(tmp_path)
            await pilot.press("enter", "enter")
            await pilot.pause()
            app.query_one("#kinds", SelectionList).deselect_all()
            await pilot.press("enter")
            await pilot.pause()
            assert app.stage == "scope"
            assert "Select at least one" in str(app.query_one("#status", Static).render())
            assert app.report is None

    asyncio.run(run())


def test_splash_keyboard_and_local_artifact_budget(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("ordinary guidance")
    (tmp_path / "SKILL.md").write_text("ordinary skill")

    async def run() -> None:
        app = ScanApp()
        async with app.run_test() as pilot:
            assert app.stage == "splash"
            await pilot.press("enter")
            await pilot.pause()
            assert app.stage == "target"
            app._set_mode("path")
            app.query_one("#path", Input).value = str(tmp_path)
            await pilot.press("enter", "enter")
            await pilot.pause()
            app.query_one("#artifacts", Input).value = "2"
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("enter")
            for _ in range(30):
                await pilot.pause(0.05)
                if app.report is not None:
                    break
            assert app.report is not None
            assert len(app.report.artifacts) == 2
            assert app.policy is not None and app.policy.scan_status == "complete"
            assert not app.report.diagnostics  # Equality alone is not budget exhaustion.
            assert app.report.coverage["fully_analyzed"] == 2

    asyncio.run(run())
