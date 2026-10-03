"""Verified local agent surfaces with inert, synthetic user/project layouts."""

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from dragonscan.installed_agents import MAX_DEPTH, MAX_ENTRIES_PER_ROOT, discover_installed
from dragonscan.models import Target
from dragonscan.reporting import json_report
from dragonscan.scanner import Scanner

# Relative user root, marker, project root, project artifact, instruction under user/project.
CASES = (
    (
        "OpenCode",
        ".config/opencode",
        "opencode.json",
        ".opencode",
        "agents/reviewer.md",
        "agents/reviewer.md",
    ),
    ("Qwen Code", ".qwen", "settings.json", ".qwen", "QWEN.md", "QWEN.md"),
    ("Kiro", ".kiro", "settings/cli.json", ".kiro", "steering/team.md", "steering/team.md"),
    (
        "Continue",
        ".continue",
        "config.yaml",
        ".continue",
        "rules/team.md",
        "rules/team.md",
    ),
    ("Cline", ".cline", "mcp.json", ".cline", "rules/team.md", "rules/team.md"),
)


def _write(root: Path, relative: str, content: str = "ordinary guidance\n") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.mark.parametrize(
    "agent,user_root,marker,project_root,instruction,project_instruction", CASES
)
def test_verified_surfaces_keep_identity_and_static_pipeline(
    tmp_path: Path,
    agent: str,
    user_root: str,
    marker: str,
    project_root: str,
    instruction: str,
    project_instruction: str,
) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    user = home / user_root
    config = _write(user, marker, "{}" if marker.endswith(".json") else "name: inert\n")
    user_rule = _write(user, instruction)
    project_rule = _write(project / project_root, project_instruction)
    skills: set[Path] = set()
    if agent in {"OpenCode", "Qwen Code", "Cline"}:
        skills = {
            _write(user, "skills/review/SKILL.md"),
            _write(project / project_root, "skills/review/SKILL.md"),
        }
    if agent == "OpenCode":
        project_config = _write(project, "opencode.json", "{}")
    elif agent == "Continue":
        project_config = _write(project, ".continuerc.json", "{}")
    elif agent == "Kiro":
        project_config = _write(project / project_root, "settings/mcp.json", "{}")
    else:
        project_config = _write(
            project / project_root, marker, "{}" if marker.endswith(".json") else "name: inert\n"
        )
    report = Scanner().scan_installed(Target(project), home=home, platform="darwin")
    paths = {item.path for item in report.artifacts}
    assert {config, user_rule, project_config, project_rule, *skills} <= paths
    assert {
        item.scope
        for item in report.installed_environments
        if item.agent == agent and item.status == "discovered"
    } == {"user", "project"}
    assert {
        item.agent
        for item in report.artifact_origins
        if item.provenance == "installed_agent"
        and item.artifact in {config, user_rule, project_config, project_rule}
    } == {agent}
    assert all(
        item.installation_evidence == "not_checked" for item in report.installed_environments
    )
    assert not report.errors
    assert {
        item["agent"]
        for item in json.loads(json_report(report))["installed_agents"]["artifacts"]
        if item["provenance"] == "installed_agent"
        and item["artifact"] in {str(config), str(project_config)}
    } == {agent}


def test_new_project_identity_requires_direct_documented_surface(tmp_path: Path) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    unsupported = _write(project, ".kiro/settings/cli.json", "{}")
    nested = _write(project, "nested/.qwen/QWEN.md")
    report = Scanner().scan_installed(Target(project), home=home, platform="darwin")
    assert not any(
        origin.provenance == "installed_agent" and origin.artifact in {unsupported, nested}
        for origin in report.artifact_origins
    )
    assert not any(
        env.scope == "project" and env.agent in {"Kiro", "Qwen Code"}
        for env in report.installed_environments
    )


def test_mcp_is_static_and_shared_files_do_not_claim_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    _write(project, "AGENTS.md")
    _write(project, "mcp.json", '{"mcpServers": {"shared": {"command": "inert"}}}')
    _write(project, ".agents/skills/shared/SKILL.md")
    _write(project, ".qwen/settings.json", '{"mcpServers": {"local": {"command": "inert"}}}')
    _write(project, ".kiro/settings/mcp.json", '{"mcpServers": {"kiro": {"command": "inert"}}}')
    _write(
        project,
        ".continue/mcpServers/mcp.json",
        '{"mcpServers": {"continue": {"command": "inert"}}}',
    )
    _write(project, ".cline/mcp.json", '{"mcpServers": {"cline": {"command": "inert"}}}')

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("execution or network during discovery")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    report = Scanner().scan_installed(Target(project), home=home)
    assert {item.agent for item in report.installed_mcp_servers if item.agent is not None} == {
        "Qwen Code",
        "Kiro",
        "Continue",
        "Cline",
    }
    assert any(item.agent is None for item in report.installed_mcp_servers)
    assert all(
        item.agent is None
        for item in report.artifact_origins
        if item.provenance == "explicit_target"
        and item.artifact
        in {project / "AGENTS.md", project / "mcp.json", project / ".agents/skills/shared/SKILL.md"}
    )
    assert report.dynamic_status == "not_requested"
    assert not report.errors


def test_absent_and_unrelated_locations_are_not_discovered(tmp_path: Path) -> None:
    _write(tmp_path, "AGENTS.md")
    _write(tmp_path, ".opencode/unknown.json", "{}")
    _write(tmp_path, ".qwen/unknown.json", "{}")
    _write(tmp_path, ".kiro/unknown.json", "{}")
    _write(tmp_path, ".continue/unknown.json", "{}")
    _write(tmp_path, ".cline/unknown.json", "{}")
    result = discover_installed(home=tmp_path)
    assert not result.artifacts
    assert all(item.status == "not_found" for item in result.environments)


def test_project_only_clinerules_and_home_only_opencode_config(tmp_path: Path) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    _write(home, ".opencode/skills/fake/SKILL.md")
    _write(project, ".clinerules/team.md")
    _write(project, ".opencode/skills/review/SKILL.md")
    _write(project, "opencode.json", "{}")
    report = Scanner().scan_installed(Target(project), home=home)
    assert {"Cline", "OpenCode"} <= {
        item.agent for item in report.installed_environments if item.scope == "project"
    }
    assert not any(item.root == home / ".opencode" for item in report.installed_environments)
    assert not report.errors


def test_new_root_budget_and_symlink_guards(tmp_path: Path) -> None:
    root = tmp_path / ".kiro"
    config = _write(root, "settings/cli.json", "{}")
    for i in range(MAX_ENTRIES_PER_ROOT):
        (root / f"ignored-{i}").touch()
    (root / "steering").mkdir()
    (root / "steering" / "escape.md").symlink_to(tmp_path / "AGENTS.md")
    result = discover_installed(home=tmp_path)
    kiro = next(item for item in result.environments if item.agent == "Kiro")
    assert kiro.resolution == "partial"
    assert config in {item.path for item in result.artifacts}
    assert not any(item.path.name == "escape.md" for item in result.artifacts)
    assert MAX_DEPTH == 4
    assert MAX_ENTRIES_PER_ROOT == 2048
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / ".cline" / "mcp.json"
        fifo.parent.mkdir(parents=True)
        os.mkfifo(fifo)
        assert not any(item.path == fifo for item in discover_installed(home=tmp_path).artifacts)
